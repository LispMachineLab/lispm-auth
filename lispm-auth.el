;;; lispm-auth.el --- LispM's secrets, encrypted and opened with a password  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Ryan.K

;; Author: Ryan.K
;; URL: https://github.com/LispMachineLab/lispm-auth
;; Version: 0.1.0
;; Package-Requires: ((emacs "30.1"))
;; Keywords: tools, data
;; SPDX-License-Identifier: AGPL-3.0-or-later

;; This file is not part of GNU Emacs.

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU Affero General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Affero General Public License for more details.

;; You should have received a copy of the GNU Affero General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; LispM Auth is where LispM keeps the API keys its backends ask with.
;; The keys are encrypted at rest by the Common Lisp authenticated-crypto
;; service, in a store opened by a password once a session.  A key is
;; never written in plaintext: each secret is authenticated independently
;; and written in one step.  GnuPG is needed only for legacy migration.
;;
;; The password does not encrypt the secrets.  It unwraps one random data
;; key, kept wrapped in a file of its own, and that key alone is what
;; memory holds while the store is open: each secret is decrypted with
;; it when it is asked for, and only then.  Changing the password rewraps
;; the data key and writes no secret again.  The store locks when it is
;; not used for `lispm-auth-auto-lock' minutes.
;;
;; LispM itself keeps no store: its core says how a backend names a
;; secret, `:key (secret . ID)', and calls the functions here through
;; the hooks it documents, `lispm-secret-get-functions' and the three
;; beside it.  Loading this file adds them.
;;
;;   (lispm-secret-get ID &optional NO-PROMPT)   a key, or nil
;;   (lispm-secret-set ID SECRET)                keep a key
;;   (lispm-secret-delete ID)                    forget a key
;;   (lispm-secret-available-p)                  whether this store is here
;;
;; NO-PROMPT non-nil is how a window showing how a backend stands reads
;; a key: the store answers nil while locked, and asks for nothing,
;; touching none of the encrypted data.
;;
;; The password is asked for at startup, and only for an application
;; about to start that declares it uses secrets:
;;
;;   (lispm-auth-app-requires-password-p 'lispm)   => t, always
;;   (lispm-auth-app-requires-password-p 'desktop) => t, unless revoked
;;   (lispm-auth-set-app-requires-password 'desktop nil)
;;
;; `lispm' always declares: LispM's editor uses keys, and a request to
;; say otherwise is refused.  `desktop' declares until Control Panels
;; says otherwise.  Any other application declares nothing until it is
;; told to.  An application that declares nothing never has the store
;; opened on its behalf; the declarations themselves are not secrets,
;; and are kept unencrypted in `lispm-auth-apps-file' so that a start
;; can read them before asking anything.
;;
;; `lispm-auth-start-apps' is how an application starts: given the
;; symbols of the applications about to start, it asks for the
;; password once when at least one of them declares, and does nothing
;; at all when none does.  The first successful opening also moves any
;; key kept as a literal string in `lispm-backends' into the store,
;; leaving `:key (secret . ID)' in its place and saving the backends so
;; that the plaintext leaves the Customize file.  Keys in environment
;; variables, auth-source entries and characters' own endpoints are
;; left alone.
;;
;; Control Panels shows where the store stands, and changes its
;; password:
;;
;;   (lispm-auth-store-exists-p)          whether a password is set
;;   (lispm-auth-locked-p)                whether the store is locked now
;;   (lispm-auth-change-password NEW)     change it for the store it opens
;;   (lispm-auth-lock)                    lock it now, forgetting the key
;;
;; `lispm-auth-auto-lock' is how many minutes an open store may go unused
;; before it locks itself: 5, 15, 30, 60, 240 or 1440, or nil for never.
;;
;; A password that is forgotten cannot be recovered: the keys it kept
;; are lost with it, and are entered again.

;;; Code:

(require 'cl-lib)
(require 'seq)
(require 'subr-x)

(declare-function lispm-backend-secret-id "lispm-settings" (name))
(declare-function lispm-settings-set "lispm-settings" (variable value &optional save))

;; LispM's own, in lispm-core.el; LispM Auth adds nothing to it, and must
;; work when LispM is not loaded.
(defvar lispm-backends)

;; Emacs', made special here so that binding it nil keeps a file's `#.'
;; forms from being evaluated when it is read.
(defvar read-eval)

(defgroup lispm-auth nil
  "LispM's secrets, encrypted and opened with a password."
  :group 'data
  :prefix "lispm-auth-")

;;;; Where things are

(defcustom lispm-auth-directory (locate-user-emacs-file "lispm-auth/")
  "Directory holding LispM Auth's store and its applications' declarations.
The store is encrypted; the declarations are not secrets.  Both are
kept private to you."
  :type 'directory
  :group 'lispm-auth)

(defcustom lispm-auth-gpg-program "gpg"
  "GnuPG program LispM Auth encrypts with.
It must be GnuPG 2.1 or later, for its loopback pinentry."
  :type 'string
  :group 'lispm-auth)

(defcustom lispm-auth-cipher-algorithm "AES256"
  "Cipher GnuPG encrypts the store with."
  :type 'string
  :group 'lispm-auth)

(defcustom lispm-auth-password-attempts 3
  "How many times a wrong password may be given before LispM Auth gives up."
  :type 'integer
  :group 'lispm-auth)

(defcustom lispm-auth-auto-lock 30
  "Minutes an open store may go unused before it locks itself.
Each secret read, stored or deleted begins the time again.  When it runs
out the data key is forgotten, and the next use asks for the password
again; nil never locks the store by itself."
  :type '(choice (const :tag "5 minutes" 5)
                 (const :tag "15 minutes" 15)
                 (const :tag "30 minutes" 30)
                 (const :tag "1 hour" 60)
                 (const :tag "4 hours" 240)
                 (const :tag "24 hours" 1440)
                 (const :tag "Never" nil))
  :group 'lispm-auth)

(defconst lispm-auth-always-required '(lispm)
  "Applications that always declare that they use secrets.
A request to say otherwise is refused, and nothing of it is kept.")

(defconst lispm-auth-required-by-default '(lispm desktop)
  "Applications that declare secret use until told otherwise.
`desktop' is one of them, and Control Panels may revoke it; `lispm' is
always required, see `lispm-auth-always-required'.")

(defvar lispm-auth-password-function #'lispm-auth--read-password
  "Function asking the user for the password.
It is called with a prompt and, non-nil, whether to ask for the
password twice, as `read-passwd' does; it returns the password, or nil
when the user gave none.  The default shows the password page, across
the monitor on a graphical display and across the frame on a terminal.
Tests replace it.")

(defvar lispm-auth--changing nil
  "Non-nil while the page is asking for a password that replaces
another.  The page then offers no way to change it again.")

(defvar lispm-auth-password-message nil
  "Why the password is asked for again, as the password page shows it.
LispM Auth sets it before a retry after a wrong password; on the first
asking it is nil.")

(defvar lispm-auth--starting-apps nil
  "The applications whose start is opening the store, while it does.
The password page names LispM after them; nil when the store is opened
by asking for a secret outside a start.")

(defcustom lispm-auth-page-background "#DDDDDD"
  "Background of the password page's window on a graphical display.
Platinum gray, as Mac OS 9's dialogs."
  :type 'color
  :group 'lispm-auth)

(defcustom lispm-auth-page-foreground "#000000"
  "Text color of the password page's window on a graphical display."
  :type 'color
  :group 'lispm-auth)

(defcustom lispm-auth-page-width 54
  "Width of the password page's content, in characters.
The rule under its title is eight characters narrower."
  :type 'integer
  :group 'lispm-auth)

(defcustom lispm-auth-page-logo nil
  "File of the logo the password page shows above its title.
nil means the LispM lambda that ships with LispM Auth, beside this file.
The logo is shown on a graphical display only."
  :type '(choice (const :tag "The one that ships with LispM Auth" nil)
                 file)
  :group 'lispm-auth)

(defcustom lispm-auth-page-logo-size 128
  "Width and height of the password page's logo, in pixels."
  :type 'integer
  :group 'lispm-auth)

(defcustom lispm-auth-page-field-width 30
  "Width of the password page's masked field, in characters."
  :type 'integer
  :group 'lispm-auth)

(defcustom lispm-auth-page-field-pixels 360
  "Width of the password page's field on a graphical display, in pixels."
  :type 'integer
  :group 'lispm-auth)

(defcustom lispm-auth-page-field-height 52
  "Height of the password page's field on a graphical display, in pixels."
  :type 'integer
  :group 'lispm-auth)

(defface lispm-auth-page-title
  '((t :family "Helvetica Neue" :weight bold :height 3.0 :foreground "#1B1B1B"))
  "Face of the password page's title."
  :group 'lispm-auth)

(defface lispm-auth-page-tagline
  '((t :family "Helvetica Neue" :slant italic :height 1.15
       :foreground "gray30"))
  "Face of the line under the password page's title."
  :group 'lispm-auth)

(defface lispm-auth-page-rule
  '((t :foreground "gray60" :height 0.9))
  "Face of the line under the password page's tagline."
  :group 'lispm-auth)

(defface lispm-auth-page-label
  '((t :family "Helvetica Neue" :height 1.1 :foreground "#303030"))
  "Face of the password page's prompt above its field."
  :group 'lispm-auth)

(defface lispm-auth-page-field
  '((((background dark)) :background "white" :foreground "black"
     :height 1.15 :box (:line-width 2 :color "gray25"))
    (((background light)) :background "white" :foreground "black"
     :height 1.15 :box (:line-width 2 :color "gray25"))
    (t :inverse-video t))
  "Face of the password page's masked password field."
  :group 'lispm-auth)

(defface lispm-auth-page-error
  '((t :foreground "red3" :weight bold))
  "Face of the password page's message about a wrong password."
  :group 'lispm-auth)

(defface lispm-auth-page-hint
  '((t :family "Helvetica Neue" :foreground "gray35" :slant italic
       :height 1.0))
  "Face of the password page's line saying what its keys do."
  :group 'lispm-auth)

(defface lispm-auth-page-footer
  '((t :family "Helvetica Neue" :foreground "gray45" :height 0.95))
  "Face of the password page's line of keys at its foot."
  :group 'lispm-auth)


(defun lispm-auth-store-file ()
  "Return the file an earlier LispM Auth kept all its secrets in.
It holds a version 1 store; it is read once, moved to the keyed form,
and kept renamed beside it."
  (expand-file-name "secrets.gpg" lispm-auth-directory))

(defun lispm-auth-key-file ()
  "Return the file the store's data key is wrapped in.
The key is 32 random bytes, encrypted with the password's key; the
secrets are encrypted with it, each in a file under
`lispm-auth--secrets-directory'."
  (expand-file-name "native/key" lispm-auth-directory))

(defun lispm-auth--secrets-directory ()
  "Return the directory the store keeps its secrets in, one file each."
  (expand-file-name "native/items/" lispm-auth-directory))

(defun lispm-auth-apps-file ()
  "Return the file LispM Auth keeps its applications' declarations in."
  (expand-file-name "apps.eld" lispm-auth-directory))

(defun lispm-auth-store-exists-p ()
  "Return non-nil when a store has been made here.
Control Panels shows whether a password is set with this.  A version 1
store counts: opening it moves it to the keyed form."
  (or (file-exists-p (expand-file-name "native" lispm-auth-directory))
      (file-exists-p (expand-file-name "key.gpg" lispm-auth-directory))
      (file-exists-p (lispm-auth-store-file))))

(defun lispm-auth--gpg-home ()
  "Return the GnuPG home directory LispM Auth uses, private to it."
  (expand-file-name "gnupg/" lispm-auth-directory))

(define-error 'lispm-auth-error "LispM Auth error")
(define-error 'lispm-auth-wrong-password "Wrong password" 'lispm-auth-error)
(define-error 'lispm-auth-unavailable "LispM Auth service is not available" 'lispm-auth-error)

;;;; Reading what applications declare

(defvar lispm-auth--apps nil
  "The applications' declarations as read, an alist (APP . BOOLEAN).")

(defvar lispm-auth--apps-time nil
  "When `lispm-auth-apps-file' was last read, as a time value.")

(defun lispm-auth--app-symbol (app)
  "Return APP, an application, as a symbol."
  (cond ((symbolp app) app)
        ((stringp app) (intern app))
        (t (user-error "LispM Auth: %s is no application" app))))

(defun lispm-auth--read-apps (&optional force)
  "Return the applications' declarations, an alist (APP . BOOLEAN).
Read them again when FORCE is non-nil, or when the file changed since
they were read."
  (let* ((file (lispm-auth-apps-file))
         (time (and (file-exists-p file)
                    (file-attribute-modification-time (file-attributes file)))))
    (when (or force (null lispm-auth--apps) (not (time-equal-p time lispm-auth--apps-time)))
      (setq lispm-auth--apps
            (if (not (file-exists-p file))
                nil
              (condition-case err
                  (with-temp-buffer
                    (insert-file-contents file)
                    (goto-char (point-min))
                    (let* ((read-eval nil)
                           (form (read (current-buffer))))
                      (when (listp form)
                        (seq-filter (lambda (entry)
                                      (and (consp entry) (symbolp (car entry))
                                           (memq (cdr entry) '(nil t))))
                                    form))))
                (error
                 (message "LispM Auth: cannot read %s: %s"
                          file (error-message-string err))
                 nil)))
            lispm-auth--apps-time time))
    lispm-auth--apps))

(defun lispm-auth-app-requires-password-p (app)
  "Return non-nil when APP, an application, declares that it uses secrets.
APP is a symbol, such as `lispm' or `desktop'.  `lispm' always does;
`desktop' does unless Control Panels revoked it; any other application
does only when it was told to with
`lispm-auth-set-app-requires-password'."
  (let* ((app (lispm-auth--app-symbol app))
         (entry (assq app (lispm-auth--read-apps))))
    (cond ((memq app lispm-auth-always-required) t)
          (entry (and (cdr entry) t))
          (t (and (memq app lispm-auth-required-by-default) t)))))

(defun lispm-auth--write-apps (apps)
  "Write APPS, the applications' declarations, atomically."
  (let* ((directory (lispm-auth--ensure-directory))
         (file (lispm-auth-apps-file))
         (temporary (make-temp-file (expand-file-name ".apps-" directory))))
    (unwind-protect
        (progn
          (with-temp-file temporary
            (insert ";; LispM Auth: which applications declare that they use secrets.\n")
            (insert ";; `lispm' always does.  Change these in LispM's Control Panels.\n")
            (prin1 apps (current-buffer))
            (insert "\n"))
          (set-file-modes temporary #o600)
          (rename-file temporary file t)
          (setq lispm-auth--apps apps
                lispm-auth--apps-time
                (file-attribute-modification-time (file-attributes file)))
          apps)
      (when (file-exists-p temporary)
        (ignore-errors (delete-file temporary))))))

(defun lispm-auth-set-app-requires-password (app required)
  "Say whether APP, an application, uses secrets, and keep it for later.
APP is a symbol, such as `lispm' or `desktop'; REQUIRED non-nil means
that it declares secret use, nil that it does not.  `lispm' always
declares, so a request to say it does not is ignored.  Return the
declaration now in force."
  (let ((app (lispm-auth--app-symbol app))
        (required (and required t)))
    (cond
     ((memq app lispm-auth-always-required)
      (when (null required)
        (message "LispM always asks for the password: it cannot stop using secrets"))
      t)
     (t
      (let* ((apps (copy-sequence (lispm-auth--read-apps)))
             (cell (assq app apps)))
        (if cell
            (setcdr cell required)
          (push (cons app required) apps))
        (lispm-auth--write-apps apps)
        required)))))

;;;; The encrypted store

(defvar lispm-auth--data-key nil
  "The store's data key, 32 random bytes as hex, while it is open.
The secrets are encrypted with it, and it never lies in a file in
plaintext: the file that holds it holds it wrapped by the password's
key.  nil while the store is locked, and no secret is read then.")

(defvar lispm-auth--unlocked nil
  "Non-nil while the store is open this session.")

(defvar lispm-auth--last-use nil
  "When the store was last used, as a time value, while it is open.
`lispm-auth-auto-lock' counts from it.")

(defvar lispm-auth--lock-timer nil
  "The timer that locks the store when it is not used in time, or nil.")

(defvar lispm-auth--migrated nil
  "Non-nil once backends' literal keys were moved into the store this session.")

(defun lispm-auth--auto-lock-seconds ()
  "Return how long the store may stay unused, in seconds, or nil."
  (and lispm-auth-auto-lock (* 60 lispm-auth-auto-lock)))

(defun lispm-auth--cancel-lock-timer ()
  "Stop the timer that would lock the store."
  (when (timerp lispm-auth--lock-timer)
    (cancel-timer lispm-auth--lock-timer))
  (setq lispm-auth--lock-timer nil))

(defun lispm-auth--arm-lock-timer ()
  "Set the timer that locks the store when it is not used in time."
  (lispm-auth--cancel-lock-timer)
  (let ((seconds (lispm-auth--auto-lock-seconds)))
    (when (and seconds lispm-auth--unlocked)
      (setq lispm-auth--lock-timer
            (run-with-timer seconds nil #'lispm-auth--auto-lock)))))

(defun lispm-auth--expired-p ()
  "Return non-nil when the open store has gone unused for its time."
  (let ((seconds (lispm-auth--auto-lock-seconds)))
    (and seconds lispm-auth--last-use
         (>= (float-time (time-since lispm-auth--last-use)) seconds))))

(defun lispm-auth--auto-lock ()
  "Lock the store when `lispm-auth-auto-lock' has run out."
  (when (and lispm-auth--unlocked (lispm-auth--expired-p))
    (lispm-auth-lock)
    (message "LispM Auth: the store is locked again")))

(defun lispm-auth--touch ()
  "Note that the store was used, and begin its time again."
  (when lispm-auth--unlocked
    (setq lispm-auth--last-use (current-time))
    (lispm-auth--arm-lock-timer)))

(defun lispm-auth--lock-if-stale ()
  "Lock the store when its time ran out while Emacs was busy or asleep."
  (when (and lispm-auth--unlocked (lispm-auth--expired-p))
    (lispm-auth-lock)))

(defun lispm-auth-locked-p ()
  "Return non-nil when the store is locked."
  (null lispm-auth--unlocked))

(defun lispm-auth-lock ()
  "Lock the store, forgetting its data key.
The store's files are not touched; the next use asks for the password."
  (interactive)
  (lispm-auth--cancel-lock-timer)
  (when (stringp lispm-auth--data-key)
    ;; A best effort: Lisp strings are not promised to be wiped.
    (ignore-errors (clear-string lispm-auth--data-key)))
  (setq lispm-auth--data-key nil
        lispm-auth--unlocked nil
        lispm-auth--last-use nil))

(add-hook 'suspend-resume-hook #'lispm-auth--lock-if-stale)

(defun lispm-auth--ensure-directory ()
  "Create and return LispM Auth's directory, private to you."
  (let ((directory (file-name-as-directory (expand-file-name lispm-auth-directory))))
    (unless (file-directory-p directory)
      (make-directory directory t)
      (ignore-errors (set-file-modes directory #o700)))
    directory))

;;;; The password page

;; The page is the same across a monitor on a graphical display and across
;; a terminal frame: a title, the prompt, a masked field, a message when the
;; password must be given again, and the keys that answer it.  The pages
;; that set a password are drawn as a window, as the setup assistant's are,
;; by the desktop's drawing; so is every page of an application opened on
;; its own.  The page that asks for the password a store already has at
;; LispM's own start fills the window instead, as the lock screen it is,
;; and so does every page elsewhere.

(defvar lispm-auth--page-event-function #'read-event
  "Function returning the next event on the password page.
Tests replace it.")

(defvar lispm-auth--page-show-function #'lispm-auth--page-show
  "Function showing the password page.  Tests replace it.")

(defvar lispm-auth--page-hide-function #'lispm-auth--page-hide
  "Function hiding the password page.  Tests replace it.")

(defvar lispm-auth-page-window-draw-function nil
  "Function drawing a password page as a window.
It is called with PAGE on a graphical display, instead of the built-in
drawing, for the pages that are windows: those that set a password, and
every page of an application opened on its own, see
`lispm-auth-page-windowed'.  The page that asks for the password a store
already has at LispM's own start fills the window instead.  The page is
drawn on the frame LispM started in, as the setup assistant's pages are;
the frame keeps the size and place it has.  PAGE's buffer is current and
empty, and its frame is shown; the function fills it and returns.  The
desktop sets this; nil draws every page the built-in way.")

(defvar lispm-auth-page-windowed nil
  "Non-nil when every password page is drawn as a window.
That is how an application opened on its own asks for the password, in a
window of LispM's own rather than across it.  The pages that set a
password are windows whether or not this is set; LispM's own start at the
password a store already has fills the window, the lock screen it is.")


(define-derived-mode lispm-auth-page-mode special-mode "LispM Password"
  "Major mode of the page asking for LispM's password.
The page reads keys as events, see `lispm-auth--page-read'."
  (setq-local truncate-lines t
              mode-line-format nil
              ;; The desktop draws each window's title bar in its tab line;
              ;; a page drawn in that window draws its own, and the tab line
              ;; would take the window's whole body from the page's image.
              header-line-format nil
              tab-line-format nil
              auto-hscroll-mode nil
              hscroll-margin 0
              cursor-type nil
              ;; The desktop turns line numbers on in the buffers it shows;
              ;; they are no part of the page.
              display-line-numbers nil
              buffer-read-only t))

(defun lispm-auth--page-app-name ()
  "Return the name of the application the password is asked for."
  (let ((app (car lispm-auth--starting-apps)))
    (cond ((null app) "LispM")
          ((memq app '(lispm desktop)) "LispM")
          (t (capitalize (symbol-name app))))))

(defun lispm-auth--page-title (&optional page)
  "Return the title PAGE shows for itself.
A page asking for a new password says so; one asking for the password
the store has names LispM, or the application it is opening."
  (pcase (plist-get page :stage)
    ((or 'new 'again) "Set a Password")
    (_ (lispm-auth--page-app-name))))

(defun lispm-auth--page-bullet ()
  "Return the character a typed password shows as."
  (if (and (display-graphic-p) (char-displayable-p ?•)) "•" "*"))

(defun lispm-auth--page-logo-file ()
  "Return the file of the password page's logo, or nil when there is none."
  (let ((file (or lispm-auth-page-logo
                  (when-let* ((library (locate-library "lispm-auth")))
                    (expand-file-name "images/lispm-lambda.png"
                                      (file-name-directory library)))
                  (when load-file-name
                    (expand-file-name "images/lispm-lambda.png"
                                      (file-name-directory load-file-name))))))
    (and file (file-readable-p file) file)))

(defvar lispm-auth--page-logo-image nil
  "The logo image object the password page shows, once made.")
(defvar lispm-auth--page-logo-image-file nil
  "The file `lispm-auth--page-logo-image' was made from.")

(defun lispm-auth--page-logo-image ()
  "Return the password page's logo as an image, or nil when there is none."
  (let ((file (lispm-auth--page-logo-file)))
    (when file
      (unless (and lispm-auth--page-logo-image
                   (equal file lispm-auth--page-logo-image-file))
        (setq lispm-auth--page-logo-image
              (ignore-errors
                (create-image file 'png nil
                              :width lispm-auth-page-logo-size
                              :height lispm-auth-page-logo-size
                              :ascent 'center))
              lispm-auth--page-logo-image-file file))
      lispm-auth--page-logo-image)))

(defun lispm-auth--page-field (password)
  "Return PASSWORD as the terminal page's masked field.
A terminal draws no face box, so the field is brackets around
underscores, which every terminal shows."
  (let* ((bullet (lispm-auth--page-bullet))
         (width lispm-auth-page-field-width)
         (masked (mapconcat (lambda (_character) bullet) password "")))
    (concat (propertize "[" 'face 'lispm-auth-page-field)
            (propertize (concat masked
                                (make-string (max 1 (- width (length masked)))
                                             ?_))
                        'face 'lispm-auth-page-field)
            (propertize "]" 'face 'lispm-auth-page-field))))

(defun lispm-auth--page-placeholder (page)
  "Return the word PAGE's empty field shows, before a key is typed."
  (pcase (plist-get page :stage)
    ('new "New password")
    ('again "Enter it again")
    (_ "LispM password")))

(defun lispm-auth--page-field-image (page)
  "Return PAGE's field as an image: a white box with what is typed in it.
Drawing it as an image keeps it the size a field has, beside a logo
many times its height, in one line."
  (let* ((password (or (plist-get page :password) ""))
         (empty (string-empty-p password))
         (bullet (lispm-auth--page-bullet))
         (masked (mapconcat (lambda (_character) bullet) password ""))
         (masked (if (> (length masked) 26) (substring masked -26) masked))
         (shown (if empty (lispm-auth--page-placeholder page) masked))
         (width lispm-auth-page-field-pixels)
         (height lispm-auth-page-field-height)
         (svg (format (concat "<svg xmlns=\"http://www.w3.org/2000/svg\""
                              " width=\"%d\" height=\"%d\">"
                              "<rect x=\"0.5\" y=\"0.5\" width=\"%d\" height=\"%d\""
                              " rx=\"7\" fill=\"#FFFFFF\" stroke=\"#8A8A8A\"/>"
                              "<text x=\"20\" y=\"%d\""
                              " font-family=\"Helvetica Neue, Helvetica, Arial\""
                              " font-size=\"20\" letter-spacing=\"%d\""
                              " fill=\"%s\" font-style=\"%s\">%s</text></svg>")
                      width height (- width 1) (- height 1)
                      (+ (/ height 2) 7)
                      (if empty 0 3)
                      (if empty "#8A8A8A" "#111111")
                      (if empty "italic" "normal")
                      shown)))
    (create-image svg 'svg t :ascent 'center)))

(defun lispm-auth--page-divider-image ()
  "Return the upright rule between the page's logo and its field."
  (create-image (concat "<svg xmlns=\"http://www.w3.org/2000/svg\""
                        " width=\"2\" height=\"88\">"
                        "<rect width=\"2\" height=\"88\" rx=\"1\""
                        " fill=\"#A0A0A0\"/></svg>")
                'svg t :ascent 'center))

(defun lispm-auth--page-stretch-to (x)
  "Return a stretch space that puts the next character at X pixels."
  (propertize " " 'display
              (list 'space :align-to (list (round x)))))

(defun lispm-auth--page-text-width (page)
  "Return the width in pixels of the text area PAGE is drawn in."
  (let ((window (and (plist-get page :buffer)
                     (get-buffer-window (plist-get page :buffer) t))))
    (if window
        (window-body-width window t)
      (frame-pixel-width (plist-get page :frame)))))

(defun lispm-auth--page-row (page)
  "Return the line showing PAGE's logo, an upright rule, and its field.
The three are placed at absolute pixels, so that the logo can move to
the field's place when PAGE's password is answered: `:slide' is how far
along that way it is, from 0 to 1."
  (let* ((window-width (lispm-auth--page-text-width page))
         (logo (lispm-auth--page-logo-image))
         (field (lispm-auth--page-field-image page))
         (divider (lispm-auth--page-divider-image))
         (gap 24)
         (logo-width (if logo lispm-auth-page-logo-size 0))
         (divider-width 2)
         (field-width lispm-auth-page-field-pixels)
         (total (+ (if logo (+ logo-width gap) 0)
                   divider-width gap field-width))
         (left (max 0 (round (- window-width total) 2)))
         (divider-x (+ left logo-width (if logo gap 0)))
         (field-x (+ divider-x divider-width gap))
         (slide (plist-get page :slide))
         (field-centre (+ field-x (/ field-width 2)))
         (logo-x (if (and slide logo)
                     (round (+ left
                               (* slide (- field-centre
                                           (+ left (/ logo-width 2))))))
                   left)))
    (propertize
     (concat
      (when logo
        (concat (lispm-auth--page-stretch-to logo-x)
                (propertize " " 'display logo 'lispm-auth-page-logo logo)))
      ;; The rule and the field are gone while the logo takes the field's
      ;; place: an absolute position cannot be given to them behind a logo
      ;; that has passed it, and they would drift across the page.
      (unless slide
        (concat (lispm-auth--page-stretch-to divider-x)
                (propertize " " 'display divider)
                (lispm-auth--page-stretch-to field-x)
                (propertize " " 'display field
                            'lispm-auth-page-field-image field))))
     'lispm-auth-page-row t)))

(defun lispm-auth--page-prompt (page)
  "Return the prompt PAGE asks its password with, without trailing blanks."
  (string-trim-right
   (if (eq (plist-get page :stage) 'again)
       "Enter the new password again:"
     (or (plist-get page :prompt) "LispM password:"))))

(defun lispm-auth--page-answer (page)
  "Return the line under PAGE's field: its message, or what Return does."
  (if-let* ((message (plist-get page :message)))
      (propertize message 'face 'lispm-auth-page-error)
    (propertize (pcase (plist-get page :stage)
                  ('new (format "Choose a password for %s's secrets.  It is asked for at each start."
                                (lispm-auth--page-app-name)))
                  ('again "It is asked for at each start.")
                  (_ "Return opens the store."))
                'face 'lispm-auth-page-hint)))

(defun lispm-auth--page-footer (page)
  "Return the line of keys PAGE answers to, at its foot."
  (concat "Return confirms        Esc cancels"
          (when (plist-get page :change)
            "        C-p changes the password")))


(defun lispm-auth--page-lines (page)
  "Return the lines PAGE shows, in order, each with the face it has.
A graphical display gets a composition with the logo and generous
spacing; a terminal, where a face's height is not drawn, the compact
one."
  (let* ((password (or (plist-get page :password) ""))
         (title (lispm-auth--page-title page))
         (prompt (lispm-auth--page-prompt page))
         (answer (lispm-auth--page-answer page))
         (footer (lispm-auth--page-footer page)))
    (if (display-graphic-p)
        (list (propertize title 'face 'lispm-auth-page-title)
              (propertize "Encrypted Secrets" 'face 'lispm-auth-page-tagline)
              ""
              (lispm-auth--page-row page)
              ""
              answer
              ""
              (propertize footer 'face 'lispm-auth-page-footer))
      (let ((rule (make-string (max 12 (- lispm-auth-page-width 8)) ?─)))
        (list (propertize title 'face 'lispm-auth-page-title)
              (propertize rule 'face 'lispm-auth-page-rule)
              (propertize "Encrypted Secrets" 'face 'lispm-auth-page-hint)
              ""
              prompt
              ""
              (lispm-auth--page-field password)
              ""
              answer
              ""
              (propertize footer 'face 'lispm-auth-page-hint))))))

(defun lispm-auth--page-group-width (lines)
  "Return the number of columns LINES take up, the widest of them."
  (apply #'max (mapcar #'string-width lines)))

(defun lispm-auth--page-text-margins ()
  "Return (LEFT TOP), in character cells, around the page on a terminal."
  (list 3 1))

(defun lispm-auth--page-line-pixels (line frame)
  "Return the height LINE takes in FRAME, in pixels."
  (cond ((get-text-property 0 'lispm-auth-page-row line)
         (max (frame-char-height frame) lispm-auth-page-logo-size))
        ((string-empty-p line) (frame-char-height frame))
        (t (let* ((face (get-text-property 0 'face line))
                  (height (and face
                               (ignore-errors
                                 (face-attribute face :height frame nil)))))
             (ceiling (* (frame-char-height frame)
                         (if (numberp height) height 1)))))))

(defun lispm-auth--page-text-height (page)
  "Return the height in pixels of the text area PAGE is drawn in."
  (let ((window (and (plist-get page :buffer)
                     (get-buffer-window (plist-get page :buffer) t))))
    (if window
        (window-body-height window t)
      (frame-pixel-height (plist-get page :frame)))))

(defun lispm-auth--page-top-lines (lines page)
  "Return how many blank lines go above LINES to centre them on PAGE.
The block sits a little above the middle, as a title page does."
  (let* ((frame (plist-get page :frame))
         (content (seq-reduce (lambda (total line)
                                (+ total (lispm-auth--page-line-pixels
                                           line frame)))
                              lines 0))
         (room (max 0 (- (lispm-auth--page-text-height page) content)))
         (top (* 0.44 room)))
    (max 0 (round top (max 1 (frame-char-height frame))))))

(defun lispm-auth--page-prefix (line)
  "Return a stretch space that centres LINE on the page's frame.
The space is an `:align-to' display specification, so faces whose font
is larger than the frame's own still centre on the screen's middle."
  (let ((logo (get-text-property 0 'lispm-auth-page-logo line)))
    (propertize " " 'display
                (if logo
                    (list 'space :align-to
                          (list '- 'center (cons 0.5 logo)))
                  (list 'space :align-to
                        (list '- 'center
                              (cons 0.5 (list (max 1 (string-pixel-width
                                                      line))))))))))

(defun lispm-auth--page-windowed-p (page)
  "Return non-nil when PAGE is drawn as a window by the desktop's function.
The pages that set a password are windows, as the setup assistant's
pages are, and so is the whole flow that changes one, which Control
Panels keeps; so is every page when `lispm-auth-page-windowed' says the
start is an application's own.  The page that asks for the password a
store already has, at LispM's own start, is not: it fills the window."
  (and (display-graphic-p)
       lispm-auth-page-window-draw-function
       (or lispm-auth-page-windowed
           lispm-auth--changing
           (memq (plist-get page :stage) '(new again)))))

(defun lispm-auth--page-redraw (page)
  "Draw PAGE in its buffer as it stands now."
  (let ((buffer (plist-get page :buffer)))
    (when (buffer-live-p buffer)
      (let* ((frame (plist-get page :frame))
             (graphic (and (display-graphic-p) (frame-live-p frame)))
             (lines (lispm-auth--page-lines page)))
        (with-current-buffer buffer
          (let ((inhibit-read-only t))
            (erase-buffer)
            (cond
             ((lispm-auth--page-windowed-p page)
              (funcall lispm-auth-page-window-draw-function page))
             (graphic
              (insert (make-string (lispm-auth--page-top-lines lines page)
                                   ?\n))
              (dolist (line lines)
                (unless (or (string-empty-p line)
                            (get-text-property 0 'lispm-auth-page-row line))
                  (insert (lispm-auth--page-prefix line)))
                (insert line "\n")))
             (t
              (let ((margins (lispm-auth--page-text-margins)))
                (insert (make-string (nth 1 margins) ?\n))
                (dolist (line lines)
                  (insert (make-string (nth 0 margins) ?\s) line "\n")))))
            (goto-char (point-min)))))))
  (when (and (not noninteractive) (buffer-live-p (plist-get page :buffer)))
    (force-mode-line-update t)
    (sit-for 0)))

(defun lispm-auth--page-show (page)
  "Show PAGE, where the page that asks for a password belongs.
A page drawn as a window, by the desktop's function, is a window in
LispM's own frame, as the setup assistant's pages are: the frame keeps
its size and place, and its windows and colours come back with the page.
Every other page fills the window it is shown in, in a terminal too."
  (let ((buffer (get-buffer-create " *LispM Password*")))
    (with-current-buffer buffer
      (lispm-auth-page-mode)
      ;; A global line-numbers mode may have come on after the page's
      ;; own mode, which runs before it; take it off the page here.
      (when (fboundp 'display-line-numbers-mode)
        (display-line-numbers-mode -1)))
    (setf (plist-get page :buffer) buffer)
    (when (not noninteractive)
      (cond
       ((lispm-auth--page-windowed-p page)
        ;; LispM's own window, as the setup assistant's pages: the frame
        ;; keeps its size and place, and what it showed comes back with
        ;; the page.
        (when (window-minibuffer-p (selected-window))
          (select-window (next-window)))
        (let ((frame (selected-frame)))
          (setf (plist-get page :frame) frame
                (plist-get page :window-configuration)
                (current-window-configuration frame)
                (plist-get page :frame-parameters)
                (append
                 (mapcar (lambda (parameter)
                           (cons parameter (frame-parameter frame parameter)))
                         '(background-color foreground-color))
                 ;; A frame started out of sight is invisible until the
                 ;; application it was started for opens; a page drawn as
                 ;; a window has to show it, and hide it again with the
                 ;; page.  See `lispm-auth-page-windowed'.
                 (unless (frame-visible-p frame)
                   (set-frame-parameter frame 'visibility t)
                   '((visibility . nil)))))
          (delete-other-windows)
          (switch-to-buffer buffer)
          ;; The window's tab line goes with its buffer, and the page's
          ;; image is drawn to the body it leaves: redisplay first, so
          ;; that the body's size is the one the page is drawn to.
          (redisplay t)))
       (t
        (when (window-minibuffer-p (selected-window))
          (select-window (next-window)))
        ;; The frame keeps its size, place and colours; remembering it
        ;; lets the page be drawn to the window's middle.
        (setf (plist-get page :frame) (selected-frame)
              (plist-get page :window-configuration)
              (current-window-configuration))
        (delete-other-windows)
        (switch-to-buffer buffer))))
    (lispm-auth--page-redraw page)))

(defun lispm-auth--page-hide (page)
  "Hide PAGE, forget its password, and put the windows back as they were."
  (let ((buffer (plist-get page :buffer))
        (configuration (plist-get page :window-configuration))
        (frame (plist-get page :frame))
        (parameters (plist-get page :frame-parameters)))
    (when (frame-live-p frame)
      ;; The page was drawn in LispM's own window: the frame stays, and
      ;; takes back the colours it had.
      (dolist (parameter parameters)
        (ignore-errors
          (set-frame-parameter frame (car parameter) (cdr parameter)))))
    (when configuration
      (ignore-errors (set-window-configuration configuration)))
    (when (buffer-live-p buffer)
      (ignore-errors (kill-buffer buffer)))
    (dolist (key '(:password :first))
      (let ((value (plist-get page key)))
        ;; `:result' is the very string `lispm-auth--page-read' returns,
        ;; and the store is encrypted with it once the page is gone:
        ;; clearing it here would answer with NUL characters.
        (when (and (stringp value) (> (length value) 0)
                   (not (eq value (plist-get page :result))))
          (ignore-errors (clear-string value)))))
    (setf (plist-get page :password) ""
          (plist-get page :first) nil
          (plist-get page :frame) nil
          (plist-get page :frame-parameters) nil
          (plist-get page :window-configuration) nil)))

(defun lispm-auth--page-add (page character)
  "Add CHARACTER to PAGE's password, and draw it masked."
  (setf (plist-get page :password)
        (concat (or (plist-get page :password) "") (char-to-string character))
        (plist-get page :message) nil)
  (lispm-auth--page-redraw page))

(defun lispm-auth--page-backspace (page)
  "Take the last character off PAGE's password."
  (let ((password (or (plist-get page :password) "")))
    (unless (string-empty-p password)
      (setf (plist-get page :password) (substring password 0 -1)
            (plist-get page :message) nil)
      (lispm-auth--page-redraw page))))

(defun lispm-auth--page-slide (page)
  "Slide PAGE's logo to its field's place, as a password is answered.
The page then closes, and what the password opened comes up in its
stead.  Nothing is drawn where a display cannot show the logo."
  (when (and (not noninteractive)
             (display-graphic-p)
             (not (lispm-auth--page-windowed-p page))
             (frame-live-p (plist-get page :frame))
             (lispm-auth--page-logo-image))
    (let ((steps 14))
      (dotimes (step (1+ steps))
        (setf (plist-get page :slide) (/ step (float steps)))
        (lispm-auth--page-redraw page)
        (sit-for 0.02))
      (setf (plist-get page :slide) nil))))

(defun lispm-auth--page-submit (page)
  "Answer PAGE as Return does: the password, or the second entry of a new one."
  (let ((password (or (plist-get page :password) ""))
        (stage (plist-get page :stage)))
    (cond
     ((string-empty-p password)
      (setf (plist-get page :message)
            (if (plist-get page :confirm)
                "Choose a password for LispM's secrets."
              "Type the password."))
      (lispm-auth--page-redraw page))
     ((eq stage 'single)
      (setf (plist-get page :result) password)
      (lispm-auth--page-slide page)
      (setf (plist-get page :done) t))
     ((eq stage 'new)
      (setf (plist-get page :first) password
            (plist-get page :password) ""
            (plist-get page :stage) 'again
            (plist-get page :message) nil)
      (lispm-auth--page-redraw page))
     ((eq stage 'again)
      (if (equal password (plist-get page :first))
          (progn
            (setf (plist-get page :result) password)
            (lispm-auth--page-slide page)
            (setf (plist-get page :done) t))
        (setf (plist-get page :message)
              "The passwords do not match.  Try again."
              (plist-get page :first) nil
              (plist-get page :password) ""
              (plist-get page :stage) 'new)
        (lispm-auth--page-redraw page))))))

(defun lispm-auth--page-handle (page event)
  "Answer PAGE's EVENT: a character of the password, Return, or Escape."
  (cond
   ((or (eq event 'return) (eq event 'kp-enter)
        (eql event ?\r) (eql event ?\n))
    (lispm-auth--page-submit page))
   ((or (eq event 'escape) (eq event 'cancel)
        (eql event ?\C-g) (eql event 27))
    (setf (plist-get page :result) nil
          (plist-get page :done) t))
   ((and (eq event ?\C-p) (plist-get page :change))
    ;; The page asks for the password the store has; C-p says it is that
    ;; password the user wants to replace, and the change asks for the old
    ;; one and then for a new one twice.
    (setf (plist-get page :result) 'change
          (plist-get page :done) t))
   ((or (eq event 'backspace) (eq event 'delete)
        (eql event ?\d) (eql event ?\C-h))
    (lispm-auth--page-backspace page))
   ((and (integerp event) (>= event 32) (/= event 127))
    (lispm-auth--page-add page event))))

(defun lispm-auth--page-read (prompt confirm message)
  "Ask for a password on the page, at PROMPT, twice when CONFIRM is non-nil.
MESSAGE is shown under the field, as why it is asked again.  Return the
password, or nil when Escape was pressed."
  (let ((page (list :prompt prompt
                    :confirm (and confirm t)
                    :message message
                    :stage (if confirm 'new 'single)
                    ;; Changing it is offered only where a password is
                    ;; already set, and not again while it is being changed.
                    :change (and (not confirm)
                                 (not lispm-auth--changing)
                                 (lispm-auth-store-exists-p))
                    :password ""
                    :first nil
                    :result nil
                    :done nil
                    ;; Keys `lispm-auth--page-show' fills: they are here,
                    ;; absent, so that putting them changes this list for
                    ;; the caller too.
                    :buffer nil
                    :frame nil
                    :frame-parameters nil
                    :slide nil
                    :window-configuration nil)))
    (unwind-protect
        (progn
          (funcall lispm-auth--page-show-function page)
          (while (not (plist-get page :done))
            (condition-case nil
                (lispm-auth--page-handle
                 page (funcall lispm-auth--page-event-function))
              (quit (setf (plist-get page :result) nil
                          (plist-get page :done) t))))
          (plist-get page :result))
      (funcall lispm-auth--page-hide-function page))))

(defun lispm-auth--read-password (prompt &optional confirm)
  "Ask for a password at PROMPT on the password page.
With CONFIRM non-nil, ask for it twice.  Return nil in a batch Emacs,
which cannot ask."
  (if noninteractive
      (progn
        (message "LispM Auth: a password is needed, and this Emacs cannot ask for one")
        nil)
    (lispm-auth--page-read prompt confirm lispm-auth-password-message)))

(defun lispm-auth--ensure-gpg-home ()
  "Create and return the GnuPG home directory, private to you.
GnuPG refuses to work in a home directory others may open."
  (let ((home (expand-file-name "gnupg/" (lispm-auth--ensure-directory))))
    (unless (file-directory-p home)
      (make-directory home))
    (ignore-errors (set-file-modes home #o700))
    home))

;;;; GnuPG

(defun lispm-auth--gpg (input arguments)
  "Run GnuPG with ARGUMENTS on INPUT, a unibyte string.
Return a plist (:status EXIT :output STRING :error STRING)."
  (let* ((stderr-file (make-temp-file "lispm-auth-gpg"))
         (home (lispm-auth--ensure-gpg-home))
         (output nil)
         (error-output nil)
         (status nil)
         (program lispm-auth-gpg-program))
    (unless (executable-find program)
      (ignore-errors (delete-file stderr-file))
      (signal 'lispm-auth-unavailable (list program)))
    (unwind-protect
        (with-temp-buffer
          (set-buffer-multibyte nil)
          (insert input)
          (let ((coding-system-for-read 'no-conversion)
                (coding-system-for-write 'no-conversion)
                (process-environment
                 (cons "GPG_TTY="
                       (seq-remove (lambda (entry)
                                     (string-prefix-p "GPG_TTY=" entry))
                                   process-environment))))
            ;; The input leaves the buffer first, so that what is read
            ;; back after GnuPG ran is its output alone.
            (setq status
                  (apply #'call-process-region
                         (point-min) (point-max) program t
                         (list t stderr-file) nil
                         (append (list "--batch" "--yes" "--no-tty"
                                       "--no-options" "--no-symkey-cache"
                                       "--pinentry-mode" "loopback"
                                       "--homedir" home)
                                 arguments)))
            (setq output (buffer-string))))
      (with-temp-buffer
        (set-buffer-multibyte nil)
        (insert-file-contents-literally stderr-file)
        (setq error-output (buffer-string)))
      (ignore-errors (delete-file stderr-file)))
    (list :status status :output output :error error-output)))

(defun lispm-auth--said (error-output)
  "Return ERROR-OUTPUT, GnuPG's, as one line to show."
  (string-trim
   (replace-regexp-in-string
    "\\`\\(?:gpg\\|gpg2\\): \\(?:[A-Za-z]+: \\)?" ""
    (string-trim error-output))))

(defun lispm-auth--key (password)
  "Return the key the store is encrypted with: the SHA-256 of PASSWORD.
The password itself never opens the store; its hash does, so that the
key is a fixed-length, high-entropy string whatever was typed."
  (secure-hash 'sha256 (encode-coding-string password 'utf-8-unix)))

(defun lispm-auth--encrypt-with (text passphrase)
  "Produce legacy OpenPGP ciphertext; only used for legacy fixtures."
  (let ((result (lispm-auth--gpg
                 (encode-coding-string (concat passphrase "\n" text) 'utf-8-unix)
                 (list "--passphrase-fd" "0" "--symmetric"
                       "--cipher-algo" lispm-auth-cipher-algorithm
                       "--s2k-digest-algo" "SHA512" "--compress-algo" "none"
                       "--output" "-"))))
    (unless (eql 0 (plist-get result :status))
      (error "LispM Auth: legacy encryption failed: %s" (plist-get result :error)))
    (plist-get result :output)))

(defun lispm-auth--encrypt (text password)
  "Return TEXT, encrypted with the key PASSWORD gives, as a unibyte string."
  (lispm-auth--encrypt-with text (lispm-auth--key password)))

(defun lispm-auth--decrypted (result what)
  "Return RESULT's output as text, or signal why WHAT did not open.
RESULT is what `lispm-auth--gpg' answered.  A wrong passphrase signals
`lispm-auth-wrong-password'; another failure is an error."
  (cond
   ((eql 0 (plist-get result :status))
    (decode-coding-string (plist-get result :output) 'utf-8-unix))
   ((string-match-p "decryption failed\\|Bad session key\\|session key decryption failed"
                    (plist-get result :error))
    (signal 'lispm-auth-wrong-password nil))
   (t
    (error "LispM Auth: cannot decrypt %s: %s"
           what (lispm-auth--said (plist-get result :error))))))

(defun lispm-auth--decrypt-with (ciphertext passphrase)
  "Decrypt legacy CIPHERTEXT using PASSPHRASE via standard input."
  (let ((file (make-temp-file "lispm-auth-ciphertext-")))
    (unwind-protect
        (progn
          (let ((coding-system-for-write 'no-conversion))
            (write-region ciphertext nil file nil 'silent))
          (lispm-auth--decrypt-file file passphrase))
      (ignore-errors (delete-file file)))))

(defun lispm-auth--decrypt (ciphertext password)
  "Return the text CIPHERTEXT, an OpenPGP message, holds, opened with
the key PASSWORD gives.  Signal `lispm-auth-wrong-password' when
PASSWORD is not the one."
  (lispm-auth--decrypt-with ciphertext (lispm-auth--key password)))

(defun lispm-auth--decrypt-file (file passphrase)
  "Return the text FILE, an OpenPGP message, holds, opened with PASSPHRASE.
PASSPHRASE goes to GnuPG on its input, so it is not written to disk."
  (lispm-auth--decrypted
   (lispm-auth--gpg (encode-coding-string (concat passphrase "\n")
                                          'utf-8-unix)
                    (list "--passphrase-fd" "0" "--decrypt" file))
   "the secret"))

(defconst lispm-auth--package-directory
  (file-name-directory (or load-file-name buffer-file-name))
  "Directory holding LispM Auth and its Common Lisp service.")

(defcustom lispm-auth-lisp-program "sbcl"
  "SBCL executable used to run the crypto service."
  :type 'string :group 'lispm-auth)

(defcustom lispm-auth-service-timeout 30
  "Maximum seconds for one crypto service request."
  :type 'number :group 'lispm-auth)

(defcustom lispm-auth-service-output-limit (* 4 1024 1024)
  "Maximum bytes accepted from the crypto service."
  :type 'integer :group 'lispm-auth)

(define-error 'lispm-auth-service-error "Crypto service rejected request" 'lispm-auth-error)
(define-error 'lispm-auth-service-auth-error "Crypto authentication failed" 'lispm-auth-service-error)

(defun lispm-auth--service (operation &rest fields)
  "Send OPERATION and hexadecimal FIELDS to a fresh crypto process.
Return its hexadecimal result.  Never retain or display its stderr."
  (let* ((program (and (stringp lispm-auth-lisp-program)
                       (executable-find lispm-auth-lisp-program)))
         (script (expand-file-name "common-lisp/service.lisp" lispm-auth--package-directory))
         (request (concat (mapconcat #'identity (cons operation fields) "\t") "\n"))
         (output "") (overflow nil) (process nil) (stderr-process nil))
    (unless (and program (file-readable-p script))
      (signal 'lispm-auth-unavailable '("Crypto service is unavailable")))
    (unwind-protect
        (with-timeout (lispm-auth-service-timeout
                       (signal 'lispm-auth-unavailable '("Crypto service timed out")))
          (condition-case nil
              (progn
                (setq stderr-process
                      (make-pipe-process :name "lispm-auth-stderr" :buffer nil
                                         :noquery t :coding 'no-conversion
                                         :filter (lambda (_process _data) nil)))
                (setq process
                      (make-process
                       :name "lispm-auth-service" :buffer nil :noquery t
                       :connection-type 'pipe :coding 'no-conversion
                       :command (list program "--noinform" "--script" script)
                       :stderr stderr-process
                       :sentinel #'ignore
                       :filter (lambda (_process data)
                                 (if (> (+ (length output) (length data))
                                        lispm-auth-service-output-limit)
                                     (setq overflow t)
                                   (setq output (concat output data))))))
                (process-send-string process request)
                (process-send-eof process)
                (while (and (process-live-p process) (not overflow))
                  (accept-process-output process 0.1))
                ;; Drain any output delivered with process termination.
                (while (and (not overflow) (accept-process-output process 0.01)))
                (unless (and (not overflow) (eq (process-status process) 'exit)
                             (= (process-exit-status process) 0))
                  (signal 'lispm-auth-unavailable '("Crypto service failed")))
                (cond ((equal output "error\tauth\n")
                       (signal 'lispm-auth-service-auth-error nil))
                      ((member output '("error\tinvalid\n" "error\tinternal\n"))
                       (signal 'lispm-auth-service-error nil))
                      ((and (string-match "\\`ok\t\\([0-9a-f]*\\)\n\\'" output)
                            (zerop (% (length (match-string 1 output)) 2)))
                       (match-string 1 output))
                      (t (signal 'lispm-auth-unavailable '("Invalid crypto service response")))))
            (file-error (signal 'lispm-auth-unavailable '("Crypto service could not start")))))
      (let ((inhibit-quit t))
        (when (processp process) (delete-process process))
        (when (processp stderr-process) (delete-process stderr-process))
        (clear-string request)
        (clear-string output)))))

(defun lispm-auth--hex (text)
  (mapconcat (lambda (byte) (format "%02x" byte))
             (encode-coding-string text 'utf-8-unix) ""))

(defun lispm-auth--unhex (hex)
  (unless (and (zerop (% (length hex) 2))
               (string-match-p "\\`[0-9a-f]*\\'" hex))
    (error "LispM Auth: invalid native encoding"))
  (decode-coding-string
   (apply #'unibyte-string
          (cl-loop for i from 0 below (length hex) by 2
                   collect (string-to-number (substring hex i (+ i 2)) 16)))
   'utf-8-unix))

(defun lispm-auth--new-data-key ()
  (lispm-auth--service "random"))

;;;; The store's contents

(defun lispm-auth--deserialize (text)
  "Return the secrets TEXT, a version 1 store's contents, holds.
Signal an error when TEXT is not a store LispM Auth understands."
  (let* ((read-eval nil)
         (form (car (read-from-string text))))
    (if (and (listp form)
             (eql (plist-get form :version) 1)
             (listp (plist-get form :secrets)))
        (plist-get form :secrets)
      (error "LispM Auth: the store is not one LispM Auth understands"))))

(defun lispm-auth--read-store (password)
  "Return the secrets a version 1 store holds, opened with PASSWORD.
A version 1 store kept them all in one file; opening it moves them to
the keyed form, one file each."
  (let* ((file (lispm-auth-store-file))
         (ciphertext (with-temp-buffer
                       (set-buffer-multibyte nil)
                       (insert-file-contents-literally file)
                       (buffer-string))))
    (lispm-auth--deserialize (lispm-auth--decrypt ciphertext password))))

(defun lispm-auth--write-ciphertext (ciphertext file)
  "Write CIPHERTEXT to FILE in one step, readable only by you; return FILE.
A failure leaves FILE as it was."
  (let* ((directory (file-name-directory file))
         (temporary (make-temp-file
                     (expand-file-name
                      (concat "." (file-name-nondirectory file) "-")
                      directory))))
    (unwind-protect
        (progn
          (with-temp-buffer
            (set-buffer-multibyte nil)
            (insert ciphertext)
            (let ((coding-system-for-write 'no-conversion))
              (write-region (point-min) (point-max) temporary nil 'silent)))
          (set-file-modes temporary #o600)
          (rename-file temporary file t)
          file)
      (when (file-exists-p temporary)
        (ignore-errors (delete-file temporary))))))

(defun lispm-auth--read-data-key (password)
  (let ((blob (with-temp-buffer
                (insert-file-contents-literally (lispm-auth-key-file))
                (buffer-string))))
    (unless (string-match-p "\\`4c415701[0-9a-f]\\{176\\}\\'" blob)
      (signal 'lispm-auth-error '("Invalid wrapped key")))
    (condition-case nil
        (lispm-auth--service "unwrap" blob (lispm-auth--hex password))
      ;; Authentication failure also covers an intact-looking corrupted key.
      (lispm-auth-service-auth-error (signal 'lispm-auth-wrong-password nil)))))

(defun lispm-auth--write-data-key (key password)
  (let* ((file (lispm-auth-key-file))
         (directory (file-name-directory file))
         (new-directory (not (file-exists-p directory)))
         (wrapped (lispm-auth--service "wrap" key (lispm-auth--hex password)))
         (written nil))
    (unwind-protect
        (progn
          (make-directory directory t)
          (lispm-auth--write-ciphertext wrapped file)
          (setq written t))
      (when (and new-directory (not written) (file-directory-p directory))
        (ignore-errors (delete-directory directory)))))
  t)

(defun lispm-auth--migrate-store (password)
  "Migrate a legacy store atomically, retaining all legacy files."
  (let* ((legacy-key (expand-file-name "key.gpg" lispm-auth-directory))
         (legacy-items (expand-file-name "secrets" lispm-auth-directory))
         (key (lispm-auth--new-data-key))
         (stage (make-temp-file (expand-file-name ".native-stage-" (lispm-auth--ensure-directory)) t))
         (destination (expand-file-name "native" lispm-auth-directory))
         (committed nil))
    (unwind-protect
        (let ((entries
               (if (file-exists-p legacy-key)
                   (let ((old-key (string-trim (lispm-auth--decrypt-file legacy-key (lispm-auth--key password))))
                         (result nil))
                     (unwind-protect
                         (progn
                           (unless (string-match-p "\\`[[:xdigit:]]\\{64\\}\\'" old-key)
                             (error "Invalid legacy key"))
                           (when (file-directory-p legacy-items)
                             (dolist (file (directory-files legacy-items t directory-files-no-dot-files-regexp))
                               (unless (and (file-regular-p file)
                                            (string-match-p "\\.gpg\\'" file))
                                 (error "Unexpected legacy item: %s" file))
                               (let* ((read-eval nil)
                                      (pair (car (read-from-string (lispm-auth--decrypt-file file old-key)))))
                                 (unless (and (consp pair) (stringp (car pair))
                                              (equal (file-name-nondirectory file)
                                                     (concat (secure-hash 'sha256 (encode-coding-string (car pair) 'utf-8-unix)) ".gpg")))
                                   (error "Invalid legacy item"))
                                 (push pair result))))
                           result)
                       (clear-string old-key)))
                 (lispm-auth--read-store password))))
          (let ((lispm-auth-directory (file-name-as-directory stage))
                (lispm-auth--data-key key)
                (lispm-auth--unlocked t))
            (dolist (entry entries)
              (unless (and (consp entry) (stringp (cdr entry)))
                (error "Invalid legacy entry"))
              (lispm-auth--set (car entry) (cdr entry)))
            (lispm-auth--write-data-key key password))
          (rename-file (expand-file-name "native" stage) destination)
          (setq committed t)
          key)
      (unless committed (clear-string key))
      (when (file-directory-p stage) (delete-directory stage t)))))

(defun lispm-auth--id (id)
  "Return ID, a secret's name, as the string the store keeps.
LispM names a backend's key by a symbol; a caller may write the same
name as a string, and finding the secret should not depend on which."
  (cond ((stringp id) id)
        ((symbolp id) (symbol-name id))
        (t (format "%s" id))))

(defun lispm-auth--item-file (id)
  "Return the file the secret ID is kept in, one secret to a file."
  (expand-file-name
   (concat (secure-hash 'sha256
                        (encode-coding-string (lispm-auth--id id)
                                              'utf-8-unix))
           ".gpg")
   (lispm-auth--secrets-directory)))

(defun lispm-auth--item-text (id secret)
  "Return the text the file of secret ID, holding SECRET, keeps.
The name is inside the message too, so that a file put in another's
place is not read as the secret asked for."
  (prin1-to-string (cons id secret)))

(defun lispm-auth--read-item (id)
  (let ((file (lispm-auth--item-file id)))
    (when (file-exists-p file)
      (let* ((blob (with-temp-buffer (insert-file-contents-literally file) (buffer-string)))
             (text (lispm-auth--unhex
                    (lispm-auth--service "decrypt" lispm-auth--data-key
                                                    (lispm-auth--hex (lispm-auth--id id)) blob)))
             (read-eval nil)
             (pair (car (read-from-string text))))
        (unless (and (consp pair) (equal (car pair) (lispm-auth--id id)))
          (error "LispM Auth: invalid secret"))
        (cdr pair)))))

(defun lispm-auth--get (id)
  "Return the secret ID the open store keeps, or nil."
  (when lispm-auth--unlocked
    (let ((secret (lispm-auth--read-item id)))
      (lispm-auth--touch)
      secret)))

(defun lispm-auth--set (id secret)
  "Keep SECRET as ID in the open store; return non-nil when stored."
  (unless (stringp lispm-auth--data-key)
    (user-error "LispM Auth: the store is locked"))
  (let* ((id (lispm-auth--id id))
         (file (lispm-auth--item-file id))
         (directory (lispm-auth--secrets-directory)))
    (unless (file-directory-p directory)
      (make-directory directory t)
      (ignore-errors (set-file-modes directory #o700)))
    (lispm-auth--write-ciphertext
     (lispm-auth--service "encrypt" lispm-auth--data-key
                                    (lispm-auth--hex id)
                                    (lispm-auth--hex (lispm-auth--item-text id secret)))
     file)
    (lispm-auth--touch)
    t))

(defun lispm-auth--delete (id)
  "Remove ID from the open store; return non-nil when it was there."
  (when lispm-auth--unlocked
    (let ((file (lispm-auth--item-file id)))
      (when (file-exists-p file)
        (delete-file file)
        (lispm-auth--touch)
        t))))

;;;; Opening the store

(defun lispm-auth--open (password)
  "Return the store's data key, unwrapped with PASSWORD.
A version 1 store is moved to the keyed form first.  Signal
`lispm-auth-wrong-password' when PASSWORD is not the one."
  (if (file-exists-p (lispm-auth-key-file))
      (lispm-auth--read-data-key password)
    (lispm-auth--migrate-store password)))

(defun lispm-auth--create ()
  "Make a store with a new password; return non-nil when it was made."
  (let* ((lispm-auth-password-message nil)
         (password (funcall lispm-auth-password-function
                            "New LispM password: " t)))
    (cond
     ((or (null password) (string-empty-p password))
      (message "LispM Auth: no password given, so no store was made")
      nil)
     ((string-match-p "\n" password)
      (user-error "LispM Auth: a password cannot span lines"))
     (t
      (let ((key (lispm-auth--new-data-key)))
        (condition-case err
            (progn
              (lispm-auth--write-data-key key password)
              (setq lispm-auth--data-key key
                    lispm-auth--unlocked t)
              (lispm-auth--touch)
              t)
          (error
           (ignore-errors (clear-string key))
           (signal (car err) (cdr err)))))))))

(defun lispm-auth--unlock-file ()
  "Ask for the store's password until it opens; return non-nil when it does.
The page also offers to change the password; that asks for the old one,
then for a new one twice, and wraps the data key with the new one."
  (let ((attempt 0)
        (cancelled nil)
        (changing nil)
        (wrong nil)
        (done nil)
        (password nil)
        (key nil)
        (lispm-auth-password-message nil))
    (while (and (not done) (not cancelled)
                (< attempt lispm-auth-password-attempts))
      (setq password (funcall lispm-auth-password-function "LispM password: "))
      (cond
       ((eq password 'change)
        (setq changing t
              done t))
       ((or (null password) (string-empty-p password))
        (setq cancelled t))
       (t
        (condition-case nil
            (setq key (lispm-auth--open password)
                  done t)
          (lispm-auth-wrong-password
           (setq attempt (1+ attempt)
                 wrong t)
           (when (< attempt lispm-auth-password-attempts)
             (setq lispm-auth-password-message
                   (format "Wrong password.  Try again (%d of %d)."
                           attempt lispm-auth-password-attempts))))))))
    (cond
     (changing
      ;; It asks for the old password first, then for the new one twice;
      ;; no password opens the store, and the start goes on as cancelled.
      (condition-case nil
          (and (lispm-auth-change-password) t)
        (user-error nil)))
     (done (setq lispm-auth--data-key key
                 lispm-auth--unlocked t)
           (lispm-auth--touch)
           t)
     ((and wrong (not cancelled))
      (user-error "LispM Auth: wrong password"))
     (t nil))))

(defun lispm-auth-unlock ()
  "Open the store for this session, asking for its password once.
Return non-nil when it is open, nil when the user gave no password.
Make a store with a new password when there is none yet.  Signal
`user-error' when the password given is not the store's."
  (if lispm-auth--unlocked
      t
    (let ((opened (if (lispm-auth-store-exists-p)
                      (lispm-auth--unlock-file)
                    (lispm-auth--create))))
      (when opened
        (unless lispm-auth--migrated
          (setq lispm-auth--migrated t)
          (lispm-auth--migrate))
        (setq opened t))
      opened)))

(defun lispm-auth--prompt-allowed-p ()
  "Return non-nil when the store may ask for its password here."
  (not (and noninteractive
            (eq lispm-auth-password-function #'lispm-auth--read-password))))

(defun lispm-auth--check-current-password ()
  "Ask for the password the store has, and return non-nil when it opens it.
Ask again while it is wrong, as a start does.  The store stays as it is;
the password is only tried against it."
  (let ((attempt 0)
        (message nil)
        (ok nil))
    (while (and (not ok) (< attempt lispm-auth-password-attempts))
      (let ((password (let ((lispm-auth-password-message message))
                        (funcall lispm-auth-password-function
                                 "LispM password: "))))
        (cond
         ((or (null password) (string-empty-p password)
              (eq password 'change))
          (setq attempt lispm-auth-password-attempts))
         (t
          (condition-case nil
              (progn (if (file-exists-p (lispm-auth-key-file))
                         (lispm-auth--read-data-key password)
                       (lispm-auth--read-store password))
                     (setq ok t))
            (lispm-auth-wrong-password
             (setq attempt (1+ attempt))
             (when (< attempt lispm-auth-password-attempts)
               (setq message
                     (format "Wrong password.  Try again (%d of %d)."
                             attempt lispm-auth-password-attempts)))))))))
    ok))

(defun lispm-auth-change-password (&optional new-password)
  "Change the password that opens the store to NEW-PASSWORD.
With NEW-PASSWORD nil, the page asks for a new password twice.  The
store is first opened with the password it has — asking for it even when
it is open, so that a password given wrongly changes nothing; a store not
made yet is made with the new password.  Only the data key is wrapped
again: no secret is encrypted anew.  Return non-nil when the password
changed."
  (interactive)
  (let ((lispm-auth--changing t)
        (key nil))
    (when (lispm-auth-store-exists-p)
      (unless (if lispm-auth--unlocked
                  (lispm-auth--check-current-password)
                (lispm-auth-unlock))
        (user-error "LispM Auth: the password was not given, so it is unchanged"))
      (setq key lispm-auth--data-key)
      (unless key
        (user-error "LispM Auth: the store is not open")))
    (let ((password (or new-password
                        (let ((lispm-auth-password-message nil))
                          (funcall lispm-auth-password-function
                                   "New LispM password: " t)))))
      (cond
       ((or (null password) (string-empty-p password))
        (user-error "LispM Auth: no password given, so it is unchanged"))
       ((string-match-p "\n" password)
        (user-error "LispM Auth: a password cannot span lines"))
       (t
        ;; The secrets are already encrypted with KEY; only it is rewrapped.
        (unless key
          (setq key (lispm-auth--new-data-key)))
        (lispm-auth--write-data-key key password)
        (unless lispm-auth--unlocked
          (setq lispm-auth--data-key key
                lispm-auth--unlocked t))
        (lispm-auth--touch)
        t)))))

(defun lispm-auth--ensure-open ()
  "Open the store, asking for its password, and return non-nil when it is.
An open store whose time ran out is locked before it is used again."
  (lispm-auth--lock-if-stale)
  (cond (lispm-auth--unlocked (lispm-auth--touch) t)
        ((not (lispm-auth--prompt-allowed-p)) nil)
        (t (lispm-auth-unlock))))

;;;; Moving backends' literal keys into the store

(defun lispm-auth--migrate ()
  "Move literal backend keys into the store, and save the backends.
Only keys kept as a string in `lispm-backends' move: a key from the
environment, an auth-source entry, a character's own endpoint or one
already in the store is left as it is."
  (when (and (boundp 'lispm-backends) lispm-backends
             (fboundp 'lispm-backend-secret-id))
    (let ((moved nil))
      (dolist (entry lispm-backends)
        (let* ((name (car entry))
               (backend (cdr entry))
               (key (plist-get backend :key)))
          (when (and (symbolp name)
                     (not (string-prefix-p "@" (symbol-name name)))
                     (stringp key)
                     (not (string-empty-p key))
                     (null (plist-get backend :key-env)))
            (let ((id (lispm-backend-secret-id name)))
              (condition-case err
                  (progn
                    (lispm-auth--set id key)
                    (plist-put backend :key (cons 'secret id))
                    (setq moved t))
                (error
                 (message "LispM Auth: cannot move %s's key into the store: %s"
                          name (error-message-string err))))))))
      (when moved
        (condition-case err
            (lispm-auth--save-backends)
          (error
           (message "LispM Auth: cannot save the backends: %s"
                    (error-message-string err))))))))

(defun lispm-auth--save-backends ()
  "Save `lispm-backends', so that a plaintext key leaves the Customize file."
  (cond ((fboundp 'lispm-settings-set)
         (lispm-settings-set 'lispm-backends lispm-backends t))
        ((fboundp 'customize-save-variable)
         (customize-save-variable 'lispm-backends lispm-backends))
        (t (customize-set-variable 'lispm-backends lispm-backends))))

;;;; Starting applications

(defun lispm-auth-start-apps (apps)
  "Open the store when one of APPS, applications, declares secret use.
APPS are symbols; a password is asked for once, and only when at least
one of them declares, so that an application that declares nothing
never touches the encrypted store.  Return non-nil when the store is
open afterwards.  An error here is shown as a message and answers nil,
so that it cannot break the start of an application."
  (when (seq-some #'lispm-auth-app-requires-password-p apps)
    (let ((lispm-auth--starting-apps apps))
      (condition-case err
          (and (lispm-auth-unlock) t)
        (error
         (message "LispM Auth: %s" (error-message-string err))
         nil)))))

(defun lispm-auth-start-app (app)
  "Open the store at the start of APP, when APP declares secret use.
See `lispm-auth-start-apps'."
  (lispm-auth-start-apps (list app)))

;;;; The hooks LispM's core asks through

(defun lispm-auth--secret-get (id no-prompt)
  "Return the secret ID, as `lispm-secret-get-functions' asks.
NO-PROMPT non-nil asks for no password: answer nil while locked, and
touch none of the encrypted data."
  (lispm-auth--lock-if-stale)
  (cond
   (lispm-auth--unlocked (lispm-auth--get id))
   (no-prompt nil)
   ((not (lispm-auth-store-exists-p)) nil)
   (t (when (lispm-auth--ensure-open)
        (lispm-auth--get id)))))

(defun lispm-auth--secret-set (id secret)
  "Keep SECRET as ID, as `lispm-secret-set-functions' asks.
Return non-nil when it was stored."
  (unless (stringp secret)
    (user-error "LispM Auth: a secret is a string"))
  (when (lispm-auth--ensure-open)
    (lispm-auth--set id secret)))

(defun lispm-auth--secret-delete (id)
  "Remove ID, as `lispm-secret-delete-functions' asks.
Return non-nil when it was there."
  (lispm-auth--lock-if-stale)
  (cond
   (lispm-auth--unlocked (lispm-auth--delete id))
   ((not (lispm-auth-store-exists-p)) nil)
   ((lispm-auth--ensure-open) (lispm-auth--delete id))))

(defun lispm-auth--secret-available ()
  "Return non-nil when LispM Auth can keep secrets here.
That is: the Common Lisp crypto service can run."
  (condition-case nil (progn (lispm-auth--new-data-key) t) (error nil)))

(defun lispm-auth--gpg-program-p ()
  "Return non-nil when the GnuPG program LispM Auth uses is here."
  (and (stringp lispm-auth-gpg-program)
       (not (string-empty-p lispm-auth-gpg-program))
       (executable-find lispm-auth-gpg-program)))

(add-hook 'lispm-secret-get-functions #'lispm-auth--secret-get)
(add-hook 'lispm-secret-set-functions #'lispm-auth--secret-set)
(add-hook 'lispm-secret-delete-functions #'lispm-auth--secret-delete)
(add-hook 'lispm-secret-available-functions #'lispm-auth--secret-available)

(provide 'lispm-auth)
;;; lispm-auth.el ends here
