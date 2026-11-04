;;; lispm-auth-test.el --- Tests of LispM Auth  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Ryan.K

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

;; Integration tests run the standalone service named by LISPM_AUTH_SERVICE,
;; each store in its own temporary directory.  Passwords come from a
;; variable, not a prompt.  No encryption command-line tool is required.
;; Without LISPM_AUTH_SERVICE the integration tests are skipped.

;;; Code:

(require 'ert)
(require 'cl-lib)
(require 'lispm-auth)

;; Layout tests simulate graphical displays in headless Emacs. Test the SVG
;; data/layout without requiring a renderer; actual image rendering is manual.
(defvar lispm-auth-test--create-image (symbol-function 'create-image))
(defun lispm-auth-test--image (data type &rest properties)
  "Represent SVG DATA in headless tests, otherwise use the real renderer."
  (if (eq type 'svg)
      (list 'image :type type :data data)
    (apply lispm-auth-test--create-image data type properties)))

(ert-deftest lispm-auth-test-svg-construction-without-renderer ()
  (let ((lispm-auth-test--create-image (lambda (&rest _) (ert-fail "Unexpected renderer"))))
    (cl-letf (((symbol-function 'create-image) #'lispm-auth-test--image))
      (should (eq (car (lispm-auth--page-field-image '(:password ""))) 'image)))))


;; LispM's own, in lispm-core.el; dynamic here so a test may give the
;; migration backends of its own.
(defvar lispm-backends)

(defvar lispm-auth-test--answers nil
  "The passwords the stand-in for the prompt answers, oldest first.")

(defvar lispm-auth-test--prompts nil
  "The prompts the stand-in for the prompt was given, newest first.")

(defun lispm-auth-test--password (prompt &optional _confirm)
  "Answer PROMPT with the next of `lispm-auth-test--answers'."
  (push prompt lispm-auth-test--prompts)
  (pop lispm-auth-test--answers))

;; A stand-in for the password page: its events, what it showed, and its
;; text as it stood before each event.

(defvar lispm-auth-test--events nil
  "Events the stand-in password page reads, oldest first.")

(defvar lispm-auth-test--page-shows nil
  "The pages shown, newest first, as plists of what they asked.")

(defvar lispm-auth-test--page-texts nil
  "The page's text before each event, and when it was hidden, newest first.")

(defvar lispm-auth-test--page-buffer nil
  "The buffer the stand-in password page draws in.")

(defun lispm-auth-test--event ()
  "Answer with the next page event, noting the page's text as it stands."
  (when (buffer-live-p lispm-auth-test--page-buffer)
    (push (with-current-buffer lispm-auth-test--page-buffer (buffer-string))
          lispm-auth-test--page-texts))
  (pop lispm-auth-test--events))

(defun lispm-auth-test--show-page (page)
  "Show PAGE in a buffer of its own, as the password page would."
  (let ((buffer (get-buffer-create " *LispM Password Test*")))
    (with-current-buffer buffer
      (lispm-auth-page-mode))
    (setf (plist-get page :buffer) buffer)
    (setq lispm-auth-test--page-buffer buffer)
    (push (list :title (lispm-auth--page-title page)
                :prompt (plist-get page :prompt)
                :confirm (plist-get page :confirm)
                :change (plist-get page :change)
                :message (plist-get page :message))
          lispm-auth-test--page-shows)
    (lispm-auth--page-redraw page)))

(defun lispm-auth-test--hide-page (page)
  "Hide PAGE, keeping its text for the test to read."
  (let ((buffer (plist-get page :buffer)))
    (when (buffer-live-p buffer)
      (push (with-current-buffer buffer (buffer-string))
            lispm-auth-test--page-texts)
      (kill-buffer buffer))
    (setq lispm-auth-test--page-buffer nil)))

(defconst lispm-auth-test--service (getenv "LISPM_AUTH_SERVICE")
  "Standalone service executable supplied by the test build.")

(defmacro lispm-auth-test--with-store (&rest body)
  "Run BODY with a store, and a prompt, of its own."
  (declare (indent 0))
  `(let ((lispm-auth-directory
          (file-name-as-directory (make-temp-file "lispm-auth-test-" t)))
         (lispm-auth-password-function #'lispm-auth-test--password)
         (lispm-auth-password-attempts 3)
         (lispm-auth-test--answers nil)
         (lispm-auth-test--prompts nil)
         (lispm-auth--apps nil)
         (lispm-auth--apps-time nil)
         (lispm-auth--data-key nil)
         (lispm-auth--unlocked nil)
         (lispm-auth--last-use nil)
         (lispm-auth--lock-timer nil)
         (lispm-auth-auto-lock nil)
         (lispm-auth--migrated nil))
     (unwind-protect
         (progn ,@body)
       (lispm-auth-lock)
       (when (file-directory-p lispm-auth-directory)
         (delete-directory lispm-auth-directory t)))))

(defmacro lispm-auth-test--with-service (&rest body)
  "Run BODY with the standalone test service, or skip when none was supplied.
An explicitly supplied but invalid executable is an error, not a skip."
  (declare (indent 0))
  `(let ((lispm-auth-service-program lispm-auth-test--service))
     (unless lispm-auth-service-program
       (ert-skip "LISPM_AUTH_SERVICE is not set"))
     (lispm-auth--service-program)
     ,@body))

(defun lispm-auth-test--make-store (password &rest secrets)
  "Make a store with PASSWORD holding SECRETS, pairs of ID and secret."
  (let ((lispm-auth-test--answers (cons password lispm-auth-test--answers)))
    (lispm-auth-unlock))
  (dolist (secret secrets)
    (lispm-auth--set (car secret) (cdr secret))))

(defun lispm-auth-test--file-bytes (file)
  "Return the contents of FILE, a string of bytes."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (insert-file-contents-literally file)
    (buffer-string)))

(defun lispm-auth-test--files-contain-p (directory text)
  "Return non-nil when a file under DIRECTORY holds TEXT."
  (seq-some (lambda (file)
              (and (file-regular-p file)
                   (string-match-p (regexp-quote text)
                                   (lispm-auth-test--file-bytes file))))
            (directory-files-recursively directory "\\`[^.]")))

(defmacro lispm-auth-test--fake-service (code &rest body)
  "Run BODY with a Python process emitting CODE instead of the service."
  (declare (indent 1))
  `(let ((original (symbol-function 'make-process))
         (lispm-auth-service-program
          (or (executable-find "python3") (ert-skip "Python unavailable"))))
     (cl-letf (((symbol-function 'make-process)
                (lambda (&rest args)
                  (setq args (plist-put args :command
                                        (list (or (executable-find "python3")
                                                  (ert-skip "Python unavailable"))
                                              "-c" ,code)))
                  (apply original args))))
       ,@body)))

(ert-deftest lispm-auth-test-service-resolver-explicit-path ()
  "Only an absolute local executable can be explicitly selected."
  (let ((lispm-auth-service-program (or (executable-find "python3")
                                        (ert-skip "Python unavailable"))))
    (should (equal (lispm-auth--service-program) lispm-auth-service-program)))
  (dolist (program '("sh" "./lispm-auth-service" "/no-such-service" ""))
    (let ((lispm-auth-service-program program))
      (should-error (lispm-auth--service-program) :type 'lispm-auth-unavailable))))

(ert-deftest lispm-auth-test-service-resolver-package-artifact ()
  "The default resolves only the packaged executable for this platform."
  (let ((lispm-auth-service-program nil)
        (lispm-auth--package-directory
         (file-name-as-directory (make-temp-file "lispm-auth-package-" t))))
    (unwind-protect
        (let* ((platform (lispm-auth--service-platform))
               (file (and platform (expand-file-name
                                    (concat "prebuilt/" platform "/lispm-auth-service")
                                    lispm-auth--package-directory))))
          (should-error (lispm-auth--service-program) :type 'lispm-auth-unavailable)
          (when platform
            (make-directory (file-name-directory file) t)
            (with-temp-file file (insert "#!/bin/sh\nexit 0\n"))
            (should-error (lispm-auth--service-program) :type 'lispm-auth-unavailable)
            (set-file-modes file #o700)
            (should (equal (lispm-auth--service-program) file))))
      (delete-directory lispm-auth--package-directory t))))

(ert-deftest lispm-auth-test-service-platforms ()
  "Recognize ARM64 aliases without treating other architectures as supported."
  (dolist (case '((darwin "aarch64-apple-darwin" "darwin-arm64")
                  (darwin "arm64-apple-darwin" "darwin-arm64")
                  (darwin "x86_64-apple-darwin" nil)
                  (gnu/linux "aarch64-unknown-linux-gnu" "linux-arm64")
                  (gnu/linux "arm64-unknown-linux-gnu" "linux-arm64")
                  (gnu/linux "x86_64-pc-linux-gnu" "linux-x86_64")
                  (gnu/linux "armv7l-unknown-linux-gnueabihf" nil)
                  (gnu/linux "riscv64-unknown-linux-gnu" nil)))
    (let ((system-type (nth 0 case))
          (system-configuration (nth 1 case)))
      (should (equal (lispm-auth--service-platform) (nth 2 case))))))

(ert-deftest lispm-auth-test-intel-macos-unsupported ()
  "Intel macOS cannot install or run a service, even with an explicit path."
  (let ((system-type 'darwin)
        (system-configuration "x86_64-apple-darwin")
        (lispm-auth-service-program "/usr/bin/true"))
    (should-not (lispm-auth--service-platform))
    (should-not (assoc "darwin-x86_64" lispm-auth-service-sha256))
    (cl-letf (((symbol-function 'lispm-auth--download-service)
               (lambda (&rest _) (ert-fail "Unexpected download")))
              ((symbol-function 'lispm-auth--extract-service)
               (lambda (&rest _) (ert-fail "Unexpected extraction")))
              ((symbol-function 'make-process)
               (lambda (&rest _) (ert-fail "Unexpected process"))))
      (dolist (operation (list #'lispm-auth--service-program
                              #'lispm-auth-install-service
                              (lambda () (lispm-auth--service "random"))))
        (let ((failure (should-error (funcall operation) :type 'lispm-auth-unavailable)))
          (should (string-match-p "Intel macOS is no longer supported"
                                  (error-message-string failure))))))))

(ert-deftest lispm-auth-test-linux-arm64-package-artifact ()
  "ARM64 Linux resolves local prebuilt artifacts without needing a release pin."
  (let ((system-type 'gnu/linux)
        (system-configuration "aarch64-unknown-linux-gnu")
        (lispm-auth-service-program nil)
        (lispm-auth--package-directory
         (file-name-as-directory (make-temp-file "lispm-auth-arm64-" t))))
    (unwind-protect
        (let ((file (expand-file-name "prebuilt/linux-arm64/lispm-auth-service"
                                      lispm-auth--package-directory)))
          (make-directory (file-name-directory file) t)
          (with-temp-file file (insert "#!/bin/sh\nexit 0\n"))
          (set-file-modes file #o700)
          (should (equal (lispm-auth--service-program) file)))
      (delete-directory lispm-auth--package-directory t))))

(ert-deftest lispm-auth-test-linux-arm64-install-needs-verified-pin ()
  "Recognition must not enable downloads with a fabricated release pin."
  (let ((system-type 'gnu/linux)
        (system-configuration "aarch64-unknown-linux-gnu")
        (lispm-auth-service-sha256 nil))
    (should-not (assoc "linux-arm64" lispm-auth-service-sha256))
    (cl-letf (((symbol-function 'lispm-auth--download-service)
               (lambda (&rest _) (ert-fail "Unexpected download")))
              ((symbol-function 'lispm-auth--extract-service)
               (lambda (&rest _) (ert-fail "Unexpected extraction"))))
      (should-error (lispm-auth-install-service) :type 'user-error))))

(ert-deftest lispm-auth-test-service-resolver-unsupported-platform ()
  (let ((lispm-auth-service-program nil)
        (system-type 'windows-nt))
    (should-not (lispm-auth--service-platform))
    (should-error (lispm-auth--service-program) :type 'lispm-auth-unavailable))
  (let ((system-type 'gnu/linux)
        (system-configuration "riscv64-unknown-linux-gnu"))
    (should-not (lispm-auth--service-platform))))

(ert-deftest lispm-auth-test-legacy-store-rejected-without-overwriting ()
  "Old stores cannot become a new store, regardless of the chosen action."
  (dolist (name '("secrets.gpg" "key.gpg" "secrets"))
    (lispm-auth-test--with-store
      (let ((file (expand-file-name name lispm-auth-directory)))
        (if (equal name "secrets")
            (make-directory file)
          (let ((file-name-handler-alist nil))
            (with-temp-file file (insert "old encrypted data"))))
        (should (lispm-auth-store-exists-p))
        (should-error (lispm-auth-unlock) :type 'lispm-auth-error)
        (should-error (lispm-auth-change-password "new") :type 'lispm-auth-error)
        (should-not lispm-auth-test--prompts)
        (should-not (file-exists-p (lispm-auth-key-file)))
        (should (if (file-directory-p file) (file-directory-p file)
                  (equal (lispm-auth-test--file-bytes file) "old encrypted data")))))))

(ert-deftest lispm-auth-test-incomplete-native-store-rejected ()
  (lispm-auth-test--with-store
    (make-directory (expand-file-name "native/items" lispm-auth-directory) t)
    (should-error (lispm-auth-unlock) :type 'lispm-auth-error)
    (should-not lispm-auth-test--prompts)
    (should-not (file-exists-p (lispm-auth-key-file)))))

(ert-deftest lispm-auth-test-service-framing-and-limits ()
  (dolist (response '("ok\t00\nextra" "ok\t0\n" "ok\tXX\n" "ok\t00" "error\nextra"))
    (lispm-auth-test--fake-service
        (format "import sys; sys.stdin.readline(); sys.stdout.write(%S)" response)
      (should-error (lispm-auth--service "random") :type 'lispm-auth-unavailable)))
  (let ((lispm-auth-service-output-limit 32))
    (lispm-auth-test--fake-service
        "import sys; sys.stdin.readline(); sys.stdout.write('x'*10000)"
      (should-error (lispm-auth--service "random") :type 'lispm-auth-unavailable)))
  (let ((lispm-auth-service-timeout 0.1))
    (lispm-auth-test--fake-service "import time; time.sleep(10)"
      (should-error (lispm-auth--service "random") :type 'lispm-auth-unavailable))))

(ert-deftest lispm-auth-test-service-failures-not-wrong-password ()
  (lispm-auth-test--with-store
    (make-directory (file-name-directory (lispm-auth-key-file)) t)
    (lispm-auth--write-ciphertext "bad" (lispm-auth-key-file))
    (should-error (lispm-auth--read-data-key "password") :type 'lispm-auth-error)
    (lispm-auth--write-ciphertext (concat "4c415701" (make-string 176 ?0))
                                  (lispm-auth-key-file))
    (let ((lispm-auth-service-program "/no-such-service-executable"))
      (should-error (lispm-auth--read-data-key "password") :type 'lispm-auth-unavailable))))

(ert-deftest lispm-auth-test-service-quit-cleans-processes ()
  (let ((original (symbol-function 'make-process)) (child nil)
        (lispm-auth-service-program
         (or (executable-find "python3") (ert-skip "Python unavailable"))))
    (cl-letf (((symbol-function 'make-process)
               (lambda (&rest args)
                 (setq args (plist-put args :command
                                       (list (executable-find "python3") "-c"
                                             "import time; time.sleep(10)")))
                 (setq child (apply original args))))
              ((symbol-function 'accept-process-output)
               (lambda (&rest _) (signal 'quit nil))))
      (should (eq 'quit (condition-case nil (lispm-auth--service "random")
                          (quit 'quit))))
      (should-not (process-live-p child)))))

(ert-deftest lispm-auth-test-native-tamper-and-id-binding ()
  (lispm-auth-test--with-store
    (lispm-auth-test--with-service
      (lispm-auth-test--make-store "hunter2" (cons "one" "sëcret") (cons "two" "other"))
      (let* ((one (lispm-auth--item-file "one"))
             (two (lispm-auth--item-file "two"))
             (blob (lispm-auth-test--file-bytes one)))
        (lispm-auth--write-ciphertext blob two)
        (should-error (lispm-auth--get "two"))
        (aset blob (1- (length blob)) (if (= (aref blob (1- (length blob))) ?0) ?1 ?0))
        (lispm-auth--write-ciphertext blob one)
        (should-error (lispm-auth--get "one")))
      (lispm-auth-lock)
      (setq lispm-auth-test--answers '("hunter2"))
      (should (lispm-auth-unlock)))))

;;;; Keeping secrets

(ert-deftest lispm-auth-test-round-trip ()
  "A secret stored comes back after the store is locked again."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2"
                                   (cons "first" "sk-first")
                                   (cons "second" "sk-second"))
      (should (equal (lispm-auth--get "first") "sk-first"))
      (should (equal (lispm-auth--get "second") "sk-second"))
      (should (file-exists-p (lispm-auth-key-file)))
      (should (eql (file-modes (lispm-auth-key-file)) #o600))
      (should (file-exists-p (lispm-auth--item-file "first")))
      (should (eql (file-modes (lispm-auth--item-file "first")) #o600))
      (lispm-auth-lock)
      (should (lispm-auth-locked-p))
      (setq lispm-auth-test--answers '("hunter2"))
      (should (lispm-auth-unlock))
      (should (equal (lispm-auth--get "first") "sk-first"))
      (should (equal (lispm-auth--get "second") "sk-second"))
      (should-not (lispm-auth--get "third")))))

(ert-deftest lispm-auth-test-nothing-in-plaintext-on-disk ()
  "Neither the secrets nor the password are written in plaintext."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2"
                                   (cons "openai" "sk-do-not-write-me-down"))
      (lispm-auth-lock)
      (should-not (lispm-auth-test--files-contain-p
                   lispm-auth-directory "sk-do-not-write-me-down")))))

(ert-deftest lispm-auth-test-wrong-password-leaves-the-file-intact ()
  "A wrong password opens nothing, and the store stays as it was."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (let ((before (lispm-auth-test--file-bytes (lispm-auth-key-file))))
        (lispm-auth-lock)
        (setq lispm-auth-test--answers '("wrong" "wrong" "wrong"))
        (should-error (lispm-auth-unlock) :type 'user-error)
        (should (lispm-auth-locked-p))
        (should (equal (lispm-auth-test--file-bytes (lispm-auth-key-file))
                       before))
        ;; The right password still opens it.
        (setq lispm-auth-test--answers '("hunter2"))
        (should (lispm-auth-unlock))
        (should (equal (lispm-auth--get "id") "sk-secret"))))))

(ert-deftest lispm-auth-test-wrong-password-then-right ()
  "A wrong password asks again, and the right one opens the store."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (lispm-auth-lock)
      (setq lispm-auth-test--prompts nil
            lispm-auth-test--answers '("wrong" "hunter2"))
      (should (lispm-auth-unlock))
      (should (equal (lispm-auth--get "id") "sk-secret"))
      (should (equal (length lispm-auth-test--prompts) 2)))))

(ert-deftest lispm-auth-test-cancelled-password-opens-nothing ()
  "Giving no password opens nothing, and says nothing is wrong."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (lispm-auth-lock)
      (setq lispm-auth-test--answers '(nil))
      (should-not (lispm-auth-unlock))
      (should (lispm-auth-locked-p)))))

(ert-deftest lispm-auth-test-failed-write-leaves-the-store ()
  "A write that fails leaves the previous secret as it was."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (let ((before (lispm-auth-test--file-bytes
                     (lispm-auth--item-file "id"))))
        (cl-letf (((symbol-function 'lispm-auth--service)
                   (lambda (&rest _) (error "No room"))))
          (should-error (lispm-auth--set "id" "sk-new")))
        (should (equal (lispm-auth-test--file-bytes
                        (lispm-auth--item-file "id"))
                       before))
        (should (equal (lispm-auth--get "id") "sk-secret"))))))

(ert-deftest lispm-auth-test-delete ()
  "A secret deleted is gone, and deleting one never there answers nil."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2"
                                   (cons "one" "sk-one")
                                   (cons "two" "sk-two"))
      (should (lispm-auth--delete "one"))
      (should-not (lispm-auth--get "one"))
      (should (equal (lispm-auth--get "two") "sk-two"))
      (should-not (lispm-auth--delete "one"))
      (lispm-auth-lock)
      (setq lispm-auth-test--answers '("hunter2"))
      (lispm-auth-unlock)
      (should-not (lispm-auth--get "one"))
      (should (equal (lispm-auth--get "two") "sk-two")))))

(ert-deftest lispm-auth-test-lock-forgets ()
  "Locking forgets the data key, and nothing of the store is left in memory."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (lispm-auth-lock)
      (should-not lispm-auth--data-key)
      (should-not lispm-auth--last-use)
      (should-not lispm-auth--lock-timer)
      (should (lispm-auth-locked-p)))))

(ert-deftest lispm-auth-test-one-file-per-secret ()
  "Each secret is a file of its own, named for its ID, not one store file."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2"
                                   (cons "one" "sk-one")
                                   (cons "two" "sk-two"))
      (should (file-exists-p (lispm-auth--item-file "one")))
      (should (file-exists-p (lispm-auth--item-file "two")))
      (should-not (equal (lispm-auth--item-file "one")
                         (lispm-auth--item-file "two")))
      (should-not (file-exists-p (expand-file-name "secrets.gpg" lispm-auth-directory))))))

(ert-deftest lispm-auth-test-memory-holds-the-data-key-not-the-password ()
  "An open store holds a random data key, and neither the password nor
its hash."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (let ((first (lispm-auth--new-data-key)))
        (should (string-match-p "\\`[0-9a-f]\\{64\\}\\'" first))
        (should-not (equal first (lispm-auth--new-data-key))))
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (should lispm-auth--data-key)
      (should-not (equal lispm-auth--data-key "hunter2"))
      (should-not (equal lispm-auth--data-key (secure-hash 'sha256 "hunter2"))))))

(ert-deftest lispm-auth-test-auto-lock-locks-an-unused-store ()
  "A store not used for `lispm-auth-auto-lock' minutes is locked, and
answers no-prompt reads with nil without asking."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (let ((lispm-auth-auto-lock 30))
        (setq lispm-auth--last-use
              (time-subtract (current-time) (seconds-to-time (* 31 60))))
        (should (lispm-auth--expired-p))
        (setq lispm-auth-test--prompts nil)
        (should-not (lispm-auth--secret-get "id" t))
        (should-not lispm-auth-test--prompts)
        (should (lispm-auth-locked-p))
        (should-not lispm-auth--data-key))
      ;; The password opens it again.
      (setq lispm-auth-test--answers '("hunter2"))
      (should (lispm-auth-unlock))
      (should (equal (lispm-auth--get "id") "sk-secret")))))

(ert-deftest lispm-auth-test-auto-lock-never ()
  "With `lispm-auth-auto-lock' nil the store never runs out of time."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (let ((lispm-auth-auto-lock nil))
        (setq lispm-auth--last-use
              (time-subtract (current-time) (seconds-to-time (* 365 24 60 60))))
        (should-not (lispm-auth--expired-p))
        (should-not lispm-auth--lock-timer)
        (should (equal (lispm-auth--get "id") "sk-secret"))
        (should-not lispm-auth--lock-timer)))))

(ert-deftest lispm-auth-test-auto-lock-timer-follows-the-store ()
  "An open store has a lock timer; locking cancels it."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (let ((lispm-auth-auto-lock 5))
        (lispm-auth--touch)
        (should (timerp lispm-auth--lock-timer))
        (lispm-auth-lock)
        (should-not lispm-auth--lock-timer))
      (let ((lispm-auth-auto-lock 5))
        (setq lispm-auth-test--answers '("hunter2"))
        (should (lispm-auth-unlock))
        (should (timerp lispm-auth--lock-timer))
        (lispm-auth-lock)
        (should-not lispm-auth--lock-timer)))))


(ert-deftest lispm-auth-test-change-password ()
  "A changed password opens the store that the old one no longer does.
The secrets are not encrypted again: only the key that opens them is
wrapped anew."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (should-not (lispm-auth-store-exists-p))
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (should (lispm-auth-store-exists-p))
      (let ((key lispm-auth--data-key)
            (key-before (lispm-auth-test--file-bytes
                         (lispm-auth-key-file)))
            (item-before (lispm-auth-test--file-bytes
                          (lispm-auth--item-file "id"))))
        ;; The old password is asked for even though the store is open.
        (setq lispm-auth-test--prompts nil
              lispm-auth-test--answers '("hunter2"))
        (should (lispm-auth-change-password "another"))
        (should (equal lispm-auth-test--prompts '("LispM password: ")))
        (should (equal lispm-auth--data-key key))
        (should-not (equal (lispm-auth-test--file-bytes
                            (lispm-auth-key-file))
                           key-before))
        (should (equal (lispm-auth-test--file-bytes
                        (lispm-auth--item-file "id"))
                       item-before))
        (should (equal (lispm-auth--get "id") "sk-secret")))
      (lispm-auth-lock)
      (setq lispm-auth-test--answers '("hunter2" "hunter2" "hunter2"))
      (should-error (lispm-auth-unlock) :type 'user-error)
      (setq lispm-auth-test--answers '("another"))
      (should (lispm-auth-unlock))
      (should (equal (lispm-auth--get "id") "sk-secret")))))

(ert-deftest lispm-auth-test-change-password-asks-when-locked ()
  "Changing a locked store's password asks for the old one first, then
asks for a new one on the page."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (lispm-auth-lock)
      (setq lispm-auth-test--prompts nil
            lispm-auth-test--answers '("hunter2" "another"))
      (should (lispm-auth-change-password))
      (should (equal lispm-auth-test--prompts
                     '("New LispM password: " "LispM password: ")))
      (lispm-auth-lock)
      (setq lispm-auth-test--answers '("another"))
      (should (lispm-auth-unlock))
      (should (equal (lispm-auth--get "id") "sk-secret")))))

(ert-deftest lispm-auth-test-change-password-cancelled-leaves-it ()
  "A new password not given leaves the old one opening the store."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (setq lispm-auth-test--answers '("hunter2" nil))
      (should-error (lispm-auth-change-password) :type 'user-error)
      (should lispm-auth--data-key)
      (should (equal (lispm-auth--get "id") "sk-secret"))
      (lispm-auth-lock)
      (setq lispm-auth-test--answers '("hunter2"))
      (should (lispm-auth-unlock))
      (should (equal (lispm-auth--get "id") "sk-secret")))))

(ert-deftest lispm-auth-test-change-password-failed-write-keeps-it ()
  "A write that fails keeps the old password, and the key file as it was."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (let ((before (lispm-auth-test--file-bytes (lispm-auth-key-file))))
        (setq lispm-auth-test--answers '("hunter2"))
        (cl-letf (((symbol-function 'lispm-auth--write-data-key)
                   (lambda (&rest _) (error "No room"))))
          (should-error (lispm-auth-change-password "another")))
        (should lispm-auth--data-key)
        (should (equal (lispm-auth-test--file-bytes (lispm-auth-key-file))
                       before)))
      (should (equal (lispm-auth--get "id") "sk-secret"))
      (lispm-auth-lock)
      (setq lispm-auth-test--answers '("hunter2"))
      (should (lispm-auth-unlock))
      (should (equal (lispm-auth--get "id") "sk-secret")))))

(ert-deftest lispm-auth-test-change-password-makes-a-store ()
  "With no store yet, a password given makes one, holding no secret."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (should (lispm-auth-change-password "hunter2"))
      (should (lispm-auth-store-exists-p))
      (should-not (lispm-auth-locked-p))
      (lispm-auth-lock)
      (setq lispm-auth-test--answers '("hunter2"))
      (should (lispm-auth-unlock))
      (should (file-exists-p (lispm-auth-key-file)))
      (should-not (lispm-auth--get "anything")))))

;;;; Starting applications

(ert-deftest lispm-auth-test-no-prompt-when-no-app-declares ()
  "Starting applications that declare nothing asks nothing, and touches nothing."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (should-not (lispm-auth-start-apps '(terminal browser)))
      (should-not lispm-auth-test--prompts)
      (should-not (lispm-auth-store-exists-p)))))

(ert-deftest lispm-auth-test-an-app-opened-alone-asks-nothing ()
  "An application opened on its own that declares nothing, as Gomoku
does, shows no page and touches none of the encrypted data."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (should-not (lispm-auth-start-app 'gomoku))
      (should-not lispm-auth-test--prompts)
      (should (lispm-auth-locked-p))
      (should-not (lispm-auth-store-exists-p)))))

(ert-deftest lispm-auth-test-lispm-opened-alone-asks ()
  "LispM opened on its own asks for the password, though Control
Panels has revoked the desktop's declaration."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-set-app-requires-password 'desktop nil)
      (setq lispm-auth-test--answers '("hunter2"))
      (should (lispm-auth-start-app 'lispm))
      (should (equal (length lispm-auth-test--prompts) 1))
      (should-not (lispm-auth-locked-p)))))

(ert-deftest lispm-auth-test-no-apps-asks-nothing ()
  "Starting with no application at all asks nothing."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (should-not (lispm-auth-start-apps nil))
      (should-not lispm-auth-test--prompts))))

(ert-deftest lispm-auth-test-desktop-asks-at-start ()
  "The desktop declares, so starting it asks for the password once."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (setq lispm-auth-test--answers '("hunter2"))
      (should (lispm-auth-start-apps '(desktop)))
      (should (equal (length lispm-auth-test--prompts) 1))
      (should-not (lispm-auth-locked-p))
      ;; Already open: another application that declares asks nothing more.
      (should (lispm-auth-start-apps '(lispm)))
      (should (equal (length lispm-auth-test--prompts) 1)))))

(ert-deftest lispm-auth-test-desktop-default-and-opt-out ()
  "The desktop declares by default, and Control Panels can revoke it."
  (lispm-auth-test--with-store
    (should (lispm-auth-app-requires-password-p 'desktop))
    (should-not (lispm-auth-set-app-requires-password 'desktop nil))
    (should-not (lispm-auth-app-requires-password-p 'desktop))
    ;; Kept for later starts: read again from the file.
    (setq lispm-auth--apps nil
          lispm-auth--apps-time nil)
    (should-not (lispm-auth-app-requires-password-p 'desktop))
    (should (lispm-auth-set-app-requires-password 'desktop t))
    (should (lispm-auth-app-requires-password-p 'desktop))))

(ert-deftest lispm-auth-test-desktop-revoked-asks-nothing-at-start ()
  "With the desktop revoked, opening it touches no encrypted data."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-set-app-requires-password 'desktop nil)
      (should-not (lispm-auth-start-apps '(desktop)))
      (should-not lispm-auth-test--prompts)
      (should-not lispm-auth--unlocked))))

(ert-deftest lispm-auth-test-lispm-always-required ()
  "LispM always declares, and saying it does not changes nothing."
  (lispm-auth-test--with-store
    (should (lispm-auth-app-requires-password-p 'lispm))
    (should (lispm-auth-set-app-requires-password 'lispm nil))
    (should (lispm-auth-app-requires-password-p 'lispm))
    (should-not (assq 'lispm (lispm-auth--read-apps)))
    (setq lispm-auth--apps nil
          lispm-auth--apps-time nil)
    (should (lispm-auth-app-requires-password-p 'lispm))))

(ert-deftest lispm-auth-test-other-apps-default-to-nothing ()
  "Another application declares nothing until it is told to."
  (lispm-auth-test--with-store
    (should-not (lispm-auth-app-requires-password-p 'terminal))
    (should (lispm-auth-set-app-requires-password 'terminal t))
    (should (lispm-auth-app-requires-password-p 'terminal))
    (lispm-auth-set-app-requires-password 'terminal nil)
    (should-not (lispm-auth-app-requires-password-p 'terminal))))

(ert-deftest lispm-auth-test-start-makes-the-first-store ()
  "The first start with a declaring application makes a store."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (setq lispm-auth-test--answers '("new-password"))
      (should (lispm-auth-start-apps '(desktop)))
      (should (file-exists-p (lispm-auth-key-file)))
      (should-not (lispm-auth-locked-p))
      (should-not (lispm-auth--get "nothing")))))

;;;; NO-PROMPT

(ert-deftest lispm-auth-test-no-prompt-never-asks ()
  "Reading with NO-PROMPT while locked answers nil, and asks nothing."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (lispm-auth-lock)
      (setq lispm-auth-test--prompts nil)
      (let ((before (lispm-auth-test--file-bytes (lispm-auth-key-file))))
        (should-not (lispm-auth--secret-get "id" t))
        (should-not lispm-auth-test--prompts)
        (should (lispm-auth-locked-p))
        (should (equal (lispm-auth-test--file-bytes (lispm-auth-key-file))
                       before))))))

(ert-deftest lispm-auth-test-no-prompt-without-a-store ()
  "Reading with NO-PROMPT without a store makes none, and asks nothing."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (should-not (lispm-auth--secret-get "id" t))
      (should-not lispm-auth-test--prompts)
      (should-not (lispm-auth-store-exists-p)))))

(ert-deftest lispm-auth-test-prompt-when-asked ()
  "Reading without NO-PROMPT asks for the password and answers."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (lispm-auth-lock)
      (setq lispm-auth-test--prompts nil
            lispm-auth-test--answers '("hunter2"))
      (should (equal (lispm-auth--secret-get "id" nil) "sk-secret"))
      (should (equal (length lispm-auth-test--prompts) 1)))))

(ert-deftest lispm-auth-test-no-prompt-when-unlocked ()
  "Reading with NO-PROMPT from an open store answers, without asking again."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (setq lispm-auth-test--prompts nil)
      (should (equal (lispm-auth--secret-get "id" t) "sk-secret"))
      (should-not lispm-auth-test--prompts))))

;;;; The hooks LispM's core asks through

(ert-deftest lispm-auth-test-hooks-registered ()
  "Loading LispM Auth adds its handlers to LispM's secret hooks."
  (should (memq #'lispm-auth--secret-get lispm-secret-get-functions))
  (should (memq #'lispm-auth--secret-set lispm-secret-set-functions))
  (should (memq #'lispm-auth--secret-delete lispm-secret-delete-functions))
  (should (memq #'lispm-auth--secret-available
                lispm-secret-available-functions)))

(ert-deftest lispm-auth-test-hooks-answer ()
  "The handlers answer as LispM's core asks them to."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (should (run-hook-with-args-until-success
               'lispm-secret-available-functions))
      (should-not (run-hook-with-args-until-success
                   'lispm-secret-get-functions "id" t))
      (setq lispm-auth-test--answers '("hunter2"))
      (should (run-hook-with-args-until-success
               'lispm-secret-set-functions "id" "sk-secret"))
      (should (equal (run-hook-with-args-until-success
                      'lispm-secret-get-functions "id" t)
                     "sk-secret"))
      (should (run-hook-with-args-until-success
               'lispm-secret-delete-functions "id"))
      (should-not (run-hook-with-args-until-success
                   'lispm-secret-get-functions "id" t)))))

(ert-deftest lispm-auth-test-available-without-a-store ()
  "The store is available before any is made: a first key can be kept."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (should (lispm-auth--secret-available))
      (should-not (lispm-auth-store-exists-p)))))

;;;; Moving backends' literal keys into the store

(defun lispm-auth-test--migrate (backends)
  "Migrate BACKENDS, returning (BACKENDS . SAVED): the backends afterwards,
and what `lispm-settings-set' was given."
  (let ((saved nil))
    (cl-letf (((symbol-function 'lispm-backend-secret-id)
               (lambda (name) (intern (format "lispm-backend-%s" name))))
              ((symbol-function 'lispm-settings-set)
               (lambda (variable value &optional _save)
                 (setq saved (list variable value)))))
      (let ((lispm-backends backends))
        (lispm-auth--migrate)
        (cons lispm-backends saved)))))

(ert-deftest lispm-auth-test-migrates-a-literal-key ()
  "A literal key moves into the store, and the backends are saved with it gone."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2")
      (setq lispm-auth-test--prompts nil)
      (let* ((result (lispm-auth-test--migrate
                      (list (cons 'gateway
                                  (list :api 'openai
                                        :url "https://example.com"
                                        :model "m"
                                        :key "sk-literal")))))
             (backends (car result))
             (saved (cdr result)))
        ;; The key is in the store, under the ID the core names it by.
        (should (equal (lispm-auth--get "lispm-backend-gateway") "sk-literal"))
        ;; The backend names it there.
        (should (equal (plist-get (cdr (assq 'gateway backends)) :key)
                       '(secret . lispm-backend-gateway)))
        ;; The backends were saved, without the plaintext.
        (should (eq (car saved) 'lispm-backends))
        (should (equal (cadr saved) backends))
        (should-not (string-match-p "sk-literal" (prin1-to-string saved)))
        (should-not lispm-auth-test--prompts)))))

(ert-deftest lispm-auth-test-migration-touches-other-keys-not ()
  "Keys from the environment, auth-source, characters, or the store stay."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2")
      (let* ((stored (list :api 'openai :url "https://a" :model "m"
                           :key '(secret . lispm-backend-stored)))
             (env (list :api 'openai :url "https://b" :model "m" :key 'openai))
             (variable (list :api 'openai :url "https://c" :model "m"
                             :key "sk-env" :key-env "MY_KEY"))
             (auth (list :api 'openai :url "https://d" :model "m"
                         :key 'auth-source))
             (character (list :api 'openai :url "https://e" :model "m"
                              :key "sk-character"))
             (backends (list (cons 'stored stored)
                             (cons 'env env)
                             (cons 'variable variable)
                             (cons 'auth auth)
                             (cons '@ada character)))
             (result (lispm-auth-test--migrate backends)))
        (should-not (cdr result))
        (should (equal (plist-get (cdr (assq 'stored (car result))) :key)
                       '(secret . lispm-backend-stored)))
        (should (equal (plist-get (cdr (assq 'env (car result))) :key) 'openai))
        (should (equal (plist-get (cdr (assq 'variable (car result))) :key) "sk-env"))
        (should (equal (plist-get (cdr (assq 'auth (car result))) :key) 'auth-source))
        (should (equal (plist-get (cdr (assq '@ada (car result))) :key) "sk-character"))
        (should-not (lispm-auth--get "lispm-backend-character"))))))

(ert-deftest lispm-auth-test-unlock-migrates-once ()
  "The first successful opening moves the literal keys."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2")
      (lispm-auth-lock)
      (setq lispm-auth--migrated nil)
      (let ((lispm-backends
             (list (cons 'gateway (list :api 'openai :url "https://x"
                                        :model "m" :key "sk-literal"))))
            (saved nil))
        (cl-letf (((symbol-function 'lispm-backend-secret-id)
                   (lambda (name) (intern (format "lispm-backend-%s" name))))
                  ((symbol-function 'lispm-settings-set)
                   (lambda (_variable _value &optional _save) (setq saved t))))
          (setq lispm-auth-test--answers '("hunter2"))
          (should (lispm-auth-unlock))
          (should saved)
          (should (equal (plist-get (cdr (assq 'gateway lispm-backends)) :key)
                         '(secret . lispm-backend-gateway)))
          (should (equal (lispm-auth--get "lispm-backend-gateway") "sk-literal")))))))

;;;; The errors

(ert-deftest lispm-auth-test-errors-are-errors ()
  "A wrong password's error is LispM Auth's, and an error besides."
  (should (equal (get 'lispm-auth-wrong-password 'error-conditions)
                 '(lispm-auth-wrong-password lispm-auth-error error)))
  (should (equal (get 'lispm-auth-unavailable 'error-conditions)
                 '(lispm-auth-unavailable lispm-auth-error error))))

;;;; The password page

;; The page's own window cannot be made in a batch Emacs.  What is checked
;; here is that it reads keys as the page does, masks what is typed, asks
;; for a new password twice, says why a password is asked for again,
;; covers the monitor's workarea rather than a window, centres its
;; content there, and draws across the frame on a terminal.  A graphical
;; page is also checked by starting LispM itself.

(ert-deftest lispm-auth-test-page-masks-the-password ()
  "The page shows a masked password, and answers with the real one."
  (let ((lispm-auth--page-show-function #'lispm-auth-test--show-page)
        (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
        (lispm-auth--page-event-function #'lispm-auth-test--event)
        (lispm-auth-test--events (append (string-to-list "hunter2") '(return)))
        (lispm-auth-test--page-shows nil)
        (lispm-auth-test--page-texts nil)
        (lispm-auth-test--page-buffer nil))
    (should (equal (lispm-auth--page-read "LispM password: " nil nil)
                   "hunter2"))
    (should (equal (length lispm-auth-test--page-shows) 1))
    (should (equal (plist-get (car lispm-auth-test--page-shows) :title)
                   "LispM"))
    (let ((text (car lispm-auth-test--page-texts)))
      (should (string-match-p "LispM" text))
      (should (string-match-p "\\*\\{7\\}" text))
      (should-not (string-match-p "hunter2" text)))
    (should-not (get-buffer " *LispM Password Test*"))))

(ert-deftest lispm-auth-test-page-keeps-the-password-it-answers ()
  "The password the page answers with survives the page's closing.
The store is encrypted with it once the page is gone, so a password
cleared as the page closes would encrypt NUL characters instead."
  (let ((lispm-auth--page-show-function #'lispm-auth-test--show-page)
        ;; The page's own hiding, not the stand-in's, which clears nothing.
        (lispm-auth--page-hide-function #'lispm-auth--page-hide)
        (lispm-auth--page-event-function #'lispm-auth-test--event)
        (lispm-auth-test--events (append (string-to-list "hunter2") '(return)))
        (lispm-auth-test--page-shows nil)
        (lispm-auth-test--page-texts nil)
        (lispm-auth-test--page-buffer nil))
    (should (equal (lispm-auth--page-read "LispM password: " nil nil)
                   "hunter2"))
    (setq lispm-auth-test--events
          (append (string-to-list "hunter2") '(return)
                  (string-to-list "hunter2") '(return)))
    (should (equal (lispm-auth--page-read "New LispM password: " t nil)
                   "hunter2"))))

(ert-deftest lispm-auth-test-page-escape-cancels ()
  "Escape closes the page, and gives no password."
  (let ((lispm-auth--page-show-function #'lispm-auth-test--show-page)
        (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
        (lispm-auth--page-event-function #'lispm-auth-test--event)
        (lispm-auth-test--events (append (string-to-list "hun") '(escape)))
        (lispm-auth-test--page-shows nil)
        (lispm-auth-test--page-texts nil)
        (lispm-auth-test--page-buffer nil))
    (should-not (lispm-auth--page-read "LispM password: " nil nil))
    (should-not (get-buffer " *LispM Password Test*"))))

(ert-deftest lispm-auth-test-page-confirms-a-new-password ()
  "A new password is asked for twice; entries that differ are refused."
  (let ((lispm-auth--page-show-function #'lispm-auth-test--show-page)
        (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
        (lispm-auth--page-event-function #'lispm-auth-test--event)
        (lispm-auth-test--events
         (append (string-to-list "one") '(return)
                 (string-to-list "two") '(return)
                 (string-to-list "one") '(return)
                 (string-to-list "one") '(return)))
        (lispm-auth-test--page-shows nil)
        (lispm-auth-test--page-texts nil)
        (lispm-auth-test--page-buffer nil))
    (should (equal (lispm-auth--page-read "New LispM password: " t nil)
                   "one"))
    (should (seq-some (lambda (text)
                        (string-match-p "The passwords do not match" text))
                      lispm-auth-test--page-texts))
    (should (seq-some (lambda (text)
                        (string-match-p "Enter the new password again" text))
                      lispm-auth-test--page-texts))))

(ert-deftest lispm-auth-test-page-mouse-actions ()
  (let ((page (list :stage 'new :confirm t :password "one" :first nil
                    :message nil :done nil :result nil))
        (action 'confirm)
        (click '(mouse-1 (nil 1 (10 . 20) 0))))
    (cl-letf (((symbol-function 'lispm-auth--page-windowed-p) (lambda (_) t))
              ((symbol-function 'lispm-auth--page-redraw) #'ignore))
      (let ((lispm-auth-page-window-event-function
             (lambda (_page event) (should (equal event click)) action)))
        (lispm-auth--page-handle page click)
        (should (eq (plist-get page :stage) 'again))
        (setf (plist-get page :password) "one")
        (lispm-auth--page-handle page click)
        (should (equal (plist-get page :result) "one"))
        (should (plist-get page :done))
        (setf (plist-get page :done) nil
              (plist-get page :result) nil)
        (setq action nil)
        (lispm-auth--page-handle page click)
        (should-not (plist-get page :done))
        (setq action 'cancel)
        (lispm-auth--page-handle page click)
        (should (plist-get page :done))
        (should-not (plist-get page :result))))))

(ert-deftest lispm-auth-test-change-page-stages ()
  (let ((lispm-auth--changing t)
        (lispm-auth--page-show-function
         (lambda (page)
           (should (eq (plist-get page :operation) 'change))
           (should (eq (plist-get page :stage) 'current))))
        (lispm-auth--page-hide-function #'ignore)
        (lispm-auth--page-event-function (lambda () 'cancel)))
    (should-not (lispm-auth--page-read "LispM password: " nil nil)))
  (let ((page (list :stage 'current :password "old" :done nil :result nil)))
    (lispm-auth--page-submit page)
    (should (equal (plist-get page :result) "old"))
    (should (plist-get page :done))))

(ert-deftest lispm-auth-test-page-asks-again-after-a-wrong-password ()
  "A wrong password is said so on the page, and asked for again."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "right" (cons "id" "sk-secret"))
      (lispm-auth-lock)
      (let ((noninteractive nil)
            (lispm-auth-password-function #'lispm-auth--read-password)
            (lispm-auth--page-show-function #'lispm-auth-test--show-page)
            (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
            (lispm-auth--page-event-function #'lispm-auth-test--event)
            (lispm-auth-test--events
             (append (string-to-list "wrong") '(return)
                     (string-to-list "right") '(return)))
            (lispm-auth-test--page-shows nil)
            (lispm-auth-test--page-texts nil)
            (lispm-auth-test--page-buffer nil))
        (should (lispm-auth-start-apps '(desktop)))
        (should (equal (length lispm-auth-test--page-shows) 2))
        ;; The pages are kept newest first.
        (should-not (plist-get (nth 1 lispm-auth-test--page-shows) :message))
        (should (equal (plist-get (nth 0 lispm-auth-test--page-shows) :message)
                       "Wrong password.  Try again (1 of 3)."))
        (should-not (lispm-auth-locked-p))
        (should (equal (lispm-auth--get "id") "sk-secret"))))))

(ert-deftest lispm-auth-test-page-not-shown-when-already-open ()
  "A store opened this session asks for nothing at a later start."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "right")
      (let ((noninteractive nil)
            (lispm-auth-password-function #'lispm-auth--read-password)
            (lispm-auth--page-show-function #'lispm-auth-test--show-page)
            (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
            (lispm-auth--page-event-function #'lispm-auth-test--event)
            (lispm-auth-test--page-shows nil))
        (should (lispm-auth-start-apps '(desktop)))
        (should (lispm-auth-start-apps '(lispm)))
        (should-not lispm-auth-test--page-shows)))))

(ert-deftest lispm-auth-test-page-not-shown-when-desktop-revoked ()
  "With the desktop revoked, starting it shows no page and opens nothing."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-set-app-requires-password 'desktop nil)
      (let ((noninteractive nil)
            (lispm-auth-password-function #'lispm-auth--read-password)
            (lispm-auth--page-show-function #'lispm-auth-test--show-page)
            (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
            (lispm-auth--page-event-function #'lispm-auth-test--event)
            (lispm-auth-test--page-shows nil))
        (should-not (lispm-auth-start-apps '(desktop)))
        (should-not lispm-auth-test--page-shows)
        (should (lispm-auth-locked-p))))))

(ert-deftest lispm-auth-test-page-first-start-makes-the-store ()
  "The first start asks for a new password twice, and makes the store."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (let ((noninteractive nil)
            (lispm-auth-password-function #'lispm-auth--read-password)
            (lispm-auth--page-show-function #'lispm-auth-test--show-page)
            (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
            (lispm-auth--page-event-function #'lispm-auth-test--event)
            (lispm-auth-test--events
             (append (string-to-list "new-password") '(return)
                     (string-to-list "new-password") '(return)))
            (lispm-auth-test--page-shows nil)
            (lispm-auth-test--page-texts nil)
            (lispm-auth-test--page-buffer nil))
        (should (lispm-auth-start-apps '(desktop)))
        (should (plist-get (car lispm-auth-test--page-shows) :confirm))
        (should (file-exists-p (lispm-auth-key-file)))
        (should-not (lispm-auth-locked-p))))))

(ert-deftest lispm-auth-test-page-offers-to-make-a-password ()
  "A page asking for a new password says that it is asked for, and what
the field takes, as a page asking for the password the store has does
not."
  (let ((page (list :prompt "New LispM password: " :confirm t :message nil
                    :stage 'new :password "")))
    (should (equal (lispm-auth--page-title page) "Set a Password"))
    (should (equal (lispm-auth--page-placeholder page) "New password"))
    (should (string-match-p "Choose a password for LispM's secrets"
                            (lispm-auth--page-answer page)))
    (setf (plist-get page :stage) 'again)
    (should (equal (lispm-auth--page-title page) "Set a Password"))
    (should (equal (lispm-auth--page-placeholder page) "Enter it again")))
  (let ((page (list :prompt "LispM password: " :confirm nil :message nil
                    :stage 'single :password "")))
    (should (equal (lispm-auth--page-title page) "LispM"))
    (should (equal (lispm-auth--page-placeholder page) "LispM password"))
    (should (string-match-p "Return opens the store"
                            (lispm-auth--page-answer page)))))

(ert-deftest lispm-auth-test-page-offers-to-change-only-a-set-password ()
  "The entry page offers C-p to change the password when one is set;
the page asking for a new password does not, and neither does the page
asking for the old one while it is changed."
  (let* ((pages nil)
         (lispm-auth-password-function #'lispm-auth--read-password)
        (lispm-auth--page-show-function
         (lambda (page) (push (copy-sequence page) pages)))
        (lispm-auth--page-hide-function #'ignore)
        (lispm-auth--page-event-function (lambda () 'escape))
        (lispm-auth--changing nil))
    (cl-letf (((symbol-function 'lispm-auth-store-exists-p) (lambda () t)))
      (lispm-auth--page-read "LispM password: " nil nil)
      (should (plist-get (car pages) :change))
      (lispm-auth--page-read "New LispM password: " t nil)
      (should-not (plist-get (car pages) :change))
      (let ((lispm-auth--changing t))
        (lispm-auth--page-read "LispM password: " nil nil)
        (should-not (plist-get (car pages) :change))))
    (cl-letf (((symbol-function 'lispm-auth-store-exists-p) (lambda () nil)))
      (lispm-auth--page-read "LispM password: " nil nil)
      (should-not (plist-get (car pages) :change)))))

(ert-deftest lispm-auth-test-page-changes-the-password ()
  "C-p on the entry page asks for the old password, then for a new one
twice, and encrypts the store with the new one; the secrets stay."
  (lispm-auth-test--with-service
    (lispm-auth-test--with-store
      (lispm-auth-test--make-store "hunter2" (cons "id" "sk-secret"))
      (lispm-auth-lock)
      (let ((noninteractive nil)
            (lispm-auth-password-function #'lispm-auth--read-password)
            (lispm-auth--page-show-function #'lispm-auth-test--show-page)
            (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
            (lispm-auth--page-event-function #'lispm-auth-test--event)
            (lispm-auth-test--events
             (append '(?\C-p)
                     (string-to-list "hunter2") '(return)
                     (string-to-list "another") '(return)
                     (string-to-list "another") '(return)))
            (lispm-auth-test--page-shows nil)
            (lispm-auth-test--page-texts nil)
            (lispm-auth-test--page-buffer nil))
        (should (lispm-auth-start-apps '(desktop)))
        (should lispm-auth--data-key)
        (should (equal (lispm-auth--get "id") "sk-secret"))
        ;; Newest first: the entry page came first and offered the change,
        ;; then the old password was asked for, then the new one twice on
        ;; one page.
        (should (equal (mapcar (lambda (shown) (plist-get shown :title))
                               (reverse lispm-auth-test--page-shows))
                       '("LispM" "LispM" "Set a Password")))
        (should (plist-get (nth 2 lispm-auth-test--page-shows) :change))
        (should-not (plist-get (nth 1 lispm-auth-test--page-shows) :change))
        ;; The store is written with the new password; opening it again
        ;; with that password, not the old one, still gives the secret.
        (lispm-auth-lock)
        (let ((lispm-auth-password-function #'lispm-auth-test--password))
          (setq lispm-auth-test--answers '("another"))
          (should (lispm-auth-unlock))
          (should (equal (lispm-auth--get "id") "sk-secret")))))))


(ert-deftest lispm-auth-test-page-fills-a-terminal-frame ()
  "On a terminal the page fills the frame, and the frame is put back."
  (let* ((noninteractive nil)
         (page (list :prompt "LispM password: " :confirm nil :message nil
                     :stage 'single :password "" :first nil
                     :result nil :done nil
                     :buffer nil :frame nil :window-configuration nil))
         (window (selected-window))
         (buffer (window-buffer window)))
    (cl-letf (((symbol-function 'display-graphic-p) #'ignore))
      (unwind-protect
          (progn
            (lispm-auth--page-show page)
            (should (eq (selected-window) window))
            (should (eq (window-buffer window) (plist-get page :buffer)))
            (with-current-buffer (plist-get page :buffer)
              (should (string-match-p "LispM" (buffer-string)))
              (should (string-match-p "\\[_\\{30\\}\\]" (buffer-string)))
              (should (string-match-p "Return confirms" (buffer-string)))))
        (lispm-auth--page-hide page)))
    (should (eq (window-buffer window) buffer))
    (should-not (get-buffer " *LispM Password*"))))

(ert-deftest lispm-auth-test-page-field-is-visible-in-a-terminal ()
  "A terminal draws no face box, so the field has a visible boundary.
Empty, it is a line of underscores; typed, the bullets sit inside it."
  (cl-letf (((symbol-function 'display-graphic-p) #'ignore))
    (should (string-match-p "\\`\\[_\\{30\\}\\]\\'"
                            (lispm-auth--page-field "")))
    (should (string-match-p "\\`\\[\\*\\{7\\}_\\{23\\}\\]\\'"
                            (lispm-auth--page-field "hunter2")))
    (should-not (string-match-p "hunter2"
                                (lispm-auth--page-field "hunter2")))))

(ert-deftest lispm-auth-test-login-page-fills-lispm-s-window ()
  "The page a start begins with, asking for the password a store
already has, fills LispM's window rather than being drawn as one.  The
frame keeps its size, place and colours, no frame is made or taken
away, and its windows come back with the page."
  (let* ((noninteractive nil)
         (drawn nil)
         (lispm-auth-page-windowed nil)
         (lispm-auth--changing nil)
         (lispm-auth-page-window-draw-function
          (lambda (_page) (setq drawn t) (insert "a window")))
         (page (list :prompt "LispM password: " :confirm nil :message nil
                     :stage 'single :change t :password "" :first nil
                     :result nil :done nil
                     :buffer nil :frame nil :frame-parameters nil
                     :slide nil :window-configuration nil))
         (shown nil) (parameters nil) (configuration nil)
         (deleted nil) (made nil))
    (cl-letf (((symbol-function 'create-image) #'lispm-auth-test--image)
              ((symbol-function 'display-graphic-p) (lambda (&optional _) t))
              ((symbol-function 'selected-frame) (lambda () 'lispm-frame))
              ((symbol-function 'selected-window) (lambda () 'lispm-window))
              ((symbol-function 'window-minibuffer-p) #'ignore)
              ((symbol-function 'frame-parameter)
               (lambda (_frame parameter)
                 (if (eq parameter 'background-color) "desktop" "ink")))
              ((symbol-function 'frame-pixel-width) (lambda (&optional _) 1120))
              ((symbol-function 'frame-pixel-height) (lambda (&optional _) 599))
              ((symbol-function 'frame-char-width) (lambda (&optional _) 10))
              ((symbol-function 'frame-char-height) (lambda (&optional _) 20))
              ((symbol-function 'string-pixel-width)
               (lambda (string) (* 10 (string-width string))))
              ((symbol-function 'lispm-auth--page-logo-image) (lambda () nil))
              ((symbol-function 'current-window-configuration)
               (lambda (&optional frame)
                 (setq configuration (list 'config frame))))
              ((symbol-function 'delete-other-windows) (lambda (&optional _) t))
              ((symbol-function 'switch-to-buffer)
               (lambda (buffer &optional _norecord) (setq shown buffer)))
              ((symbol-function 'redisplay) (lambda (&optional _force) t))
              ((symbol-function 'make-frame)
               (lambda (&optional _parameters) (setq made t) 'page-frame))
              ((symbol-function 'set-frame-parameter)
               (lambda (_frame parameter value)
                 (push (list parameter value) parameters)))
              ((symbol-function 'frame-live-p)
               (lambda (frame) (eq frame 'lispm-frame)))
              ((symbol-function 'delete-frame)
               (lambda (frame &optional _force) (setq deleted frame)))
              ((symbol-function 'set-window-configuration)
               (lambda (one &optional _) (setq configuration one))))
      (unwind-protect
          (progn
            (should-not (lispm-auth--page-windowed-p page))
            (lispm-auth--page-show page)
            ;; LispM's own frame, filled, not one over the screen.
            (should-not made)
            (should (eq (plist-get page :frame) 'lispm-frame))
            (should-not (plist-get page :frame-parameters))
            (should (equal configuration '(config nil)))
            (should (eq shown (plist-get page :buffer)))
            ;; The window's own drawing, not the desktop's.
            (should-not drawn)
            (with-current-buffer (plist-get page :buffer)
              (should (string-match-p "Encrypted Secrets" (buffer-string)))
              (should (string-match-p "Return confirms" (buffer-string))))
            (lispm-auth--page-hide page)
            ;; The frame stays, with the colours it had.
            (should-not deleted)
            (should-not parameters)
            (should (equal configuration '(config nil)))
            (should-not (plist-get page :frame)))
        (when (buffer-live-p (plist-get page :buffer))
          (kill-buffer (plist-get page :buffer)))))))

(ert-deftest lispm-auth-test-page-centres-its-content ()
  "Each line of the page is centred, and the block sits above the middle.
On a graphical display a stretch space before every line aligns it to
the frame's centre, so a face larger than the frame's own font still
centres; the block starts above the middle, as a title page does."
  (let ((buffer (get-buffer-create " *LispM Password Test*"))
        (page (list :prompt "LispM password: " :confirm nil :message nil
                    :stage 'single :password "" :first nil
                    :result nil :done nil
                    :buffer nil :frame 'page-frame :window-configuration nil)))
    (unwind-protect
        (progn
          (with-current-buffer buffer (lispm-auth-page-mode))
          (setf (plist-get page :buffer) buffer)
          (cl-letf (((symbol-function 'create-image) #'lispm-auth-test--image)
                    ((symbol-function 'display-graphic-p) (lambda (&optional _) t))
                    ((symbol-function 'frame-live-p)
                     (lambda (frame) (eq frame 'page-frame)))
                    ((symbol-function 'lispm-auth--page-logo-image)
                     (lambda () nil))
                    ((symbol-function 'frame-pixel-width) (lambda (&optional _) 1600))
                    ((symbol-function 'frame-pixel-height) (lambda (&optional _) 1200))
                    ((symbol-function 'frame-char-width) (lambda (&optional _) 10))
                    ((symbol-function 'frame-char-height) (lambda (&optional _) 20))
                    ((symbol-function 'string-pixel-width)
                     (lambda (string) (* 10 (string-width string)))))
            (lispm-auth--page-redraw page))
          (with-current-buffer buffer
            (goto-char (point-min))
            (should (> (skip-chars-forward "\n") 0))
            (let ((display (get-text-property (point) 'display)))
              (should (eq (car display) 'space))
              (should (eq (nth 1 display) :align-to))
              (should (memq 'center (flatten-tree display))))
            (forward-char 1)
            (should (looking-at "LispM"))
            (should (string-match-p "Encrypted Secrets" (buffer-string)))
            (should (string-match-p "Return opens the store" (buffer-string)))
            (should (string-match-p "Return confirms" (buffer-string)))))
      (kill-buffer buffer))))

(ert-deftest lispm-auth-test-page-draws-a-set-password-in-a-window ()
  "A new password is drawn by the desktop's window drawing.
The page asking for a password a store already has at a start is drawn
that way too, and asks for the old password before a change as well."
  (let* ((drawn nil)
         (lispm-auth-page-windowed nil)
         (lispm-auth--changing nil)
         (lispm-auth-page-window-draw-function
         (lambda (page)
           (push (list (plist-get page :stage)
                       (plist-get page :password))
                 drawn)
           (insert "a window")))
        (lispm-auth--page-show-function #'lispm-auth-test--show-page)
        (lispm-auth--page-hide-function #'lispm-auth-test--hide-page)
        (lispm-auth--page-event-function #'lispm-auth-test--event)
        (lispm-auth-test--events
         (append (string-to-list "one") '(return)
                 (string-to-list "one") '(return)))
        (lispm-auth-test--page-shows nil)
        (lispm-auth-test--page-texts nil)
        (lispm-auth-test--page-buffer nil))
    (cl-letf (((symbol-function 'create-image) #'lispm-auth-test--image)
              ((symbol-function 'display-graphic-p) (lambda (&optional _) t)))
      (should (equal (lispm-auth--page-read "New LispM password: " t nil)
                     "one"))
      ;; Both entries of the new password, and the empty field the second
      ;; one starts from, went through the desktop's drawing.
      (should (equal (delete-dups (mapcar #'car (reverse drawn)))
                     '(new again)))
      (should (equal (seq-filter (lambda (entry) (string-empty-p (cadr entry)))
                                 drawn)
                     '((again "") (new ""))))
      (should (seq-some (lambda (text) (string-match-p "a window" text))
                        lispm-auth-test--page-texts))
      ;; The pages that set a password are windows; the page LispM's own
      ;; start begins with fills the window, unless it is changing the
      ;; password or the start is an application's own.
      (should (lispm-auth--page-windowed-p '(:stage new)))
      (should (lispm-auth--page-windowed-p '(:stage again)))
      (should-not (lispm-auth--page-windowed-p '(:stage single :change t)))
      (should-not (lispm-auth--page-windowed-p '(:stage single)))
      (let ((lispm-auth--changing t))
        (should (lispm-auth--page-windowed-p '(:stage single :change t)))
        (should (lispm-auth--page-windowed-p '(:stage single))))
      (let ((lispm-auth-page-windowed t))
        (should (lispm-auth--page-windowed-p '(:stage single :change t)))))))

(ert-deftest lispm-auth-test-set-password-page-keeps-lispm-s-window ()
  "A page setting or changing a password is drawn in LispM's own frame.
That frame keeps its size and place, rather than the page making one
over the screen, and it takes back its colours and windows with the
page."
  (let* ((noninteractive nil)
         (page (list :prompt "New LispM password: " :confirm t :message nil
                     :stage 'new :password "" :first nil
                     :result nil :done nil
                     :buffer nil :frame nil :frame-parameters nil
                     :slide nil :window-configuration nil))
         (lispm-auth-page-window-draw-function #'ignore)
         (shown nil) (redrawn nil) (parameters nil) (configuration nil)
         (deleted nil) (made nil))
    (cl-letf (((symbol-function 'create-image) #'lispm-auth-test--image)
              ((symbol-function 'display-graphic-p) (lambda (&optional _) t))
              ((symbol-function 'selected-frame) (lambda () 'lispm-frame))
              ((symbol-function 'selected-window) (lambda () 'lispm-window))
              ((symbol-function 'window-minibuffer-p) #'ignore)
              ((symbol-function 'frame-parameter)
               (lambda (_frame parameter)
                 (if (eq parameter 'background-color) "desktop" "ink")))
              ((symbol-function 'frame-pixel-width) (lambda (&optional _) 1120))
              ((symbol-function 'frame-pixel-height) (lambda (&optional _) 599))
              ((symbol-function 'frame-visible-p) (lambda (_frame) t))
              ((symbol-function 'current-window-configuration)
               (lambda (&optional frame) (setq configuration (list 'config frame))))
              ((symbol-function 'delete-other-windows) (lambda (&optional _) t))
              ((symbol-function 'switch-to-buffer)
               (lambda (buffer &optional _norecord) (setq shown buffer)))
              ((symbol-function 'make-frame)
               (lambda (&optional _parameters) (setq made t) 'page-frame))
              ((symbol-function 'lispm-auth--page-redraw)
               (lambda (_page) (setq redrawn t)))
              ((symbol-function 'frame-live-p)
               (lambda (frame) (eq frame 'lispm-frame)))
              ((symbol-function 'delete-frame)
               (lambda (frame &optional _force) (setq deleted frame)))
              ((symbol-function 'set-frame-parameter)
               (lambda (frame parameter value)
                 (push (list frame parameter value) parameters)))
              ((symbol-function 'set-window-configuration)
               (lambda (one &optional _) (setq configuration one))))
      (unwind-protect
          (progn
            (lispm-auth--page-show page)
            ;; LispM's frame, not one over the screen.
            (should-not made)
            (should (eq (plist-get page :frame) 'lispm-frame))
            (should (equal configuration '(config lispm-frame)))
            (should (eq shown (plist-get page :buffer)))
            (should redrawn)
            (lispm-auth--page-hide page)
            ;; The frame stays, with the colours it had.
            (should-not deleted)
            (should (equal (sort (mapcar (lambda (entry)
                                           (list (car entry) (cadr entry) (nth 2 entry)))
                                         parameters)
                                 (lambda (one two)
                                   (string< (format "%S" one) (format "%S" two))))
                           '((lispm-frame background-color "desktop")
                             (lispm-frame foreground-color "ink"))))
            (should (equal configuration '(config lispm-frame)))
            (should-not (plist-get page :frame)))
        (when (buffer-live-p (plist-get page :buffer))
          (kill-buffer (plist-get page :buffer)))))))

(ert-deftest lispm-auth-test-windowed-page-shows-a-frame-started-out-of-sight ()
  "A page drawn as a window shows a frame started out of sight, as an
application opened on its own starts LispM, and hides it with the page."
  (let* ((noninteractive nil)
         (page (list :prompt "LispM password: " :confirm nil :message nil
                     :stage 'single :change t :password "" :first nil
                     :result nil :done nil
                     :buffer nil :frame nil :frame-parameters nil
                     :slide nil :window-configuration nil))
         (lispm-auth-page-windowed t)
         (lispm-auth-page-window-draw-function #'ignore)
         (parameters nil))
    (cl-letf (((symbol-function 'create-image) #'lispm-auth-test--image)
              ((symbol-function 'display-graphic-p) (lambda (&optional _) t))
              ((symbol-function 'selected-frame) (lambda () 'lispm-frame))
              ((symbol-function 'selected-window) (lambda () 'lispm-window))
              ((symbol-function 'window-minibuffer-p) #'ignore)
              ((symbol-function 'frame-parameter)
               (lambda (_frame parameter)
                 (if (eq parameter 'background-color) "desktop" "ink")))
              ((symbol-function 'frame-visible-p) #'ignore)
              ((symbol-function 'current-window-configuration)
               (lambda (&optional _) 'config))
              ((symbol-function 'delete-other-windows) (lambda (&optional _) t))
              ((symbol-function 'switch-to-buffer)
               (lambda (_buffer &optional _norecord) t))
              ((symbol-function 'redisplay) (lambda (&optional _force) t))
              ((symbol-function 'lispm-auth--page-redraw) #'ignore)
              ((symbol-function 'frame-live-p)
               (lambda (frame) (eq frame 'lispm-frame)))
              ((symbol-function 'set-frame-parameter)
               (lambda (frame parameter value)
                 (push (list frame parameter value) parameters)))
              ((symbol-function 'set-window-configuration)
               (lambda (_one &optional _) t)))
      (unwind-protect
          (progn
            (lispm-auth--page-show page)
            ;; The frame started out of sight is shown with the page.
            (should (equal (seq-filter (lambda (entry)
                                         (eq (nth 1 entry) 'visibility))
                                       parameters)
                           '((lispm-frame visibility t))))
            (lispm-auth--page-hide page)
            ;; It is put out of sight again with the page.
            (should (equal (seq-filter (lambda (entry)
                                         (eq (nth 1 entry) 'visibility))
                                       parameters)
                           '((lispm-frame visibility nil)
                             (lispm-frame visibility t)))))
        (when (buffer-live-p (plist-get page :buffer))
          (kill-buffer (plist-get page :buffer)))))))

(ert-deftest lispm-auth-test-page-shows-its-logo-when-it-has-one ()
  "The logo comes first, centred as an image of its own."
  (let ((buffer (get-buffer-create " *LispM Password Test*"))
        (page (list :prompt "LispM password: " :confirm nil :message nil
                    :stage 'single :password "" :first nil
                    :result nil :done nil
                    :buffer nil :frame 'page-frame :window-configuration nil)))
    (unwind-protect
        (progn
          (with-current-buffer buffer (lispm-auth-page-mode))
          (setf (plist-get page :buffer) buffer)
          (cl-letf (((symbol-function 'create-image) #'lispm-auth-test--image)
                    ((symbol-function 'display-graphic-p) (lambda (&optional _) t))
                    ((symbol-function 'frame-live-p)
                     (lambda (frame) (eq frame 'page-frame)))
                    ((symbol-function 'lispm-auth--page-logo-image)
                     (lambda () 'logo))
                    ((symbol-function 'frame-pixel-width) (lambda (&optional _) 1600))
                    ((symbol-function 'frame-pixel-height) (lambda (&optional _) 1200))
                    ((symbol-function 'frame-char-width) (lambda (&optional _) 10))
                    ((symbol-function 'frame-char-height) (lambda (&optional _) 20))
                    ((symbol-function 'string-pixel-width)
                     (lambda (string) (* 10 (string-width string)))))
            (lispm-auth--page-redraw page))
          (with-current-buffer buffer
            (let ((row (text-property-not-all (point-min) (point-max)
                                              'lispm-auth-page-row nil)))
              (should row)
              (should (eq (get-text-property row 'lispm-auth-page-row) t)))
            (let ((logo (text-property-not-all (point-min) (point-max)
                                               'lispm-auth-page-logo nil)))
              (should logo)
              (should (eq (get-text-property logo 'lispm-auth-page-logo) 'logo))
              (should (eq (get-text-property logo 'display) 'logo)))))
      (kill-buffer buffer))))

(ert-deftest lispm-auth-test-page-logo-takes-the-fields-place ()
  "While the logo goes to the field's place the rule and the field are
gone, so that nothing drifts across the page behind it."
  (let ((buffer (get-buffer-create " *LispM Password Test*"))
        (page (list :prompt "LispM password: " :confirm nil :message nil
                    :stage 'single :password "" :first nil
                    :result nil :done nil
                    :buffer nil :frame 'page-frame :window-configuration nil
                    :slide 0.5)))
    (unwind-protect
        (progn
          (with-current-buffer buffer (lispm-auth-page-mode))
          (setf (plist-get page :buffer) buffer)
          (cl-letf (((symbol-function 'create-image) #'lispm-auth-test--image)
                    ((symbol-function 'display-graphic-p) (lambda (&optional _) t))
                    ((symbol-function 'frame-live-p)
                     (lambda (frame) (eq frame 'page-frame)))
                    ((symbol-function 'lispm-auth--page-logo-image)
                     (lambda () 'logo))
                    ((symbol-function 'frame-pixel-width) (lambda (&optional _) 1600))
                    ((symbol-function 'frame-pixel-height) (lambda (&optional _) 1200))
                    ((symbol-function 'frame-char-width) (lambda (&optional _) 10))
                    ((symbol-function 'frame-char-height) (lambda (&optional _) 20))
                    ((symbol-function 'string-pixel-width)
                     (lambda (string) (* 10 (string-width string)))))
            (lispm-auth--page-redraw page))
          (with-current-buffer buffer
            (let* ((start (text-property-not-all (point-min) (point-max)
                                                 'lispm-auth-page-row nil))
                   (end (next-single-property-change start
                                                     'lispm-auth-page-row))
                   (row (get-text-property start 'lispm-auth-page-row))
                   (logo (text-property-not-all (point-min) (point-max)
                                                'lispm-auth-page-logo nil)))
              (should row)
              (should logo)
              (should (eq (get-text-property logo 'lispm-auth-page-logo) 'logo))
              ;; Only the logo's stretch space and the logo are left.
              (should (= (length (buffer-substring start end)) 2))
              (should-not (text-property-not-all
                           (point-min) (point-max)
                           'lispm-auth-page-field-image nil)))))
      (kill-buffer buffer))))

(ert-deftest lispm-auth-test-change-idle-time-reschedules ()
  (let ((lispm-auth--unlocked t)
        (lispm-auth--data-key nil)
        (lispm-auth--last-use (time-subtract (current-time) (seconds-to-time 120)))
        (lispm-auth--lock-timer nil)
        (lispm-auth-auto-lock nil))
    (unwind-protect
        (progn
          (lispm-auth-set-auto-lock 5)
          (should (timerp lispm-auth--lock-timer))
          (lispm-auth-set-auto-lock nil)
          (should-not lispm-auth--lock-timer)
          (lispm-auth-set-auto-lock 1)
          (should-not lispm-auth--unlocked))
      (lispm-auth--cancel-lock-timer))))

(ert-deftest lispm-auth-test-unlock-checks-idle-expiration ()
  (let ((lispm-auth--unlocked t)
        (lispm-auth--data-key nil)
        (lispm-auth--last-use (time-subtract (current-time) (seconds-to-time 120)))
        (lispm-auth--lock-timer nil)
        (lispm-auth-auto-lock 1))
    (cl-letf (((symbol-function 'lispm-auth--check-store-format) #'ignore)
              ((symbol-function 'lispm-auth-store-exists-p) (lambda () t))
              ((symbol-function 'lispm-auth--unlock-file) (lambda () nil)))
      (should-not (lispm-auth-unlock))
      (should-not lispm-auth--unlocked))))

(ert-deftest lispm-auth-test-early-timer-rearms-after-extension ()
  (let ((lispm-auth--unlocked t)
        (lispm-auth--data-key nil)
        (lispm-auth--last-use (time-subtract (current-time) (seconds-to-time 60)))
        (lispm-auth--lock-timer nil)
        (lispm-auth-auto-lock 5))
    (unwind-protect
        (progn
          (lispm-auth--auto-lock)
          (should lispm-auth--unlocked)
          (should (timerp lispm-auth--lock-timer)))
      (lispm-auth--cancel-lock-timer))))

(ert-deftest lispm-auth-test-first-password-is-setup-operation ()
  (let ((lispm-auth-password-function
         (lambda (&rest _) (should-not lispm-auth--changing) nil)))
    (cl-letf (((symbol-function 'lispm-auth--check-store-format) #'ignore)
              ((symbol-function 'lispm-auth-store-exists-p) #'ignore))
      (should-error (lispm-auth-change-password) :type 'user-error))))

(provide 'lispm-auth-test)
;;; lispm-auth-test.el ends here
