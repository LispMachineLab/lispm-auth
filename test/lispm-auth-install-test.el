;;; lispm-auth-install-test.el --- Release installer tests -*- lexical-binding: t; -*-
(require 'ert)
(require 'cl-lib)
(require 'lispm-auth)

(defun lispm-auth-install-test--archive (file name &optional kind)
  "Write a small USTAR archive with NAME and KIND to FILE, using Python."
  (unless (zerop (call-process
                 (or (executable-find "python3") (ert-skip "Python unavailable"))
                 nil nil nil "-c"
                 (concat "import io,sys,tarfile; "
                         "t=tarfile.open(sys.argv[1],'w:gz',format=tarfile.USTAR_FORMAT); "
                         "i=tarfile.TarInfo(sys.argv[2]); i.type=sys.argv[3].encode(); "
                         "i.linkname='outside'; i.size=4 if i.type==b'0' else 0; "
                         "t.addfile(i,io.BytesIO(b'test') if i.size else None); t.close()")
                 file name (or kind "0")))
    (error "Cannot create test archive")))

(defmacro lispm-auth-install-test--temporary (&rest body)
  (declare (indent 0))
  `(let* ((root (make-temp-file "lispm-auth-install-test-" t))
          (archive (expand-file-name "release.tar.gz" root))
          (target (expand-file-name "target" root))
          (lispm-auth-service-directory (expand-file-name "installed/" root)))
     (unwind-protect (progn (make-directory target) ,@body)
       (delete-directory root t))))

(ert-deftest lispm-auth-install-test-no-pin-no-download ()
  (let ((lispm-auth-service-sha256 nil))
    (cl-letf (((symbol-function 'lispm-auth--download-service)
               (lambda (&rest _) (ert-fail "Unexpected network"))))
      (should-error (lispm-auth-install-service) :type 'user-error))))

(ert-deftest lispm-auth-install-test-checksum-before-extraction ()
  (lispm-auth-install-test--temporary
    (lispm-auth-install-test--archive archive "lispm-auth-service")
    (let ((lispm-auth-service-sha256
           (list (cons (lispm-auth--service-platform) (make-string 64 ?0)))))
      (cl-letf (((symbol-function 'lispm-auth--extract-service)
                 (lambda (&rest _) (ert-fail "Extracted an unverified archive"))))
        (should-error (lispm-auth-install-service archive) :type 'lispm-auth-error))
      (should-not (file-exists-p (lispm-auth--installed-service-directory
                                 (lispm-auth--service-platform)))))))

(ert-deftest lispm-auth-install-test-safe-extraction ()
  (lispm-auth-install-test--temporary
    (lispm-auth-install-test--archive archive "lib/example.dylib")
    (lispm-auth--extract-service archive target)
    (should (equal (with-temp-buffer
                     (insert-file-contents (expand-file-name "lib/example.dylib" target))
                     (buffer-string)) "test"))))

(ert-deftest lispm-auth-install-test-rejects-paths-and-links ()
  (dolist (entry '(("../outside" "0") ("/outside" "0") ("lib/../../outside" "0")
                   ("./file" "0") ("lib/link" "2") ("hardlink" "1")
                   ("device" "3") ("extension" "x")))
    (lispm-auth-install-test--temporary
      (lispm-auth-install-test--archive archive (car entry) (cadr entry))
      (should-error (lispm-auth--extract-service archive target) :type 'lispm-auth-error)
      (should-not (file-exists-p (expand-file-name "outside" root))))))

(ert-deftest lispm-auth-install-test-atomic-activation-and-no-overwrite ()
  (lispm-auth-install-test--temporary
    (lispm-auth-install-test--archive archive "lispm-auth-service")
    (let* ((platform (lispm-auth--service-platform))
           (lispm-auth-service-sha256
            (list (cons platform (with-temp-buffer
                                   (set-buffer-multibyte nil)
                                   (insert-file-contents-literally archive)
                                   (secure-hash 'sha256 (current-buffer)))))))
      (cl-letf (((symbol-function 'lispm-auth--service)
                 (lambda (&rest _) (signal 'lispm-auth-unavailable nil))))
        (should-error (lispm-auth-install-service archive) :type 'lispm-auth-unavailable))
      (should-not (file-exists-p (lispm-auth--installed-service-directory platform)))
      (cl-letf (((symbol-function 'lispm-auth--service)
                 (lambda (&rest _) (make-string 64 ?0))))
        (lispm-auth-install-service archive))
      (let ((program (expand-file-name "lispm-auth-service"
                                      (lispm-auth--installed-service-directory platform))))
        (should (file-executable-p program))
        (let ((lispm-auth-service-program nil)
              (lispm-auth--package-directory (expand-file-name "missing-package/" root)))
          (should (equal (lispm-auth--service-program) program)))
        (should-error (lispm-auth-install-service archive) :type 'user-error)))))

(ert-deftest lispm-auth-install-test-download-error-leaves-no-installation ()
  (lispm-auth-install-test--temporary
    (let ((lispm-auth-service-sha256
           (list (cons (lispm-auth--service-platform) (make-string 64 ?0)))))
      (cl-letf (((symbol-function 'lispm-auth--download-service)
                 (lambda (&rest _) (signal 'file-error '("Network unavailable")))))
        (should-error (lispm-auth-install-service) :type 'file-error))
      (should-not (file-exists-p (lispm-auth--installed-service-directory
                                 (lispm-auth--service-platform)))))))

(ert-deftest lispm-auth-install-test-corrupted-header ()
  (lispm-auth-install-test--temporary
    (lispm-auth-install-test--archive archive "lispm-auth-service")
    (with-temp-buffer
      (set-buffer-multibyte nil)
      (insert-file-contents-literally archive)
      (zlib-decompress-region (point-min) (point-max))
      (goto-char (point-min))
      (delete-char 1)
      (insert "X")
      (cl-letf (((symbol-function 'zlib-decompress-region) (lambda (&rest _) t)))
        (let ((bytes (buffer-string)))
          (let ((file-name-handler-alist nil)
                (coding-system-for-write 'no-conversion))
            (with-temp-file archive
              (set-buffer-multibyte nil)
              (insert bytes)))
          (should-error (lispm-auth--extract-service archive target) :type 'lispm-auth-error))))))

(ert-deftest lispm-auth-install-test-real-release ()
  "Exercise actual packaging output when explicitly supplied by CI."
  (let ((release (getenv "LISPM_AUTH_RELEASE_ARCHIVE")))
    (when release
      (lispm-auth-install-test--temporary
        (let* ((platform (lispm-auth--service-platform))
               (lispm-auth-service-sha256
                (list (cons platform
                            (with-temp-buffer
                              (set-buffer-multibyte nil)
                              (insert-file-contents-literally release)
                              (secure-hash 'sha256 (current-buffer))))))
               (lispm-auth-service-program nil)
               (lispm-auth--package-directory (expand-file-name "missing/" root)))
          (lispm-auth-install-service release)
          (should (string-match-p "\\`[0-9a-f]\\{64\\}\\'" (lispm-auth--service "random")))
          (let* ((key (lispm-auth--service "random"))
                 (blob (lispm-auth--service "encrypt" key "6964" "736563726574")))
            (should (equal (lispm-auth--service "decrypt" key "6964" blob)
                           "736563726574"))))))))

(provide 'lispm-auth-install-test)
