;;; lispm-auth-release-test.el --- Generated release gate -*- lexical-binding: t; -*-
(require 'ert)
(require 'lispm-auth)

(ert-deftest lispm-auth-release-test-production-pins ()
  "Install the actual archive with unmodified generated production pins."
  (let* ((archive (getenv "LISPM_AUTH_RELEASE_ARCHIVE"))
         (version (getenv "LISPM_AUTH_EXPECTED_VERSION"))
         (platform (getenv "LISPM_AUTH_EXPECTED_PLATFORM")))
    ;; Unlike optional packaging tests, this release gate never silently skips.
    (should (and archive (file-regular-p archive)))
    (should (equal lispm-auth-service-version version))
    (should (equal (lispm-auth--service-platform) platform))
    (should (= (length lispm-auth-service-sha256) 4))
    (dolist (name '("darwin-arm64" "darwin-x86_64" "linux-x86_64" "linux-arm64"))
      (should (string-match-p "\\`[0-9a-f]\\{64\\}\\'"
                              (cdr (assoc name lispm-auth-service-sha256)))))
    (let* ((root (make-temp-file "lispm-auth-release-" t))
           (lispm-auth-service-directory (expand-file-name "installed/" root))
           (lispm-auth-service-program nil)
           (lispm-auth--package-directory (expand-file-name "no-prebuilt/" root)))
      (unwind-protect
          (progn
            (lispm-auth-install-service archive)
            (should (file-executable-p (lispm-auth--service-program)))
            (should (string-prefix-p lispm-auth-service-directory
                                     (lispm-auth--service-program)))
            (let* ((key (lispm-auth--service "random"))
                   (blob (lispm-auth--service "encrypt" key "6964" "736563726574")))
              (should (equal (lispm-auth--service "decrypt" key "6964" blob)
                             "736563726574")))
            (should-error (lispm-auth-install-service archive) :type 'user-error))
        (delete-directory root t)))))

(provide 'lispm-auth-release-test)
