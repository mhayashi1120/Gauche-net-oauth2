;;;
;;; Test net_oauth2
;;;

(use gauche.test)

(test-start "net.oauth2")
(use net.oauth2)
(test-module 'net.oauth2)

;; If you don't want `gosh' to exit with nonzero status even if
;; test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)




