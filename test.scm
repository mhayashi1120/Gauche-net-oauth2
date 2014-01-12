;;;
;;; Test net_oauth2
;;;

(use gauche.test)

(test-start "net.oauth2")
(use net.oauth2)
(test-module 'net.oauth2)

;; The following is a dummy test code.
;; Replace it for your tests.
(test* "test-net_oauth2" "net_oauth2 is working"
       (test-net_oauth2))

;; If you don't want `gosh' to exit with nonzero status even if
;; test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)




