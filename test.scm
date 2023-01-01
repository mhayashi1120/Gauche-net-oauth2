;;;
;;; Test net_oauth2
;;;

(use gauche.test)

(test-start "net.oauth2")

(use net.oauth2)
(test-module 'net.oauth2)

(use net.oauth2.code-verifier)
(test-module 'net.oauth2.code-verifier)

(use net.oauth2.native-app)
(test-module 'net.oauth2.native-app)

(test-end :exit-on-failure #t)
