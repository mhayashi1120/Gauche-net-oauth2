;;;
;;; Test net_oauth2
;;;

(use gauche.test)

(test-start "net.oauth2")

(use net.oauth2)
(test-module 'net.oauth2)

(library-for-each
 'net.oauth2.*
 ;; gauche `load` need ./ or ../ prefix.
 (^ [module path] (load #"./~|path|") (test-module module)))

(test-end :exit-on-failure #t)
