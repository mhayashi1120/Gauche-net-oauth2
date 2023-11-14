;;;
;;; Test net_oauth2
;;;

(use gauche.test)

(test-start "net.oauth2")

(use net.oauth2)
(test-module 'net.oauth2)

(use file.util)

(library-for-each
 'net.oauth2.*
 ;; gauche `load` need ./ or ../ prefix.
 (^ [module path]
   (let1 path* (if (absolute-path? path)
                 path
                 #"./~|path|")
     (load path*))
   (test-module module)))

(test-end :exit-on-failure #t)
