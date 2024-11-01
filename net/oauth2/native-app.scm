;;;
;;; net.oauth2.native-app
;;;
(define-module net.oauth2.native-app
  (use data.queue)
  (use gauche.net)
  (use gauche.threads)
  (use rfc.uri)
  (use srfi-13)
  (use srfi-19)
  (use util.match)

  (export
   bind-loopback-redirect! ensure-socket-close!
   bind-loopback-server!
   installed-app-receive-code))
(select-module net.oauth2.native-app)

;; # Basic concepts:
;; - ref: https://www.rfc-editor.org/rfc/rfc8252
;; - ref: https://tex2e.github.io/rfc-translater/html/rfc8252.html
;; - Maybe not enough implemented rfc8252. But working well.

;; # TODO
;; - Simple HTTP server might be abort if too many size recv for security reason

;;;
;;; Port Listener
;;;

(autoload gauche.connection connection-input-port connection-output-port)

(define (%polling-socket serv state :key (sender! #f))
  (guard (e [else (report-error e)])
    (let* ([client (socket-accept serv)]
           [code (receive-code-with-http
                  (connection-input-port client)
                  (connection-output-port client)
                  state)])
      (cond
       [sender! (sender! code)]
       [else code]))))

(autoload www.cgi cgi-parse-parameters)
(autoload rfc.822 date->rfc822-date
          rfc822-write-headers rfc822-read-headers
          rfc822-header-ref)

;; -> CODE:<string>
(define (receive-code-with-http client-ip client-op state)
  (define (http-response http-code :key (additionals ()) (body #f))
    (with-output-to-port client-op
      (^[]
        (format #t "~a\r\n" http-code)
        (rfc822-write-headers (cond-list
                               [(and body
                                     (< 0 (string-length body)))
                                (list "Content-Type" "text/plain")]
                               [#t (list "Content-Length"
                                         ;; assume string just ascii.
                                         (if body (x->string (string-length body)) "0"))]
                               [#t (list "Date" (date->rfc822-date (current-date)))]
                               [#t @ additionals]
                               ))
        (when body
          (format #t "~a" body))
        ))
    (close-port client-op))

  (define (response-bad!)
    (http-response "HTTP 403 Forbidden" :body "Forbidden"))

  (define (response-ok!)
    (http-response "HTTP 200 OK" :body "Success"))

  (let* ([http-request (read-line client-ip)]
         [http-hdrs (rfc822-read-headers client-ip)])
    (match (string-split http-request #[ \t])
      [("GET" uri . _) (=> bad)
       (match (values->list (uri-parse uri))
         [(#f #f #f #f (? string?) (? string? query-string)  . _)
          ;; If `state` passed from caller, check the value is correct.
          (let1 q (cgi-parse-parameters :query-string query-string)
            (cond
             [(not state)]
             [(rfc822-header-ref q "state") =>
              (^ [state*]
                (unless (equal? state state*)
                  (bad)))]
             [else (bad)])
            (cond
             [(rfc822-header-ref q "code") =>
              (^ [code]
                (response-ok!)
                code)]
             [else
              (bad)]))]
         [_
          (bad)])]
      [_
       (response-bad!)
       #f])))

;; ## Simple HTTP server starter
;; - :sender! :  <procedure> (CODE:<string>) -> <void>
(define (sock-listener$ serv :key (sender! #f) (state #f))
  (^[] (%polling-socket serv state :sender! sender!)))

;;;
;;; Console prompt
;;;

(define (%polling-console :key (sender! #f))
  (let loop ()
    (format #t "Input CODE: ")
    (flush)
    (let1 code (read-line)
      (cond
       [(eof-object? code)
        (print "Quit the authorization.")
        #f]
       [(string-null? code)
        (loop)]
       [sender!
        (sender! code)]
       [else
        code]))))

(define (console-reader$ url :key (sender! #f))
  (format #t "Open the following url with your favorite browser.\n")
  (format #t "If you admit the permission type in the shown CODE.\n")
  (format #t "\n")
  (format #t "~a\n" url)
  (format #t "\n")
  (^[] (%polling-console :sender! sender!)))


;;;
;;; Browser (Maybe GUI)
;;;

(autoload file.util find-file-in-paths)
(autoload gauche.process do-process! do-process)

(define (browser-starter$ behavior url)
  (define *opener* (find-file-in-paths "xdg-open"))

  (define (start!)
    (do-process! `(,*opener* ,url) :output :null :error :null))

  (^[]
    (ecase behavior
      [(:try)
       (and *opener*
            (start!))]
      [(:force)
       (unless *opener*
         (error "No acceptable browser found."))
       (start!)])))

;;;
;;; Receive
;;;

(define (start-watch! receiver timeout)
  (let1 th (make-thread
            (^[]
              (let loop ()
                (cond
                 [(receiver) =>
                  (^ [code] code)]
                 [else
                  (sys-sleep 1)
                  (loop)]))))
    (thread-start! th)
    (thread-join! th timeout)))

(define (%make-notifier)
  (let1 q (make-mtqueue)
    (values
     (^[msg] (enqueue! q msg))
     (^[] (dequeue! q #f)))))

;;;
;;; API
;;;

;; ## This procedure mentioned in `7.1.  Private-Use URI Scheme`
;; *Currently not used*
;; RFC mentioned in following URI.
;; > com.example.app:/oauth2redirect/example-provider
;; -> <string>
(define (private-uri-scheme fqdn)
  ($ (cut string-join <> ".")
     $ reverse
     $ string-split fqdn "."))

;; ## Bind loopback server. Should close by `ensure-socket-close!`
;; - :ipv6? : #t If want to use IPv6
;; - :path : <string> | #f path part of redirect-uri
;; -> [SOCKET:<sockaddr*>, REDIRECT:<string>]
(define (bind-loopback-redirect! :key (ipv6? #f) (path #f) (port #f))
  (let* ([in (make (if ipv6? <sockaddr-in6> <sockaddr-in>)
               :host :loopback
               :port (or port 0))]
         [serv (make-server-socket in)]
         [sock (socket-address serv)]
         [address (sockaddr-name sock)]
         )
    (values serv (format "http://~a/~a" address
                         (or path "")))))

;; ## TODO still testing. Maybe change future release.
;; Utility to wrap [=bind-loopback-redirect!]()
;; This work on Twitter. Twitter seems doesn't support dynamic port binding. So,
;;  REDIRECT-URI should contain port.
;; - REDIRECT-URI : <string> URL that is registered callback or redirect url on
;;        OAuth2 provider.
;; -> <sockaddr*>
(define (bind-loopback-server! redirect-uri)
  (receive (scheme _ host port path . _) (uri-parse redirect-uri)

    (unless (member scheme '("http"))
      (error "Not a supported scheme" scheme))

    (unless (member host '("localhost" "127.0.0.1" "::1"))
      (error "Not a valid host" host))

    (receive (serv _) (bind-loopback-redirect!
                       :ipv6? (string=? host "::1")
                       :path path
                       :port (or port 80))
      serv)))

;; ## SOCKET should be generated by [=bind-loopback-redirect!]()
;; -> <void>
(define (ensure-socket-close! socket)
  (unless (memq (socket-status socket) '(shutdown closed))
    (socket-shutdown socket)))

(autoload control.thread-pool make-thread-pool add-job! terminate-all!)

;; ## Read code from user action.
;; - :bind-server : <socket> that is generated by [=bind-loopback-redirect!]()
;; - :prompt? : Show prompt which can read `code` on console.
;; - :browser : <keyword> :never / :try / :force
;; - :state : <string> | #f If need check local side `state` is valid or not.
;;         This `state` might be generated and appended `Authorization Request` URL.
;; - :timeout : <integer> Seconds to timeout
;; -> CODE:<string>
(define (installed-app-receive-code
         url
         :key (prompt? #t) (http-listener #f)
         (browser :try)
         (state #f) (bind-server #f)
         (timeout 180))

  (receive (sender! receiver) (%make-notifier)
    (let1 pool (make-thread-pool 5) ; 5 maybe enough ;-)

      (case browser
        [(:never)]
        [else
         (add-job! pool (browser-starter$ browser url))])

      (when bind-server
        (add-job! pool (sock-listener$ bind-server :sender! sender! :state state)))

      (when prompt?
        (add-job! pool (console-reader$ url :sender! sender!)))

      (rlet1 code (start-watch! receiver timeout)
        ;; Forcibly terminate all job
        (terminate-all! pool :force-timeout 1)))))
