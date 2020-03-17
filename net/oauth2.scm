;;;
;;; OAuth 2.0 (rfc6749, rfc6750)
;;;

;; RFC 6749 is almost working now.
;; RFC 6750 is implementing now.

(define-module net.oauth2
  (use util.match)
  (use rfc.822)
  (use text.tr)
  (use rfc.http)
  (use rfc.sha)
  (use rfc.hmac)
  (use rfc.base64)
  (use rfc.uri)
  (use srfi-1)
  (use math.mt-random)
  (use gauche.version)

  (export
   <oauth2-cred>
   oauth2-request-password-credential
   oauth2-request-implicit-grant
   oauth2-construct-auth-request-url
   oauth2-request-auth-token
   oauth2-request-client-credential
   oauth2-refresh-token
   oauth2-bearer-header

   ;; Utility procedures
   oauth2-write-token oauth2-read-token

   oauth2-request oauth2-request/json
   oauth2-stringify-scope
   ))
(select-module net.oauth2)

(unless (version>? (gauche-version) "0.9")
  (error "Unable to load oauth2 (https is not supported)"))

(autoload rfc.json parse-json-string)
(autoload www.cgi cgi-parse-parameters)
(autoload rfc.mime mime-parse-content-type)
(autoload sxml.ssax ssax:xml->sxml)

;;;
;;; inner utilities
;;;

(define (stringify-scope scope)
  (cond
   [(pair? scope)
    (string-join scope " ")]
   [(string? scope)
    scope]))

(define (valid-scope? x)
  (or (pair? x)
      (string? x)))

(define (other-keys->params keys)
  (define (->string x)
    (cond
     [(keyword? x)
      (keyword->string x)]
     [else
      (x->string x)]))

  (define (x->name x)
    (string-tr (->string x) "-" "_"))

  (let loop ([params keys]
             [res '()])
    (cond
     [(null? params)
      (reverse res)]
     [(not (cadr params))
      (loop (cddr params) res)]
     [else
      (let ([k (car params)]
            [v (cadr params)])
        (loop (cddr params)
              (cons
               `(,(x->name k) ,(x->string v))
               res)))])))

;;TODO no-redirect when fragment
(define (request-oauth2 method url params :key (auth #f) (accept #f))
  (receive (scheme specific) (uri-scheme&specific url)
    (receive (host path . rest) (uri-decompose-hierarchical specific)
      (receive (status header body)
          (case method
            [(post)
             (http-post host path params
                        :secure #t
                        :Accept accept
                        :Authorization auth)]
            [(get)
             (http-get host #`",|path|?,(http-compose-query #f params 'utf-8)"
                       :secure #t
                       :Authorization auth
                       ;;TODO
                       :no-redirect #t)]
            (else (error "oauth2-request: unsupported method" method)))
        ;; may respond 302
        (unless (#/^[23][0-9][0-9]$/ status)
          (errorf "oauth-request: service provider responded ~a: ~a"
                  status body))
        (values body header status)))))

;; Utility wrapper to parse response body with content-type
(define (request->response/content-type . args)
  (receive (body header status)
      (apply request-oauth2 args)
    (and-let* ([content-type (rfc822-header-ref header "content-type")]
               [ct (mime-parse-content-type content-type)])
      (match ct
        [(_ "json" . _)
         (set! body (parse-json-string body))]
        [(_ "xml" . _)
         (set! body (call-with-input-string body (cut ssax:xml->sxml <> '())))]
        [(_ "x-www-form-urlencoded" . _)
         (set! body (cgi-parse-parameters :query-string body))]
        [else
         (errorf "Not a supported Content-Type: ~a" content-type)]))
    (values body header status)))

;; http://oauth.net/2/
;; http://tools.ietf.org/rfc/rfc6749.txt

;;;
;;; Public type
;;;

(define-class <oauth2-cred> ()
  ((access-token  :init-keyword :access-token)
   (refresh-token :init-keyword :refresh-token)))

;; 4.  Obtaining Authorization
;; ....
;; OAuth defines four grant types: authorization code, implicit,
;; resource owner password credentials, and client credentials.
;; ....

;;;
;;; Authorization Code (Section 4.1)
;;;

;; 4.1.1.  Authorization Request
(define (oauth2-construct-auth-request-url
         url client-id
         :key
         ;; optional
         (redirect #f) (scope '())
         ;; recommended
         (state #f)
         :allow-other-keys _keys)
  (let* ([params
          (cond-list
           [#t `("response_type" "code")]
           [#t `("client_id" ,client-id)]
           [redirect `("redirect_uri" ,redirect)]
           [(valid-scope? scope) `("scope" ,(stringify-scope scope))]
           [state `("state" ,state)]
           [#t @ (other-keys->params _keys)])]
         [query (http-compose-query #f params 'utf-8)])
    #`",|url|?,|query|"))

;; 4.1.2.  Authorization Response (In user browser)

;; 4.1.3.  Access Token Request
(define (oauth2-request-auth-token url code redirect client-id . keys)
  (request->response/content-type
   'post url
   (cond-list
    [#t `("grant_type" "authorization_code")]
    [#t `("code" ,code)]
    [#t `("redirect_uri" ,redirect)]
    [#t `("client_id" ,client-id)]
    ;;TODO not described in doc
    [#t @ (other-keys->params keys)])))

;;;
;;; Implicit Grant (Section 4.2)
;;;

(define (oauth2-request-implicit-grant
         url client-id
         :key (redirect #f) (scope '()) (state #f)
         :allow-other-keys params)
  (request-oauth2
   'get url
   (cond-list
    [#t `("response_type" "token")]
    [#t `("client_id" ,client-id)]
    [redirect `("redirect_uri" ,redirect)]
    [(valid-scope? scope) `("scope" ,(stringify-scope scope))]
    [state `("state" ,state)]
    [#t @ (other-keys->params params)])))

;;;
;;; Resource Owner Password Credentials (Section 4.3)
;;;

(define (oauth2-request-password-credential
         url username password :key (scope '())
         :allow-other-keys params)
  (request->response/content-type
   'post url
   (cond-list
    [#t `("grant_type" "password")]
    [#t `("username" ,username)]
    [#t `("password" ,password)]
    [(valid-scope? scope) `("scope" ,(stringify-scope scope))]
    [#t @ (other-keys->params params)])
   :auth (basic-authentication username password)))

;;;
;;; Client Credentials (Section 4.4)
;;;

(define (oauth2-request-client-credential
         url username password :key (scope '())
         :allow-other-keys params)
  (request->response/content-type
   'post url
   (cond-list
    [#t `("grant_type" "client_credentials")]
    [(valid-scope? scope) `("scope" ,(stringify-scope scope))]
    [#t @ (other-keys->params params)])
   :auth (basic-authentication username password)))

;; todo Extensions (Section 4.5)
;; (define (oauth2-request-extensions url)
;;   )

;;TODO rfc6750
(define (oauth2-bearer-header cred)
  (format "Bearer ~a" (slot-ref cred 'access-token)))

(define (basic-authentication user pass)
  (format "Basic ~a" (base64-encode-string #`",|user|:,|pass|")))

;; (Section 6)
(define (oauth2-refresh-token url refresh-token :key (scope '())
                              :allow-other-keys _keys)
  (request->response/content-type
   'post url
   (cond-list
    [#t `("grant_type" "refresh_token")]
    [#t `("refresh_token" ,refresh-token)]
    [(valid-scope? scope)
     `("scope" ,(stringify-scope scope))]
    [#t @ (other-keys->params _keys)])))

;;;
;;; Utilities to save credential
;;;

(define (oauth2-write-token cred :optional (output-port (current-output-port)))
  (format output-port "(\n")
  (dolist (slot (class-slots (class-of cred)))
    (let1 name (car slot)
      (when (slot-bound? cred name)
        (let1 value (~ cred name)
          (format output-port " ~s\n" (cons name value))))))
  (format output-port ")\n"))

(define (oauth2-read-token
         :optional (class <oauth2-cred>) (input-port (current-input-port)))
  (let ([sexp (with-input-from-port input-port read)]
        [cred (make class)])
    (dolist (slot (class-slots class))
      (slot-set! cred (car slot) (assoc-ref sexp (car slot))))
    cred))

;;;
;;; Utilities for special implementation
;;;

;; Backward compatibility. Should be obsoleted. Wrapper `oauth2-request` .
(define (oauth2-request/json . args)
  (apply oauth2-request (append args (list :accept "application/json"))))

;; METHOD: `post` / `get`
;; URL: endpoint of Oauth provider.
;; PARAMS: pass to `http-compose-query`
;; KEYWORDS: Accept `:auth` `:accept` .
(define (oauth2-request method url params . keywords)
  (apply request-oauth2 method url params keywords))

(define oauth2-stringify-scope stringify-scope)
