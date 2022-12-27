;;;
;;; OAuth 2.0 (rfc6749, rfc6750)
;;;

;; # Status the develop:
;; - RFC 6749 is almost working now.
;; - RFC 6750 is implementing now.
;; - Need cleanup and might be obsoleted some of api.

(define-module net.oauth2
  (use util.match)
  (use rfc.822)
  (use text.tr)
  (use rfc.http)
  (use rfc.sha)
  (use rfc.hmac)
  (use rfc.uri)
  (use srfi-1)
  (use math.mt-random)
  (use gauche.version)

  (export
;;;
;;; These procedure return 3 values (BODY HEADERS STATUS)
;;; Not like rfc.http procedures (`http-post` / `http-get` ...)
;;;
   oauth2-request-password-credential
   oauth2-request-implicit-grant
   oauth2-request-access-token
   oauth2-request-client-credential
   oauth2-refresh-token
   
   oauth2-construct-auth-request-url

   oauth2-bearer-header

   oauth2-stringify-scope
   oauth2-post oauth2-get
   )

  ;; Testing exports
  (export
   basic-authentication
   )

  ;; Obsoleting exports
  (export
   ;; should use `oauth2-request-access-token`
   oauth2-request-auth-token

   oauth2-request/json
   oauth2-request
   )
  )
(select-module net.oauth2)

;; # About :request-content-type
;; TODO describe more.

(unless (version>? (gauche-version) "0.9")
  (error "Unable to load oauth2 (https is not supported)"))

(autoload rfc.json parse-json-string construct-json-string)
(autoload www.cgi cgi-parse-parameters)
(autoload rfc.mime mime-parse-content-type)
(autoload sxml.ssax ssax:xml->sxml)

;;;
;;; inner utilities
;;;

(define (%stringify-scope scope)
  (cond
   [(pair? scope)
    (string-join scope " ")]
   [(string? scope)
    scope]))

(define (%is-scope? x)
  (or (pair? x)
      (string? x)))

(define (%other-keys->params keys)
  (define (->string x)
    (cond
     [(keyword? x)
      (keyword->string x)]
     [else
      (x->string x)]))

  ;; Scheme generic separator `-` (Hyphen) to Oauth2 parameter separator `_` (Underscore)
  (define (name->parameter x)
    (string-tr (->string x) "-" "_"))

  (let loop ([params keys]
             [res '()])
    (match params
      [()
       (reverse! res)]
      [(_ #f . rest)
       (loop rest res)]
      [(k v . rest)
       (loop rest
             (cons
              `(,(name->parameter k) ,(x->string v))
              res))])))

(define (%request method url query-params request-body
                  :key (auth #f) (accept #f)
                  :allow-other-keys http-options)
  (receive (_ specific) (uri-scheme&specific url)
    (receive (host path query . _) (uri-decompose-hierarchical specific)
      (let* ([query* (if query
                       (cgi-parse-parameters :query-string query)
                       ())]
             [params* (or query-params ())]
             [req-resource (http-compose-query path (append query* params*) 'utf-8)])
        (receive (status header body)
            (case method
              [(post)
               (apply http-post host req-resource request-body
                      :secure #t
                      :Accept accept
                      :Authorization auth
                      http-options)]
              [(get)
               (apply http-get host req-resource
                      :secure #t
                      :Accept accept
                      :Authorization auth
                      http-options)]
              [else (error "oauth2-request: unsupported method" method)])
          ;; 2xx exactly ok, Not enough consideration about 3xx now. (TODO)
          (unless (#/^[23][0-9][0-9]$/ status)
            (errorf "oauth-request: service provider responded ~a: ~a"
                    status body))
          (values body header status))))))

(define (%response-receivr body header status)
  (and-let* ([(#/^2/ status)]  ;; Might be a redirect status.
             [content-type (rfc822-header-ref header "content-type")]
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
  (values body header status))

(define (%construct-request params-or-blob http-options)
  (let-keywords http-options
      ([content-type #f]
       . other-http-options)
    (cond
     [(not content-type)
      (values params-or-blob http-options)]
     [(string? content-type)
      (match (mime-parse-content-type content-type)
        [#f
         (values params-or-blob http-options)]
        [(_ "x-www-form-urlencoded" . _)
         (values (http-compose-query #f params-or-blob)
                 http-options)]
        [(_ "json" . _)
         (values (construct-json-string params-or-blob)
                 http-options)]
        [else
         (errorf "Not a supported Content-Type: ~a" content-type)])]
     [(procedure? content-type)
      ;; This procedure should return STRING body and new Content-Type:
      (receive (body content-type)
          (content-type params-or-blob)
        (values body
                `(
                  :content-type ,content-type
                  ,@(delete-keyword :content-type http-options))))]
     [else
      (errorf "Not a supported Content-Type: ~a" content-type)])))

(define (post/content-type url query body . http-options)
  (receive (request-body request-args)
      (%construct-request body http-options)
    (receive (body header status)
        (apply %request 'post url () request-body request-args)
      (%response-receivr body header status))))

(define (get/content-type url params . http-options)
  (receive (body header status)
      (apply %request 'get url params #f http-options)
    (%response-receivr body header status)))

;; http://oauth.net/2/
;; http://tools.ietf.org/rfc/rfc6749.txt

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
           [(%is-scope? scope)
            `("scope" ,(%stringify-scope scope))]
           [state `("state" ,state)]
           [#t @ (%other-keys->params _keys)])]
         [query (http-compose-query #f params 'utf-8)])
    #"~|url|?~|query|"))

;; 4.1.2.  Authorization Response (In user browser)

;; 4.1.3.  Access Token Request
(define (oauth2-request-access-token
         url code client-id
         :key (redirect #f) (request-content-type #f)
         :allow-other-keys keys)
  (post/content-type
   url #f
   (cond-list
    [#t `("grant_type" "authorization_code")]
    [#t `("code" ,code)]
    ;; e.g. github doesn't need redirect
    [redirect `("redirect_uri" ,redirect)]
    [#t `("client_id" ,client-id)]
    ;;TODO not described in doc
    [#t @ (%other-keys->params keys)])
   :content-type request-content-type))

;; Obsoleted
(define (oauth2-request-auth-token url code redirect client-id . keys)
  (apply oauth2-request-access-token
         url code client-id
         :redirect redirect
         keys))

;;;
;;; Implicit Grant (Section 4.2)
;;;

;;TODO reconsider check content-type?
(define (oauth2-request-implicit-grant
         url client-id
         :key (redirect #f) (scope '()) (state #f)
         :allow-other-keys keys)
  (get/content-type
   url
   (cond-list
    [#t `("response_type" "token")]
    [#t `("client_id" ,client-id)]
    [redirect `("redirect_uri" ,redirect)]
    [(%is-scope? scope)
     `("scope" ,(%stringify-scope scope))]
    [state `("state" ,state)]
    [#t @ (%other-keys->params keys)])))

;;;
;;; Resource Owner Password Credentials (Section 4.3)
;;;

(define (oauth2-request-password-credential
         url username password
         :key (scope '()) (request-content-type #f)
         :allow-other-keys keys)
  (post/content-type
   url #f
   (cond-list
    [#t `("grant_type" "password")]
    [#t `("username" ,username)]
    [#t `("password" ,password)]
    [(%is-scope? scope)
     `("scope" ,(%stringify-scope scope))]
    [#t @ (%other-keys->params keys)])
   :auth (basic-authentication username password)
   :content-type request-content-type))

;;;
;;; Client Credentials (Section 4.4)
;;;

(define (oauth2-request-client-credential
         url username password
         :key (scope '()) (request-content-type #f)
         :allow-other-keys keys)
  (post/content-type
   url #f
   (cond-list
    [#t `("grant_type" "client_credentials")]
    [(%is-scope? scope)
     `("scope" ,(%stringify-scope scope))]
    [#t @ (%other-keys->params keys)])
   :auth (basic-authentication username password)
   :content-type request-content-type))

;; todo Extensions (Section 4.5)
;; (define (oauth2-request-extensions url)
;;   )

;; ## Mentioned in rfc6750
;; -> <string>
(define (oauth2-bearer-header cred)
  (format "Bearer ~a" (slot-ref cred 'access-token)))

(autoload rfc.base64 base64-encode-string)

;; ##
;; - USER: Might be client-id or api-key
;; - PASS: Might be client-secret or api-secret
;; -> <string>
(define (basic-authentication user pass)
  (format "Basic ~a" (base64-encode-string #"~|user|:~|pass|" :line-width #f)))

;; (Section 6)
(define (oauth2-refresh-token
         url refresh-token
         :key (scope '()) (request-content-type #f)
         :allow-other-keys keys)
  (post/content-type
   url #f
   (cond-list
    [#t `("grant_type" "refresh_token")]
    [#t `("refresh_token" ,refresh-token)]
    [(%is-scope? scope)
     `("scope" ,(%stringify-scope scope))]
    [#t @ (%other-keys->params keys)])
   :content-type request-content-type))

;;;
;;; Utilities for special implementation
;;;

;; ## TODO Obsoleting
;; Backward compatibility. Obsoleted. Should use `oauth2-request` .
(define (oauth2-request/json . args)
  (apply oauth2-request (append args (list :accept "application/json"))))

;; ## TODO Obsoleting. Should use `oauth2-post` or `oauth2-get`
;; - METHOD: `post` / `get`
;; - URL: <string> endpoint of oauth2 provider.
;; - PARAMS: <query> | <json> | <string> | 
;;      passed to `http-post` (Default). `:content-type` in http-options change
;;      this behavior.
(define (oauth2-request method url params . http-options)
  (ecase method
   [(post)
    (apply post/content-type url #f params http-options)]
   [(get)
    (apply get/content-type url params http-options)]))

;; ## Consider to use s-exp -> s-exp
;; - URL : <string> Basic URL before construct with QUERY-PARAMS
;; - QUERY-PARAMS : <alist> | #f Append to URL as query part.
;; - BODY : <top> Accept any type TODO describe about :request-content-type
;; - HTTP-OPTIONS: Accept `:auth` `:accept` and others are passed to `http-get` `http-post`.
;;    This procedure especially handling `:content-type` and `:request-content-type` which are
;;    described below.
;; - :request-content-type MIME:<string> | {PARAMS:<top> -> [REQUEST-BODY:<string>, CONTENT-TYPE:<string>]}:<procedure>
;;    content-type string or Procedure that handle one arg and must return 2 values
;;       Request body as STRING and new Content-Type: field that send to oauth provider.
;; -> <top>
(define (oauth2-post url query-params body . http-options)
  (apply post/content-type url query-params body http-options))

;; ## Arguments are same as `oauth2-get` except BODY
;; -> <top>
(define (oauth2-get url query-params . http-options)
  (apply get/content-type url query-params http-options))

(define oauth2-stringify-scope %stringify-scope)
