;;;
;;; OAuth 2.0 (rfc6749, rfc6750)
;;;

;; Status of the develop:
;; - RFC 6749 is almost working now.
;; - RFC 6750 is implementing now.
;; - Need cleanup and might be obsoleted some of api.

;; # Basic usage:
;; - :scope keyword accept string / list.

(define-module net.oauth2
  (use util.match)
  (use rfc.822)
  (use text.tr)
  (use rfc.http)
  (use rfc.uri)
  (use gauche.version)

  (export
   ;; These procedure return 3 values (BODY HEADERS STATUS)
   ;; Unlike rfc.http procedures (`http-post` / `http-get` ...)
   oauth2-request-password-credential
   oauth2-request-implicit-grant
   oauth2-request-access-token
   oauth2-request-client-credential
   oauth2-refresh-token
   
   oauth2-construct-auth-request-url

   oauth2-bearer basic-authentication
   ;; TODO might be obsoleted
   oauth2-bearer-header 

   oauth2-stringify-scope
   oauth2-post oauth2-get
   )

  ;; Obsoleting exports
  (export
   ;; should use `oauth2-request-access-token`
   oauth2-request-auth-token

   ;; should use `oauth2-post` `oauth2-get`
   oauth2-request/json
   oauth2-request
   )
  )
(select-module net.oauth2)

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

(define (%construct-request handler params-or-blob http-options)
  (let-keywords http-options
      ([content-type #f]
       . http-options*)
    (cond
     [(not handler)
      (values params-or-blob http-options)]
     [(string? handler)
      (let1 options* (cond-list
                      [#t @ (list :content-type handler)]
                      [#t @ http-options*])
        (match (mime-parse-content-type handler)
          [#f
           (values params-or-blob options*)]
          [(_ "x-www-form-urlencoded" . _)
           (values (http-compose-query #f params-or-blob)
                   options*)]
          [(_ "json" . _)
           (values (construct-json-string params-or-blob)
                   options*)]
          [else
           (errorf "Not a supported Content-Type: ~a" handler)]))]
     [(procedure? handler)
      ;; This procedure should return STRING body and new Content-Type:
      (receive (body content-type*) (handler params-or-blob)
        (values body
                (cond-list
                 [#t @ (list :content-type content-type*)]
                 [#t @  http-options*])))]
     [else
      (errorf "Not a supported content handler ~a" handler)])))

(define (post/content-type
         url query
         body :key (content-handler #f)
         :allow-other-keys http-options)
  (receive (request-body request-args)
      (%construct-request content-handler body http-options)
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

;; ## 4.1.1.  Authorization Request
;; Generate URL which each oauth2 provider's one.
;; -> URL:<string>
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

;; ## 4.1.3.  Access Token Request
;; If something wrong any provider consider to use
;;    :request-content-type as "application/x-www-form-urlencoded"
;; - URL : <string>
;; - CODE : <string>
;; - CLIENT-ID : <string>
;; -> <json>
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
    [#t @ (%other-keys->params keys)])
   :content-handler request-content-type))

;; Obsoleted
(define (oauth2-request-auth-token url code redirect client-id . keys)
  (apply oauth2-request-access-token
         url code client-id
         :redirect redirect
         keys))

;;;
;;; Implicit Grant (Section 4.2)
;;;

;; ##
;; -> <json>
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

;; ##
;; - URL : <string>
;; - USERNAME : <string>
;; - PASSWORD : <string>
;; -> <json>
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
   :content-handler request-content-type))

;;;
;;; Client Credentials (Section 4.4)
;;;

;; ##
;; - URL : <string>
;; - USERNAME : <string> Might be called api-key, client-id
;; - PASSWORD : <string> Might be called api-secret, client-secret
;; -> <json>
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
   :content-handler request-content-type))

;; todo Extensions (Section 4.5)
;; (define (oauth2-request-extensions url)
;;   )

;; ## TODO should be obsoleted. Just wrapper of `oauth2-bearer`
;; Probablly missed introduce the procedure.
;; -> <string>
(define (oauth2-bearer-header cred)
  (oauth2-bearer (slot-ref cred 'access-token)))

;; ## Mentioned in rfc6750 (TODO should be obsoleted)
;; -> <string>
(define (oauth2-bearer token)
  (format "Bearer ~a" token))

(autoload rfc.base64 base64-encode-string)

;; ## Utility procedure HTTP Basic authentication
;; - USER: Might be client-id or api-key
;; - PASS: Might be client-secret or api-secret
;; -> <string>
(define (basic-authentication user pass)
  (format "Basic ~a" (base64-encode-string #"~|user|:~|pass|" :line-width #f)))

;; ##
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
   :content-handler request-content-type))

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

;; ## Utility procedure (s-exp -> s-exp)
;; - URL : <string> Basic URL before construct with QUERY-PARAMS
;; - QUERY-PARAMS : <alist> | #f Append to URL as query part.
;; - BODY : <string> | <top> Accept any type that might be handled `:request-content-type` .
;; - HTTP-OPTIONS : Accept `:auth` `:accept` and others are passed to `http-get` `http-post`.
;;    This procedure especially handling `:request-content-type` which are
;;    described below.
;; - :request-content-type : MIME:<string> | {PARAMS:<top> -> [REQUEST-BODY:<string>, CONTENT-TYPE:<string>]}:<procedure>
;;    When procedure that must handle one arg and return 2 values.
;;       Request body as STRING and new Content-Type: field that send to oauth provider.
;;    if this value is a <string> regarded as Content-Type, BODY handled as the sexp data type.
;;       supported are `x-www-form-urlencoded` and `json`.
;;       then overwrite `http-options` :content-type by this value.
;; -> <top>
(define (oauth2-post
         url query-params body
         :key (request-content-type #f)
         :allow-other-keys http-options)
  (apply post/content-type url query-params body
         :content-handler request-content-type
         http-options))

;; ## Utility procedure. Arguments are same as `oauth2-get` except BODY
;; -> <top>
(define (oauth2-get url query-params . http-options)
  (apply get/content-type url query-params http-options))

;; ##
(define oauth2-stringify-scope %stringify-scope)
