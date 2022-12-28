;;;
;;; net.oauth2.code-verifier
;;;
(define-module net.oauth2.code-verifier
  (use rfc.base64)
  (use rfc.sha1)
  (use rfc.uri)
  (use scheme.charset)
  (use scheme.list)
  (use srfi-13)
  (use srfi-27)
  (export
   generate-code-verifier encode-challenge))
(select-module net.oauth2.code-verifier)

;; Worked fine on Google oauth v2 endpoint below.
;;  https://accounts.google.com/o/oauth2/v2/auth

;; # Basic concepts:
;; - rfc7636 (ref: https://www.rfc-editor.org/rfc/rfc7636)
;; - PKCE:  Proof Key for Code Exchange
;; - ref: https://developers.google.com/identity/protocols/oauth2/native-app

;; ## Basic PKCE flow:
;;
;; ### 4.3.  Client Sends the Code Challenge with the Authorization Request
;;  Send following parameters:
;; - "code_challenge"
;; - "code_challenge_method"
;;
;; ### 4.4.  Server Returns the Code
;; Server keep "code_challenge" and "code_challenge_method" to each client session.
;; Then return any code any proper way.
;;
;; ### 4.5.  Client Sends the Authorization Code and the Code Verifier to the Token Endpoint
;; "code_verifier"
;;
;; ### 4.6.  Server Verifies code_verifier before Returning the Tokens

;;;
;;; Internal
;;;

;; ##
;; - LEN : <integer>
;; -> <string>
(define (random-string len)
  (with-output-to-string
    (^[]
      (dotimes (_ len)
        (write-byte (random-integer #x100))))))

;; ## `b64url` is: base64 url-safe and trim last "="
(define (string->b64url s)
  ($ (cut string-trim-right <> #[=])
     $ base64-encode-string s :line-width #f :url-safe #t))

;; ## -> BASE64-URL:<string>
(define (sha256/b64url s)
  ($ string->b64url $ sha256-digest-string s))

;;;
;;; # API
;;;

;; ##
;; -> BASE64-URL:<string>
(define (generate-code-verifier :optional (base-size 32))
  ($ string->b64url $ random-string base-size))

;; ##
;; - METHOD : <string> "S256" / "plain"
;; <string> -> <string> -> <string>
(define (encode-challenge verifier method)
  (ecase (string->symbol method)
    [(plain)
     verifier]
    ;; RFC mention about `S256` but following contains `s256`
    ;; /apps-script-oauth2/src/Utilities.js
    [(S256 s256)
     (sha256/b64url verifier)]))
