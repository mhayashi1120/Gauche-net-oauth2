;;;
;;; net.oauth2.code-verifier
;;;
(define-module net.oauth2.code-verifier
  (use rfc.uri)
  (use srfi-27)
  (use scheme.list)
  (use scheme.charset)
  (use toolbox.secure)
  (use toolbox.token)
  (export
   generate-code-verifier encode-challenge))
(select-module net.oauth2.code-verifier)

;; # Basic concepts:
;; - rfc7636 (ref: https://www.rfc-editor.org/rfc/rfc7636)
;; - PKCE:  Proof Key for Code Exchange
;; - ref: https://developers.google.com/identity/protocols/oauth2/native-app

;; ## Basic PKCE flow:
;; > 4.3.  Client Sends the Code Challenge with the Authorization Request
;;  Send following parameters:
;; - "code_challenge"
;; - "code_challenge_method"
;;
;; > 4.4.  Server Returns the Code
;; Server keep "code_challenge" and "code_challenge_method" to each client session.
;; Then return any code any proper way.
;;
;; > 4.5.  Client Sends the Authorization Code and the Code Verifier to the Token Endpoint
;; "code_verifier"
;;
;; > 4.6.  Server Verifies code_verifier before Returning the Tokens

;; ##
;; -> B64URL:<string>
(define (generate-code-verifier :optional (base-size 32))
  ($ string->b64url $ random-string base-size))

;; ##
;; :method : <string>
;; <string> -> <string>
(define (encode-challenge verifier :key (method "S256"))
  (ecase (string->symbol method)
    [(plain)
     verifier]
    ;; RFC mention about `S256` but following contains `s256`
    ;; /apps-script-oauth2/src/Utilities.js
    [(S256 s256)
     (sha256/b64url verifier)]))
