package middleware

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v3"
)

// Key is a type used to denote specific unique object instances in the request context.
type Key int

const (
	// KeyClaims is the identifier used for storage of authentication token claims on the request context.
	KeyClaims Key = iota
)

type authConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	ConfigURI    string `json:"config_uri"`
}

type signingKey struct {
	Type      string
	KeyID     string
	PublicKey interface{}
}

var config authConfig
var signingKeys map[string]*signingKey

func init() {
	/* read the auth configuration file, auth.json */
	const AuthConfig string = "auth.json"

	data, err := ioutil.ReadFile(AuthConfig)

	if err != nil {
		log.Fatalf("Unable to read authentication configuration file. Error: %v", err)
	}

	err = json.Unmarshal(data, &config)

	if err != nil {
		log.Fatalf("Unable to parse authentication configuration file. Error: %v", err)
	}

	initializeSigningKeys()
}

func initializeSigningKeys() {
	var openIDConfig map[string]interface{} // Stores the JSON deserialized OpenID Connect configuration document
	var openIDKeys map[string]interface{}   // Stores the JSON deserialized JWKS document

	response, err := http.Get(config.ConfigURI)

	if err != nil {
		log.Fatalf("Unable to retrieve OpenID Connect configuration document at %v. Error: %v", config.ConfigURI, err)
	}

	configBody, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Fatalf("Unable to read OpenID Connect configuration document request response. Error: %v", err)
	}

	err = json.Unmarshal(configBody, &openIDConfig)

	if err != nil {
		log.Fatalf("Failed to deserialize the OpenID Connect configuration document retrieves from %v. Error: %v", config.ConfigURI, err)
	}

	response, err = http.Get(openIDConfig["jwks_uri"].(string))

	if err != nil {
		log.Fatalf("Failed to retrieve the OpenID JSON Web Key Set from %v. Error: %v", openIDConfig["jwks_uri"].(string), err)
	}

	jwksBody, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Fatalf("Failed to read the OpenID Connect JSON Web Key Set request response. Error: %v", err)
	}

	err = json.Unmarshal(jwksBody, &openIDKeys)

	signingKeys = make(map[string]*signingKey, 5)

	for _, keyData := range openIDKeys["keys"].([]interface{}) {
		for _, x5c := range keyData.(map[string]interface{})["x5c"].([]interface{}) {
			var sk signingKey

			sk.KeyID = keyData.(map[string]interface{})["kid"].(string)
			sk.Type = keyData.(map[string]interface{})["kty"].(string)

			certData, err := base64.StdEncoding.DecodeString(x5c.(string))

			if err != nil {
				log.Fatalf("Failed to decode certificate data. Error: %v", err)
			}

			cert, err := x509.ParseCertificate(certData)

			if err != nil {
				log.Fatalf("Failed to parse certificate data. Error: %v", err)
			}

			switch cert.PublicKey.(type) {
			case *rsa.PublicKey:
				sk.PublicKey = cert.PublicKey
			case *dsa.PublicKey:
				sk.PublicKey = cert.PublicKey
			case *ecdsa.PublicKey:
				sk.PublicKey = cert.PublicKey
			case ed25519.PublicKey:
				sk.PublicKey = cert.PublicKey
			default:
				log.Fatalf("Unknown public key type: %v", cert.PublicKeyAlgorithm)
			}

			signingKeys[sk.KeyID] = &sk
		}
	}
}

func badRequestError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(msg))

	log.Printf("[REQUEST FATAL ERROR] %v\n", msg)
}

func redirectToMsa(w http.ResponseWriter, r *http.Request, nonce string) {
	redirectURL := html.EscapeString(r.URL.String())

	const redirectURITemplate string = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_id=%v&response_type=id_token&redirect_uri=%v&scope=openid&response_mode=form_post&nonce=%v&state=%v&prompt=select_account"
	redirectURI := fmt.Sprintf(redirectURITemplate, config.ClientID, html.EscapeString(config.RedirectURI), nonce, redirectURL)

	http.Redirect(w, r, redirectURI, http.StatusTemporaryRedirect)
}

// MethodFilteringMiddleware invokes a specific handler depending on the request method being used.
func MethodFilteringMiddleware(handlerMap map[string]http.Handler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method

		handler, ok := handlerMap[method]

		if ok {
			handler.ServeHTTP(w, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

//TODO: break token parsing and validation out into its own middleware, so we can be authentication aware
// on non-authenticated endpoints (e.g., we can light up identification of users)

// AuthMiddleware ensures that the incoming request is authenticated, and redirects the request if not. Used on paths to ensure that users requesting those resources are authenticated.
func AuthMiddleware(next http.Handler) http.Handler {
	/* Check the incoming request for a valid token. If not present, redirect.
	   Tokens can be present in two places: one, presented as part of the Authorization header as a Bearer token
	   or alternatively stored in an auth cookie, authToken.

	   TODO: Validate nonce

	   If the token is not found in either these places, redirect to MSA for authentication. */

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
		var authToken string = ""

		if len(authHeader) == 2 {
			authToken = authHeader[1]
		} else {
			// No auth header. Cookie?
			if cookie, err := r.Cookie("authToken"); err == nil {
				authToken = cookie.Value
			} else {
				log.Printf("ERROR: Failed to retrieve authentication cookie and no bearer token present on the request. Redirect to MSA. Error: %v", err)
			}
		}

		if len(authToken) == 0 {
			// No auth cookie. Redirect to MSA
			redirectToMsa(w, r, "1234")
			return
		}

		token, err := jwt.ParseString(authToken)

		if err != nil {
			msg := fmt.Sprintf("A token was received but was malformed: %v", err)
			badRequestError(w, msg)

			return
		}

		var stdClaims jwt.StandardClaims

		err = json.Unmarshal(token.RawClaims(), &stdClaims)

		if err != nil {
			msg := fmt.Sprintf("An error occured deserializing the standard claims on the token. Error: %v", err)
			badRequestError(w, msg)
		}

		if !stdClaims.IsValidAt(time.Now()) {
			redirectToMsa(w, r, "1234")
			return
		}

		var verifier jwt.Verifier

		if token.Header().Algorithm[0:2] == "HS" {
			verifier, err = jwt.NewVerifierHS(token.Header().Algorithm, []byte(config.ClientSecret))
		} else {
			// We should have a key identifier claim in the header so we know which key to use for signature verification purposes
			encodedHeaderBytes := token.RawHeader()
			var headerBytes []byte = make([]byte, base64.StdEncoding.DecodedLen(len(encodedHeaderBytes)))
			_, err = base64.StdEncoding.Decode(headerBytes, encodedHeaderBytes)

			if err != nil {
				msg := fmt.Sprintf("A token was received but the header was malformed: %v", err)
				badRequestError(w, msg)

				return
			}

			// Figure out which certificate we need for token verification purposes
			var headerClaims map[string]interface{}
			err = json.Unmarshal(headerBytes, &headerClaims)

			if err != nil {
				msg := fmt.Sprintf("A token was received, but the header was not parsable JSON: %v", err)
				badRequestError(w, msg)

				return
			}

			kid := headerClaims["kid"].(string)

			if len(kid) == 0 {
				msg := "A token was received, but the header lacked a key identification claim. Unable to validate token."
				badRequestError(w, msg)

				return
			}

			sk := signingKeys[kid]

			if sk == nil {
				msg := "A token was received, but the header-identifier signing key is unknown to us. Unable to validate token."
				badRequestError(w, msg)

				return
			}

			switch alg := token.Header().Algorithm; alg[0:2] {
			case "RS":
				verifier, err = jwt.NewVerifierRS(token.Header().Algorithm, sk.PublicKey.(*rsa.PublicKey))
			case "ES":
				verifier, err = jwt.NewVerifierES(token.Header().Algorithm, sk.PublicKey.(*ecdsa.PublicKey))
			case "PS":
				verifier, err = jwt.NewVerifierPS(token.Header().Algorithm, sk.PublicKey.(*rsa.PublicKey))
			}
		}

		if err != nil {
			msg := fmt.Sprintf("A token was received, but the while constructing the verifier for the token an unexpected error occurred: %v", err)
			badRequestError(w, msg)

			return
		}

		// verifier now contains the needed token verifier
		err = verifier.Verify(token.Payload(), token.Signature())

		if err != nil {
			msg := fmt.Sprintf("The token is invalid: %v", err)
			badRequestError(w, msg)

			return
		}

		// Deserialize Claims
		var tokenClaims map[string]interface{}
		err = json.Unmarshal(token.RawClaims(), &tokenClaims)

		if err != nil {
			msg := fmt.Sprintf("A token was received, but a failure was encountered while deserializing the claims the token contains. Error: %v", err)
			badRequestError(w, msg)

			return
		}

		// Token is now verified, and we have extracted the passed claims
		// Associated the claims to the request context
		ctx := context.WithValue(r.Context(), KeyClaims, tokenClaims)

		// Token is now verified.
		// TODO: add claims to request context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
