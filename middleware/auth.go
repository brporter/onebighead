package middleware

import (
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
var refreshTimer *time.Timer

const refreshDuration time.Duration = time.Hour // refresh interval is every hour

/* Internal Functions */

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

	// set up the refresh timer to refresh our signing keys hourly
	refreshTimer = time.NewTimer(refreshDuration)
	go refreshSigningKeys()
}

// initializeSigningKeys examines the OpenID Connect configuration document identified in auth.json and downloads the keys specified
// in the jwks_url property of that document. The jwks (JSON Web Key Set) document is then parsed and stored in a map of
// signingKey structures, indexed by keyid.
//
// Later, when a token is received, we examine the header of that token for a key id (kid) claim, and use the value of that claim
// to lookup the signing key for the token for verification purposes.
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

func refreshSigningKeys() {
	<-refreshTimer.C

	initializeSigningKeys()

	refreshTimer.Reset(refreshDuration)
}

func badRequestError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(msg))

	log.Printf("[REQUEST FATAL ERROR] %v\n", msg)
}

func generateNonce() ([]byte, error) {
	retVal := make([]byte, 64)

	_, err := rand.Read(retVal)

	if err != nil {
		return nil, err
	}

	return retVal, nil
}

func setContextAndForward(token *jwt.Token, w http.ResponseWriter, r *http.Request, next http.Handler) {
	if token != nil {
		// Deserialize Claims
		var tokenClaims map[string]interface{}
		err := json.Unmarshal(token.RawClaims(), &tokenClaims)

		if err != nil {
			msg := fmt.Sprintf("A token was received, but a failure was encountered while deserializing the claims the token contains. Error: %v", err)
			badRequestError(w, msg)

			return
		}

		// Token is now verified, and we have extracted the passed claims
		// Associated the claims to the request context
		ctx := context.WithValue(r.Context(), KeyClaims, tokenClaims)

		// Token is now verified.
		r = r.WithContext(ctx)
	}

	next.ServeHTTP(w, r)
}

// evaluateToken evaluates the request for the presence of a token. If the token is present and is valid,
// this function returns the token and a nil error value. Otherwise, the token returned is nil and an error value is returned.
// If the token is simply not present, err will be a tokenNotPresentError
func evaluateToken(r *http.Request) (*jwt.Token, error) {
	authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
	var authToken string = ""

	if len(authHeader) == 2 {
		authToken = authHeader[1]
	} else {
		// No auth header. Cookie?
		if cookie, err := r.Cookie("authToken"); err == nil {
			authToken = cookie.Value
		} else {
			return nil, TokenNotPresentError(0)
		}
	}

	return evaluateTokenValue(authToken)

}

func evaluateTokenValue(tokenValue string) (*jwt.Token, error) {
	// parse the auth token
	token, err := jwt.ParseString(tokenValue)

	if err != nil {
		return nil, fmt.Errorf("A token was received but was malformed: %v", err)
	}

	var stdClaims jwt.StandardClaims
	err = json.Unmarshal(token.RawClaims(), &stdClaims)

	if err != nil {
		return nil, fmt.Errorf("An error occured deserializing the standard claims on the token. Error: %v", err)
	}

	if !stdClaims.IsValidAt(time.Now()) {
		return nil, fmt.Errorf("The token provided is no longer valid. Expiration: %v", stdClaims.ExpiresAt)
	}

	alg := token.Header().Algorithm
	var kid string

	if alg[0:2] != "HS" {
		// We should have a key identifier claim in the header so we know which key to use for signature verification purposes
		encodedHeaderBytes := token.RawHeader()
		var headerBytes []byte = make([]byte, base64.StdEncoding.DecodedLen(len(encodedHeaderBytes)))
		_, err = base64.StdEncoding.Decode(headerBytes, encodedHeaderBytes)

		if err != nil {
			return nil, fmt.Errorf("A token was received but the header was malformed: %v", err)
		}

		// Figure out which certificate we need for token verification purposes
		var headerClaims map[string]interface{}
		err = json.Unmarshal(headerBytes, &headerClaims)

		if err != nil {
			return nil, fmt.Errorf("A token was received, but the header was not parsable JSON: %v", err)
		}

		kid = headerClaims["kid"].(string)
	}

	verifierList, err := constructVerifierList(kid, alg)

	if err != nil {
		return nil, fmt.Errorf("An error was encountered constructing the verifier list for the presented token: %v", err)
	}

	// verifierList is now filled with a set of potential verifiers for our public keys
	var verifierErrors []error
	for _, v := range verifierList {
		err = v.Verify(token.Payload(), token.Signature())

		if err == nil {
			return token, nil
		}

		verifierErrors = append(verifierErrors, err)
	}

	return nil, fmt.Errorf("A token was received, but could not be verified: %v", verifierErrors)
}

func constructVerifierList(kid string, alg jwt.Algorithm) ([]jwt.Verifier, error) {
	var signingKeysForConsideration []*signingKey
	var verifierList []jwt.Verifier

	if alg[0:2] == "HS" {
		v, err := jwt.NewVerifierHS(alg, []byte(config.ClientSecret))

		if err != nil {
			return nil, fmt.Errorf("An error occurred while constructing the HMAC verifier for the presented auth token: %v", err)
		}

		verifierList = append(verifierList, v)
	} else {
		if len(kid) != 0 {
			// token specified a key id. seek that key
			sk, ok := signingKeys[kid]

			if ok {
				signingKeysForConsideration = append(signingKeysForConsideration, sk)
			}
		}

		if len(signingKeysForConsideration) == 0 {
			// consider all of our signing keys
			for _, v := range signingKeys {
				signingKeysForConsideration = append(signingKeysForConsideration, v)
			}
		}

		var v jwt.Verifier
		var err error

		for _, sk := range signingKeysForConsideration {
			if sk == nil {
				return nil, fmt.Errorf("A nil valued signing key was presented for consideration")
			}

			switch alg[0:2] {
			case "RS":
				v, err = jwt.NewVerifierRS(alg, sk.PublicKey.(*rsa.PublicKey))
			case "ES":
				v, err = jwt.NewVerifierES(alg, sk.PublicKey.(*ecdsa.PublicKey))
			case "PS":
				v, err = jwt.NewVerifierPS(alg, sk.PublicKey.(*rsa.PublicKey))
			}

			if err != nil {
				return nil, fmt.Errorf("While constructing the verifier list, an error was encountered constructing a verifier: %v", err)
			}

			verifierList = append(verifierList, v)
		}
	}

	return verifierList, nil
}

/* Public Functions */

// TokenNotPresentError represents an error that indicates that an authentication token was not present
type TokenNotPresentError int

func (TokenNotPresentError) Error() string {
	return fmt.Sprintf("No token was present.")
}

// SignInController serves as a sign-in process initiation controller and token exchange endpoint. This controller starts and concludes the sign-in process.
func SignInController(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		const redirectURITemplate string = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_id=%v&response_type=id_token&redirect_uri=%v&scope=openid&response_mode=form_post&nonce=%v&state=%v"

		destination := r.URL.Query().Get("destination")

		nonce, err := generateNonce()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))

			log.Printf("[ERROR] A fatal error occurred generating a nonce for sign in: %v", err)

			return
		}

		nonceValue := base64.StdEncoding.EncodeToString(nonce)

		signInDestinationURI := fmt.Sprintf(redirectURITemplate, config.ClientID, url.QueryEscape(config.RedirectURI), url.QueryEscape(nonceValue), url.QueryEscape(destination))

		http.SetCookie(w, &http.Cookie{Name: "nonce", Value: nonceValue, Expires: time.Now().Add(time.Minute), HttpOnly: true})
		http.Redirect(w, r, signInDestinationURI, http.StatusTemporaryRedirect)
	}

	if r.Method == "POST" {
		// A token may be present in a POST form field called 'id_token'.
		// Retrieve this token, and place it in a cookie
		nonceCookie, err := r.Cookie("nonce")

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("400 Bad Request"))

			log.Printf("[ERROR] A token postback was received that lacked a nonce cookie.")
		}

		r.ParseForm()

		var redirectURL string

		if r.Form["state"] != nil && len(r.Form["state"]) > 0 && len(r.Form["state"][0]) != 0 {
			redirectURL = r.Form["state"][0]
		} else {
			redirectURL = "/"
		}

		if r.Form["id_token"] != nil && len(r.Form["id_token"]) > 0 && len(r.Form["id_token"][0]) != 0 {
			tokenValue := r.Form["id_token"][0]

			token, err := evaluateTokenValue(tokenValue)

			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("400 Bad Request"))

				log.Printf("[ERROR] A POST was received with an invalid token.")
				return
			}

			// check nonce
			var tokenClaims map[string]interface{}
			err = json.Unmarshal(token.RawClaims(), &tokenClaims)

			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("400 Bad Request"))

				log.Printf("[ERROR] A POST was received with a token whose claims could not be deserialized for nonce verfication: %v", err)
				return
			}

			nonceClaim, ok := tokenClaims["nonce"].(string)

			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("400 Bad Request"))

				log.Println("[ERROR] A POST was received with a token whose nonce was invalid.")

				return
			}

			nonceClaimValue, err := base64.StdEncoding.DecodeString(nonceClaim)

			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("400 Bad Request"))

				log.Println("[ERROR] A POST was received with a nonce claim that was not decodable")

				return
			}

			nonceValue, err := base64.StdEncoding.DecodeString(nonceCookie.Value)

			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("400 Bad Request"))

				log.Println("[ERROR] A POST was received with a nonce cookie that was not decodable")

				return
			}

			if string(nonceValue) != string(nonceClaimValue) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("400 Bad Request"))

				log.Println("[ERROR] A POST was received with a token whose nonce was not expected.")

				return
			}

			// expire the cookie when the token is scheduled to expire
			expire := time.Unix(int64(tokenClaims["exp"].(float64)), 0)
			cookie := http.Cookie{Name: "authToken", Value: r.Form["id_token"][0], Expires: expire}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, redirectURL, 302)
		}
	}
}

// SignOutController removes any auth token cookies present and redirects to /
func SignOutController(w http.ResponseWriter, r *http.Request) {
	authToken, err := r.Cookie("authToken")

	if err == nil {
		authToken.Expires = time.Now().AddDate(0, 0, -10)
		http.SetCookie(w, authToken)
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// MethodFilteringMiddleware invokes a specific handler depending on the request method being used.
// If no mapping exists for the requests method, the handler identified by other is invoked instead.
func MethodFilteringMiddleware(handlerMap map[string]http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method

		handler, ok := handlerMap[method]

		if ok {
			handler.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("405 Method Not Allowed"))
		}
	})
}

func AuthClaimMiddleware(map[string]interface{} demand, next http.Handler) http.Handler {
	return AuthClaimMiddlewareWithRedirect(demand, "", next)
}

func AuthClaimMiddlewareWithRedirect(map[string]interface{} demand, string redirectURL, next http.Handler) http.Handler {
	return AuthContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(KeyClaims).(map[string]interface{})

		for k, v := range demand {
			m, ok := claims[k]

			if !ok || m != v {

				if (len(redirectURL) == 0) {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("401 Unauthorized"))

					return
				}

				http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
				return
			}
		}

		next.ServeHTTP(w, r)
	}))
}

// AuthContextMiddleware evaluates the request for the presence of an authentication token. If it is present,
// it decodes and validates the token presented; if the token is deemed valid, it sets the context on the request.
func AuthContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := evaluateToken(r)

		if err != nil {
			if _, ok := err.(TokenNotPresentError); !ok {
				// token was present, but there was an error
				log.Printf("A token was present on the request, but setting context failed: %v", err)
			}

			// token just wasn't present
			next.ServeHTTP(w, r)
			return
		}

		setContextAndForward(token, w, r, next)
	})
}

// AuthRequiredMiddleware evaluates the request for the present of an authentication token. If no token is found, or if a token is found
// but is invalid, a 403 is returned.
func AuthRequiredMiddleware(next http.Handler) http.Handler {
	return AuthRequiredMiddlewareWithRedirect("", next)
}

func AuthRequiredMiddlewareWithRedirect(string redirectURL, next http.Handler) http.Handler {
	return AuthContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(KeyClaims)

		if claims == nil {

			if len(redirectURL) == 0 {
				// no claims context on the request; respond with 403 forbidden!
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("403 Forbidden"))
	
				return
			}

			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		}

		next.ServeHTTP(w, r)
	}))
}
