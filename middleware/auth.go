package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
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

type SigningKey struct {
	Type      string
	KeyID     string
	PublicKey interface{}
}

type SignInProvider struct {
	ProviderName    string
	Issuers         []string
	SupportedScopes []string
	SignInURL       string
	SignOutURL      string
	ClientID        string
	ClientSecret    string
	RedirectURI     string
}

var providers []SignInProvider
var signingKeys map[string]SigningKey
var encodings []*base64.Encoding

const refreshDuration time.Duration = time.Hour // refresh interval is every hour

/* Internal Functions */

func init() {
	// initialize possible base64 encoding providers, as the various OIDC providers use different base64 encoding standards.
	encodings = make([]*base64.Encoding, 4)
	encodings[0] = base64.StdEncoding
	encodings[1] = base64.RawURLEncoding
	encodings[2] = base64.URLEncoding

	signingKeys = make(map[string]SigningKey, 10)

	/* read the auth configuration file, auth.json */
	const AuthConfig string = "auth.json"

	data, err := ioutil.ReadFile(AuthConfig)

	if err != nil {
		log.Fatalf("Unable to read authentication configuration file: %v", err)
	}

	// TODO: move this into a single call firing off the goroutine for refreshes, rely on signals to
	// hold initialization until the goroutine finishes the first iteration
	identityProviders, sigKeys, err := ParseAuthConfig(data)

	if err != nil {
		log.Fatalf("Unable to parse the authentication configuration data: %v", err)
	}

	providers = identityProviders

	for _, v := range sigKeys {
		signingKeys[v.KeyID] = v
	}

	// set up the refresh timer to refresh our auth configuration hourly
	go refreshAuthConfig(time.NewTimer(refreshDuration), data)
}

// initializeSigningKeys examines the OpenID Connect configuration document identified in and downloads the keys specified
// in the jwks_url property of that document. The jwks (JSON Web Key Set) document is then parsed and stored in a map of
// signingKey structures, indexed by keyid.
//
// Later, when a token is received, we examine the header of that token for a key id (kid) claim, and use the value of that claim
// to lookup the signing key for the token for verification purposes.
func initializeSigningKeys(jwksURL string) ([]SigningKey, error) {
	response, err := http.Get(jwksURL)

	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve the OpenID JSON Web Key Set from %v: %v", jwksURL, err)
	}

	jwksBody, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, fmt.Errorf("Failed to read the OpenID Connect JSON Web Key Set request response: %v", err)
	}

	var keyDataEntries struct {
		Keys []struct {
			KeyType  string `json:"kty"`
			Use      string `json:"use"`
			KeyID    string `json:"kid"`
			Modulus  string `json:"n"`
			Exponent string `json:"e"`
		} `json:"keys"`
	}

	keyDataEntries.Keys = make([]struct {
		KeyType  string `json:"kty"`
		Use      string `json:"use"`
		KeyID    string `json:"kid"`
		Modulus  string `json:"n"`
		Exponent string `json:"e"`
	}, 5)

	err = json.Unmarshal(jwksBody, &keyDataEntries)

	if err != nil {
		return nil, fmt.Errorf("Failed to decode the JWKS document retrieved from %v: %v", jwksURL, err)
	}

	signingKeys := make([]SigningKey, len(keyDataEntries.Keys))

	// The below ONLY supports RSA
	for _, keyData := range keyDataEntries.Keys {
		var sk SigningKey

		if keyData.KeyType != "RSA" {
			log.Printf("Unkown key type '%v' found in JWKS retrieved at %v. Skipping.\n", keyData.KeyType, jwksURL)
			continue
		}

		if keyData.Use != "sig" {
			log.Printf("Unknown key use '%v' found in JWKS retrieved at %v. Skipping.\n", keyData.Use, jwksURL)
			continue
		}

		modulusBytes, err := base64.RawURLEncoding.DecodeString(keyData.Modulus)

		if err != nil {
			log.Printf("Failed to decode modulus component from key with id %v, in document retrieved at %v; modulus component was recorded as '%v': %v", keyData.KeyID, jwksURL, keyData.Modulus, err)
		}

		exponentBytes, err := base64.RawURLEncoding.DecodeString(keyData.Exponent)

		if err != nil {
			log.Printf("Failed to decode exponent component from key with id %v, in document retrieved at %v; exponent component was recorded as '%v': %v", keyData.KeyID, jwksURL, keyData.Exponent, err)
		}

		var modulus big.Int
		modulus.SetBytes(modulusBytes)

		for i := len(exponentBytes); i < 4; i++ {
			exponentBytes = append(exponentBytes, 0)
		}

		exponent := int(exponentBytes[0])
		exponent |= int(exponentBytes[1]) << 8
		exponent |= int(exponentBytes[2]) << 16
		exponent |= int(exponentBytes[3]) << 24

		sk.KeyID = keyData.KeyID
		sk.Type = keyData.KeyType
		sk.PublicKey = &rsa.PublicKey{N: &modulus, E: exponent}

		signingKeys = append(signingKeys, sk)
	}

	return signingKeys, nil
}

func refreshAuthConfig(refreshTimer *time.Timer, data []byte) {
	for {
		<-refreshTimer.C

		identityProviders, sigKeys, err := ParseAuthConfig(data)

		if err != nil {
			log.Printf("Failed to refresh auth configuration: %v", err)
		}

		providers = identityProviders

		for _, v := range sigKeys {
			signingKeys[v.KeyID] = v
		}

		refreshTimer.Reset(refreshDuration)
	}
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

		// guess at std encoding
		var headerBytes []byte
		for encoderIndex, encoder := range encodings {
			headerBytes = make([]byte, encoder.DecodedLen(len(encodedHeaderBytes)))

			_, err = encoder.Decode(headerBytes, encodedHeaderBytes)

			if err == nil {
				break
			} else {
				log.Printf("[WARNING] Using encoder %v failed with error %v", encoderIndex, err)
			}
		}

		if headerBytes == nil {
			return nil, fmt.Errorf("A token was received but the header was malformed and could not be decoded by any available Base64 decoder")
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
	var signingKeysForConsideration []SigningKey
	var verifierList []jwt.Verifier

	if alg[0:2] == "HS" {
		for _, v := range providers {
			v, err := jwt.NewVerifierHS(alg, []byte(v.ClientSecret))

			if err != nil {
				return nil, fmt.Errorf("An error occurred while constructing the HMAC verifier for the presented auth token: %v", err)
			}

			verifierList = append(verifierList, v)
		}
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

// ParseAuthConfig parses the bytes provided in configBytes as an auth configuration document, and then
// initializes a SignInProvider struct for each configured signin provider.
func ParseAuthConfig(configBytes []byte) ([]SignInProvider, []SigningKey, error) {
	providers := make([]SignInProvider, 0)
	keys := make([]SigningKey, 0)

	parsedAuthConfig := make([]struct {
		Provider     string   `json:"provider"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURI  string   `json:"redirect_uri"`
		ConfigURI    string   `json:"config_uri"`
		Issuers      []string `json:"issuers"`
	}, 0)

	err := json.Unmarshal(configBytes, &parsedAuthConfig)

	if err != nil {
		return nil, nil, fmt.Errorf("Unable to parse the specified bytes as JSON: %v", err)
	}

	for _, config := range parsedAuthConfig {
		var provider SignInProvider

		// make certain all required values are present
		provider.ProviderName = config.Provider
		provider.ClientID = config.ClientID
		provider.ClientSecret = config.ClientSecret
		provider.RedirectURI = config.RedirectURI
		provider.Issuers = config.Issuers

		configURIResponse, err := http.Get(config.ConfigURI)

		if err != nil {
			return nil, nil, fmt.Errorf("Failed to retrieve the configuration document for the %v provider at url %v: %v", provider.ProviderName, config.ConfigURI, err)
		}

		providerConfigBytes, err := ioutil.ReadAll(configURIResponse.Body)

		if err != nil {
			return nil, nil, fmt.Errorf("Failed to read the returned configuration document for the %v provider, retrieved from url %v: %v", provider.ProviderName, config.ConfigURI, err)
		}

		providerConfig := struct {
			KeyURL           string   `json:"jwks_uri"`
			SignInURL        string   `json:"authorization_endpoint"`
			SignOutSupported bool     `json:"http_logout_supported"`
			SignOutURL       string   `json:"end_session_endpoint"`
			SupportedScopes  []string `json:"scopes_supported"`
		}{}

		err = json.Unmarshal(providerConfigBytes, &providerConfig)

		if err != nil {
			return nil, nil, fmt.Errorf("Failed to deserialize the JSON retrieved from the configuration document for %v provider, retrieved from url %v: %v", provider.ProviderName, config.ConfigURI, err)
		}

		signingKeys, err := initializeSigningKeys(providerConfig.KeyURL)

		if err != nil {
			return nil, nil, fmt.Errorf("Failed to initialize signing keys for provider '%v': %v", provider.ProviderName, err)
		}

		provider.SignInURL = providerConfig.SignInURL
		provider.SignOutURL = providerConfig.SignOutURL
		provider.SupportedScopes = providerConfig.SupportedScopes

		providers = append(providers, provider)
		keys = append(keys, signingKeys...)
	}

	return providers, keys, nil
}

// TokenNotPresentError represents an error that indicates that an authentication token was not present
type TokenNotPresentError int

func (TokenNotPresentError) Error() string {
	return fmt.Sprintf("No token was present.")
}

// SignInController serves as a sign-in process initiation controller and token exchange endpoint. This controller starts and concludes the sign-in process.
func SignInController(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		const redirectURITemplate string = "%v?client_id=%v&response_type=id_token&redirect_uri=%v&scope=%v&response_mode=form_post&nonce=%v&state=%v"

		providerName := strings.ToLower(r.URL.Query().Get("provider"))

		var provider SignInProvider
		var foundProvider = false

		for _, p := range providers {
			if p.ProviderName == providerName {
				provider = p
				foundProvider = true
				break
			}
		}

		if !foundProvider {
			// try and use the first provider specified in the auth config
			if len(providers) > 0 {
				provider = providers[0]
			} else {
				// there are no providers!!
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("500 Interna Server Error"))

				log.Printf("[ERROR] A request was received without a sign-in provider or specifying a sign-in provider that could not be found (%v), and no providers are configured. This condition is likely fatal and not recoverable", providerName)
				return
			}
		}

		destination := r.URL.Query().Get("destination")

		nonce, err := generateNonce()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))

			log.Printf("[ERROR] A fatal error occurred generating a nonce for sign in: %v", err)

			return
		}

		nonceValue := base64.StdEncoding.EncodeToString(nonce)

		scopes := strings.Join(provider.SupportedScopes, "%20")

		signInDestinationURI := fmt.Sprintf(redirectURITemplate, provider.SignInURL, provider.ClientID, provider.RedirectURI, scopes, url.QueryEscape(nonceValue), url.QueryEscape(destination))
		// signInDestinationURI := "/"

		http.SetCookie(w, &http.Cookie{Name: "nonce", Value: nonceValue, Expires: time.Now().Add(time.Minute), HttpOnly: true})
		http.Redirect(w, r, signInDestinationURI, http.StatusTemporaryRedirect)

		return
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

				log.Printf("[ERROR] A POST was received with an invalid token: %v\n", err)
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

		return
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

func AuthClaimMiddleware(demand map[string]interface{}, next http.Handler) http.Handler {
	return AuthClaimMiddlewareWithRedirect(demand, "", next)
}

func AuthClaimMiddlewareWithRedirect(demand map[string]interface{}, redirectURL string, next http.Handler) http.Handler {
	return AuthContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(KeyClaims).(map[string]interface{})

		for k, v := range demand {
			m, ok := claims[k]

			if !ok || m != v {

				if len(redirectURL) == 0 {
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

func AuthRequiredMiddlewareWithRedirect(redirectURL string, next http.Handler) http.Handler {
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
