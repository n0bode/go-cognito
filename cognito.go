package cognito

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/dgrijalva/jwt-go"
)

// Cognito struct contains AWS info for cognito
type Cognito struct {
	userPoolID string
	region     string
	appID      string
	keys       map[string]jwt.MapClaims
	lock       *sync.RWMutex
	parser     *jwt.Parser
}

// New creates a cognito middleware
func New(config Config) *Cognito {
	return &Cognito{
		region:     config.Region,
		appID:      config.AppID,
		userPoolID: config.UserPoolID,
		keys:       make(map[string]jwt.MapClaims),
		lock:       &sync.RWMutex{},
		parser:     &jwt.Parser{},
	}
}

// ParseJWT gets KID from header JWT
func (cog *Cognito) ParseJWT(token string) (kid string, claims jwt.MapClaims, valid bool) {
	claims = jwt.MapClaims{}

	re, _, err := cog.parser.ParseUnverified(token, claims)

	if err != nil {
		return kid, claims, false
	}

	// if kid exists in header jwt
	raw, exists := re.Header["kid"]
	if !exists {
		return kid, claims, false
	}

	// if kid (interface{}) is a string
	kid, valid = raw.(string)
	return kid, claims, valid
}

// LoadTokens loads tokens (kids) from aws
func (cog *Cognito) LoadTokens() (err error) {
	cog.lock.Lock()
	defer cog.lock.Unlock()

	var url string = "https://cognito-idp." + cog.region + ".amazonaws.com/" + cog.userPoolID + "/.well-known/jwks.json"

	// consult JWTs tokens in AWS
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var data RespCognito
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	cog.keys = make(map[string]jwt.MapClaims)
	for _, key := range data.Keys {
		kid := key["kid"].(string)
		log.Println(kid)
		cog.keys[kid] = key
	}
	log.Println(len(cog.keys))
	return nil
}

// HasKID checks if exists kid in keys
func (cog *Cognito) HasKID(kid string) (exists bool) {
	cog.lock.RLock()
	defer cog.lock.RUnlock()

	_, exists = cog.keys[kid]
	return exists
}

// ClaimsByKID get claims by kid
func (cog *Cognito) ClaimsByKID(kid string) (claims jwt.MapClaims, exists bool) {
	cog.lock.RLock()
	defer cog.lock.RUnlock()

	claims, exists = cog.keys[kid]
	return claims, exists
}

// RSAPublicKey creates RSSPublicKey from jwk
func (cog *Cognito) RSAPublicKey(claims jwt.MapClaims) (*rsa.PublicKey, error) {
	var es string = claims["e"].(string)
	var ns string = claims["n"].(string)

	ed, err := base64.RawURLEncoding.DecodeString(es)
	if err != nil {
		return nil, err
	}

	nd, err := base64.RawURLEncoding.DecodeString(ns)
	if err != nil {
		return nil, err
	}

	number := new(big.Int)
	number.SetBytes(nd)

	var buffer bytes.Buffer
	buffer.WriteByte(0)
	buffer.Write(ed)

	return &rsa.PublicKey{
		E: int(binary.BigEndian.Uint32(buffer.Bytes())),
		N: number,
	}, nil
}

// Verify verify JWT token signature with JWK
func (cog *Cognito) Verify(token string, jwk jwt.MapClaims) bool {
	publicKey, err := cog.RSAPublicKey(jwk)
	if err != nil {
		return false
	}

	split := strings.Split(token, ".")
	message := []byte(split[0] + "." + split[1])

	signature, err := base64.RawURLEncoding.DecodeString(split[2])
	if err != nil {
		return false
	}

	sum := sha256.Sum256(message)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, sum[:], signature)
	if err != nil {
		return false
	}
	return true
}

// Authorized checks if token is authorized
func (cog *Cognito) Authorized(token string) bool {
	kid, claims, valid := cog.ParseJWT(token)
	if !valid {
		return false
	}

	jwk, exists := cog.ClaimsByKID(kid)

	// if not exists, can be two things
	// never gets keys yet
	// or kid does not exist, but can exist now
	if !exists {
		if err := cog.LoadTokens(); err != nil {
			return false
		}
		// gets claims again, checks if exists now
		jwk, exists = cog.ClaimsByKID(kid)
	}

	// check again, cos it may get new keys
	if !exists {
		return false
	}

	if !cog.Verify(token, jwk) {
		return false
	}

	if claims["aud"].(string) != cog.appID {
		return false
	}
	return true
}

// Handler middleware function to check cognito
func (cog *Cognito) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := GetAuthHeader(r)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !cog.Authorized(token) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
