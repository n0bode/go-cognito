package cognito

import (
	"github.com/dgrijalva/jwt-go"
)

// RespCognito struct refers cognito list KIDs
type RespCognito struct {
	Keys []jwt.MapClaims `json:"keys"`
}
