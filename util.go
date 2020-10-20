package cognito

import (
	"net/http"
	"strings"
)

// GetAuthHeader gets from header authorization field
func GetAuthHeader(r *http.Request) (auth string) {
	auth = r.Header.Get("Authorization")

	// checks starts with bearer
	if strings.HasPrefix(auth, "Bearer ") {
		auth = auth[len("Bearer "):]
	}

	return auth
}
