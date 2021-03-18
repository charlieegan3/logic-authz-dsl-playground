package helpers

import (
	"net/http"
	"strings"

	"github.com/charlieegan3/go-authz-dsls/internal/types"
)

func AuthnUser(header *http.Header, users *map[string]types.User) (userName string, responseCode int) {
	auth := header.Get("Authorization")
	if auth == "" {
		return "", http.StatusUnauthorized
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", http.StatusBadRequest
	}
	token := strings.TrimSpace(strings.Replace(auth, "Bearer ", "", 1))

	found := false
	for name, user := range *users {
		if user.Token == token {
			userName = name
			found = true
			break
		}
	}

	if !found {
		return "", http.StatusUnauthorized
	}

	return userName, 0
}
