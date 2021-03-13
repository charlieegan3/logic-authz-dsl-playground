package golang

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/charlieegan3/go-authz-dsls/internal/types"
)

// WhoAmIHandler is the go implementation of the first task
func WhoAmIHandler(users *map[string]types.User) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// extract the token if supplied
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token := strings.TrimSpace(strings.Replace(auth, "Bearer ", "", 1))

		// naively look up the user
		var userName string
		var found bool
		for name, user := range *users {
			if user.Token == token {
				found = true
				userName = name
			}
		}

		// return 401 when we can't find a user
		if !found {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// report back the to the user who they are
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, userName)
	}
}
