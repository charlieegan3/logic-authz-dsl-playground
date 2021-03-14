package golang

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
)

// EntryHandler is the go implementation of the second task
func EntryHandler(users *map[string]types.User, entries *map[int]types.Entry) func(w http.ResponseWriter, r *http.Request) {
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
		for name, user := range *users {
			if user.Token == token {
				userName = name
			}
		}

		// extract the requested entry id
		id, ok := mux.Vars(r)["id"]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		idInt, err := strconv.Atoi(id)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// check if the user matches the requested entry
		entry, ok := (*entries)[idInt]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if entry.User != userName {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// report back the to the user who they are
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, entry.Content)
	}
}
