package polar

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/osohq/go-oso"
	osotypes "github.com/osohq/go-oso/types"
)

var o oso.Oso

func init() {
	// configure a new Oso instance and load in our whoami 'policy' (read:
	// lookup in polar in this case...)
	o, _ = oso.NewOso()
	// make polar aware of our application types
	o.RegisterClass(reflect.TypeOf(types.User{}), nil)
	// set a whoami policy for looking up users by token
	o.LoadString(`
whoami(userName, users, user: User) if
  [userName, match] in users and
  match.Token = user.Token;`)
}

// WhoAmIHandler is the polar implementation of the first task
func WhoAmIHandler(users *map[string]types.User) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// extract the token and proceed if supplied
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

		// use the token and users as input to the query
		query, err := o.NewQueryFromRule(
			"whoami",
			osotypes.ValueVariable("userName"),
			users,
			// pass token as a 'User' to demo typed Polar param
			types.User{Token: token},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		results, err := query.GetAllResults()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// if there were no solutions to the policy, then a user with that token
		// did not exist and so they must be unauthorized
		if len(results) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// naively extract the username from the results
		username := results[0]["userName"].(string)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, username)
	}
}
