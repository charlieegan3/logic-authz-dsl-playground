package polar

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/osohq/go-oso"
)

func CreateFriendRequestHandler(users *map[string]types.User) func(w http.ResponseWriter, r *http.Request) {
	var o oso.Oso

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

		// look up requesting user
		var requestingUsername string
		for name, user := range *users {
			if user.Token == token {
				requestingUsername = name
				break
			}
		}

		// token matched no user
		if requestingUsername == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// look up requested friend
		payloadBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		type Payload struct {
			Friend string `json:"friend"`
		}
		var payload Payload
		err = json.Unmarshal(payloadBytes, &payload)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var friendUsername string
		for name := range *users {
			if name == payload.Friend {
				friendUsername = name
				break
			}
		}

		// no user exists, retrun 404
		if friendUsername == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// configure a new Oso instance
		o, _ = oso.NewOso()

		// load in the current friendships
		for k, v := range *users {
			for _, f := range v.Friends {
				// sort names of pair and only add when ordered to avoid cycles
				// bit of a hack, but simple
				if k > f {
					o.LoadString(fmt.Sprintf("friends(\"%s\", \"%s\");", k, f))
				}
			}
		}

		// policy code which determines mutual friendships logically (in either
		// direction)
		o.LoadString(`
        connected(x, y) if friends(x, y) or friends(y, x);
        connected(x, y) if friends(x, p) and connected(p, y);
        connected(x, y) if friends(y, p) and connected(p, x);

	    allow(user, friend) if connected(user, friend);
	    `)

		query, err := o.NewQueryFromRule(
			"allow",
			requestingUsername,
			friendUsername,
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// don't care about getting all results, just that one exists
		result, err := query.Next()
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// if no solution, then unauthorized
		if result == nil {
			w.WriteHeader(http.StatusUnauthorized)
		}

		// just return 200 ok if allowed, don't bother to update the state
		// since not a real application
		w.WriteHeader(http.StatusOK)
	}
}
