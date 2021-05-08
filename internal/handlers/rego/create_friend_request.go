package rego

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// CreateFriendRequestHandler will create a new friend request between two
// users, if permitted
func CreateFriendRequestHandler(users *map[string]types.User) func(w http.ResponseWriter, r *http.Request) {
	var createFriendRequestRule rego.PartialResult
	compiler, err := ast.CompileModules(map[string]string{
		"get_entry.rego": `
		package auth

        user_graph[user] = friends {
            friends := input.Users[user].Friends
        }

        default allow = false
		allow {
			friends_of_friends := graph.reachable(user_graph, {input.User})
			friends_of_friends[input.RequestedFriend]
		}`,
	})
	if err != nil {
		log.Fatalf("rule failed to compile: %s", err)
	}

	createFriendRequestRule, err = rego.
		New(rego.Compiler(compiler), rego.Query("data.auth.allow")).
		PartialResult(context.Background())
	if err != nil {
		log.Fatalf("failed to compute partial result: %s", err)
	}

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

		// no user exists, return 404
		if friendUsername == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// authzInputData is a structure passed to the Rego policy evaluation
		authzInputData := struct {
			User            string
			Users           *map[string]types.User
			RequestedFriend string
		}{
			User:            requestingUsername,
			Users:           users,
			RequestedFriend: friendUsername,
		}

		resultSet, err := createFriendRequestRule.Rego(rego.Input(authzInputData)).Eval(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// convert to data to make extracting the result easier
		bytes, err := json.MarshalIndent(resultSet, "", "    ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// wrap the data in gabs to make it easier to extract values
		result, err := gabs.ParseJSON(bytes)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// extract the allowed value from the response using gabs
		allowed, ok := result.Path("0.expressions.0.value").Data().(bool)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !allowed {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// just return 200 ok if allowed, don't bother to update the state
		// since not a real application
		w.WriteHeader(http.StatusOK)
	}
}
