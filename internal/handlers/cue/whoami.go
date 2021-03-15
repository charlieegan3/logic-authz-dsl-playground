package cue

import (
	"fmt"
	"log"
	"net/http"

	"cuelang.org/go/cue"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
)

// WhoAmIHandler is the cue implementation of the first task
func WhoAmIHandler(users *map[string]types.User) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		const config = `
import "strings"

users: [string]: {
    Token: string
}
headers: [string]: [string]

_auth_header_value: *headers.Authorization[0] | ""
_token: *strings.Split(_auth_header_value, " ")[1] | ""

_matched: [
	for name, user in users
	if user.Token == _token {
		name
	}
]

result: {
	auth_header_set: _auth_header_value != "",
	token: _token,
	found: len(_matched) > 0,
	name: *_matched[0] | ""
}
`

		var rt cue.Runtime

		// first compile the cue code to make sure it's valid
		instance, err := rt.Compile("whoami", config)
		if err != nil {
			log.Fatalf("comp %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// next, poplate the list of users and the headers from the request
		instance, err = instance.Fill(users, "users")
		if err != nil {
			log.Fatalf("fill %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		instance, err = instance.Fill(r.Header, "headers")
		if err != nil {
			log.Fatalf("fill %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// load the result struct from the instance
		var result struct {
			AuthHeaderSet bool   `json:"auth_header_set"`
			Token         string `json:"token"`
			Found         bool   `json:"found"`
			Name          string `json:"name"`
		}
		err = instance.Lookup("result").Decode(&result)
		if err != nil {
			log.Fatalf("look %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !result.AuthHeaderSet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if result.Token == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// if there was no user matched, then 401
		if !result.Found {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, result.Name)
	}
}
