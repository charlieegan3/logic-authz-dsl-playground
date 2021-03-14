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

token: strings.Split(headers.Authorization[0], " ")[1]

_matched: [
	for name, user in users
	if user.Token == token {
		name
	},
]

_count: len(_matched)
_name: ""
if len(_matched) > 0 {
	_name: _matched[0]
}

result: {
	found: _count > 0,
	name: _name,
}
`

		var rt cue.Runtime

		// first compile the cue code to make sure it's valid
		instance, err := rt.Compile("whoami", config)
		if err != nil {
			log.Fatalf("%s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// next, poplate the list of users and the headers from the request
		instance, err = instance.Fill(users, "users")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		instance, err = instance.Fill(r.Header, "headers")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// load the result struct from the instance
		var result struct {
			Found bool   `json:"found"`
			Name  string `json:"name"`
		}
		err = instance.Lookup("result").Decode(&result)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
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
