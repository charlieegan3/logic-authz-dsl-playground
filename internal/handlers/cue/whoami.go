package cue

import (
	"fmt"
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

#auth_header_value: *headers.Authorization[0] | ""
#token: *strings.Split(#auth_header_value, " ")[1] | ""

#matched: [
	for name, user in users
	if user.Token == #token {
		name
	}
]

#codes: [
	{
		set: name != "",
		value: 200,
	},
	{
		set: #auth_header_value != "" && #token == "",
		value: 400,
	},
	{
		set: #auth_header_value == "" || len(#matched) != 1,
		value: 401,
	},
	{
		set: true, // default code if no other matches
		value: 500,
	},
]

name: *#matched[0] | ""
code: [ for c in #codes if c.set { c.value } ][0]
`

		var rt cue.Runtime

		// first compile the cue code to make sure it's valid
		instance, err := rt.Compile("whoami", config)
		if err != nil {
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

		// load the results from the instance
		code, err := instance.Lookup("code").Int64()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		name, err := instance.Lookup("name").String()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(int(code))
		fmt.Fprintf(w, name)
	}
}
