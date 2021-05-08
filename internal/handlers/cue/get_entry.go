package cue

import (
	"fmt"
	"net/http"

	"cuelang.org/go/cue"
	"github.com/charlieegan3/go-authz-dsls/internal/helpers"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
)

func GetEntryHandler(users *map[string]types.User, entries *map[string]types.Entry) func(w http.ResponseWriter, r *http.Request) {
	// config is our CUE 'policy' code
	const config = `
entry: {
    User: string
}
user: string

allowed: entry.User == user
`

	// we're going to share the CUE runtime between requests
	var rt cue.Runtime

	return func(w http.ResponseWriter, r *http.Request) {
		// we're using a bearer token, we have a helper to look up the user
		// from using the data in the headers
		userName, responseCode := helpers.AuthnUser(&r.Header, users)
		if responseCode > 0 {
			w.WriteHeader(responseCode)
			return
		}

		// get the entryID from the request vars set for us by go mux
		entryID, ok := mux.Vars(r)["entryID"]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// check that the entry exists
		entry, ok := (*entries)[entryID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// first compile the cue code to make sure it's valid
		instance, err := rt.Compile("get_entry", config)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// next, poplate the list of users and the headers from the request
		instance, err = instance.Fill(userName, "user")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		instance, err = instance.Fill(entry, "entry")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// load the results from the instance
		allowed, err := instance.Lookup("allowed").Bool()
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !allowed {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, fmt.Sprintf("%v", entry.Content))
	}
}
