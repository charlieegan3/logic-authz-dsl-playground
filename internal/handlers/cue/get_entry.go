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
	const config = `
entry: {
    User: string
}
user: string

allowed: entry.User == user
`

	var rt cue.Runtime

	return func(w http.ResponseWriter, r *http.Request) {
		userName, responseCode := helpers.AuthnUser(&r.Header, users)
		if responseCode > 0 {
			w.WriteHeader(responseCode)
			return
		}

		entryID, ok := mux.Vars(r)["entryID"]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

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
