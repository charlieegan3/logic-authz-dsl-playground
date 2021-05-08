package golang

import (
	"fmt"
	"net/http"

	"github.com/charlieegan3/go-authz-dsls/internal/helpers"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
)

func GetEntryHandler(users *map[string]types.User, entries *map[string]types.Entry) func(w http.ResponseWriter, r *http.Request) {
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

		// check that the existing entry has the same name as the current user
		if entry.User != userName {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// return ok with the entry content
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, entry.Content)
	}
}
