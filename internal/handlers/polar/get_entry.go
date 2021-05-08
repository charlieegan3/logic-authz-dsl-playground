package polar

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/charlieegan3/go-authz-dsls/internal/helpers"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
	"github.com/osohq/go-oso"
)

func GetEntryHandler(users *map[string]types.User, entries *map[string]types.Entry) func(w http.ResponseWriter, r *http.Request) {
	var o oso.Oso

	// configure a new Oso instance
	o, _ = oso.NewOso()

	// make polar aware of our application types
	o.RegisterClass(reflect.TypeOf(types.Entry{}), nil)

	// create a simple rule where the user and the entry name must match
	o.LoadString(`allow(userName, _: Entry { User: userName });`)

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

		// submit the name and the entry requested to the policy
		query, err := o.NewQueryFromRule(
			"allow",
			userName,
			entry,
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

		// if there are no results, then the request was not allowed
		if len(results) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, entry.Content)
	}
}
