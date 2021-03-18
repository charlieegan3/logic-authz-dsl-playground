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

	o.LoadString(`allow(userName, _: Entry { User: userName });`)

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

		if len(results) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, entry.Content)
	}
}
