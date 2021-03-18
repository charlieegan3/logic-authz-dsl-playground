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

		if entry.User != userName {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, entry.Content)
	}
}
