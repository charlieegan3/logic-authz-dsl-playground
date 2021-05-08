package rego

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/Jeffail/gabs/v2"
	"github.com/charlieegan3/go-authz-dsls/internal/helpers"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

func GetEntryHandler(users *map[string]types.User, entries *map[string]types.Entry) func(w http.ResponseWriter, r *http.Request) {
	// create a rule which can be partially evaluated at boot time and reused
	// in each call to the handler
	var getEntryRule rego.PartialResult
	compiler, err := ast.CompileModules(map[string]string{
		// simple rego rule to check the data in the input conforms. i.e. that
		// the user and entry/user match
		"get_entry.rego": `
	package auth
	allow {
		input.Entry.User == input.User
	}`,
	})
	if err != nil {
		log.Fatalf("rule failed to compile: %s", err)
	}

	getEntryRule, err = rego.
		New(rego.Compiler(compiler), rego.Query("data.auth.allow")).
		PartialResult(context.Background())
	if err != nil {
		log.Fatalf("failed to compute partial result: %s", err)
	}

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

		// build the input data for the Rego evaluation containing the entry
		// and the requesting user
		authzInputData := struct {
			User  string
			Entry types.Entry
		}{
			User:  userName,
			Entry: entry,
		}

		// get the results from the rego evaluation
		resultSet, err := getEntryRule.Rego(rego.Input(authzInputData)).Eval(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// if there are no 'solutions' then we can return unauthorized
		if len(resultSet) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// next we convert the output into JSON. This is a bit of a hack but it
		// allows us to use gabs to extracts data from the response more in a
		// terse manner
		bytes, err := json.MarshalIndent(resultSet, "", "    ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		result, err := gabs.ParseJSON(bytes)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// use a gabs query to get the data we want and assert it's a boolean
		allowed, ok := result.Path("0.expressions.0.value").Data().(bool)
		if !ok {
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
