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
	var getEntryRule rego.PartialResult
	compiler, err := ast.CompileModules(map[string]string{
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

		authzInputData := struct {
			User  string
			Entry types.Entry
		}{
			User:  userName,
			Entry: entry,
		}

		resultSet, err := getEntryRule.Rego(rego.Input(authzInputData)).Eval(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if len(resultSet) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

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
