package rego

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// whoAmiRule is partially evaluated at boot time and then available to make
// decisions during the execution of the handler
var whoAmiRule rego.PartialResult

func init() {
	// initialize the various gubbins for Rego evaluation.
	// we can load and partially evaluate the rule before using it in our
	// handler.
	compiler, err := ast.CompileModules(map[string]string{
		"whoami.rego": `
		package auth
		whoami[user] {
			token := split(input.Headers.Authorization[0], " ")[1]
			user := [u| input.Users[u].Token == token][0]
		}`,
	})
	if err != nil {
		log.Fatalf("rule failed to compile: %s", err)
	}

	// create a partially evaluated result ready for use in our handlers when
	// evaluating requests
	whoAmiRule, err = rego.
		New(rego.Compiler(compiler), rego.Query("data.auth.whoami")).
		PartialResult(context.TODO())
	if err != nil {
		log.Fatalf("failed to compute partial result: %s", err)
	}
}

// WhoAmIHandler is the rego implementation of the first task
func WhoAmIHandler(users *map[string]types.User) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// this data will be used by Rego to determine the user making the request
		authzInputData := struct {
			Headers http.Header
			Users   *map[string]types.User
		}{
			Headers: r.Header,
			Users:   users,
		}

		// this evaluates our rule for the endpoint with the request and the user
		// data (clearly it'd be unwise to load all the users into an authz
		// check in a real application...)
		resultSet, err := whoAmiRule.Rego(rego.Input(authzInputData)).Eval(context.TODO())
		if err != nil || resultSet == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// extract the data from the response into a list of matched users, there
		// may be more than one with the same key
		users := []string{}
		for _, result := range resultSet {
			for _, exp := range result.Expressions {
				interfaceSlice, ok := (exp.Value).([]interface{})
				if !ok {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				for _, v := range interfaceSlice {
					str, ok := v.(string)
					if !ok {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					users = append(users, str)
				}
			}
		}

		// we expect there to be a single solution in the valid case of identifying
		// a user
		if len(users) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// report back the to the user who they are
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, users[0])
	}
}
