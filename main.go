package main

import (
	"log"
	"net/http"

	"github.com/charlieegan3/go-authz-dsls/internal/handlers/cue"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/golang"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/polar"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/rego"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
)

var users = map[string]types.User{
	"Alice": {Token: "123"},
	"Bob":   {Token: "456"},
}

var entries = map[int]types.Entry{
	1: {
		User:    "Alice",
		Content: "dear diary...",
	},
	2: {
		User:    "Bob",
		Content: "there was this one time at band camp...",
	},
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/golang/whoami", golang.WhoAmIHandler(&users)).Methods("GET")
	r.HandleFunc("/rego/whoami", rego.WhoAmIHandler(&users)).Methods("GET")
	r.HandleFunc("/polar/whoami", polar.WhoAmIHandler(&users)).Methods("GET")
	r.HandleFunc("/cue/whoami", cue.WhoAmIHandler(&users)).Methods("GET")

	r.HandleFunc("/golang/entries/{id:[0-9]+}", golang.EntryHandler(&users, &entries)).Methods("GET")

	http.Handle("/", r)
	srv := &http.Server{
		Handler: r,
		Addr:    "127.0.0.1:8000",
	}
	log.Printf("server started")
	log.Fatal(srv.ListenAndServe())
}
