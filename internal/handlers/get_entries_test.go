package handlers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/charlieegan3/go-authz-dsls/internal/handlers/cue"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/golang"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/polar"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/rego"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
)

func TestGetEntriesEndpoints(t *testing.T) {
	var users = map[string]types.User{
		"Alice": {Token: "123"},
		"Bob":   {Token: "456"},
	}
	var entries = map[string]types.Entry{
		"1": {User: "Alice", Content: "Dear diary..."},
		"2": {User: "Bob", Content: "I have a secret to tell..."},
	}

	router := mux.NewRouter()
	router.HandleFunc("/golang/entries/{entryID}", golang.GetEntryHandler(&users, &entries))
	router.HandleFunc("/rego/entries/{entryID}", rego.GetEntryHandler(&users, &entries))
	router.HandleFunc("/cue/entries/{entryID}", cue.GetEntryHandler(&users, &entries))
	router.HandleFunc("/polar/entries/{entryID}", polar.GetEntryHandler(&users, &entries))

	languages := []string{"golang", "rego", "cue", "polar"}

	testCases := []struct {
		Description      string
		Headers          map[string]string
		EntryID          int
		ExpectedStatus   int
		ExpectedResponse string
	}{
		{
			Description: "permitted request for alice",
			Headers: map[string]string{
				"Authorization": "Bearer 123",
			},
			EntryID:          1,
			ExpectedStatus:   http.StatusOK,
			ExpectedResponse: "Dear diary...",
		},
		{
			Description: "permitted request for bob",
			Headers: map[string]string{
				"Authorization": "Bearer 456",
			},
			EntryID:          2,
			ExpectedStatus:   http.StatusOK,
			ExpectedResponse: "I have a secret to tell...",
		},
		{
			Description: "denied request",
			Headers: map[string]string{
				"Authorization": "Bearer 123",
			},
			EntryID:        2,
			ExpectedStatus: http.StatusUnauthorized,
		},
		{
			Description: "not found",
			Headers: map[string]string{
				"Authorization": "Bearer 123",
			},
			EntryID:        3,
			ExpectedStatus: http.StatusNotFound,
		},
		{
			Description: "bad request",
			Headers: map[string]string{
				"Authorization": "123", // missing bearer
			},
			ExpectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		for _, language := range languages {
			t.Run(fmt.Sprintf("%s %s", tc.Description, language), func(t *testing.T) {
				req, err := http.NewRequest("GET", fmt.Sprintf("/%s/entries/%d", language, tc.EntryID), nil)

				for k, v := range tc.Headers {
					req.Header.Set(k, v)
				}

				if err != nil {
					t.Fatalf("failed to build request: %s", err)
				}

				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				body, err := ioutil.ReadAll(w.Body)
				if err != nil {
					t.Fatalf("failed to read request: %s", err)
				}

				if got, want := w.Code, tc.ExpectedStatus; got != want {
					t.Fatalf("unexpected response code: got %d want %d", got, want)
				}

				if got, want := string(body), tc.ExpectedResponse; got != want {
					t.Fatalf("unexpected body: got %s want %s", got, want)
				}
			})
		}
	}
}
