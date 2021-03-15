package handlers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/charlieegan3/go-authz-dsls/internal/handlers/cue"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/golang"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/rego"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
)

func TestWhoAmIEndpoints(t *testing.T) {
	var users = map[string]types.User{
		"Alice": {Token: "123"},
		"Bob":   {Token: "456"},
	}
	router := mux.NewRouter()
	router.HandleFunc("/golang/whoami", golang.WhoAmIHandler(&users))
	router.HandleFunc("/rego/whoami", rego.WhoAmIHandler(&users))
	router.HandleFunc("/cue/whoami", cue.WhoAmIHandler(&users))

	languages := []string{"golang", "rego", "cue"}

	testCases := []struct {
		Description      string
		Headers          map[string]string
		Language         string
		ExpectedStatus   int
		ExpectedResponse string
	}{
		{
			Description: "permitted request for alice",
			Headers: map[string]string{
				"Authorization": "Bearer 123",
			},
			ExpectedStatus:   http.StatusOK,
			ExpectedResponse: "Alice",
		},
		{
			Description: "permitted request for bob",
			Headers: map[string]string{
				"Authorization": "Bearer 456",
			},
			ExpectedStatus:   http.StatusOK,
			ExpectedResponse: "Bob",
		},
		{
			Description: "bad request",
			Headers: map[string]string{
				"Authorization": "456",
			},
			ExpectedStatus:   http.StatusBadRequest,
			ExpectedResponse: "",
		},
		{
			Description:      "missing auth header",
			Headers:          map[string]string{},
			ExpectedStatus:   http.StatusUnauthorized,
			ExpectedResponse: "",
		},
		{
			Description: "unknown token",
			Headers: map[string]string{
				"Authorization": "Bearer 789",
			},
			ExpectedStatus:   http.StatusUnauthorized,
			ExpectedResponse: "",
		},
	}

	for _, tc := range testCases {
		for _, language := range languages {
			t.Run(fmt.Sprintf("%s %s", tc.Description, language), func(t *testing.T) {
				req, err := http.NewRequest("GET", fmt.Sprintf("/%s/whoami", language), nil)

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
					t.Fatalf("unexpected body: got %d want %d", got, want)
				}

				if got, want := string(body), tc.ExpectedResponse; got != want {
					t.Fatalf("unexpected body: got %s want %s", got, want)
				}
			})
		}
	}
}
