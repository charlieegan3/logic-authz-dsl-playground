package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/charlieegan3/go-authz-dsls/internal/handlers/golang"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/polar"
	"github.com/charlieegan3/go-authz-dsls/internal/handlers/rego"
	"github.com/charlieegan3/go-authz-dsls/internal/types"
	"github.com/gorilla/mux"
)

func TestCreateFriendRequestEndpoint(t *testing.T) {
	var users = map[string]types.User{
		"Alice":   {Token: "123", Friends: []string{"Bob"}},
		"Bob":     {Token: "456", Friends: []string{"Alice", "Charlie"}},
		"Charlie": {Token: "789", Friends: []string{"Bob", "Edward"}},
		"Dennis":  {Token: "101", Friends: []string{}},
		"Edward":  {Token: "112", Friends: []string{"Charlie"}},
	}

	router := mux.NewRouter()
	router.HandleFunc("/golang/friendrequests", golang.CreateFriendRequestHandler(&users))
	router.HandleFunc("/polar/friendrequests", polar.CreateFriendRequestHandler(&users))
	router.HandleFunc("/rego/friendrequests", rego.CreateFriendRequestHandler(&users))

	languages := []string{"golang", "rego", "polar"}

	testCases := []struct {
		Description      string
		Headers          map[string]string
		FriendName       string
		ExpectedStatus   int
		ExpectedResponse string
	}{
		{
			Description: "alice can add charlie as a friend since bob is their mutual friend",
			Headers: map[string]string{
				"Authorization": "Bearer 123",
			},
			FriendName:     "Charlie",
			ExpectedStatus: http.StatusOK,
		},
		{
			Description: "alice cannot add dennis as a friend since they have no mutual friends",
			Headers: map[string]string{
				"Authorization": "Bearer 123",
			},
			FriendName:     "Dennis",
			ExpectedStatus: http.StatusUnauthorized,
		},
		{
			Description: "alice can add edward as a friend since bob then charlie is their mutual friend",
			Headers: map[string]string{
				"Authorization": "Bearer 123",
			},
			FriendName:     "Edward",
			ExpectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		for _, language := range languages {
			t.Run(fmt.Sprintf("%s %s", tc.Description, language), func(t *testing.T) {
				payload, err := json.Marshal(struct {
					Friend string `json:"friend"`
				}{
					Friend: tc.FriendName,
				})

				req, err := http.NewRequest("POST", fmt.Sprintf("/%s/friendrequests", language), bytes.NewReader(payload))

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
