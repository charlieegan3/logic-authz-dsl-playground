package golang

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/charlieegan3/go-authz-dsls/internal/types"
)

// CreateFriendRequestHandler will create a new friend request between two
// users, if permitted
func CreateFriendRequestHandler(users *map[string]types.User) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// extract the token if supplied
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token := strings.TrimSpace(strings.Replace(auth, "Bearer ", "", 1))

		// look up requesting user
		var requestingUsername string
		var requestingUser *types.User
		for name, user := range *users {
			if user.Token == token {
				requestingUser = &user
				requestingUsername = name
				break
			}
		}

		// token matched no user
		if requestingUsername == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// look up requested friend
		payloadBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		type Payload struct {
			Friend string `json:"friend"`
		}
		var payload Payload
		err = json.Unmarshal(payloadBytes, &payload)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var friendUsername string
		var friendUser *types.User
		for name, user := range *users {
			if name == payload.Friend {
				friendUser = &user
				friendUsername = name
				break
			}
		}

		// no user exists, retrun 404
		if friendUsername == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// find any mutual friends
		var mutualFriends []string
		for _, existingFriend := range requestingUser.Friends {
			fmt.Println("existingFriend", existingFriend)
			for _, maybeMutualFriend := range friendUser.Friends {
				fmt.Println("maybeMutualFriend", maybeMutualFriend)
				if existingFriend == maybeMutualFriend {
					fmt.Println("added")
					mutualFriends = append(mutualFriends, maybeMutualFriend)
				}
			}
		}

		// must have mutual friend to make request
		if len(mutualFriends) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// update the target user's list of FriendRequests
		friendUser.FriendRequests = append(friendUser.FriendRequests, requestingUsername)

		// report back the to the user who they are
		w.WriteHeader(http.StatusOK)
	}
}
