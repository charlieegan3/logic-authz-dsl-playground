package golang

import (
	"encoding/json"
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

		// find path of mutual friends
		var reachedFriends []string
		var unexploredFriends []string
		for _, existingFriend := range requestingUser.Friends {
			unexploredFriends = append(unexploredFriends, existingFriend)
		}
		for {
			if len(unexploredFriends) == 0 {
				break
			}

			currentFriend := unexploredFriends[0]
			unexploredFriends = unexploredFriends[1:]
			reachedFriends = append(reachedFriends, currentFriend)

			currentFriendUser, _ := (*users)[currentFriend]
			for _, friend := range currentFriendUser.Friends {
				alreadyReached := false
				for _, reachedFriend := range reachedFriends {
					if friend == reachedFriend {
						alreadyReached = true
						break
					}
				}
				if !alreadyReached {
					unexploredFriends = append(unexploredFriends, friend)
				}

				if friend == friendUsername {
					// update the target user's list of FriendRequests
					friendUser.FriendRequests = append(friendUser.FriendRequests, requestingUsername)

					// report back the to the user who they are
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}

		w.WriteHeader(http.StatusUnauthorized)
	}
}
