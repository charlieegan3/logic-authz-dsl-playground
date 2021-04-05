package types

type User struct {
	// Token is the bearer token that the user includes with requests to id
	// themselves
	Token string

	// Friends is a list of userNames of current accepted friends
	Friends []string

	// FriendRequests is a list of userNames of unaccepted FriendRequests the
	// user has yet to accept. E.g. If Bob is allowed to send a FriendRequest
	// to Alice, and is allowed to do so, then Alice's list of FriendRequests
	// is extended to include Bob.
	FriendRequests []string
}
