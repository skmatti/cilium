package cmd

import "errors"

var (
	errNotFound = errors.New("not found")

	errAlreadyExist = errors.New("already exists")

	// ErrNotAlive is an error which indicates that the endpoint should not be
	// rlocked because it is currently being removed.
	ErrNotAlive = errors.New("rlock failed: endpoint is in the process of being removed")
)

func IsNotFound(err error) bool {
	return err == errNotFound
}
