package connector

import (
	"math/rand/v2"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// Endpoint2TempRandIfName returns a random, temporary interface name for the
// given endpointID. This is similar to Endpoint2TempIfName() but uses a
// random string instead of endpoint ID.
func Endpoint2TempRandIfName() string {
	return temporaryInterfacePrefix + "_" + RandomLowercaseStringWithLen(5)
}

// RandomLowercaseStringWithLen returns a random string of specified length
// containing lowercase runes.
func RandomLowercaseStringWithLen(n int) string {
	return randomStringFromSliceWithLen(letterRunes[:26], n)
}

func randomStringFromSliceWithLen(runes []rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.IntN(len(runes))]
	}
	return string(b)
}
