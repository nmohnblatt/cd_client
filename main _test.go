package main

import (
	"testing"
)

func TestKeyDerivation(t *testing.T) {
	// setup two user, Alice and Bob
	alice := newUser("Alice", "07111111111")
	bob := newUser("Bob", "07222222222")

	// Both clients get their private keys
	alice.dummyRequestKeys()
	bob.dummyRequestKeys()

	// Both clients compute a shared key
	aShared12, aShared21 := deriveSharedKeys(alice, bob.phoneNumber)
	bShared12, bShared21 := deriveSharedKeys(bob, alice.phoneNumber)

	if !aShared12.Equal(bShared21) {
		t.Errorf("Keys don't match: Alice AB does not match with Bob's")
	}

	if !aShared21.Equal(bShared12) {
		t.Errorf("Keys don't match: Alice BA does not match with Bob")
	}
}
