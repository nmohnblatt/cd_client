package main

import (
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestKeyDerivation(t *testing.T) {
	// setup two user, Alice and Bob
	alice := newUser("Alice", "07111111111")
	bob := newUser("Bob", "07222222222")
	charlie := newUser("Charlie", "07333333333")

	// Both clients get their private keys
	alice.dummyRequestKeys()
	bob.dummyRequestKeys()
	charlie.dummyRequestKeys()

	// Both clients compute a shared key
	aSharedab, aSharedba := deriveSharedKeys(alice, bob.phoneNumber)
	bSharedba, bSharedab := deriveSharedKeys(bob, alice.phoneNumber)
	cSharedca, cSharedac := deriveSharedKeys(charlie, alice.phoneNumber)
	cSharedcb, cSharedbc := deriveSharedKeys(charlie, bob.phoneNumber)

	if !aSharedab.Equal(bSharedab) {
		t.Errorf("Keys don't match: Alice AB does not match with Bob's")
	}

	if !aSharedba.Equal(bSharedba) {
		t.Errorf("Keys don't match: Alice BA does not match with Bob")
	}

	aliceBobKeys := [4]kyber.Point{aSharedab, aSharedba, bSharedab, bSharedba}
	charlieKeys := [4]kyber.Point{cSharedac, cSharedca, cSharedcb, cSharedbc}

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if charlieKeys[i].Equal(aliceBobKeys[j]) {
				t.Errorf("Charlie computed one of Alice and Bob's keys")
			}
		}
	}
}
