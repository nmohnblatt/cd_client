package main

import (
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestKeyDerivationLocal(t *testing.T) {
	s1 := newDummyServer(1)
	// setup three users: Alice, Bob and Charlie
	alice := newUser("Alice", "07111111111")
	bob := newUser("Bob", "07222222222")
	charlie := newUser("Charlie", "07333333333")

	alice.obtainPrivateKeys(s1)
	bob.obtainPrivateKeys(s1)
	charlie.obtainPrivateKeys(s1)

	// Alice and Bob compute shared keys. Charlie tries to use his key material to find A and B's shared keys
	// Format xSharedxy = e(H(x)^s, H(y)) i.e. the key with x in G1 and y in G2 computed using x's private key
	aSharedab, aSharedba := deriveSharedKeys(alice, bob.phoneNumber)
	bSharedba, bSharedab := deriveSharedKeys(bob, alice.phoneNumber)
	cSharedca, cSharedac := deriveSharedKeys(charlie, alice.phoneNumber)
	cSharedcb, cSharedbc := deriveSharedKeys(charlie, bob.phoneNumber)

	// Check that Alice and Bob's computatins match
	if !aSharedab.Equal(bSharedab) {
		t.Errorf("Keys don't match: Alice AB does not match with Bob's")
	}
	if !aSharedba.Equal(bSharedba) {
		t.Errorf("Keys don't match: Alice BA does not match with Bob")
	}

	// Check that Charlie's computations are different from those of Alice and Bob
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

func TestKeyDerivationMultiLocal(t *testing.T) {
	// Vary the number of servers
	n := 6

	var servers []server

	// Using dummy servers to test locally (no connection to server)
	for i := 0; i < n; i++ {
		servers = append(servers, newDummyServer(i))
	}

	alice := newUser("Alice", "07111111111")
	bob := newUser("Bob", "07222222222")
	charlie := newUser("Charlie", "07333333333")

	alice.obtainPrivateKeys(servers...)
	bob.obtainPrivateKeys(servers...)
	charlie.obtainPrivateKeys(servers...)

	// Alice and Bob compute shared keys. Charlie tries to use his key material to find A and B's shared keys
	aSharedab, aSharedba := deriveSharedKeys(alice, bob.phoneNumber)
	bSharedba, bSharedab := deriveSharedKeys(bob, alice.phoneNumber)
	cSharedca, cSharedac := deriveSharedKeys(charlie, alice.phoneNumber)
	cSharedcb, cSharedbc := deriveSharedKeys(charlie, bob.phoneNumber)

	// Check that Alice and Bob's computatins match
	if !aSharedab.Equal(bSharedab) {
		t.Errorf("Keys don't match: Alice AB does not match with Bob's")
	}
	if !aSharedba.Equal(bSharedba) {
		t.Errorf("Keys don't match: Alice BA does not match with Bob")
	}

	// Check that Charlie's computations are different from those of Alice and Bob
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
