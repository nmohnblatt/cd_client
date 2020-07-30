package main

import (
	"testing"

	"github.com/nmohnblatt/cd_client/moretbls"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/kyber/v3/util/random"
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
	// Format xSharedxy = e(H(x)^s, H(y)) i.e. the shared point in GT with x in G1 and y in G2 computed using x's private key
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
	// Format xSharedxy = e(H(x)^s, H(y)) i.e. the shared point in GT with x in G1 and y in G2 computed using x's private key
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

func TestThresholdG1(t *testing.T) {
	// Initialise client
	alice := newUser("Alice", "07111111111")
	msg := []byte(alice.phoneNumber)

	// Set number of servers and threshold
	n := 10
	thr := n/2 + 1

	// Create a master secret
	secret := suite.GT().Scalar().Pick(random.New())

	// Set-up the sharing scheme and give one share to each server
	priPoly := share.NewPriPoly(suite.G2(), thr, secret, random.New())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	serverKeys := priPoly.Shares(n)

	// Use the first thr keys to sign alice's number
	var alicePartialKeys [][]byte
	for _, key := range serverKeys[:thr] {
		sig, err := tbls.Sign(suite, key, msg)
		if err != nil {
			t.Errorf("Error whilst signing")
		}
		alicePartialKeys = append(alicePartialKeys, sig)
	}

	// Compute Alice's key in G1 using her partial keys
	fullKey, err := tbls.Recover(suite, pubPoly, msg, alicePartialKeys, thr, n)
	if err != nil {
		t.Errorf("Error whilst recovering")
	}
	test := suite.G1().Point()
	err = test.UnmarshalBinary(fullKey)
	if err != nil {
		t.Errorf("could not unmarshall point")
	}

	// Compute the expected value for Alice's private key in G1
	want := suite.G1().Point().Mul(secret, alice.pk1)

	// Compare Alice's computation with the expected value
	if !test.Equal(want) {
		t.Errorf("value is not as expected")
	}

}

func TestThresholdG2(t *testing.T) {
	// Initialise client
	alice := newUser("Alice", "07111111111")
	msg := []byte(alice.phoneNumber)

	// Set number of servers and threshold
	n := 10
	thr := n/2 + 1

	// Create a master secret
	secret := suite.GT().Scalar().Pick(random.New())

	// Set-up the sharing scheme and give one share to each server
	priPoly := share.NewPriPoly(suite.G1(), thr, secret, random.New())
	pubPoly := priPoly.Commit(suite.G1().Point().Base())
	serverKeys := priPoly.Shares(n)

	// Use the first thr keys to sign alice's number
	var alicePartialKeys [][]byte
	for _, key := range serverKeys[0:thr] {
		sig, err := moretbls.Sign2(suite, key, msg)
		if err != nil {
			t.Errorf("Error whilst signing")
		}
		alicePartialKeys = append(alicePartialKeys, sig)
	}

	// Compute Alice's key in G2 using her partial keys
	fullKey, err := moretbls.Recover2(suite, pubPoly, msg, alicePartialKeys, thr, n)
	if err != nil {
		t.Errorf("Error whilst recovering")
	}
	test := suite.G2().Point()
	err = test.UnmarshalBinary(fullKey)
	if err != nil {
		t.Errorf("could not unmarshall point")
	}

	// Compute the expected value for Alice's private key in G2
	want := suite.G2().Point().Mul(secret, alice.pk2)

	// Compare Alice's computation with the expected value
	if !test.Equal(want) {
		t.Errorf("value is not as expected")
	}

}

func TestThresholdUserKeys(t *testing.T) {
	// Initialise client
	alice := newUser("Alice", "07111111111")

	// Set number of servers and threshold
	n := 10
	thr := n/2 + 1

	// Create a master secret and deal shares
	secret := suite.GT().Scalar().Pick(random.New())
	serverList, pubPoly1, pubPoly2 := setupThresholdServers(suite, secret, n, thr)

	// Obtain private key from t servers
	alice.obtainPrivateKeysThreshold(suite, serverList[:thr], pubPoly1, pubPoly2, thr, n)

	// Compute the expected values for Alice's private keys
	want1 := suite.G1().Point().Mul(secret, alice.pk1)
	want2 := suite.G2().Point().Mul(secret, alice.pk2)

	// Check the value recovered from servers matches the expected value
	if !alice.sk1.Equal(want1) {
		t.Errorf("Did not compute correct private key 1")
	}
	if !alice.sk2.Equal(want2) {
		t.Errorf("Did not compute correct private key 2")
	}

}
