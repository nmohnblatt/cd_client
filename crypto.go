package main

import (
	"go.dedis.ch/kyber/v3"
)

func derivePublicKeys(phoneNumber string) (pk1, pk2 kyber.Point) {

	pk1 = hashtoG1([]byte(phoneNumber))
	pk2 = insecureHashtoG2([]byte(phoneNumber))

	return pk1, pk2
}

func deriveSharedKeys(alice *user, contactNumber string) (kyber.Point, kyber.Point) {
	bobPk1, bobPk2 := derivePublicKeys(contactNumber)
	shared12 := suite.Pair(alice.sk1, bobPk2)
	shared21 := suite.Pair(bobPk1, alice.sk2)

	return shared12, shared21
}
