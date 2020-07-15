package main

import (
	"errors"

	"go.dedis.ch/kyber/v3"
)

// Derive "Public Keys" pk1 =  H1(id), pk2 = H2(id) by hashing phone number to points
func derivePublicKeys(phoneNumber string) (pk1, pk2 kyber.Point) {

	pk1 = hashtoG1([]byte(phoneNumber))
	pk2 = insecureHashtoG2([]byte(phoneNumber))

	return pk1, pk2
}

// Derive shared keys between users A and B:
// shared12 = e(H1(idA)^s, H2(idB)) = e(H1(idA), H2(idB))^s
// shared21 = e(H1(idB), H2(idA)^s) = e(H1(idB), H2(idA))^s
func deriveSharedKeys(alice *user, contactNumber string) (kyber.Point, kyber.Point) {
	bobPk1, bobPk2 := derivePublicKeys(contactNumber)
	shared12 := suite.Pair(alice.sk1, bobPk2)
	shared21 := suite.Pair(bobPk1, alice.sk2)

	return shared12, shared21
}

// Blind a point in any curve from the suite (G1, G2, GT) using a predefined blinding factor
func blind(p kyber.Point, blindingFactor kyber.Scalar) kyber.Point {
	blinded := p.Clone()
	blinded.Mul(blindingFactor, p)
	return blinded
}

// Unblind a point in any curve from the suite (G1, G2, GT) using a predefined blinding factor
func unblind(p kyber.Point, blindingFactor kyber.Scalar) kyber.Point {
	unblinded := p.Clone()
	inverse := blindingFactor.Clone()
	unblinded.Mul(inverse.Inv(blindingFactor), p)
	return unblinded
}

func xorBytes(a, b []byte) ([]byte, error) {
	var c []byte
	if len(a) != len(b) {
		return nil, errors.New("xorBytes: arguments must be of the same length")
	}

	for i := 0; i < len(a); i++ {
		buf := (int(a[i]) + int(b[i])) % 256
		c = append(c, byte(buf))
	}

	return c, nil
}
