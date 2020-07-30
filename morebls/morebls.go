// Package morebls mirrors the kyber/bls package.
// Here, signatures are points on G2 and public keys are points on G1.
//
// WARNING: relies on an insecure hash-to-G2 function !
package morebls

import (
	"crypto/cipher"
	"errors"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

// Hashes a message to a point in G2 by using the message as a seed for the Pick method
// !!! Unsure whether this is collision resistant !!!
// To be replaced by a secure version that follows https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07
func insecureHashtoG2(suite pairing.Suite, msg []byte) kyber.Point {
	seed := blake2xb.New(msg)
	hashed := suite.G2().Point().Pick(seed)

	return hashed
}

// NewKeyPair2 creates a new BLS signing key pair. The private key x is a scalar
// and the public key X is a point on curve G1.
func NewKeyPair2(suite pairing.Suite, random cipher.Stream) (kyber.Scalar, kyber.Point) {
	x := suite.G1().Scalar().Pick(random)
	X := suite.G1().Point().Mul(x, nil)
	return x, X
}

// Sign2 creates a BLS signature S = x * H(m) on a message m using the private
// key x. The signature S is a point on curve G2.
func Sign2(suite pairing.Suite, x kyber.Scalar, msg []byte) ([]byte, error) {
	HM := insecureHashtoG2(suite, msg)
	xHM := HM.Mul(x, HM)

	s, err := xHM.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Verify2 checks the given BLS signature S on the message m using the public
// key X by verifying that the equality e(X, H(m)) == e(x*B1, H(m)) ==
// e(B1, x*H(m)) == e(B1, S) holds where e is the pairing operation and B1 is
// the base point from curve G1.
func Verify2(suite pairing.Suite, X kyber.Point, msg, sig []byte) error {
	HM := insecureHashtoG2(suite, msg)
	left := suite.Pair(X, HM)
	s := suite.G2().Point()
	if err := s.UnmarshalBinary(sig); err != nil {
		return err
	}
	right := suite.Pair(suite.G1().Point().Base(), s)
	if !left.Equal(right) {
		return errors.New("bls: invalid signature")
	}
	return nil
}
