package hash

import (
	"errors"
	"log"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type hashablePoint interface {
	Hash([]byte) kyber.Point
}

// HashtoG1 securely hashes a message into a point on G1
func HashtoG1(suite pairing.Suite, msg []byte) kyber.Point {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		log.Printf("Point cannot be hashed")
	}
	hashed := hashable.Hash(msg)
	return hashed
}

// InsecureHashtoG2 hashes a message to a point in G2 by using the message as a seed for the Pick method
// !!! Unsure whether this is collision resistant !!!
// To be replaced by a secure version that follows https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07
func InsecureHashtoG2(suite pairing.Suite, msg []byte) kyber.Point {
	seed := blake2xb.New(msg)
	hashed := suite.G2().Point().Pick(seed)

	return hashed
}

// Hash hashes a nsg to a point on the requested curve
func Hash(suite pairing.Suite, group kyber.Group, msg []byte) (kyber.Point, error) {
	if group.String() == "bn256.G1" {
		return HashtoG1(suite, msg), nil
	} else if group.String() == "bn256.G2" {
		return InsecureHashtoG2(suite, msg), nil
	} else {
		return nil, errors.New("hash: group not recognised")
	}
}
