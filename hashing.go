package main

import (
	"log"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type hashablePoint interface {
	Hash([]byte) kyber.Point
}

func hashtoG1(msg []byte) kyber.Point {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		log.Printf("Point cannot be hashed")
	}
	hashed := hashable.Hash(msg)
	return hashed
}

func insecureHashtoG2(msg []byte) kyber.Point {
	seed := blake2xb.New(msg)
	hashed := suite.G2().Point().Pick(seed)

	return hashed
}
