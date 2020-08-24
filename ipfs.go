package main

import (
	"crypto/sha256"
	"fmt"

	"go.dedis.ch/kyber/v3"
)

func createMeetingPoint(u *user, sharedAB, sharedBA kyber.Point) []byte {
	bytesSharedAB, _ := sharedAB.MarshalBinary()
	bytesSharedBA, _ := sharedBA.MarshalBinary()

	keymaterial, err := xorBytes(bytesSharedAB, bytesSharedBA)
	if err != nil {
		panic(fmt.Errorf("Could not xor bytes"))
	}

	h := sha256.New()
	h.Write(keymaterial)

	return h.Sum(nil)
}
