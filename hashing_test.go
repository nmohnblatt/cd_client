package main

import (
	"testing"
)

func TestHashToG2(t *testing.T) {
	testMsg := "this is a test message"
	hash1 := insecureHashtoG2([]byte(testMsg))
	hash2 := insecureHashtoG2([]byte(testMsg))

	if !hash1.Equal(hash2) {
		t.Errorf("Hashing the same message yield different points")
	}
}
