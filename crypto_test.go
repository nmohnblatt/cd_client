package main

import (
	"testing"

	"go.dedis.ch/kyber/v3/util/random"
)

func TestBlindUnblindG1(t *testing.T) {
	p := suite.G1().Point().Pick(random.New())
	blindingFactor := suite.G1().Scalar().Pick(random.New())

	blindedP := blind(p, blindingFactor)

	if blindedP.Equal(p) {
		t.Errorf("blind: G1 Point was not blinded properly")
	}

	check := unblind(blindedP, blindingFactor)

	if !check.Equal(p) {
		t.Errorf("unblind: G1 Point was not recovered")
	}

}

func TestBlindUnblindG2(t *testing.T) {
	p := suite.G2().Point().Pick(random.New())
	blindingFactor := suite.G2().Scalar().Pick(random.New())

	blindedP := blind(p, blindingFactor)

	if blindedP.Equal(p) {
		t.Errorf("blind: G2 Point was not blinded properly")
	}

	check := unblind(blindedP, blindingFactor)

	if !check.Equal(p) {
		t.Errorf("unblind: G2 Point was not recovered")
	}

}

func TestBlindUnblindGT(t *testing.T) {
	p := suite.GT().Point().Pick(random.New())
	blindingFactor := suite.GT().Scalar().Pick(random.New())

	blindedP := blind(p, blindingFactor)

	if blindedP.Equal(p) {
		t.Errorf("blind: GT Point was not blinded properly")
	}

	check := unblind(blindedP, blindingFactor)

	if !check.Equal(p) {
		t.Errorf("unblind: GT Point was not recovered")
	}

}
