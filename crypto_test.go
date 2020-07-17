package main

import (
	"bytes"
	"testing"

	"go.dedis.ch/kyber/v3"
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

func TestXorBytes(t *testing.T) {
	// Check for correct error handling
	a := []byte{1, 2}
	b := []byte{0, 0, 0}
	_, err := xorBytes(a, b)
	if err == nil {
		t.Errorf("xor: allowed to XOR arguments of different lengths")
	}

	// Check XOR without modular reduction
	a = []byte{1, 2}
	b = []byte{3, 4}
	want := []byte{4, 6}
	c, err := xorBytes(a, b)
	if err != nil {
		t.Errorf("xor: error arose: %s", err)
	}
	if bytes.Compare(c, want) != 0 {
		t.Errorf("xor: not added properly before modular reduction")
	}

	// Check XOR with modular reduction
	a = []byte{255, 200}
	b = []byte{1, 100}
	want = []byte{0, 44}
	c, err = xorBytes(a, b)
	if err != nil {
		t.Errorf("xor: error arose: %s", err)
	}
	if bytes.Compare(c, want) != 0 {
		t.Errorf("xor: not added properly after modular reduction")
	}
}

func TestSumG1Points(t *testing.T) {
	n := 2
	var scalars []kyber.Scalar

	for i := 0; i < n; i++ {
		scalars = append(scalars, suite.GT().Scalar().Pick(random.New()))
	}

	scalarSum := sumScalars(scalars...)

	p := suite.G1().Point().Pick(random.New())

	want := suite.G1().Point().Mul(scalarSum, p)

	var points []kyber.Point
	for _, X := range scalars {
		points = append(points, suite.G1().Point().Mul(X, p))
	}

	test := sumG1Points(points...)

	if !test.Equal(want) {
		t.Errorf("did not add points properly")
	}

}

func TestSumG2Points(t *testing.T) {
	n := 4
	var scalars []kyber.Scalar

	for i := 0; i < n; i++ {
		scalars = append(scalars, suite.GT().Scalar().Pick(random.New()))
	}

	scalarSum := sumScalars(scalars...)

	p := suite.G2().Point().Pick(random.New())

	want := suite.G2().Point().Mul(scalarSum, p)

	var points []kyber.Point
	for _, X := range scalars {
		points = append(points, suite.G2().Point().Mul(X, p))
	}

	test := sumG2Points(points...)

	if !test.Equal(want) {
		t.Errorf("did not add points properly")
	}

}

func TestSumScalars(t *testing.T) {
	a := suite.GT().Scalar().Pick(random.New())
	b := suite.GT().Scalar().Pick(random.New())
	c := suite.GT().Scalar().Pick(random.New())
	sumAB := suite.GT().Scalar().Add(a, b)
	sumABC := suite.G1().Scalar().Add(sumAB, c)

	if !sumScalars(a, b, c).Equal(sumABC) {
		t.Errorf("Did not add scalars correctly")
	}
}
