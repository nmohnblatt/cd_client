package main

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type server interface {
	sign(kyber.Point, kyber.Point) (kyber.Point, kyber.Point)
}

type dummyServer struct {
	ID int
	sk kyber.Scalar
}

type tcpServer struct {
	ID   int
	addr string
	sk   kyber.Scalar
}

func newDummyServer(id int) *dummyServer {
	return &dummyServer{id, suite.GT().Scalar().Pick(blake2xb.New([]byte("this is a seed" + string(id))))}
}

func newTCPServer(id int, addr string) *tcpServer {
	s := tcpServer{id, addr, suite.GT().Scalar().Pick(random.New())}
	return &s
}

func (s dummyServer) sign(pk1, pk2 kyber.Point) (kyber.Point, kyber.Point) {
	return suite.G1().Point().Mul(s.sk, pk1), suite.G2().Point().Mul(s.sk, pk2)
}