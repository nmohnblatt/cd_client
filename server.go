package main

import (
	"github.com/nmohnblatt/cd_client/moretbls"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type server interface {
	sign(string) (kyber.Point, kyber.Point)
}

// Local server for testing purposes
type dummyServer struct {
	ID int
	sk kyber.Scalar
}

type multiServer struct {
	ID  int
	sk1 *share.PriShare
	sk2 *share.PriShare
}

func newDummyServer(id int) *dummyServer {
	return &dummyServer{id, suite.GT().Scalar().Pick(blake2xb.New([]byte("this is a seed" + string(id))))}
}

func (s dummyServer) sign(phoneNumber string) (kyber.Point, kyber.Point) {
	pk1, pk2 := derivePublicKeys(phoneNumber)
	return suite.G1().Point().Mul(s.sk, pk1), suite.G2().Point().Mul(s.sk, pk2)
}

func setupThresholdServers(suite pairing.Suite, secret kyber.Scalar, n, t int) ([]*multiServer, *share.PubPoly, *share.PubPoly) {
	serverList := make([]*multiServer, n)
	if secret == nil {
		secret = suite.GT().Scalar().Pick(random.New())
	}

	priPoly1 := share.NewPriPoly(suite.G2(), t, secret, random.New())
	pubPoly1 := priPoly1.Commit(suite.G2().Point().Base())
	serverPrivateKeys1 := priPoly1.Shares(n)

	priPoly2 := share.NewPriPoly(suite.G1(), t, secret, random.New())
	pubPoly2 := priPoly2.Commit(suite.G1().Point().Base())
	serverPrivateKeys2 := priPoly2.Shares(n)

	for i := 0; i < n; i++ {
		serverList[i] = newMultiServer(i, serverPrivateKeys1[i], serverPrivateKeys2[i])
	}

	return serverList, pubPoly1, pubPoly2
}

func newMultiServer(id int, key1, key2 *share.PriShare) *multiServer {
	return &multiServer{
		ID:  id,
		sk1: key1,
		sk2: key2,
	}
}

func (s multiServer) sign(phoneNumber string) ([]byte, []byte) {
	toSign := []byte(phoneNumber)
	buf1, _ := tbls.Sign(suite, s.sk1, toSign)
	buf2, _ := moretbls.Sign2(suite, s.sk2, toSign)

	return buf1, buf2
}

// TCP server to test a networked version of our service
type tcpServer struct {
	ID   int
	addr string
	sk   kyber.Scalar
}

func newTCPServer(id int, addr string) *tcpServer {
	s := tcpServer{id, addr, suite.GT().Scalar().Pick(random.New())}
	return &s
}

// TODO: implement a "sign" method for TCP server (dial, send public keys, perform checks (?), etc)
