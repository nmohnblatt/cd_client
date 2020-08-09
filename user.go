package main

import (
	"errors"

	"github.com/nmohnblatt/cd_client/blindbls"
	"github.com/nmohnblatt/cd_client/blindtbls"
	"github.com/nmohnblatt/cd_client/moretbls"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type user struct {
	name               string
	phoneNumber        string
	pk1, pk2, sk1, sk2 kyber.Point
}

// Creates a new user with the name and phone number specified.
// Automatically derive public keys. (Private keys need to be provided by server)
func newUser(Name, Number string) *user {
	var u user

	u.name = Name
	u.phoneNumber = Number

	u.pk1, u.pk2 = derivePublicKeys(u.phoneNumber)

	return &u
}

/*
// Request private key from a TCP server
func (u *user) requestKeysTCP(server string) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		panic(err)
	}

	// send to socket
	fmt.Fprintf(conn, u.pk1.String()+u.pk2.String()+"\n")

	// listen for reply
	message, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Print("Message from server: " + message)

}
*/

// Request private key from a dummy server (i.e. one that runs locally)
func dummyRequestKeys(u *user, serverID string) (kyber.Point, kyber.Point) {
	// Use a fixed server key for testing purposes
	seed := blake2xb.New([]byte("this is a seed" + serverID))
	serverKey := suite.GT().Scalar().Pick(seed)

	sk1 := suite.G1().Point().Mul(serverKey, u.pk1)
	sk2 := suite.G2().Point().Mul(serverKey, u.pk2)

	return sk1, sk2
}

func (u *user) obtainPrivateKeys(servers ...server) {
	buf1 := suite.G1().Point()
	buf2 := suite.G2().Point()
	for _, s := range servers {
		partial1, partial2 := s.sign(u.phoneNumber)
		buf1.Add(buf1, partial1)
		buf2.Add(buf2, partial2)
	}

	u.sk1 = buf1
	u.sk2 = buf2
}

func (u *user) obtainPrivateKeysThreshold(suite pairing.Suite, servers []*multiServer, pubPoly1, pubPoly2 *share.PubPoly, t, n int) error {
	if len(servers) < t {
		return errors.New("Not enough servers to meet thre threshold")
	}

	buf1 := make([][]byte, len(servers))
	buf2 := make([][]byte, len(servers))

	for i, s := range servers {
		buf1[i], buf2[i] = s.sign(u.phoneNumber)
	}

	key1, _ := tbls.Recover(suite, pubPoly1, []byte(u.phoneNumber), buf1, t, n)
	key2, _ := moretbls.Recover2(suite, pubPoly2, []byte(u.phoneNumber), buf2, t, n)

	u.sk1 = suite.G1().Point()
	err := u.sk1.UnmarshalBinary(key1)
	if err != nil {
		return err
	}
	u.sk2 = suite.G2().Point()
	err = u.sk2.UnmarshalBinary(key2)
	if err != nil {
		return err
	}

	return nil
}

func (u *user) obtainPrivateKeysBlindThreshold(suite pairing.Suite, servers []*multiServer, pubPoly1, pubPoly2 *share.PubPoly, t, n int) error {
	if len(servers) < t {
		return errors.New("Not enough servers to meet the threshold")
	}

	// Choose blinding factor
	BF := [2]kyber.Scalar{suite.G1().Scalar().Pick(random.New()), suite.G2().Scalar().Pick(random.New())}

	// Blind
	aH1M, err := blindtbls.Blind(suite.G1(), BF[0], u.pk1)
	if err != nil {
		return err
	}
	aH2M, err := blindtbls.Blind(suite.G2(), BF[1], u.pk2)
	if err != nil {
		return err
	}

	// Sign
	buf1 := make([][]byte, len(servers))
	buf2 := make([][]byte, len(servers))

	for i, s := range servers {
		buf1[i], buf2[i], err = s.blindsign(aH1M, aH2M)
		if err != nil {
			return err
		}
	}

	// Recover
	aH1MPoint := suite.G1().Point()
	if err := aH1MPoint.UnmarshalBinary(aH1M); err != nil {
		return err
	}
	aH2MPoint := suite.G2().Point()
	if err := aH2MPoint.UnmarshalBinary(aH2M); err != nil {
		return err
	}

	buf1Formatted := make([]*share.PubShare, len(buf1))
	buf2Formatted := make([]*share.PubShare, len(buf2))
	for i := 0; i < len(buf1); i++ {
		buf1Formatted[i], err = blindtbls.SigSharetoPubShare(suite.G1(), tbls.SigShare(buf1[i]))
		if err != nil {
			return err
		}
		buf2Formatted[i], err = blindtbls.SigSharetoPubShare(suite.G2(), tbls.SigShare(buf2[i]))
		if err != nil {
			return err
		}
	}
	blindKey1, err := blindtbls.Recover(suite, suite.G1(), pubPoly1, aH1MPoint, buf1Formatted[:t], t, n)
	if err != nil {
		return err
	}
	blindKey2, err := blindtbls.Recover(suite, suite.G2(), pubPoly2, aH2MPoint, buf2Formatted[:t], t, n)
	if err != nil {
		return err
	}

	// Unblind
	u.sk1, _ = blindbls.Unblind(suite.G1(), BF[0], blindKey1)
	u.sk2, _ = blindbls.Unblind(suite.G2(), BF[1], blindKey2)

	return nil
}
