package main

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type user struct {
	name               string
	phoneNumber        string
	pk1, pk2, sk1, sk2 kyber.Point
}

// Creates a new user with the name and phone number specified
func newUser(Name, Number string) *user {
	var u user

	u.name = Name
	u.phoneNumber = Number

	u.pk1, u.pk2 = derivePublicKeys(u.phoneNumber)

	return &u
}

/*
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

func (u *user) dummyRequestKeys() {
	// Use a fixed server key for testing purposes
	seed := blake2xb.New([]byte("this is a seed"))
	serverKey := suite.GT().Scalar().Pick(seed)

	u.sk1 = suite.G1().Point().Mul(serverKey, u.pk1)
	u.sk2 = suite.G2().Point().Mul(serverKey, u.pk2)
}
