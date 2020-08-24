package main

import (
	"fmt"
	"io/ioutil"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

var suite = bn256.NewSuite()

const prompt string = "> "

// Create a simple UI
// User will be able to enter their details and contact lists.
// Program should find existing rendez-vous points and create new ones where needed.
func main() {
	// Setup Phase:
	n := 10
	t := n/2 + 1

	rng := blake2xb.New(nil) // A pseudo RNG which makes this code repeatable for testing.

	masterSecret := suite.GT().Scalar().Pick(rng)
	serverList, pubPoly1, pubPoly2 := setupThresholdServers(suite, masterSecret, n, t)

	// Initialise the service's user
	u1 := initialiseUser()

	// Communicate with servers to obtain the user's private keys
	fmt.Printf(prompt+"Fetching private keys from %d out of %d servers... \n", t, n)
	u1.obtainPrivateKeysBlindThreshold(suite, serverList[0:t], pubPoly1, pubPoly2, t, n)
	fmt.Println(prompt + "Keys successfully received.")

	// Compute shared key material with a manually entered contact number
	sharedAB, sharedBA := processSingleContactManualInput(u1)
	// fmt.Println(prompt + "Derived the following keys:\n" + sharedAB.String() + "\n" + sharedBA.String())

	meetingPoint := createMeetingPoint(u1, sharedAB, sharedBA)
	output := append([]byte("Meeting point "), meetingPoint...)
	if err := ioutil.WriteFile("mp.txt", output, 0644); err != nil {
		panic(fmt.Errorf("Could not generate file"))
	}
}

// A function that promts the user for their name and number.
// The function returns a pointer to a new user created with the name and number provided.
// Public keys are automatically computed. Private keys will need to be fetched from server
func initialiseUser() *user {
	fmt.Println(prompt + "Initialising. Please enter your name:")
	var Name string
	fmt.Scanf("%s", &Name)
	fmt.Printf(prompt+"Thank you %s. Please enter your phone number:\n", Name)
	var Number string
	fmt.Scanf("%s", &Number)
	u1 := newUser(Name, Number)
	fmt.Println(prompt + "You have been registered as a user.")

	return u1
}

// A function that prompts the user for their contact's phone number.
// The function computes the contact's corresponding public key and derives shared keys
func processSingleContactManualInput(u *user) (kyber.Point, kyber.Point) {
	fmt.Println(prompt + "Enter your contact's phone number:")
	var contactNumber string
	fmt.Scanf("%s", &contactNumber)

	sharedAB, sharedBA := deriveSharedKeys(u, contactNumber)

	return sharedAB, sharedBA
}
