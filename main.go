package main

import (
	"fmt"

	"go.dedis.ch/kyber/v3/pairing/bn256"
)

var suite = bn256.NewSuite()

const prompt string = "> "

// Create a simple UI
// User will be able to enter their details and contact lists.
// Program should find existing rendez-vous points and create new ones where needed.
func main() {
	u1 := initialiseUser()
	processSingleContactManualInput(u1)
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
	fmt.Println(prompt + "Fetching private keys from server...")
	u1.sk1, u1.sk2 = dummyRequestKeys(u1, "server1")
	fmt.Println(prompt + "Done")

	return u1
}

// A function that prompts the user for their contact's phone number.
// The function computes the contact's corresponding public key and derives shared keys
func processSingleContactManualInput(u *user) {
	fmt.Println(prompt + "Enter your contact's phone number:")
	var contactNumber string
	fmt.Scanf("%s", &contactNumber)

	sharedAB, sharedBA := deriveSharedKeys(u, contactNumber)

	fmt.Println(prompt + "Derived the following keys:\n" + sharedAB.String() + "\n" + sharedBA.String())
}
