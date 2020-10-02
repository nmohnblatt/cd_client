# Privacy-Preserving Contact Discovery - Client Application
UCL COMP0064 - An application to be run by clients using our privacy-preserving Contact Discovery (CD) service (see [dissertation](https://github.com/nmohnblatt/ucl_dissertation))

This application interacts with the matching server-side application "cd_server" (to be built soon...)

## System Requirements
Application has only been tested on Linux. Requires [Go](https://golang.org) v1.14 or later and the [IPFS command-line tool](https://ipfs.io/#install).

## Current Functionnality
- Generate public keys from human-readable identifiers
- Local emulation of servers
- User computes shared key material with contact
- Process single contact upon manual input
- n-out-of-n server version implemented
- t-out-of-n version of the multi-server service (threshold cryptography)
- Use a blinding factor when communicating with a server


## Running the application

In a new terminal window, clone the repository into your `GOPATH/src` directory and install the application. In this example, `GOPATH` is set to the default value `$HOME/go`:

    $ cd $HOME/go/src
    $ git clone https://github.com/nmohnblatt/cd_client.git
    $ go install github.com/nmohnblatt/cd_client

NOTE: you can check the value of GOPATH by running the command `go env GOPATH`

**In a separate Terminal window**, run the IPFS daemon:

    $ ipfs daemon

Make sure that the daemon is running (check for the message "Daemon is running"). Leave it to run in the background. You can now **go back to the first Terminal window** and run the application by simply typing:

    $ cd_client

Alternatively, you can navigate to your `GOPATH/bin` directory and run the application. Again in this example `GOPATH` is set to the default value `$HOME/go`:

    $ cd $HOME/go/bin
    $ ./cd_client


## Features coming soon
- Networked version of the service (server-side application)
- Use key material to establish IPFS meeting point
- Use key material and meeting point to establish end-to-end encryption (link w/ Signal Protocol)
- Import contacts from file
