# Privacy-Preserving Contact Discovery - Client Application
UCL COMP0064 - An application to be run by clients using our privacy-preserving Contact Discovery (CD) service.

This application interacts with the matching server-side application "cd_server" (to be built soon...)


## Current Functionnality
- Generate public keys from human-readible identifiers
- User computes shared key material with contact (requires to obtain private keys from servers)
- n-out-of-n server version implemented (no theshold crypto yet)

## TODO
- Networked version of the service
- t-out-of-n version of the multi-server service (threshold)
- Use key material to establish IPFS meeting point
- Use key material and meeting point to establish end-to-end encryption (link w/ Signal Protocol)

