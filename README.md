this is a clone of https://github.com/github/smimesign/tree/main/certstore, The primary change that was made was to add support for differnet stores available in windows. Like machine / service stores. 

## Example

```go
package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"

	"crypto/rand"
	"crypto/sha256"

	"github.com/github/smimesign/certstore"
)

func main() {
	sig, err := signWithMyIdentity("Ben Toews", "hello, world!")
	if err != nil {
		panic(err)
	}

	fmt.Println(hex.EncodeToString(sig))
}

func signWithMyIdentity(cn, msg string) ([]byte, error) {
	//specify which store to use for windows
	certstore.UseMachineStore()

	// Open the certificate store for use. This must be Close()'ed once you're
	// finished with the store and any identities it contains.

	store, err := certstore.Open()
	if err != nil {
		return nil, err
	}
	defer store.Close()

	// Get an Identity slice, containing every identity in the store. Each of
	// these must be Close()'ed when you're done with them.
	idents, err := store.Identities()
	if err != nil {
		return nil, err
	}

	// Iterate through the identities, looking for the one we want.
	var me certstore.Identity
	for _, ident := range idents {
		defer ident.Close()

		crt, errr := ident.Certificate()
		if errr != nil {
			return nil, errr
		}

		if crt.Subject.CommonName == "Ben Toews" {
			me = ident
		}
	}

	if me == nil {
		return nil, errors.New("Couldn't find my identity")
	}

	// Get a crypto.Signer for the identity.
	signer, err := me.Signer()
	if err != nil {
		return nil, err
	}

	// Digest and sign our message.
	digest := sha256.Sum256([]byte(msg))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

```
