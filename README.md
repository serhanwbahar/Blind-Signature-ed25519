# Blind Signatures with ed25519

This repository contains a Go implementation of blind signatures using the elliptic curve algorithm Curve25519. Blind signatures allow for signing a message without the signer knowing the message's content, providing privacy and anonymity.

## Prerequisites

Before using this code, make sure you have Go installed on your system. You can download it from the [official Go website](https://golang.org/dl/).

## Dependencies

This implementation uses the `golang.org/x/crypto/curve25519` library for elliptic curve operations. To install the library, run the following command:

```
go get -u golang.org/x/crypto/curve25519
```

## Usage

To use this implementation, include the `blind_signatures.go` file in your project and import it as needed.

Here's a simple example of how to use the blind signatures implementation:

```
package main

import (
    "fmt"
    "blind-signatures" // Replace with the actual import path of the `blind_signatures.go` file
)

func main() {
    // Example usage of the blind signatures implementation
    message := []byte("Hello, World!")

    signerPrivateKey, signerPublicKey, _ := blindsignatures.GenerateKeyPair()
    userPrivateKey, userPublicKey, _ := blindsignatures.GenerateKeyPair()

    blindedMessage, unblinder, _ := blindsignatures.BlindMessage(message, signerPublicKey)
    signature, _ := blindsignatures.SignBlindedMessage(blindedMessage, signerPrivateKey)
    unblindedSignature := blindsignatures.UnblindSignature(signature, unblinder)

    valid := blindsignatures.VerifySignature(message, unblindedSignature, signerPublicKey, userPublicKey)
    fmt.Printf("Signature valid: %v\n", valid)
}
```

## Contributing

Contributions are welcome! If you'd like to report a bug, request a feature, or submit a pull request, please feel free to open an issue or create a pull request on this repository.

## Note

This implementation is  only experimental purposes and should be used at your own risk. The code is not audited.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more information.
