package blindsig

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func generateBlindingFactor() (*big.Int, error) {
	blindingFactor := make([]byte, ed25519.PrivateKeySize)
	_, err := rand.Read(blindingFactor)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(blindingFactor), nil
}

func blindMessage(message *big.Int, blindingFactor *big.Int) (*big.Int, error) {
	if message == nil || blindingFactor == nil {
		return nil, errors.New("message and blinding factor cannot be nil")
	}
	blindMessage := new(big.Int).Mul(message, blindingFactor)
	blindMessage.Mod(blindMessage, ed25519.P)
	return blindMessage, nil
}

func blindSignature(privateKey ed25519.PrivateKey, blindMessage *big.Int) (*big.Int, error) {
	if privateKey == nil || blindMessage == nil {
		return nil, errors.New("private key and blind message cannot be nil")
	}
	sig := ed25519.Sign(privateKey, blindMessage.Bytes())
	return new(big.Int).SetBytes(sig), nil
}

func unblindSignature(blindSig *big.Int, blindingFactor *big.Int) (*big.Int, error) {
	if blindSig == nil || blindingFactor == nil {
		return nil, errors.New("blind signature and blinding factor cannot be nil")
	}
	sig := new(big.Int).Mul(blindSig, new(big.Int).ModInverse(blindingFactor, ed25519.P))
	sig.Mod(sig, ed25519.P)
	return sig, nil
}

func main() {
	// Generate a private key for signing
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}

	// Generate a random message
	messageBytes := make([]byte, 32)
	_, err = rand.Read(messageBytes)
	if err != nil {
		fmt.Println("Error generating random message:", err)
		return
	}
	message := new(big.Int).SetBytes(messageBytes)
	fmt.Println("Message: ", message)

	// Generate a blinding factor
	blindingFactor, err := generateBlindingFactor()
	if err != nil {
		fmt.Println("Error generating blinding factor:", err)
		return
	}

	// Create a blind message
	blindMsg, err := blindMessage(message, blindingFactor)
	if err != nil {
		fmt.Println("Error blinding message:", err)
		return
	}
	fmt.Println("Blind message: ", blindMsg)

	// Create a blind signature
	blindSig, err := blindSignature(privateKey, blindMsg)
	if err != nil {
		fmt.Println("Error creating blind signature:", err)
		return
	}
	fmt.Println("Blind signature: ", blindSig)

	// Unblind the signature
	sig, err := unblindSignature(blindSig, blindingFactor)
	if err != nil {
		fmt.Println("Error unblinding signature:", err)
		return
	}
	fmt.Println("Unblinded signature: ", sig)

	// Verify the signature
	isValid := ed25519.Verify(publicKey, message.Bytes(), sig.Bytes())
	fmt.Println("Signature is valid: ", isValid)
}
