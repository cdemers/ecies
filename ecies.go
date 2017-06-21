package ecies

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeys generates and returns two 32 bytes ECC keys
func GenerateKeys() (encKey, decKey [32]byte, err error) {

	if _, err := rand.Read(decKey[:]); err != nil {
		err = fmt.Errorf("could not generate decKey: %v", err)
		return encKey, decKey, err
	}

	decKey[0] &= 248
	decKey[31] &= 127
	decKey[31] |= 64

	curve25519.ScalarBaseMult(&encKey, &decKey)

	return encKey, decKey, nil
}

// Encrypt returns a Curve25519 encrypted byte array
func Encrypt(plainText []byte, publicKey [32]byte) ([]byte, error) {
	var r, R, S, K_B [32]byte

	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	r[0] &= 248
	r[31] &= 127
	r[31] |= 64

	// copy(K_B, publicKey)
	K_B = publicKey

	curve25519.ScalarBaseMult(&R, &r)
	curve25519.ScalarMult(&S, &r, &K_B)
	k_E := sha512.Sum512(S[:])

	cipherText := make([]byte, 32+len(plainText))
	copy(cipherText[:32], R[:])
	for i := 0; i < len(plainText); i++ {
		cipherText[32+i] = plainText[i] ^ k_E[i]
	}

	return cipherText, nil
}

// Decrypt returns a Curve25519 decrypted byte array
func Decrypt(cipherText []byte, privateKey [32]byte) ([]byte, error) {
	var R, S, k_B [32]byte
	copy(R[:], cipherText[:32])
	// copy(k_B[:], privateKey)
	k_B = privateKey

	curve25519.ScalarMult(&S, &k_B, &R)

	k_E := sha512.Sum512(S[:])

	plainText := make([]byte, len(cipherText)-32)
	for i := 0; i < len(plainText); i++ {
		plainText[i] = cipherText[32+i] ^ k_E[i]
	}

	return plainText, nil
}
