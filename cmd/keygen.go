package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"hash"
)

func NewKeyGen(hashType hash.Hash, decryptOps *rsa.OAEPOptions, size int) (*Encrypt, *Decrypt) {
	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		panic(err)
	}

	publicKey := privateKey.PublicKey
	encrypt := NewEncrypt(hashType, publicKey)
	decrypt := NewDecrypt(hashType, decryptOps, *privateKey)

	return encrypt, decrypt
}
