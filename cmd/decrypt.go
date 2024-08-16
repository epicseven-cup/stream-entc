package cmd

import (
	"crypto"
	"crypto/rsa"
	"hash"
)

type Decrypt struct {
	hashType   hash.Hash
	privateKey rsa.PrivateKey
	decryptOps crypto.DecrypterOpts
	incoming   chan []byte
	exit       chan bool
}

func NewDecrypt(hashType hash.Hash, decryptOps crypto.DecrypterOpts, privateKey rsa.PrivateKey) *Decrypt {
	return &Decrypt{
		hashType:   hashType,
		privateKey: privateKey,
		decryptOps: decryptOps,
		incoming:   make(chan []byte),
		exit:       make(chan bool),
	}
}

func (decrypt *Decrypt) InputStream(data []byte) {
	decrypt.incoming <- data
}

func (decrypt *Decrypt) DecryptBytes(data []byte) []byte {
	decrypted, err := decrypt.privateKey.Decrypt(nil, data, decrypt.decryptOps)
	if err != nil {
		panic(err)
	}
	return decrypted
}

func (decrypt *Decrypt) DecryptStream(outgoing chan []byte) {
	for {
		select {
		case input := <-decrypt.incoming:
			decrypted := decrypt.DecryptBytes(input)
			outgoing <- decrypted
		case <-decrypt.exit:
			return
		}
	}
}

func (decrypt *Decrypt) ExitStream() {
	decrypt.exit <- true
}
