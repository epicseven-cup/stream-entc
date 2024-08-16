package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"hash"
)

type Encrypt struct {
	hashType  hash.Hash
	publicKey rsa.PublicKey
	incoming  chan []byte
	exit      chan bool
}

func NewEncrypt(hashType hash.Hash, publicKey rsa.PublicKey) *Encrypt {
	return &Encrypt{
		hashType:  hashType,
		publicKey: publicKey,
		incoming:  make(chan []byte),
		exit:      make(chan bool),
	}
}

func (encrypt *Encrypt) InputStream(data []byte) {
	encrypt.incoming <- data
}

func (encrypt *Encrypt) EncryptBytes(data []byte) []byte {
	encrypted, err := rsa.EncryptOAEP(
		encrypt.hashType,
		rand.Reader,
		&encrypt.publicKey,
		data,
		nil,
	)

	if err != nil {
		panic(err)
	}
	return encrypted
}

func (encrypt *Encrypt) EncryptStream(outgoing chan []byte) {
	for {
		select {
		case input := <-encrypt.incoming:
			encrypted := encrypt.EncryptBytes(input)
			// Send the bytes to the output stream
			outgoing <- encrypted
		case <-encrypt.exit:
			return
		}
	}
}

func (encrypt *Encrypt) ExitStream() {
	encrypt.exit <- true
}
