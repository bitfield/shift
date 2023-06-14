package cipher

import (
	"bytes"
	"errors"
)

func Encipher(plaintext []byte, key byte) (ciphertext []byte) {
	ciphertext = make([]byte, len(plaintext))
	for i, b := range plaintext {
		ciphertext[i] = b + key
	}
	return ciphertext
}

func Decipher(ciphertext []byte, key byte) (plaintext []byte) {
	return Encipher(ciphertext, -key)
}

func Crack(ciphertext, crib []byte) (key byte, err error) {
	for key = 0; key <= 255; key++ {
		result := Decipher(ciphertext[:len(crib)], key)
		if bytes.Equal(result, crib) {
			return key, nil
		}
	}
	return 0, errors.New("no key found")
}
