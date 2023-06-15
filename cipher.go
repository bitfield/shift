package cipher

import (
	"bytes"
	"errors"
)

const MaxKeyLen = 32

func Encipher(plaintext []byte, key []byte) (ciphertext []byte) {
	ciphertext = make([]byte, len(plaintext))
	for i, b := range plaintext {
		ciphertext[i] = b + key[i%len(key)]
	}
	return ciphertext
}

func Decipher(ciphertext []byte, key []byte) (plaintext []byte) {
	plaintext = make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		plaintext[i] = b - key[i%len(key)]
	}
	return plaintext
}

func Crack(ciphertext, crib []byte) (key []byte, err error) {
	var b byte
	for keyPos := 0; keyPos < MaxKeyLen && keyPos < len(ciphertext); keyPos++ {
		for b = 0; b <= 255; b++ {
			result := ciphertext[keyPos] - b
			if result == crib[keyPos] {
				key = append(key, b)
				break
			}
		}
		if bytes.Equal(crib, Decipher(ciphertext[:len(crib)], key)) {
			return key, nil
		}
	}
	return nil, errors.New("no key found")
}
