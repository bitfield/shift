package shift

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
)

const BlockSize = 32

var ErrKeySize = errors.New("shift: invalid key size")

type shiftCipher struct {
	key [BlockSize]byte
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, fmt.Errorf("%w %d (must be %d)", ErrKeySize, len(key), BlockSize)
	}
	return &shiftCipher{
		key: [BlockSize]byte(key),
	}, nil
}

func (c shiftCipher) BlockSize() int {
	return BlockSize
}

func (c *shiftCipher) Encrypt(dst, src []byte) {
	for i, b := range src {
		dst[i] = b + c.key[i]
	}
}

func (c *shiftCipher) Decrypt(dst, src []byte) {
	for i, b := range src {
		dst[i] = b - c.key[i]
	}
}

type encrypter struct {
	block     cipher.Block
	blockSize int
}

func NewEncrypter(block cipher.Block) cipher.BlockMode {
	return &encrypter{
		block:     block,
		blockSize: block.BlockSize(),
	}
}

func (e encrypter) BlockSize() int {
	return e.blockSize
}

func (e *encrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("encrypter: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("encrypter: output smaller than input")
	}
	for len(src) > 0 {
		e.block.Encrypt(dst[:e.blockSize], src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

type decrypter struct {
	block     cipher.Block
	blockSize int
}

func NewDecrypter(block cipher.Block) cipher.BlockMode {
	return &decrypter{
		block:     block,
		blockSize: block.BlockSize(),
	}
}

func (e decrypter) BlockSize() int {
	return e.blockSize
}

func (e *decrypter) CryptBlocks(dst, src []byte) {
	for len(src) > 0 {
		e.block.Decrypt(dst[:e.blockSize], src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

func Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(n)}, n)
	return append(data, padding...)
}

func Unpad(data []byte, blockSize int) []byte {
	n := int(data[len(data)-1])
	return data[:len(data)-n]
}

// func Crack(ciphertext, crib []byte) (key []byte, err error) {
// 	plaintext := make([]byte, BlockSize)
// 	key = make([]byte, BlockSize)
// 	for keyPos := 0; keyPos < BlockSize; keyPos++ {
// 		for b := byte(0); b <= 255; b++ {
// 			result := ciphertext[keyPos] - b
// 			if result == crib[keyPos] {
// 				key[keyPos] = b
// 				break
// 			}
// 		}
// 		block, err := NewCipher(key)
// 		if err != nil {
// 			return nil, err
// 		}
// 		block.Decrypt(plaintext, ciphertext[:len(crib)])
// 		if bytes.Equal(crib, plaintext) {
// 			return key, nil
// 		}
// 	}
// 	return nil, errors.New("no key found")
// }
