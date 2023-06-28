package shift_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/bitfield/shift"
)

var testKey = bytes.Repeat([]byte{1}, shift.BlockSize)

var cases = []struct {
	plaintext, ciphertext []byte
}{
	{
		plaintext:  []byte{0, 1, 2, 3, 4, 5},
		ciphertext: []byte{1, 2, 3, 4, 5, 6},
	},
}

func TestEncipherBlock(t *testing.T) {
	t.Parallel()
	for _, tc := range cases {
		name := fmt.Sprintf("%v + %s = %v", tc.plaintext, testKey, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			block, err := shift.NewCipher(testKey)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(tc.plaintext))
			block.Encrypt(got, tc.plaintext)
			if !bytes.Equal(tc.ciphertext, got) {
				t.Errorf("want %q, got %q", tc.ciphertext, got)
			}
		})
	}
}

func TestDecipherBlock(t *testing.T) {
	t.Parallel()
	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		name := fmt.Sprintf("%v - %s = %v", tc.ciphertext, testKey, tc.plaintext)
		t.Run(name, func(t *testing.T) {
			got := make([]byte, len(tc.ciphertext))
			block.Decrypt(got, tc.ciphertext)
			if !bytes.Equal(tc.plaintext, got) {
				t.Errorf("want %q, got %q", tc.plaintext, got)
			}
		})
	}
}

func TestNewCipher_GivesErrKeySizeForInvalidKey(t *testing.T) {
	t.Parallel()
	_, err := shift.NewCipher([]byte{})
	if !errors.Is(err, shift.ErrKeySize) {
		t.Errorf("want ErrKeySize, got %v", err)
	}
}

func TestNewCipher_GivesNoErrorForValidKey(t *testing.T) {
	t.Parallel()
	_, err := shift.NewCipher(make([]byte, shift.BlockSize))
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
}

func TestBlockSize_ReturnsBlockSize(t *testing.T) {
	t.Parallel()
	block, err := shift.NewCipher(make([]byte, shift.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	want := shift.BlockSize
	got := block.BlockSize()
	if want != got {
		t.Errorf("want %d, got %d", want, got)
	}
}

func TestEncrypterCorrectlyEnciphersPlaintext(t *testing.T) {
	t.Parallel()
	plaintext := []byte("This message is exactly 32 bytes")
	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	enc := shift.NewEncrypter(block)
	want := []byte("Uijt!nfttbhf!jt!fybdumz!43!czuft")
	got := make([]byte, 32)
	enc.CryptBlocks(got, plaintext)
	if !bytes.Equal(want, got) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestDecrypterCryptBlocks(t *testing.T) {
	t.Parallel()
	ciphertext := []byte("Uijt!nfttbhf!jt!fybdumz!43!czuft")
	block, err := shift.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	dec := shift.NewDecrypter(block)
	want := []byte("This message is exactly 32 bytes")
	got := make([]byte, 32)
	dec.CryptBlocks(got, ciphertext)
	if !bytes.Equal(want, got) {
		t.Errorf("want %v, got %v", want, got)
	}
}

// func TestCrack(t *testing.T) {
// 	t.Parallel()
// 	for _, tc := range cases {
// 		name := fmt.Sprintf("%s + %d = %s", tc.plaintext, tc.key, tc.ciphertext)
// 		t.Run(name, func(t *testing.T) {
// 			got, err := shift.Crack(tc.ciphertext, tc.plaintext[:3])
// 			if err != nil {
// 				t.Fatal(err)
// 			}
// 			if !bytes.Equal(tc.key, got) {
// 				t.Fatalf("want %d, got %d", tc.key, got)
// 			}
// 		})
// 	}
// }
