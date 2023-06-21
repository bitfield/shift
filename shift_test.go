package shift_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/bitfield/shift"
)

var cases = []struct {
	key                   string
	plaintext, ciphertext []byte
}{
	{
		key:        "0101010101010101010101010101010101010101010101010101010101010101",
		plaintext:  []byte{0, 1, 2, 3, 4, 5},
		ciphertext: []byte{1, 2, 3, 4, 5, 6},
	},
}

func TestEncipherBlock(t *testing.T) {
	t.Parallel()
	for _, tc := range cases {
		name := fmt.Sprintf("%v + %s = %v", tc.plaintext, tc.key, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			block, err := shift.NewCipher(key)
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
	for _, tc := range cases {
		name := fmt.Sprintf("%v - %s = %v", tc.ciphertext, tc.key, tc.plaintext)
		t.Run(name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			block, err := shift.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(tc.ciphertext))
			block.Decrypt(got, tc.ciphertext)
			if !bytes.Equal(tc.plaintext, got) {
				t.Errorf("want %q, got %q", tc.plaintext, got)
			}
		})
	}
}

func TestNewCipher_ErrorsIfKeyDoesNotMatchBlockSize(t *testing.T) {
	t.Parallel()
	_, err := shift.NewCipher([]byte{})
	if !errors.Is(err, shift.ErrKeySize) {
		t.Errorf("want ErrKeySize, got %v", err)
	}
}

func TestNewCipher_GivesNoErrorIfKeyMatchesBlockSize(t *testing.T) {
	t.Parallel()
	_, err := shift.NewCipher(make([]byte, shift.BlockSize))
	if err != nil {
		t.Errorf("want no error, got %v", err)
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

func TestEncrypterCryptBlocks(t *testing.T) {
	t.Parallel()
	plaintext := []byte("This message is exactly 32 bytes")
	key, err := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	if err != nil {
		t.Fatal(err)
	}
	block, err := shift.NewCipher(key)
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
	key, err := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	if err != nil {
		t.Fatal(err)
	}
	block, err := shift.NewCipher(key)
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
