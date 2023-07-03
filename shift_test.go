package shift_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/bitfield/shift"
)

var testKey = bytes.Repeat([]byte{1}, shift.BlockSize)

var cipherCases = []struct {
	plaintext, ciphertext []byte
}{
	{
		plaintext:  []byte{0, 1, 2, 3, 4, 5},
		ciphertext: []byte{1, 2, 3, 4, 5, 6},
	},
}

func TestEncipherBlock(t *testing.T) {
	t.Parallel()
	for _, tc := range cipherCases {
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
	for _, tc := range cipherCases {
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
// 	for _, tc := range cipherCases {
// 		name := fmt.Sprintf("%s + %d = %s", tc.plaintext, testKey, tc.ciphertext)
// 		t.Run(name, func(t *testing.T) {
// 			got, err := shift.Crack(tc.ciphertext, tc.plaintext[:3])
// 			if err != nil {
// 				t.Fatal(err)
// 			}
// 			if !bytes.Equal(testKey, got) {
// 				t.Fatalf("want %d, got %d", testKey, got)
// 			}
// 		})
// 	}
// }

var padCases = []struct {
	name           string
	actual, padded []byte
}{
	{
		name:   "1 short of full block",
		actual: []byte{1, 2, 3},
		padded: []byte{1, 2, 3, 1},
	},
	{
		name:   "2 short of full block",
		actual: []byte{1, 2},
		padded: []byte{1, 2, 2, 2},
	},
	{
		name:   "3 short of full block",
		actual: []byte{1},
		padded: []byte{1, 3, 3, 3},
	},
	{
		name:   "full block",
		actual: []byte{1, 2, 3, 4},
		padded: []byte{1, 2, 3, 4, 4, 4, 4, 4},
	},
	{
		name:   "empty block",
		actual: []byte{},
		padded: []byte{4, 4, 4, 4},
	},
}

func TestPad(t *testing.T) {
	t.Parallel()
	blockSize := 4
	for _, tc := range padCases {
		t.Run(tc.name, func(t *testing.T) {
			got := shift.Pad(tc.actual, blockSize)
			if !bytes.Equal(tc.padded, got) {
				t.Errorf("want %v, got %v", tc.padded, got)
			}
		})
	}
}

func TestUnpad(t *testing.T) {
	t.Parallel()
	blockSize := 4
	for _, tc := range padCases {
		t.Run(tc.name, func(t *testing.T) {
			got := shift.Unpad(tc.padded, blockSize)
			if !bytes.Equal(tc.actual, got) {
				t.Errorf("want %v, got %v", tc.actual, got)
			}
		})
	}
}
