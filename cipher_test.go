package cipher_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/bitfield/cipher"
)

var cases = []struct {
	key                   []byte
	plaintext, ciphertext []byte
}{
	{
		key:        []byte{1},
		plaintext:  []byte("HAL"),
		ciphertext: []byte("IBM"),
	},
	{
		key:        []byte{2},
		plaintext:  []byte("SPEC"),
		ciphertext: []byte("URGE"),
	},
	{
		key:        []byte{3},
		plaintext:  []byte("PERK"),
		ciphertext: []byte("SHUN"),
	},
	{
		key:        []byte{4},
		plaintext:  []byte("GEL"),
		ciphertext: []byte("KIP"),
	},
	{
		key:        []byte{7},
		plaintext:  []byte("CHEER"),
		ciphertext: []byte("JOLLY"),
	},
	{
		key:        []byte{10},
		plaintext:  []byte("BEEF"),
		ciphertext: []byte("LOOP"),
	},
	{
		key:        []byte{1, 2},
		plaintext:  []byte{0, 1, 2},
		ciphertext: []byte{1, 3, 3},
	},
	{
		key:        []byte{1, 2, 3},
		plaintext:  []byte{0, 0, 0},
		ciphertext: []byte{1, 2, 3},
	},
	{
		key:        []byte{1, 2, 3},
		plaintext:  []byte{255, 255, 255, 255, 255},
		ciphertext: []byte{0, 1, 2, 0, 1},
	},
}

func TestEncipher(t *testing.T) {
	t.Parallel()
	for _, tc := range cases {
		name := fmt.Sprintf("%s + %d = %s", tc.plaintext, tc.key, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			got := cipher.Encipher(tc.plaintext, tc.key)
			if !bytes.Equal(tc.ciphertext, got) {
				t.Errorf("want %q, got %q", tc.ciphertext, got)
			}
		})
	}
}

func TestDecipher(t *testing.T) {
	t.Parallel()
	for _, tc := range cases {
		name := fmt.Sprintf("%s - %d = %s", tc.ciphertext, tc.key, tc.plaintext)
		t.Run(name, func(t *testing.T) {
			got := cipher.Decipher(tc.ciphertext, tc.key)
			if !bytes.Equal(tc.plaintext, got) {
				t.Errorf("want %q, got %q", tc.plaintext, got)
			}
		})
	}
}

func BenchmarkEncipher(b *testing.B) {
	ciphertext := []byte("These pretzels are making me thirsty")
	key := []byte("Hello, Newman")
	for i := 0; i < b.N; i++ {
		cipher.Encipher(ciphertext, key)
	}
}

func TestCrack(t *testing.T) {
	t.Parallel()
	for _, tc := range cases {
		name := fmt.Sprintf("%s + %d = %s", tc.plaintext, tc.key, tc.ciphertext)
		t.Run(name, func(t *testing.T) {
			got, err := cipher.Crack(tc.ciphertext, tc.plaintext[:3])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tc.key, got) {
				t.Fatalf("want %d, got %d", tc.key, got)
			}
		})
	}
}

func BenchmarkCrack(b *testing.B) {
	plaintext := []byte("These pretzels are making me thirsty")
	key := []byte("Hello, Newman")
	ciphertext := cipher.Encipher(plaintext, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Crack(ciphertext, plaintext[:3])
	}
}
