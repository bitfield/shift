package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bitfield/cipher"
)

func main() {
	key := flag.String("key", "01", "key in hexadecimal (for example 'FF')")
	flag.Parse()
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	keyBytes, err := hex.DecodeString(*key)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(cipher.Decipher(data, keyBytes))
}
