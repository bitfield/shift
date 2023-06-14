package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bitfield/cipher"
)

func main() {
	crib := flag.String("crib", "", "crib text")
	flag.Parse()
	if *crib == "" {
		fmt.Fprintln(os.Stderr, "Please specify a crib text with -crib")
		os.Exit(1)
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	key, err := cipher.Crack(data, []byte(*crib))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(cipher.Decipher(data, byte(key)))
}
