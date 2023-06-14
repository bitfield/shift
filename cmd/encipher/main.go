package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bitfield/cipher"
)

func main() {
	key := flag.Int("key", 1, "shift value")
	flag.Parse()
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(cipher.Encipher(data, byte(*key)))
}
