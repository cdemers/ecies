package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/cdemers/ecies"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	verbose = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()

	generateCommand = kingpin.Command("generate", "Generate a key pair.").Alias("gen")
	encryptCommand  = kingpin.Command("encrypt", "Encrypt using the provided encryption key.").Alias("enc")
	encKey          = encryptCommand.Arg("key", "The encryption key.").Required().Envar("EC_EKEY").String()
	decryptCommand  = kingpin.Command("decrypt", "Decrypt using the provided decryption key.").Alias("dec")
	decKey          = decryptCommand.Arg("key", "The decryption key.").Required().Envar("EC_DKEY").String()
)

func generate() (err error) {
	encKey, decKey, err := ecies.GenerateKeys()
	if err != nil {
		return err
	}
	fmt.Printf("export EC_EKEY='%v'\n", base64.StdEncoding.EncodeToString(encKey[:]))
	fmt.Printf("export EC_DKEY='%v'\n", base64.StdEncoding.EncodeToString(decKey[:]))

	return nil
}

func readStdIn() (input []byte, err error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		input, overflow, err := reader.ReadLine()
		if err == io.EOF {
			return nil, fmt.Errorf("no data provided for input")
		}
		if err != nil {
			return nil, err
		}
		if overflow {
			return nil, fmt.Errorf("STDIN buffer overflow")
		}

		return input, nil
	}
}

func writeStdOut(output []byte) {
	f := bufio.NewWriter(os.Stdout)
	defer f.Flush()
	f.Write(output)
}

func encrypt(input []byte, key [32]byte) (output []byte, err error) {
	output, err = ecies.Encrypt(input, key)
	return output, err
}

func decrypt(input []byte, key [32]byte) (output []byte, err error) {
	output, err = ecies.Decrypt(input, key)
	return output, err
}

func main() {
	kingpin.UsageTemplate(kingpin.CompactUsageTemplate).Version("0.2b").Author("Charle Demers")
	kingpin.Parse()

	switch kingpin.Parse() {
	case "generate":
		kingpin.FatalIfError(generate(), "Keys generation failed.")

	case "decrypt":
		input, err := readStdIn()
		if err != nil {
			kingpin.Fatalf("fatal error reading STDIN: %s", err)
		}

		k, err := base64.StdEncoding.DecodeString(*decKey)
		if err != nil {
			kingpin.Fatalf("fatal error decoding key: %s", err)
		}

		var key [32]byte
		copy(key[:], k)
		output, err := decrypt(input, key)
		if err != nil {
			kingpin.Fatalf("fatal error decrypting: %s", err)
		}

		writeStdOut(output)

	case "encrypt":
		input, err := readStdIn()

		if err != nil {
			kingpin.Fatalf("fatal error reading STDIN: %s", err)
		}

		k, err := base64.StdEncoding.DecodeString(*encKey)
		if err != nil {
			kingpin.Fatalf("fatal error decoding key: %s", err)
		}

		var key [32]byte
		copy(key[:], k)
		output, err := encrypt(input, key)
		if err != nil {
			kingpin.Fatalf("fatal error encrypting: %s", err)
		}
		writeStdOut(output)
		// fmt.Println(base64.StdEncoding.EncodeToString(output))

	default:
		fmt.Printf("%#v\n", kingpin.Parse())
	}

}
