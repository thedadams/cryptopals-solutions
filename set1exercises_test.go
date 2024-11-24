package cryptopals

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

//go:embed set1exercise4input.txt
var exercise4input string

//go:embed set1exercise6input.txt
var exercise6input string

//go:embed set1exercise7input.txt
var exercise7input string

//go:embed set1exercise7output.txt
var exercise7output string

//go:embed set1exercise8input.txt
var exercise8input string

// Title: Convert hex to base64
func TestSet1Exercise1(t *testing.T) {
	output, err := hexStringTo64String("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Errorf("unexpected error for exercise 1: %s", err)
	}

	if output != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Errorf("unexpected output for exercise 1: %s", output)
	}
}

// Title: Fixed XOR
// Description: Write a function that takes two equal-length buffers and produces their XOR combination.
func TestSet1Exercise2(t *testing.T) {
	msg1, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		t.Errorf("unexpected error for exercise 2: %s", err)
	}

	msg2, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		t.Errorf("unexpected error for exercise 2: %s", err)
	}

	output := hex.EncodeToString(xorTwoByteStrings(msg1, msg2))
	if output != "746865206b696420646f6e277420706c6179" {
		t.Errorf("unexpected output for exercise 2: %s", output)
	}
}

// Title: Single-byte XOR cipher
// Description: The string has been XOR-ed against a single character. Find the key, decrypt the message.
func TestSet1Exercise3(t *testing.T) {
	toDecrypt, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		t.Errorf("unexpected error for exercise 3: %s", err)
	}

	decrypted, _, _ := decryptSingleCharXOR(toDecrypt, false)
	if string(decrypted) != "Cooking MC's like a pound of bacon" {
		t.Errorf("unexpected output for exercise 3: %s", decrypted)
	}
}

// Title: Detect single-character XOR
// One of the 60-character strings in this file has been encrypted by single-character XOR. Find it.
func TestSet1Exercise4(t *testing.T) {
	plainText, cipherText := findStringThatHasBeenEncrypted(exercise4input)
	if string(plainText) != "Now that the party is jumping\n" {
		t.Errorf("unexpected output for exercise 4: %s", plainText)
	}

	if encodedCipherText := hex.EncodeToString(cipherText); encodedCipherText != "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f" {
		t.Errorf("unexpected cipher text for exercise 4: %s", encodedCipherText)
	}
}

// Title: Implement repeating-key XOR
// Description: encrypt the string, under the key "ICE", using repeating-key XOR.
func TestSet1Exercise5(t *testing.T) {
	text, key := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE")
	output := hex.EncodeToString(repeatedKeyXOR(text, key))
	if output != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		t.Errorf("unexpected output for exercise 5: %s", output)
	}
}

// Title: Break repeating-key XOR
// Description: There's a file here. It's been base64'd after being encrypted with repeating-key XOR. decrypt it.
func TestSet1Exercise6(t *testing.T) {
	dst, err := base64.StdEncoding.DecodeString(exercise6input)
	if err != nil {
		t.Fatalf("unexpected error decoding input for exercise 6: %s", err)
	}

	_, key := breakRepeatingXOR(dst, guessKeySize(dst), false)
	if !bytes.Equal(key, []byte("Terminator X: Bring the noise")) {
		t.Errorf("unexpected key for exercise 6: %s", key)
	}
}

// Title: AES in ECB mode
// Description: The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key "YELLOW SUBMARINE". Decrypt it.
func TestSet1Exercise7(t *testing.T) {
	fileTextAsBytes, err := base64.StdEncoding.DecodeString(exercise7input)
	if err != nil {
		t.Fatalf("unexpected error decoding input for exercise 7: %s", err)
	}

	ecb, err := newAESECB([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Fatalf("unexpected error creating ECB: %s", err)
	}

	output, err := ecb.decrypt(fileTextAsBytes)
	if err != nil {
		t.Fatalf("unexpected error decrypting file: %s", err)
	}
	if string(bytes.TrimSpace(output)) != exercise7output {
		t.Errorf("unexpected output for exercise 7: %s", output)
	}
}

// Title: Detect AES in ECB mode
// Description: In this file are a bunch of hex-encoded ciphertexts. One of them has been encrypted with ECB. Detect it.
func TestSet1Exercise8(t *testing.T) {
	line := detectAESECB(exercise8input)
	if line != "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a" {
		t.Errorf("unexpected output for exercise 8: %s", line)
	}
}
