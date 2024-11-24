package cryptopals

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"math"
	"strings"
	"testing"
)

//go:embed set3exercise19input.txt
var set3exercise19input string

//go:embed set3exercise20input.txt
var set3exercise20input string

// Title: The CBC padding oracle
// Description: decrypt strings encrypted in CBC mode by checking the padding on an altered ciphertext.
func TestExercise17(t *testing.T) {
	for _, s := range []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	} {
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Errorf("unexpected error deocding string for exercise 17: %s", err)
		}

		// Both parameters being nil here means we will get a random key and iv.
		c, err := newAESCBC(nil, nil)
		if err != nil {
			t.Fatalf("unexpected error creating CBC: %s", err)
		}

		if decrypted := decryptCBCPaddingOracle(c.encrypt(decoded), c.iv, c.decryptAndCheckPadding); !bytes.Equal(decrypted, decoded) {
			t.Errorf("unexpected output for exercise 17: %s != %s", decrypted, decrypted)
		}
	}
}

// Title: Implement ctr, the stream cipher mode
// Description: implement ctr
func TestExercise18(t *testing.T) {
	cipherText, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		t.Fatalf("unexpected error decoding input for exercise 18: %s", err)
	}

	if output := string(newCTR(nil, nil, []byte("YELLOW SUBMARINE")).decrypt(cipherText)); output != "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby " {
		t.Errorf("unexpected output for exercise 18: %s", output)
	}
}

// Title: Break fixed-nonce ctr mode using substitutions.
// Description: Attack this cryptosystem piecemeal: guess letters, use expected English language frequency to validate guesses, catch common English trigrams, and so on.
// I misunderstood what this problem wanted me to do. I finished it as Exercise 20 wanted us to do without realizing it.
func TestExercise19(t *testing.T) {
	ctrMode := newCTR(nil, nil, nil)
	var firstBlocksOfCipherText []byte
	for _, text := range strings.Split(set3exercise19input, "\n") {
		if text == "" {
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			t.Errorf("unexpected error decoding string for exercise 19: %s", err)
		}

		firstBlocksOfCipherText = append(firstBlocksOfCipherText, ctrMode.encrypt(decoded)[:ctrMode.block.BlockSize()]...)
	}

	_, key := breakRepeatingXOR(firstBlocksOfCipherText, 16, true)
	if !bytes.Equal(key[:ctrMode.block.BlockSize()], ctrMode.keystream(make([]byte, ctrMode.block.BlockSize()))) {
		t.Errorf("unexpected output for exercise 19")
	}
}

// Title: Break fixed-nonce ctr statistically
// Description: Treat the collection of ciphertexts the same way you would repeating-key XOR.
func TestExercise20(t *testing.T) {
	ctrMode := newCTR(nil, nil, nil)
	shortestCipherTextLength := math.MaxInt
	var cipherTexts [][]byte
	for _, text := range strings.Split(set3exercise20input, "\n") {
		if text == "" {
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			t.Errorf("unexpected error decoding string for exercise 19: %s", err)
		}

		cipherTexts = append(cipherTexts, ctrMode.encrypt(decoded))
		if len(cipherTexts[len(cipherTexts)-1]) < shortestCipherTextLength {
			shortestCipherTextLength = len(cipherTexts[len(cipherTexts)-1])
		}
	}

	cipherTextBlocks := make([]byte, 0, len(cipherTexts)*shortestCipherTextLength)
	for _, cipherText := range cipherTexts {
		cipherTextBlocks = append(cipherTextBlocks, cipherText[:shortestCipherTextLength]...)
	}

	_, key := breakRepeatingXOR(cipherTextBlocks, shortestCipherTextLength, true)
	if !bytes.Equal(key[:ctrMode.block.BlockSize()], ctrMode.keystream(make([]byte, ctrMode.block.BlockSize()))) {
		t.Errorf("unexpected output for exercise 19")
	}
}
