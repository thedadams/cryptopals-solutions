package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"math/rand"
)

// PaddingOracleEncrypt encrypts one of 10 strings chosen at random and provides the
// cipher text and IV to the attacker.
func (c AESCBC) PaddingOracleEncrypt() ([]byte, []byte) {
	randomStrings := []string{"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"}
	s, _ := base64.StdEncoding.DecodeString(randomStrings[rand.Intn(10)])
	return c.Encrypt([]byte(s)), c.iv

}

// DecryptAndCheckPadding decrypts and consumes the cipher text and returns whether the padding is valid.
func (c AESCBC) DecryptAndCheckPadding(cipherText []byte) bool {
	_, err := isValidPadding(c.Decrypt(cipherText), c.block.BlockSize())
	return err == nil
}

// CTR implements CTR stream cipher mode.
type CTR struct {
	counter []byte
	nonce   []byte
	block   cipher.Block
	iv      []byte
}

// NewCTR is a helper function from creating CTR mode decrypter and encrypter.
func NewCTR(nonce, counter, key []byte) CTR {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if nonce == nil {
		nonce = make([]byte, block.BlockSize()/2)
	}
	if counter == nil {
		counter = make([]byte, block.BlockSize()/2)
	}
	return CTR{counter: counter, nonce: nonce, iv: make([]byte, block.BlockSize()), block: block}
}

// keystream generates the next block of keystream.
func (c CTR) keystream(nonceCounter []byte) []byte {
	mode := cipher.NewCBCEncrypter(c.block, c.iv)
	keystream := make([]byte, c.block.BlockSize())
	mode.CryptBlocks(keystream, nonceCounter)
	return keystream
}

// Encrypt encrypts using stream cipher mode.
func (c CTR) Encrypt(plainText []byte) []byte {
	counter := make([]byte, len(c.counter))
	copy(counter, c.counter)
	cipherText := make([]byte, 0)
	numBlocks := 0
	for len(plainText) > len(cipherText) {
		// Get the next keystream.
		keystream := c.keystream(append(c.nonce, counter...))
		// XOR and append to the ciphertext
		cipherText = append(cipherText, XORTwoByteStrings(keystream, plainText[numBlocks*c.block.BlockSize():])...)
		counter[0]++
		numBlocks++
	}
	return cipherText
}

// Decrypt decrypts using stream cipher mode.
func (c CTR) Decrypt(cipherText []byte) []byte {
	return c.Encrypt(cipherText)
}
