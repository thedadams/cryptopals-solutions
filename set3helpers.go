package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func decryptCBCPaddingOracle(cipherText, iv []byte, decryptAndCheckPadding func([]byte) bool) []byte {
	var (
		plainText          []byte
		cipherTextToChange []byte
	)
	for len(cipherText) > 0 {
		thisBlock := make([]byte, aes.BlockSize)
		for i := 1; i <= len(thisBlock); i++ {
			// XOR with the appropriate padding bytes.
			xorTwoByteStringsInPlace(thisBlock[len(thisBlock)-i:], bytes.Repeat([]byte{byte(i)}, i))
			// If we're decrypting the last block, then we need to change the IV.
			if len(cipherText) <= aes.BlockSize {
				cipherTextToChange = iv[:]
			} else {
				// Otherwise, we get the appropriate chunk of cipher text.
				cipherTextToChange = cipherText[len(cipherText)-2*aes.BlockSize : len(cipherText)-aes.BlockSize]
			}
			for j := 255; j >= 0; j-- {
				// Check this byte.
				thisBlock[len(thisBlock)-i] ^= byte(j)
				// XOR, check padding, and XOR back.
				xorTwoByteStringsInPlace(cipherTextToChange, thisBlock)
				validPadding := decryptAndCheckPadding(cipherText)
				xorTwoByteStringsInPlace(cipherTextToChange, thisBlock)
				// If we have the right padding, then we have the right byte.
				if validPadding {
					break
				}
				// Undo the XOR to try another.
				thisBlock[len(thisBlock)-i] ^= byte(j)
			}
			// Undo the XOR padding because we are done with this byte.
			xorTwoByteStringsInPlace(thisBlock[len(thisBlock)-i:], bytes.Repeat([]byte{byte(i)}, i))
		}
		// We're done with this check of cipher text so we append the plain text to it.
		// We're doing this from last chunk to first, so we append backwards.
		plainText = append(thisBlock, plainText...)
		// Shorten the cipher text so we can check padding easily.
		cipherText = cipherText[:len(cipherText)-aes.BlockSize]
	}

	return removePadding(plainText)
}

// decryptAndCheckPadding decrypts and consumes the cipher text and returns whether the padding is valid.
func (c aescbc) decryptAndCheckPadding(cipherText []byte) bool {
	decryptedText, err := c.decrypt(cipherText)
	if err != nil {
		return false
	}

	_, err = isValidPadding(decryptedText, c.block.BlockSize())
	return err == nil
}

// ctr implements ctr stream cipher mode.
type ctr struct {
	counter []byte
	nonce   []byte
	block   cipher.Block
	key     []byte
	iv      []byte
}

// newCTR is a helper function from creating ctr mode decrypter and encrypter.
func newCTR(nonce, counter, key []byte) ctr {
	if key == nil {
		key = randomBytes(aes.BlockSize)
	}
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
	return ctr{counter: counter, nonce: nonce, iv: make([]byte, block.BlockSize()), key: key, block: block}
}

// keystream generates the next block of keystream.
func (c ctr) keystream(nonceCounter []byte) []byte {
	mode := cipher.NewCBCEncrypter(c.block, c.iv)
	keystream := make([]byte, c.block.BlockSize())
	mode.CryptBlocks(keystream, nonceCounter)
	return keystream
}

// encrypt encrypts using stream cipher mode.
func (c ctr) encrypt(plainText []byte) []byte {
	counter := make([]byte, len(c.counter))
	copy(counter, c.counter)
	cipherText := make([]byte, 0)
	numBlocks := 0
	for len(plainText) > len(cipherText) {
		// Get the next keystream.
		keystream := c.keystream(append(c.nonce, counter...))
		// XOR and append to the ciphertext
		cipherText = append(cipherText, xorTwoByteStrings(keystream, plainText[numBlocks*c.block.BlockSize():])...)
		counter[0]++
		numBlocks++
	}
	return cipherText
}

// decrypt decrypts using stream cipher mode.
func (c ctr) decrypt(cipherText []byte) []byte {
	return c.encrypt(cipherText)
}

// xorTwoByteStringsInPlace does exactly as it sounds, but modifies the first argument.
func xorTwoByteStringsInPlace(s1, s2 []byte) {
	length := len(s1)
	if length > len(s2) {
		length = len(s2)
	}
	for i := 0; i < length; i++ {
		s1[i] = s1[i] ^ s2[i]
	}
}
