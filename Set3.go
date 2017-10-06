package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
)

// Exercise17 performs the corresponding exercise from cryptopals.
// Title: The CBC padding oracle
// Description: Decrypt strings encrypted in CBC mode by checking the padding on an altered ciphertext.
func Exercise17() {
	// Get the CBC encrypter and decrypter.
	// The key and iv are both nil so they will be random.
	c := NewAESCBC(nil, nil)
	cipherText, _ := c.PaddingOracleEncrypt()
	// Store the decrypted text so we can check that the algorithm works
	decryptForCheck := c.Decrypt(cipherText)
	// Number of blocks we need to find.
	numBlocks := len(cipherText) / aes.BlockSize
	blocksFound := 0
	// A place to store the plaintext as we decrypt it.
	plainText := make([]byte, 0)
	// A place to store the chunk of ciphertext or iv that we are changing.
	var cipherTextToChange []byte
	for blocksFound < numBlocks {
		thisBlock := make([]byte, aes.BlockSize)
		for i := 1; i <= len(thisBlock); i++ {
			// XOR with the appropriate padding bytes.
			XORTwoByteStringsInPlace(thisBlock[len(thisBlock)-i:len(thisBlock)], bytes.Repeat([]byte{byte(i)}, i))
			// If we are decrypting the last block, then we need to change the IV.
			if blocksFound == numBlocks-1 {
				cipherTextToChange = c.iv[:]
			} else {
				// Otherwise we get the appropriate chunk of cipher text.
				cipherTextToChange = cipherText[len(cipherText)-2*aes.BlockSize : len(cipherText)-aes.BlockSize]
			}
			for j := 255; j >= 0; j-- {
				// Check this bytes.
				thisBlock[len(thisBlock)-i] ^= byte(j)
				// XOR, check padding, and XOR back.
				XORTwoByteStringsInPlace(cipherTextToChange, thisBlock)
				validPadding := c.DecryptAndCheckPadding(cipherText)
				XORTwoByteStringsInPlace(cipherTextToChange, thisBlock)
				// If we have the right padding, then we have the right byte.
				if validPadding {
					break
				}
				// Undo the XOR to try another.
				thisBlock[len(thisBlock)-i] ^= byte(j)
			}
			// Undo the XOR padding because we are done with this byte.
			XORTwoByteStringsInPlace(thisBlock[len(thisBlock)-i:len(thisBlock)], bytes.Repeat([]byte{byte(i)}, i))
		}
		// We are done with this check of cipher text so we append the plain text to it.
		// We are doing this from last chunk to first so we append backwards.
		plainText = append(thisBlock, plainText...)
		// Shorten the cipher text so we can check padding easily.
		cipherText = cipherText[:len(cipherText)-aes.BlockSize]
		blocksFound++
	}
	// Print to check that we completed this correctly.
	// If we did, this should print true.
	fmt.Println(bytes.Equal(plainText, decryptForCheck))
}

// Exercise18 performs the corresponding exercise from cryptopals.
// Title: Implement CTR, the stream cipher mode
// Description: implement CTR
func Exercise18() {
	cipherText, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	c := NewCTR(nil, nil, []byte("YELLOW SUBMARINE"))
	fmt.Println(string(c.Decrypt(cipherText)))
}
