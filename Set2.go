package crypto

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

// Exercise9 performs the corresponding exercise from cryptopals.
// Title: Implement PKCS#7 padding
//Description: Pad any block to a specific block length, by appending the number of bytes of padding to the end of the block.
func Exercise9() []byte {
	return PadToMultipleNBytes([]byte("YELLOW SUBMARINE"), 20)
}

// Exercise10 performs the corresponding exercise from cryptopals.
// Title: Implement CBC mode
// Description: Implement CBC mode by hand by taking the ECB function you wrote earlier.
// The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
func Exercise10(filename string) []byte {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, aes.BlockSize)
	e := NewAESCBC(key, iv)
	fileText, _ := ioutil.ReadFile("Set2_10.txt")
	fileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(fileText))
	return e.Decrypt(fileTextAsBytes)
}

// Exercise11 performs the corresponding exercise from cryptopals
// Title: An ECB/CBC detection oracle
// Description: Detect the block cipher mode the function is using each time.
// You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
func Exercise11() {
	for i := 0; i < 10; i++ {
		GuessedCorrectly := DetectRandomEBCCBCMode()
		fmt.Print(GuessedCorrectly)
	}
}

// Exercise12 performs the corresponding exercise from cryptopals
// Title: Byte-at-a-time ECB decryption (Simple)
// Description: What you have now is a function that produces: AES-128-ECB(your-string || unknown-string, random-key)
// It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
func Exercise12(unknownString []byte) []byte {
	e := NewECBEncryptionOracle(make([]byte, 0), unknownString)
	blockSize := e.GuessBlockSizeOfCipher()
	blocksFound := 0
	knownPartOfString := make([]byte, 0)
	numBlocksToFind := len(e.Encrypt(nil)) / blockSize
	for blocksFound < numBlocksToFind {
		// Following directions, we create a repeated string one smaller than the block size.
		identicalString := bytes.Repeat([]byte{byte(0)}, blockSize-1)
		// Now we find the byte that will take the empty spot in the repeated string.
		// We build thisBlock byte by byte.
		thisBlock := make([]byte, 0)
		for j := 0; j < blockSize; j++ {
			thisBlock = append(thisBlock, byte(0))
			for i := 0; i < 512; i++ {
				thisBlock[j] = byte(i)
				thisTest := e.Encrypt(append(append(append(identicalString, knownPartOfString...), thisBlock...), identicalString[:blockSize-j-1]...))
				// Test the appropriate encrypted blocks to see if they are the same.
				// If they are, then we have the next byte.
				if bytes.Equal(thisTest[:blockSize*(blocksFound+1)], thisTest[blockSize*(blocksFound+1):2*(blockSize*(blocksFound+1))]) {
					// If we haven't completed this block, we append to thisBlock, shorten the identicalString
					// and keep going.
					if blockSize-j-2 > -1 {
						identicalString = identicalString[:blockSize-j-2]
					}
					break
				}
			}
		}
		// At this point, we know the next block so we add it to the end of the known part of the string.
		knownPartOfString = append(knownPartOfString, thisBlock...)
		blocksFound++
	}
	// Trim non-English characters, that is any padding that we may have caught.
	knownPartOfString = bytes.Trim(knownPartOfString, string(nonEnglishChars()))
	return knownPartOfString
}

// Exercise13 performs the corresponding exercise from cryptopals
// Title: ECB cut-and-paste
// Description: Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
func Exercise13() {
	e := NewAESECB(nil)
	email := []byte("thedad@me.")
	// We need admin to be in its own block so we can cut it.
	admin := PadToMultipleNBytes([]byte("admin"), aes.BlockSize)
	leftOver := []byte("com")
	encryptedProfile := e.ProfileAndEncrypt(string(append(email, append(admin, leftOver...)...)))
	// Cut and paste part here.
	fmt.Println(e.DecryptAndParse(encryptedProfile[:aes.BlockSize] + encryptedProfile[2*aes.BlockSize:3*aes.BlockSize] + encryptedProfile[aes.BlockSize:2*aes.BlockSize])["role"])
}

// Exercise14 performs the corresponding exercise from cryptopals
// Title: Byte-at-a-time ECB decryption (Harder)
// Description: Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext.
// You are now doing: AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
// Same goal: decrypt the target-bytes.
func Exercise14(unknownString []byte) []byte {
	// For the most part, this is the same as Exercise 12.
	// We just need to take care of the prepended bytes.
	e := NewECBEncryptionOracle(nil, unknownString)
	blockSize := e.GuessBlockSizeOfCipher()
	blocksFound := 0
	knownPartOfString := make([]byte, 0)
	lengthOfRandomPrepend := e.DetectLengthOfRandomBytes(blockSize)
	// We fill so that the prepended portion looks like it ends exactly at a block.
	fillPrependToBlockSize := make([]byte, blockSize-(lengthOfRandomPrepend%blockSize))
	numBlocksToFind := len(e.Encrypt(fillPrependToBlockSize))
	numBlocksToFind = (numBlocksToFind - 1) / blockSize
	numBlocksForPrepend := (lengthOfRandomPrepend / blockSize) + 1
	// Everything else is the same, except we append the fill for the prepended blocks each time.
	for blocksFound < numBlocksToFind && blockSize > 0 {
		identicalString := bytes.Repeat([]byte{byte(62)}, blockSize-1)
		thisBlock := make([]byte, 1)
		for j := 0; j < blockSize && j < len(thisBlock); j++ {
			for i := 0; i < 512; i++ {
				thisBlock[j] = byte(i)
				thisTest := e.Encrypt(append(append(append(append(fillPrependToBlockSize, identicalString...), knownPartOfString...), thisBlock...), identicalString[:blockSize-j-1]...))[numBlocksForPrepend*blockSize:]
				if bytes.Equal(thisTest[:blockSize*(blocksFound+1)], thisTest[blockSize*(blocksFound+1):2*(blockSize*(blocksFound+1))]) {
					if blockSize-j-2 > -1 {
						thisBlock = append(thisBlock, byte(1))
						identicalString = identicalString[:blockSize-j-2]
					}
					break
				}
			}
		}
		if len(thisBlock) < blockSize {
			blockSize = len(thisBlock) - 1
		}
		knownPartOfString = append(knownPartOfString, thisBlock[:blockSize]...)
		blocksFound++
	}
	// Trim non-English characters, that is any padding that we may have caught.
	knownPartOfString = bytes.Trim(knownPartOfString, string(nonEnglishChars()))
	return knownPartOfString
}

// Exercise15 performs the corresponding exercise from cryptopals
// Title: PKCS#7 padding validation
// Description: Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
func Exercise15() {
	_, err := VerifyPadding([]byte("ICE ICE BABY\x04\x04\x04\x04"), 16)
	fmt.Print(err == nil)
	_, err = VerifyPadding([]byte("ICE ICE BABY\x05\x05\x05\x05"), 16)
	fmt.Print(err == nil)
	_, err = VerifyPadding([]byte("ICE ICE BABY\x01\x02\x03\x04"), 16)
	fmt.Print(err == nil)
	_, err = VerifyPadding([]byte("ICE ICE BABY OH\x01"), 16)
	fmt.Print(err == nil)
}

// Exercise16 performs the corresponding exercise from cryptopals
// Title: CBC bitflipping attacks
// Description: Return true or false based on whether admin=true exists.
// If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.
// Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
func Exercise16() {
	c := NewAESCBC(nil, nil)
	adminText := PadToMultipleNBytes([]byte(";admin=true;a=b"), aes.BlockSize)
	firstBlock := PadToMultipleNBytes([]byte("YELLOW SUBMARINE"), aes.BlockSize)
	secondBlock := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		secondBlock[i] = 0
	}
	encryptedText := c.PrependAppendEncrypt(append(firstBlock, secondBlock...))
	for i := 3 * aes.BlockSize; i < 4*aes.BlockSize; i++ {
		encryptedText[i] ^= adminText[i%aes.BlockSize]
	}
	fmt.Println(c.DecryptCheckAdmin(encryptedText))
}
