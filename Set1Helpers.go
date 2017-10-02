package crypto

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

// The AESECB type is used to encrypt and decrypt in ECB mode.
type AESECB struct {
	block cipher.Block
	key   []byte
	iv    []byte // We don't need the IV for ECB, but the Go implementation we are using requires one.
}

// NewAESECB is a helper to create a new AESECB type.
func NewAESECB(key []byte) AESECB {
	if key == nil {
		key = RandomBytes(aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// Use a blank IV.
	return AESECB{block: block, key: key, iv: make([]byte, aes.BlockSize)}
}

// Decrypt decrypts text that was encrypted using ECB.
func (ecb AESECB) Decrypt(cipherText []byte) []byte {
	for i := 0; i < len(cipherText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode := cipher.NewCBCDecrypter(ecb.block, ecb.iv)
		mode.CryptBlocks(cipherText[i*aes.BlockSize:(i+1)*aes.BlockSize], cipherText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return cipherText
}

// Encrypt encrypts plain text using ECB mode.
func (ecb AESECB) Encrypt(plainText []byte) []byte {
	plainText = PadToMultipleNBytes(plainText, aes.BlockSize)

	for i := 0; i < len(plainText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode := cipher.NewCBCEncrypter(ecb.block, ecb.iv)
		mode.CryptBlocks(plainText[i*aes.BlockSize:(i+1)*aes.BlockSize], plainText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return plainText
}

// HexStringTo64String decodes a hex string and encodes it as base64.
func HexStringTo64String(hexString string) string {
	msg, err := hex.DecodeString(hexString)
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(msg))
	return encoded
}

// XORTwoByteStrings does exactly as it sounds.
func XORTwoByteStrings(s1, s2 []byte) []byte {
	// If the byte strings are different lengths, we cannot XOR them.
	if len(s1) != len(s2) {
		fmt.Println("error: byte arrays must have the same length.")
		return nil
	}
	dest := make([]byte, len(s1))
	for i := 0; i < len(dest); i++ {
		dest[i] = s1[i] ^ s2[i]
	}
	return dest
}

func isEnglishChar(a byte) bool {
	return !(a != 32 && (a < 65 || a > 122))
}

func countEnglishChars(decrypted []byte) int {
	count := 0
	for i := 0; i < len(decrypted); i++ {
		if isEnglishChar(decrypted[i]) {
			count++
		}
	}
	return count
}

// DecryptSingleCharXOR finds a single character key for the cipherText
// and decrypts the cipherText.
func DecryptSingleCharXOR(cipherText []byte) (plainText []byte, score int, key []byte) {
	maxScore, thisScore := -1, -1
	// The guess we use for the key,
	keyGuess := []byte(" ")
	// The best key to this point
	key = []byte(" ")
	plainText = make([]byte, len(cipherText))
	for keyGuess[0] <= []byte("~")[0] {
		// XOR the cipherText with the keyGuess.
		dest := XORTwoByteStrings(cipherText, bytes.Repeat(keyGuess, len(cipherText)))
		// Score this guess.
		thisScore = countEnglishChars(dest)
		// If this is our best score to this point, we update.
		if thisScore > maxScore {
			maxScore = thisScore
			copy(plainText, dest)
			copy(key, keyGuess)
		}
		keyGuess[0]++
	}
	return plainText, maxScore, key
}

// FindStringThatHasBeenEncrypted searches a file called filename for the string that has been
// encrypted using a single character encryption method.
func FindStringThatHasBeenEncrypted(filename string) (plaintext []byte, cipherText []byte) {
	maxScore := -1
	// Open the file
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		fmt.Println("You don't have the proper file: " + filename)
		return nil, nil
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, _ := hex.DecodeString(scanner.Text())
		// For each line, we try to decrypt with single char xor.
		decryptedLine, thisScore, _ := DecryptSingleCharXOR(line)
		// If this line's score is the best we've seen so far, we update.
		if thisScore > maxScore {
			maxScore = thisScore
			plaintext = make([]byte, len(line))
			cipherText = make([]byte, len(decryptedLine))
			copy(plaintext, line)
			copy(cipherText, decryptedLine)
		}
	}
	// We can simply return because we named the return variables.
	return
}

// RepeatedKeyXOR takes an arbitrary key and repeatedly XOR text with the key in blocks.
func RepeatedKeyXOR(text, key []byte) []byte {
	keyLength := len(key)
	byteDest := make([]byte, 0)
	for len(text) > 0 {
		// If we don't have enough text for this key, we shorten the key.
		if len(text) < keyLength {
			keyLength = len(text)
			key = key[:keyLength]
		}
		// XOR this portion of the text.
		byteDest = append(byteDest, XORTwoByteStrings(text[:keyLength], key)...)
		// Shorten the text to remove the bytes that were XOR-ed.
		text = text[keyLength:]
	}
	return byteDest
}

// hasBit checks if n has a 1-bit at position pos.
func hasBit(n byte, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}

// HammingDistance calculates the Hamming Distance between two []byte.
func HammingDistance(word1, word2 []byte) int {
	var j uint
	dist := 0
	// We need the length of the shorter of the two strings.
	n := len(word1)
	if len(word2) < n {
		n = len(word2)
	}
	// Loop through the shorter string.
	for i := 0; i < n; i++ {
		xorEd := word1[i] ^ word2[i]
		// Loop through the size of a byte.
		for j = 0; j < 8; j++ {
			// Compute the Hamming Distance of this byte.
			if hasBit(xorEd, j) {
				dist++
			}
		}
	}
	return dist
}

// GuessKeySize guesses the repeated XOR key size using the Hamming Distance.
func GuessKeySize(text []byte) (keySize int) {
	// The maximum length of key we should consider.
	maxGuess := 60
	// If the length of the text is less than twice the length maximum key guess,
	// then we double our mass guess.
	if len(text) < 2*maxGuess {
		maxGuess = len(text) / 2
	}
	// Set minDist to the maximum distance possible in this situation.
	minDist := float64(8 * len(text))
	for k := 1; k <= maxGuess; k++ {
		thisDist := 0.0
		i := 0
		// We loop over keyLength chunks of the text.
		for (i+2)*k < len(text) {
			// Find the Hamming Distance of two consecutive keyLength chunks of the text.
			thisDist += float64(HammingDistance(text[i*k:(i+1)*k], text[(i+1)*k:(i+2)*k]))
			i++
		}
		// Average this distance per key length
		thisDist /= (float64(k) * 8.0 * float64(i))
		// If this Hamming distance is less our minimum so far, we update.
		if thisDist < minDist {
			minDist = thisDist
			keySize = k
		}
	}
	// We can just return because we named our output value.
	return
}

// BreakRepeatingXOR finds the key for and decrypts cipher text.
func BreakRepeatingXOR(cipherText []byte) (plainText []byte, key []byte, keyLength int) {
	// First, guess the keySize.
	keySize := GuessKeySize(cipherText)
	// transposedText is an array where each row contains letters that would be XOR-ed the same character of the key.
	transposedText := make([][]byte, keySize)
	key = make([]byte, 0)
	for i := 0; i < keySize; i++ {
		transposedText[i] = make([]byte, 0)
	}
	for i := 0; i < len(cipherText)/keySize; i++ {
		for j := 0; j < keySize && j+keySize*i < len(cipherText); j++ {
			transposedText[j] = append(transposedText[j], cipherText[j+keySize*i])
		}
	}
	// Now we have the transposedData
	for i := 0; i < len(transposedText); i++ {
		// Now we can decrypt each row of transposedText using our single char decryption.
		_, _, singleCharOfKey := DecryptSingleCharXOR(transposedText[i])
		key = append(key, singleCharOfKey...)
	}
	// Decrypt the cipherText
	plainText = RepeatedKeyXOR(cipherText, key)
	keyLength = len(key)
	// We can just return because we named our output values.
	return
}

// DetectAESECB searches a file named filedname for the string that was encrypted with ECB mode.
func DetectAESECB(filename string) string {
	blockLength := aes.BlockSize
	minScore := 10000.0
	var possibleLine []byte
	// Open the file.
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("You don't have the proper file: " + filename)
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	// Each line of the code is encrypted, possibly in ECB mode.
	for scanner.Scan() {
		thisScore := 0.0
		line, _ := hex.DecodeString(scanner.Text())
		for i := 0; (i+1)*blockLength < len(line); i++ {
			for j := i + 1; (i+j+1)*blockLength < len(line); j++ {
				// The idea is that identical blocks are encrypted identically in ECB mode.
				// We look for identically encrypted blocks.
				// If the blocks are identical, then nothing is added to thisScore
				thisScore += math.Abs(float64(bytes.Compare(line[i*blockLength:(i+1)*blockLength], line[(i+j)*blockLength:(i+j+1)*blockLength])))
			}
		}
		// Average the score.
		thisScore /= float64(blockLength)
		// If thisScore is minimum, we update.
		if thisScore < minScore {
			minScore = thisScore
			possibleLine = make([]byte, len(line))
			copy(possibleLine, line)
		}
	}
	return hex.EncodeToString(possibleLine)
}
