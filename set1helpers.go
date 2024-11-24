package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
)

// The aesecb type is used to encrypt and decrypt in ECB mode.
type aesecb struct {
	block cipher.Block
	key   []byte
	iv    []byte // We don't need the IV for ECB, but the Go implementation we are using requires one.
}

// newAESECB is a helper to create a new aesecb type.
func newAESECB(key []byte) (aesecb, error) {
	if key == nil {
		key = randomBytes(aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return aesecb{}, err
	}
	// Use a blank IV.
	return aesecb{block: block, key: key, iv: make([]byte, aes.BlockSize)}, nil
}

// decrypt decrypts text that was encrypted using ECB.
func (ecb aesecb) decrypt(cipherText []byte) ([]byte, error) {
	// ECB mode always works in whole blocks.
	if len(cipherText)%aes.BlockSize != 0 {
		return nil, errors.New("cipher text is not a multiple of the block size")
	}

	decryptedText := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText)/aes.BlockSize; i++ {
		mode := cipher.NewCBCDecrypter(ecb.block, ecb.iv)
		mode.CryptBlocks(decryptedText[i*aes.BlockSize:(i+1)*aes.BlockSize], cipherText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}

	return removePadding(decryptedText), nil
}

// encrypt encrypts plain text using ECB mode.
func (ecb aesecb) encrypt(plainText []byte) []byte {
	plainText = padToMultipleNBytes(plainText, aes.BlockSize)
	encryptedText := make([]byte, len(plainText))
	for i := 0; i < len(plainText)/aes.BlockSize; i++ {
		mode := cipher.NewCBCEncrypter(ecb.block, ecb.iv)
		mode.CryptBlocks(encryptedText[i*aes.BlockSize:(i+1)*aes.BlockSize], plainText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return encryptedText
}

// hexStringTo64String decodes a hex string and encodes it as base64.
func hexStringTo64String(hexString string) (string, error) {
	msg, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(msg), nil
}

// xorTwoByteStrings does exactly as it sounds.
func xorTwoByteStrings(s1, s2 []byte) []byte {
	length := len(s1)
	if length > len(s2) {
		length = len(s2)
	}
	dest := make([]byte, length)
	for i := 0; i < length; i++ {
		dest[i] = s1[i] ^ s2[i]
	}
	return dest
}

// padToMultipleNBytes pads the bytes to the nearest multiple of N.
func padToMultipleNBytes(text []byte, N int) []byte {
	// If the padding is already valid, then we shouldn't pad.
	if _, err := isValidPadding(text, N); err == nil {
		return text
	}
	bytesToAdd := N - (len(text) % N)
	return append(text, bytes.Repeat([]byte{byte(bytesToAdd)}, bytesToAdd)...)
}

// removePadding will remove valid padding bytes
func removePadding(text []byte) []byte {
	paddedByte := text[len(text)-1]
	for i := len(text) - 1; i > len(text)-1-int(paddedByte); i-- {
		if text[i] != paddedByte {
			return text[:len(text)-int(paddedByte)]
		}
	}
	return text[:len(text)-int(paddedByte)]
}

// paddingError is a type used to indicate that there is a padding error with a plain text
type paddingError []byte

func (f paddingError) Error() string {
	return fmt.Sprintf("math: square root of negative number %v", []byte(f))
}

// isValidPadding verifies that the text has the proper padding, strips it, and returns the text.
// If we encounter an error, then we return a paddingError
// Otherwise, the error is nil.
func isValidPadding(text []byte, blockSize int) ([]byte, error) {
	if len(text) == 0 {
		return text, paddingError(text)
	}
	paddedByte := text[len(text)-1]
	// If the last byte is 0 or greater than the block length, then we know the padding is invalid.
	if paddedByte > byte(blockSize) || paddedByte <= 0 {
		return text, paddingError(text)
	}
	for i := len(text) - 1; i > len(text)-1-int(paddedByte); i-- {
		if text[i] != paddedByte {
			return text, paddingError(text)
		}
	}
	return text[:len(text)-int(paddedByte)], nil
}

// randomBytes generates a random number of bytes.
// Used for things like keys and ivs.
func randomBytes(numBytes int) []byte {
	key := make([]byte, numBytes)
	// Read random bytes into key.
	n, err := rand.Read(key)
	if err != nil || n != numBytes {
		fmt.Println("ERROR: could not generate random bytes.")
		return nil
	}
	return key
}

func isEnglishChar(a byte) bool {
	return a == 32 || (a >= 65 && a <= 90) || (a >= 97 && a <= 122)
}

func lowerCaseLetterRatio(plainText []byte) float64 {
	totalEnglishLetters, lowerCaseLetters := 0.0, 0.0
	for _, b := range plainText {
		if isEnglishChar(b) {
			if bytes.Equal(bytes.ToLower([]byte{b}), []byte{b}) {
				lowerCaseLetters++
			}
			totalEnglishLetters++
		}
	}
	return lowerCaseLetters / totalEnglishLetters
}

func countEnglishChars(decrypted []byte) float64 {
	count := 0.0
	for i := 0; i < len(decrypted); i++ {
		if isEnglishChar(decrypted[i]) {
			count++
		}
	}
	return count
}

func frequencyScore(decrypted []byte) float64 {
	ranks := []byte(" etaoinshrdlcumwfgypbvk")
	frequencies := make(map[byte]int)
	maxFreq := 0
	score := 0.0
	for _, b := range decrypted {
		b = bytes.ToLower([]byte{b})[0]
		if _, ok := frequencies[b]; !ok {
			frequencies[b] = 0
		}
		frequencies[b]++
		if maxFreq < frequencies[b] {
			maxFreq = frequencies[b]
		}
	}
	freqArray := make([][]byte, maxFreq+1)
	for i := 0; i < maxFreq+1; i++ {
		freqArray[i] = make([]byte, 0)
	}
	for key, val := range frequencies {
		freqArray[val] = append(freqArray[val], key)
	}
	rank := 0.0
	for i := maxFreq; i >= 0; i-- {
		rank = (1.0 + float64(len(freqArray[i]))) / float64(len(freqArray))
		for _, b := range freqArray[i] {
			if bytes.Contains(ranks, []byte{b}) {
				score += math.Abs(rank - float64(bytes.Index(ranks, []byte{b})))
			} else {
				score += 255
			}
		}
	}
	return 1 / (score + 1)
}

// decryptSingleCharXOR finds a single character key for the cipherText
// and decrypts the cipherText.
func decryptSingleCharXOR(cipherText []byte, mostlyUpperCase bool) ([]byte, float64, []byte) {
	maxScore := -1.0
	// The guess we use for the key,
	keyGuess := []byte{0}
	// The best key to this point
	key := []byte{0}
	plainText := make([]byte, len(cipherText))
	var thisScore float64
	for keyGuess[0] < 255 {
		// XOR the cipherText with the keyGuess.
		dest := xorTwoByteStrings(cipherText, bytes.Repeat(keyGuess, len(cipherText)))
		// Score this guess.
		thisScore = countEnglishChars(dest)/float64(len(dest)) + frequencyScore(dest)
		// If this is our best score to this point, we update.
		if thisScore > maxScore {
			maxScore = thisScore
			copy(plainText, dest)
			copy(key, keyGuess)
		}
		keyGuess[0]++
	}
	if mostlyUpperCase && lowerCaseLetterRatio(xorTwoByteStrings(cipherText, bytes.Repeat(key, len(cipherText)))) > lowerCaseLetterRatio(xorTwoByteStrings(cipherText, bytes.Repeat([]byte{key[0] + 32}, len(cipherText)))) {
		key[0] += 32
	}
	return plainText, maxScore, key
}

// findStringThatHasBeenEncrypted searches a file called filename for the string that has been
// encrypted using a single character encryption method.
func findStringThatHasBeenEncrypted(input string) ([]byte, []byte) {
	var (
		plainText, cipherText []byte

		maxScore = -1.0
		scanner  = bufio.NewScanner(strings.NewReader(input))
	)

	for scanner.Scan() {
		line, err := hex.DecodeString(scanner.Text())
		if err != nil {
			// If we can't decode the line, we skip it.
			continue
		}

		// For each line, we try to decrypt with single char xor.
		decryptedLine, thisScore, _ := decryptSingleCharXOR(line, false)
		// If this line's score is the best we've seen so far, we update.
		if thisScore > maxScore {
			maxScore = thisScore
			plainText = decryptedLine
			cipherText = line
		}
	}

	return plainText, cipherText
}

// repeatedKeyXOR takes an arbitrary key and repeatedly XOR text with the key in blocks.
func repeatedKeyXOR(text, key []byte) []byte {
	keyLength := len(key)
	byteDest := make([]byte, 0)
	for len(text) > 0 {
		// If we don't have enough text for this key, we shorten the key.
		if len(text) < keyLength {
			keyLength = len(text)
			key = key[:keyLength]
		}
		// XOR this portion of the text.
		byteDest = append(byteDest, xorTwoByteStrings(text[:keyLength], key)...)
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

// hammingDistance calculates the Hamming Distance between two []byte.
func hammingDistance(word1, word2 []byte) int {
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

// guessKeySize guesses the repeated XOR key size using the Hamming Distance.
func guessKeySize(text []byte) int {
	var keySize int
	// The maximum length of key we should consider.
	maxGuess := 60
	// If the length of the text is less than twice the length maximum key guess,
	// then we double our max guess.
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
			thisDist += float64(hammingDistance(text[i*k:(i+1)*k], text[(i+1)*k:(i+2)*k]))
			i++
		}
		// Average this distance per key length
		thisDist /= float64(k*i) * 8.0
		// If this Hamming distance is less our minimum so far, we update.
		if thisDist < minDist {
			minDist = thisDist
			keySize = k
		}
	}

	return keySize
}

// breakRepeatingXOR finds the key for and decrypts cipher text.
func breakRepeatingXOR(cipherText []byte, keySize int, firstLetterOfBlockCapitalized bool) ([]byte, []byte) {
	// transposedText is an array where each row contains letters that would be XOR-ed the same character of the key.
	transposedText := make([][]byte, keySize)
	var key []byte
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
		_, _, singleCharOfKey := decryptSingleCharXOR(transposedText[i], i == 0 && firstLetterOfBlockCapitalized)
		key = append(key, singleCharOfKey...)
	}
	// decrypt the cipherText
	return repeatedKeyXOR(cipherText, key), key
}

// detectAESECB searches contents for a line encrypted with ECB mode.
func detectAESECB(contents string) string {
	blockLength := aes.BlockSize
	minScore := 10000.0
	var possibleLine []byte
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		thisScore := 0.0
		line, err := hex.DecodeString(scanner.Text())
		if err != nil {
			// Not valid hex, so can be ignored
			continue
		}

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
