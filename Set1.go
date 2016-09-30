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

func HexStringTo64String(hexString string) string {
	msg, err := hex.DecodeString(hexString)
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(msg))
	return encoded
}

func XORTwoByteStrings(s1, s2 []byte) []byte {
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
	if a != 32 && (a < 65 || a > 122) {
		return false
	}
	return true
}

func countEnglishChars(decoded []byte) int {
	count := 0
	for i := 0; i < len(decoded); i++ {
		if isEnglishChar(decoded[i]) {
			count++
		}
	}
	return count
}

func DecryptSingleCharXOR(toDecrypt []byte) ([]byte, int, []byte) {
	maxScore, thisScore := -1, -1
	keyGuess := []byte(" ")
	key := []byte(" ")
	dest := make([]byte, len(toDecrypt))
	decoded := make([]byte, len(toDecrypt))
	for keyGuess[0] <= []byte("~")[0] {
		for i := 0; i < len(toDecrypt); i++ {
			dest[i] = keyGuess[0] ^ toDecrypt[i]
		}
		thisScore = countEnglishChars(dest)
		if thisScore > maxScore {
			maxScore = thisScore
			copy(decoded, dest)
			copy(key, keyGuess)
		}
		keyGuess[0]++
	}
	return decoded, maxScore, key
}

func FindStringThatHasBeenEncrypted(filename string) ([]byte, []byte) {
	maxScore := -1
	var encrypted, decrypted []byte
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		fmt.Println("You don't have the proper file: " + filename)
		return nil, nil
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, _ := hex.DecodeString(scanner.Text())
		decryptedLine, thisScore, _ := DecryptSingleCharXOR(line)
		if thisScore > maxScore {
			maxScore = thisScore
			encrypted = make([]byte, len(line))
			decrypted = make([]byte, len(decryptedLine))
			copy(encrypted, line)
			copy(decrypted, decryptedLine)
		}
	}
	return encrypted, decrypted
}

func RepeatedKeyXOR(Text, Key []byte) []byte {
	KeyLength := len(Key)
	ByteDest := make([]byte, 0)
	for len(Text) > 0 {
		if len(Text) < KeyLength {
			KeyLength = len(Text)
			Key = Key[:KeyLength]
		}
		ByteDest = append(ByteDest, XORTwoByteStrings(Text[:KeyLength], Key)...)
		Text = Text[KeyLength:]
	}
	return ByteDest
}

func hasBit(n byte, pos uint) bool {
	val := n & (1 << pos)
	return (val > 0)
}

func HammingDistance(word1, word2 []byte) int {
	var j uint
	dist := 0
	n := len(word1)
	if len(word2) < n {
		n = len(word2)
	}
	for i := 0; i < n; i++ {
		for j = 0; j < 8; j++ {
			xored := word1[i] ^ word2[i]
			if hasBit(xored, j) {
				dist++
			}
		}
	}
	return dist
}

func GuessKeySize(text []byte) int {
	MaxGuess := 40
	if len(text) < 2*MaxGuess {
		MaxGuess = len(text) / 2
	}
	KeySize := 1
	MinDist := float64(8 * len(text))
	for k := 1; k <= MaxGuess; k++ {
		ThisDist := 0.0
		i := 0
		for (i+2)*k < len(text) {
			ThisDist += float64(HammingDistance(text[i*k:(i+1)*k], text[(i+1)*k:(i+2)*k]))
			i++
		}
		ThisDist /= (float64(k) * 8.0 * float64(i))
		if ThisDist < MinDist {
			MinDist = ThisDist
			KeySize = k
		}
	}
	return KeySize
}

func BreakRepeatingXOR(TextAsBytes []byte) ([]byte, []byte, int) {
	KeySize := GuessKeySize(TextAsBytes)
	TransposedText := make([][]byte, KeySize)
	key := make([]byte, 0)
	for i := 0; i < KeySize; i++ {
		TransposedText[i] = make([]byte, 0)
	}
	for i := 0; i < len(TextAsBytes)/KeySize; i++ {
		for j := 0; j < KeySize && j+KeySize*i < len(TextAsBytes); j++ {
			TransposedText[j] = append(TransposedText[j], TextAsBytes[j+KeySize*i])
		}
	}
	for i := 0; i < len(TransposedText); i++ {
		_, _, SingleCharOfKey := DecryptSingleCharXOR(TransposedText[i])
		key = append(key, SingleCharOfKey...)
	}
	DecryptedText := RepeatedKeyXOR(TextAsBytes, key)

	return DecryptedText, key, len(key)
}

func DecryptAESECB(CipherText, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(CipherText) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		iv[i] = 0
	}

	// EBC mode always works in whole blocks.
	if len(CipherText)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	for i := 0; i < len(CipherText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(CipherText[i*aes.BlockSize:(i+1)*aes.BlockSize], CipherText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return CipherText
}

func EncryptAESECB(PlainText, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(PlainText) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		iv[i] = 0
	}

	// EBC mode always works in whole blocks.
	if len(PlainText)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	for i := 0; i < len(PlainText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(PlainText[i*aes.BlockSize:(i+1)*aes.BlockSize], PlainText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return PlainText
}

func DetectAESECB(filename string) string {
	blockLength := 16
	minScore := 10000.0
	var possibleLine []byte
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		fmt.Println("You don't have the proper file: " + filename)
		return ""
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		thisScore := 0.0
		line, _ := hex.DecodeString(scanner.Text())
		for i := 0; (i+1)*blockLength < len(line); i++ {
			for j := i + 1; (i+j+1)*blockLength < len(line); j++ {
				thisScore += math.Abs(float64(bytes.Compare(line[i*blockLength:(i+1)*blockLength], line[(i+j)*blockLength:(i+j+1)*blockLength])))
			}
		}
		thisScore /= float64(blockLength)
		if thisScore < minScore {
			minScore = thisScore
			possibleLine = make([]byte, len(line))
			copy(possibleLine, line)
		}
	}
	return hex.EncodeToString(possibleLine)
}
