package crypto

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
		for i < len(text)/k {
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
