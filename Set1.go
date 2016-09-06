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

func XORTwoHexStrings(hex1, hex2 string) string {
	msg1, err := hex.DecodeString(hex1)
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}
	msg2, err := hex.DecodeString(hex2)
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}
	dest := xorTwoByteStrings(msg1, msg2)
	return hex.EncodeToString(dest)
}

func xorTwoByteStrings(s1, s2 []byte) []byte {
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

func DecryptSingleCharXOR(HexString string) (string, int) {
	maxScore, thisScore := -1, -1
	key := []byte(" ")
	msg, err := hex.DecodeString(HexString)
	if err != nil {
		fmt.Println("error:", err)
		return "", -1
	}
	dest := make([]byte, len(msg))
	decoded := make([]byte, len(msg))
	for key[0] <= []byte("~")[0] {
		for i := 0; i < len(msg); i++ {
			dest[i] = key[0] ^ msg[i]
		}
		thisScore = countEnglishChars(dest)
		if thisScore > maxScore {
			maxScore = thisScore
			copy(decoded, dest)
		}
		key[0]++
	}
	return hex.EncodeToString(decoded), maxScore
}

func FindStringThatHasBeenEncrypted(filename string) (string, string, string) {
	maxScore := -1
	encryptedHex, decryptedHex, decryptedString := "", "", ""
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		fmt.Println("You don't have the proper file: " + filename)
		return "", "", ""
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		decryptedLine, thisScore := DecryptSingleCharXOR(line)
		decryptedBytes, _ := hex.DecodeString(decryptedLine)
		if thisScore > maxScore {
			maxScore = thisScore
			encryptedHex = line
			decryptedHex = decryptedLine
			decryptedString = string(decryptedBytes)
		}
	}
	return encryptedHex, decryptedHex, decryptedString
}

func RepeatedKeyXOR(Text, Key string) string {
	ByteText := []byte(Text)
	ByteKey := []byte(Key)
	KeyLength := len(ByteKey)
	ByteDest := make([]byte, 0)
	for len(ByteText) > 0 {
		if len(ByteText) < KeyLength {
			KeyLength = len(ByteText)
			ByteKey = ByteKey[:KeyLength]
		}
		ByteDest = append(ByteDest, xorTwoByteStrings(ByteText[:KeyLength], ByteKey)...)
		ByteText = ByteText[KeyLength:]
	}
	return hex.EncodeToString(ByteDest)
}
