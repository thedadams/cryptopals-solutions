package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
)

// Exercise1 performs the corresponding exercise from cryptopals.
func Exercise1() string {
	return HexStringTo64String("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
}

// Exercise2 performs the corresponding exercise from cryptopals.
func Exercise2() string {
	msg1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	msg2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	return hex.EncodeToString(XORTwoByteStrings(msg1, msg2))
}

// Exercise3 performs the corresponding exercise from cryptopals.
func Exercise3() (decrypted []byte, score int, key []byte) {
	toDecrypt, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	decrypted, score, key = DecryptSingleCharXOR(toDecrypt)
	return decrypted, score, key
}

// Exercise4 performs the corresponding exercise from cryptopals.
func Exercise4() ([]byte, []byte) {
	return FindStringThatHasBeenEncrypted("Set1_4.txt")
}

// Exercise5 performs the corresponding exercise from cryptopals.
func Exercise5() string {
	text, key := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE")
	return hex.EncodeToString(RepeatedKeyXOR(text, key))
}

// Exercise6 performs the corresponding exercise from cryptopals.
func Exercise6() string {
	fileText, _ := ioutil.ReadFile("Set1_6.txt")
	fileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(fileText))
	_, key, _ := BreakRepeatingXOR(fileTextAsBytes)
	return string(key)
}

// Exercise7 performs the corresponding exercise from cryptopals.
func Exercise7() []byte {
	fileText, _ := ioutil.ReadFile("Set1_7.txt")
	fileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(fileText))
	ecb := NewAESECB([]byte("YELLOW SUBMARINE"))
	return ecb.Decrypt(fileTextAsBytes)
}

// Exercise8 performs the corresponding exercise from cryptopals.
func Exercise8() string {
	return DetectAESECB("Set1_8.txt")
}
