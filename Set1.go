package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
)

// Exercise1 performs the corresponding exercise from cryptopals.
// Title: Convert hex to base64
func Exercise1() string {
	return HexStringTo64String("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
}

// Exercise2 performs the corresponding exercise from cryptopals.
// Title: Fixed XOR
// Description: Write a function that takes two equal-length buffers and produces their XOR combination.
func Exercise2() string {
	msg1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	msg2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	return hex.EncodeToString(XORTwoByteStrings(msg1, msg2))
}

// Exercise3 performs the corresponding exercise from cryptopals.
// Title: Single-byte XOR cipher
// Description: The string has been XOR-ed against a single character. Find the key, decrypt the message.
func Exercise3() (decrypted []byte, score int, key []byte) {
	toDecrypt, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	decrypted, score, key = DecryptSingleCharXOR(toDecrypt)
	return decrypted, score, key
}

// Exercise4 performs the corresponding exercise from cryptopals.
// Title: Detect single-character XOR
// One of the 60-character strings in this file has been encrypted by single-character XOR. Find it.
func Exercise4() ([]byte, []byte) {
	return FindStringThatHasBeenEncrypted("Set1_4.txt")
}

// Exercise5 performs the corresponding exercise from cryptopals.
// Title: Implement repeating-key XOR
// Description: Encrypt the string, under the key "ICE", using repeating-key XOR.
func Exercise5() string {
	text, key := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE")
	return hex.EncodeToString(RepeatedKeyXOR(text, key))
}

// Exercise6 performs the corresponding exercise from cryptopals.
// Title: Break repeating-key XOR
// Description: There's a file here. It's been base64'd after being encrypted with repeating-key XOR. Decrypt it.
func Exercise6() string {
	fileText, _ := ioutil.ReadFile("Set1_6.txt")
	fileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(fileText))
	_, key, _ := BreakRepeatingXOR(fileTextAsBytes)
	return string(key)
}

// Exercise7 performs the corresponding exercise from cryptopals.
// Title: AES in ECB mode
// Description: The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key "YELLOW SUBMARINE". Decrypt it.
func Exercise7() []byte {
	fileText, _ := ioutil.ReadFile("Set1_7.txt")
	fileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(fileText))
	ecb := NewAESECB([]byte("YELLOW SUBMARINE"))
	return ecb.Decrypt(fileTextAsBytes)
}

// Exercise8 performs the corresponding exercise from cryptopals.
// Title: Detect AES in ECB mode
// Description: In this file are a bunch of hex-encoded ciphertexts. One of them has been encrypted with ECB. Detect it.
func Exercise8() string {
	return DetectAESECB("Set1_8.txt")
}
