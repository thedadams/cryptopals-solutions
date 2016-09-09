package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
)

func ExampleHexTo64() {
	fmt.Println(HexStringTo64String("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	// Output: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
}

func ExampleHexXOR() {
	msg1, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	msg2, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(hex.EncodeToString(XORTwoByteStrings(msg1, msg2)))
	// Output: 746865206b696420646f6e277420706c6179
}

func ExampleSingleCharXORDecrypt() {
	toDecrypt, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	decrypted, score, key := DecryptSingleCharXOR(toDecrypt)
	fmt.Println(string(decrypted), score, string(key))
	// Output: Cooking MC's like a pound of bacon 33 X
}

func ExampleFindEncryptedLine() {
	encrypted, decrypted := FindStringThatHasBeenEncrypted("Set1_4.txt")
	fmt.Println(hex.EncodeToString(encrypted), hex.EncodeToString(decrypted), string(decrypted))
	// Output: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f 4e6f77207468617420746865207061727479206973206a756d70696e670a Now that the party is jumping
}

func ExampleRepeatedKeyXOR() {
	fmt.Println(hex.EncodeToString(RepeatedKeyXOR([]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), []byte("ICE"))))
	// Output: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
}

func ExampleHammingDistance() {
	fmt.Println(HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")))
	// Output: 37
}

func ExampleGuessKeySize() {
	FileText, _ := ioutil.ReadFile("Set1_6.txt")
	FileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(FileText))
	keySize := GuessKeySize(FileTextAsBytes)
	fmt.Println(keySize)
	// Output: 29
}

func ExampleBreakRepeatingXOR() {
	FileText, _ := ioutil.ReadFile("Set1_6.txt")
	FileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(FileText))
	_, key, _ := BreakRepeatingXOR(FileTextAsBytes)
	fmt.Println(string(key))
	// Output: Terminator X: Bring the noise
}

func ExampleDecryptAESECB() {
	FileText, _ := ioutil.ReadFile("Set1_7.txt")
	ExpectedOutput, _ := ioutil.ReadFile("Set1_7Output.txt")
	FileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(FileText))
	PlainText := DecryptAESECB(FileTextAsBytes, []byte("YELLOW SUBMARINE"))
	fmt.Println(bytes.Compare(PlainText, ExpectedOutput))
	// Output: 0
}
