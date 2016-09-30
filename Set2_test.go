package crypto

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

func ExamplePadToNBytes() {
	Padded := PadToMultipleNBytes([]byte("YELLOW SUBMARINE"), 20)
	fmt.Println(len(Padded), string(Padded))
	// Output: 20 YELLOW SUBMARINE
}

func ExampleDecryptAESCBC() {
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		iv[i] = 0
	}
	FileText, _ := ioutil.ReadFile("Set2_10.txt")
	ExpectedOutput, _ := ioutil.ReadFile("Set2_10Output.txt")
	FileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(FileText))
	PlainText := DecryptAESCBC(FileTextAsBytes, []byte("YELLOW SUBMARINE"), iv)
	fmt.Println(bytes.Compare(PlainText, ExpectedOutput))
	// Output: 0
}

func ExampleDetectRandomEBCCBCMode() {
	for i := 0; i < 10; i++ {
		fmt.Print(DetectRandomEBCCBCMode(16))
	}
	// Output: truetruetruetruetruetruetruetruetruetrue
}
