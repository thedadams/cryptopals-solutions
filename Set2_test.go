package crypto

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

func ExamplePadToNBytes() {
	fmt.Println(string(PadToNBytes([]byte("YELLOW SUBMARINE"), 20)))
	// Output: YELLOW SUBMARINE
}

func ExampleDecryptAESCBC() {
	FileText, _ := ioutil.ReadFile("Set2_10.txt")
	ExpectedOutput, _ := ioutil.ReadFile("Set2_10Output.txt")
	FileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(FileText))
	PlainText := DecryptAESCBC(FileTextAsBytes, []byte("YELLOW SUBMARINE"))
	fmt.Println(bytes.Compare(PlainText, ExpectedOutput))
	// Output: 0
}
