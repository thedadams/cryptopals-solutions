package crypto

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"sort"
)

func ExampleExercise9() {
	Padded := PadToMultipleNBytes([]byte("YELLOW SUBMARINE"), 20)
	fmt.Println(len(Padded), string(Padded))
	// Output: 20 YELLOW SUBMARINE
}

func ExampleExercise10() {
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

func ExampleExercise11() {
	for i := 0; i < 10; i++ {
		GuessedCorrectly, _ := DetectRandomEBCCBCMode(16)
		fmt.Print(GuessedCorrectly)
	}
	// Output: truetruetruetruetruetruetruetruetruetrue
}

func ExampleExercise12() {
	ExpectedOutput, _ := ioutil.ReadFile("Set2_12Output.txt")
	Key := RandomBytes(16)
	BlockSize := GuessBlockSizeOfCipher(Key)
	BlocksFound := 0
	KnownPartOfString := make([]byte, 0)
	NumBlocksToFind := len(EBCEncryptionOracle(nil, Key)) / BlockSize
	for BlocksFound < NumBlocksToFind {
		IdenticalString := bytes.Repeat([]byte{byte(62)}, BlockSize-1)
		ThisBlock := make([]byte, 1)
		for j := 0; j < BlockSize && j < len(ThisBlock); j++ {
			for i := 0; i < 512; i++ {
				ThisBlock[j] = byte(i)
				ThisTest := EBCEncryptionOracle(append(append(append(IdenticalString, KnownPartOfString...), ThisBlock...), IdenticalString[:BlockSize-j-1]...), Key)
				if bytes.Compare(ThisTest[:BlockSize*(BlocksFound+1)], ThisTest[BlockSize*(BlocksFound+1):2*(BlockSize*(BlocksFound+1))]) == 0 {
					if BlockSize-j-2 > -1 {
						ThisBlock = append(ThisBlock, byte(1))
						IdenticalString = IdenticalString[:BlockSize-j-2]
					}
					break
				}
			}
		}
		if len(ThisBlock) < BlockSize {
			BlockSize = len(ThisBlock) - 1
		}
		KnownPartOfString = append(KnownPartOfString, ThisBlock[:BlockSize]...)
		BlocksFound++
	}
	fmt.Println(bytes.Compare(KnownPartOfString, ExpectedOutput))
	// Output: 0
}

func ExampleParseCookie() {
	Output := ParsedCookie("foo=bar&baz=qux&zap=zazzle")
	keys := []string{}
	for k, _ := range Output {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Print(key + "=" + Output[key] + ",")
	}
	// Output: baz=qux,foo=bar,zap=zazzle,
}

func ExampleProfileFor() {
	fmt.Println(ProfileFor("foo@bar.com"))
	fmt.Println(ProfileFor("foo@bar.com&role=admin"))
	// Output: email=foo@bar.com&uid=10&role=user
	// email=foo@bar.comroleadmin&uid=10&role=user
}

func ExampleExercise13() {
	Key := RandomBytes(16)
	BlockSize := GuessBlockSizeOfCipher(Key)
	Email := []byte("thedad@me.")
	Admin := PadToMultipleNBytes([]byte("admin"), BlockSize)
	LeftOver := []byte("com")
	EncryptedProfile := ProfileAndEncrypt(string(append(Email, append(Admin, LeftOver...)...)), Key)
	fmt.Println(DecryptAndParse(EncryptedProfile[:BlockSize]+EncryptedProfile[2*BlockSize:3*BlockSize]+EncryptedProfile[BlockSize:2*BlockSize], Key)["role"])
	// Output: admin
}
