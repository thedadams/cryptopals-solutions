package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
)

func ExampleExercise1() {
	fmt.Println(Exercise1())
	// Output: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
}

func ExampleExercise2() {
	fmt.Println(Exercise2())
	// Output: 746865206b696420646f6e277420706c6179
}

func ExampleExercise3() {
	d, l, k := Exercise3()
	fmt.Println(string(d), l, string(k))
	// Output: Cooking MC's like a pound of bacon 33 X
}

func ExampleExercise4() {
	encrypted, decrypted := Exercise4()
	fmt.Println(hex.EncodeToString(encrypted), hex.EncodeToString(decrypted), string(decrypted))
	// Output: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f 4e6f77207468617420746865207061727479206973206a756d70696e670a Now that the party is jumping
}

func ExampleExercise5() {
	fmt.Println(Exercise5())
	// Output: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
}

func ExampleHammingDistance() {
	fmt.Println(HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")))
	// Output: 37
}

func ExampleGuessKeySize() {
	fileText, _ := ioutil.ReadFile("Set1_6.txt")
	fileTextAsBytes, _ := base64.StdEncoding.DecodeString(string(fileText))
	keySize := GuessKeySize(fileTextAsBytes)
	fmt.Println(keySize)
	// Output: 29
}

func ExampleExercise6() {
	fmt.Println(Exercise6())
	// Output: Terminator X: Bring the noise
}

func ExampleExercise7() {
	expectedOutput, _ := ioutil.ReadFile("Set1_7Output.txt")
	plainText := Exercise7()
	fmt.Println(bytes.Equal(plainText, expectedOutput))
	// Output: true
}

func ExampleExercise8() {
	fmt.Println(Exercise8())
	// Output: d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a
}
