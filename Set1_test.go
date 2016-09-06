package crypto

import (
	"encoding/hex"
	"fmt"
)

func ExampleHexTo64() {
	fmt.Println(HexStringTo64String("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	// Output: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
}

func ExampleHexXOR() {
	fmt.Println(XORTwoHexStrings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
	// Output: 746865206b696420646f6e277420706c6179
}

func ExampleByteXOR() {
	msg1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	msg2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	fmt.Println(hex.EncodeToString(xorTwoByteStrings(msg1, msg2)))
	// Output: 746865206b696420646f6e277420706c6179
}

func ExampleSingleCharXORDecrypt() {
	fmt.Println(DecryptSingleCharXOR("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	// Output: 436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e 33
}

func ExampleFindEncryptedLine() {
	fmt.Println(FindStringThatHasBeenEncrypted("Set1_4.txt"))
	// Output: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f 4e6f77207468617420746865207061727479206973206a756d70696e670a Now that the party is jumping
}

func ExampleRepeatedKeyXOR() {
	fmt.Println(RepeatedKeyXOR("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"))
	// Output: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
}
