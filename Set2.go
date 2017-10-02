package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	mrand "math/rand"
	"strings"
	"time"
)

type PaddingError []byte

func (f PaddingError) Error() string {
	return fmt.Sprintf("math: square root of negative number %v", []byte(f))
}

// Given an int, we pad the bytes to the nearest multiple of N.
func PadToMultipleNBytes(text []byte, N int) []byte {
	BytesToAdd := N - (len(text) % N)
	return append(text, bytes.Repeat([]byte{byte(BytesToAdd)}, BytesToAdd)...)
}

func DecryptAESCBC(CipherText, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(CipherText) < aes.BlockSize {
		panic("ciphertext too short")
	}

	// CBC mode always works in whole blocks.
	if len(CipherText)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	for i := 0; i < len(CipherText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode.CryptBlocks(CipherText[i*aes.BlockSize:(i+1)*aes.BlockSize], CipherText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return CipherText
}

func EncryptAESCBC(PlainText, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the plaintext.
	if len(PlainText) < aes.BlockSize {
		panic("Plain text too short")
	}

	// CBC mode always works in whole blocks.
	if len(PlainText)%aes.BlockSize != 0 {
		panic("Plain text is not a multiple of the block size")
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	for i := 0; i < len(PlainText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode.CryptBlocks(PlainText[i*aes.BlockSize:(i+1)*aes.BlockSize], PlainText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return PlainText
}

func RandomBytes(NumBytes int) []byte {
	Key := make([]byte, NumBytes)
	n, err := crand.Read(Key)
	if err != nil || n != NumBytes {
		fmt.Println("ERROR: could not generate random bytes.")
		return nil
	}
	return Key
}

func EncryptionOracle(InputData []byte, BlockSize int) ([]byte, int) {
	mrand.Seed(time.Now().UTC().UnixNano())
	Key := RandomBytes(BlockSize)
	InputData = append(RandomBytes(mrand.Intn(6)+5), InputData...)
	InputData = append(InputData, RandomBytes(mrand.Intn(6)+5)...)
	InputData = PadToMultipleNBytes(InputData, BlockSize)
	if mrand.Intn(2) == 1 {
		IV := RandomBytes(BlockSize)
		return EncryptAESCBC(InputData, Key, IV), 1
	} else {
		return EncryptAESECB(InputData, Key), 0
	}
}

func DetectRandomEBCCBCMode(BlockSize int) (bool, int) {
	blockMatches := 0
	CipherText, Mode := EncryptionOracle(bytes.Repeat([]byte{byte(mrand.Intn(BlockSize))}, BlockSize*5), BlockSize)
	for i := 0; i < len(CipherText)/BlockSize-1; i++ {
		if bytes.Compare(CipherText[BlockSize*i:BlockSize*(i+1)], CipherText[BlockSize*(i+1):BlockSize*(i+2)]) == 0 {
			blockMatches++
		}
	}
	if blockMatches > 0 {
		return Mode == 0, 0
	} else {
		return Mode == 1, 0
	}
}

func EBCEncryptionOracle(Prepend, MyString, Key []byte) []byte {
	UnknownString, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	UnknownString = append(Prepend, append(MyString, UnknownString...)...)
	UnknownString = PadToMultipleNBytes(UnknownString, len(Key))
	return EncryptAESECB(UnknownString, Key)
}

func GuessBlockSizeOfCipher(Key []byte) int {
	IdenticalString := make([]byte, 1)
	IdenticalString[0] = byte(1)
	Prepend := make([]byte, 0)
	OutputSize := len(EBCEncryptionOracle(Prepend, IdenticalString, Key))
	for OutputSize == len(EBCEncryptionOracle(Prepend, IdenticalString, Key)) {
		IdenticalString = append(IdenticalString, byte(1))
	}
	return len(EBCEncryptionOracle(Prepend, IdenticalString, Key)) - OutputSize
}

func DetectLengthOfRandomBytes(RandomPrepend, Key []byte, BlockSize int) int {
	FillPrependToBlockSize := make([]byte, 0)
	NumBlocks := len(EBCEncryptionOracle(RandomPrepend, FillPrependToBlockSize, Key))
	for NumBlocks == len(EBCEncryptionOracle(RandomPrepend, append(FillPrependToBlockSize, byte(0)), Key)) {
		FillPrependToBlockSize = append(FillPrependToBlockSize, byte(0))
	}
	TotalExtraPadding := len(FillPrependToBlockSize)
	FillPrependToBlockSize = append(FillPrependToBlockSize, make([]byte, 3*BlockSize)...)
	EncryptedDataToFind := EBCEncryptionOracle(RandomPrepend, FillPrependToBlockSize, Key)
	i := 0
	j := -1
	for bytes.Compare(EncryptedDataToFind[i*BlockSize:(i+1)*BlockSize], EncryptedDataToFind[(i+1)*BlockSize:(i+2)*BlockSize]) != 0 {
		i++
	}
	for bytes.Compare(EncryptedDataToFind[i*BlockSize:(i+1)*BlockSize], EncryptedDataToFind[(i+1)*BlockSize:(i+2)*BlockSize]) == 0 {
		FillPrependToBlockSize = FillPrependToBlockSize[:len(FillPrependToBlockSize)-1]
		EncryptedDataToFind = EBCEncryptionOracle(RandomPrepend, FillPrependToBlockSize, Key)
		j++
	}
	for bytes.Compare(EncryptedDataToFind[(i-1)*BlockSize:i*BlockSize], EncryptedDataToFind[i*BlockSize:(i+1)*BlockSize]) == 0 {
		i--
	}
	return i*BlockSize - TotalExtraPadding + (j % BlockSize) - BlockSize*(1-j/BlockSize)
}

func ParsedCookie(Cookie string) map[string]string {
	Tokens := strings.Split(Cookie, "&")
	ParsedCookie := make(map[string]string)
	for _, val := range Tokens {
		Item := strings.Split(val, "=")
		if len(Item) != 2 {
			fmt.Println("ERROR: Invalid Cookie")
		} else {
			ParsedCookie[Item[0]] = Item[1]
		}
	}
	return ParsedCookie
}

func ProfileFor(Email string) string {
	Email = strings.Replace(Email, "&", "", -1)
	Email = strings.Replace(Email, "=", "", -1)
	return "email=" + Email + "&uid=10&role=user"
}

func ProfileAndEncrypt(Email string, Key []byte) string {
	BlockSize := GuessBlockSizeOfCipher([]byte(Key))
	return string(EncryptAESECB(PadToMultipleNBytes([]byte(ProfileFor(Email)), BlockSize), Key))
}

func DecryptAndParse(CipherText string, Key []byte) map[string]string {
	return ParsedCookie(string(DecryptAESECB([]byte(CipherText), Key)))
}

func VerifyPadding(Text []byte, BlockSize int) ([]byte, error) {
	if Text[len(Text)-1] >= byte(BlockSize) {
		return Text, nil
	}
	PaddedByte := Text[len(Text)-1]
	for i := len(Text) - 1; i > len(Text)-1-int(PaddedByte); i-- {
		if Text[i] != PaddedByte {
			return PaddingError(Text), PaddingError(Text)
		}
	}
	return Text[:len(Text)-1-int(PaddedByte)], nil
}

func PrependAppendCBCEncrypt(Text, Key, IV []byte) []byte {
	Prepend := []byte("comment1=cooking%20MCs;userdata=")
	Append := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	Text = bytes.Replace(bytes.Replace(Text, []byte("="), []byte(""), -1), []byte(";"), []byte(""), -1)
	return EncryptAESCBC(PadToMultipleNBytes(append(append(Prepend, Text...), Append...), 16), Key, IV)
}

func DecryptCBCCheckAdim(CipherText, Key, IV []byte) bool {
	Text := DecryptAESCBC(CipherText, Key, IV)
	for _, val := range bytes.Split(Text, []byte(";")) {
		tuple := bytes.Split(val, []byte("="))
		if len(tuple) == 2 && bytes.Equal(tuple[0], []byte("admin")) && bytes.Equal(tuple[1], []byte("true")) {
			return true
		}
	}
	return false
}
