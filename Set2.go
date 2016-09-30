package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	mrand "math/rand"
	"time"
)

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

func EncryptionOracle(InputData []byte) ([]byte, int) {
	mrand.Seed(time.Now().UTC().UnixNano())
	Key := RandomBytes(16)
	InputData = append(RandomBytes(mrand.Intn(6)+5), InputData...)
	InputData = append(InputData, RandomBytes(mrand.Intn(6)+5)...)
	InputData = PadToMultipleNBytes(InputData, 16)
	if mrand.Intn(2) == 1 {
		IV := RandomBytes(16)
		return EncryptAESCBC(InputData, Key, IV), 1
	} else {
		return EncryptAESECB(InputData, Key), 0
	}
}

func DetectRandomEBCCBCMode(BlockSize int) bool {
	blockMatches := 0
	CipherText, Mode := EncryptionOracle(bytes.Repeat([]byte{byte(mrand.Intn(BlockSize))}, BlockSize*5))
	for i := 0; i < len(CipherText)/BlockSize-1; i++ {
		if bytes.Compare(CipherText[BlockSize*i:BlockSize*(i+1)], CipherText[BlockSize*(i+1):BlockSize*(i+2)]) == 0 {
			blockMatches++
		}
	}
	if blockMatches > 0 {
		return Mode == 0
	} else {
		return Mode == 1
	}
}
