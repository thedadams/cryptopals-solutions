package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
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

func DetectRandomEBCCBCMode(BlockSize int) bool {
	blockMatches := 0
	CipherText, Mode := EncryptionOracle(bytes.Repeat([]byte{byte(mrand.Intn(BlockSize))}, BlockSize*5), BlockSize)
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

func EBCEncryptionOracle(MyString, Key []byte) []byte {
	UnknownString, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	UnknownString = append(MyString, UnknownString...)
	UnknownString = PadToMultipleNBytes(UnknownString, len(Key))
	return EncryptAESECB(UnknownString, Key)
}

func GuessBlockSizeOfCipher(Key []byte) int {
	IdenticalString := make([]byte, 1)
	IdenticalString[0] = byte(1)
	OutputSize := len(EBCEncryptionOracle(IdenticalString, Key))
	for OutputSize == len(EBCEncryptionOracle(IdenticalString, Key)) {
		IdenticalString = append(IdenticalString, byte(1))
	}
	return len(EBCEncryptionOracle(IdenticalString, Key)) - OutputSize
}

func ByteAtATimeEBCDecryption() []byte {
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
	return KnownPartOfString
}
