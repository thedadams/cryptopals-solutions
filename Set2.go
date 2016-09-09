package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func PadToNBytes(text []byte, N int) []byte {
	BytesToAdd := N - len(text)
	for i := 0; i < BytesToAdd; i++ {
		text = append(text, bytes.Repeat([]byte{byte(BytesToAdd)}, BytesToAdd)...)
	}
	return text
}

func DecryptAESCBC(CipherText, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(CipherText) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		iv[i] = 0
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
