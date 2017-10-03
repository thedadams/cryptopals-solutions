package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cRand "crypto/rand"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// PaddingError is a type used to indicate that there is a padding error with a plain text
type PaddingError []byte

func (f PaddingError) Error() string {
	return fmt.Sprintf("math: square root of negative number %v", []byte(f))
}

// AESCBC is used to encrypt and decrypt using CBC mode.
type AESCBC struct {
	block cipher.Block
	key   []byte
	iv    []byte
}

// NewAESCBC takes a Key and IV and creates a new AESCBC.
func NewAESCBC(key, iv []byte) AESCBC {
	// If the key is nil, we create a random one.
	if key == nil {
		key = RandomBytes(aes.BlockSize)
	}
	// If the IV is nil, then we create a random one.
	if iv == nil {
		iv = RandomBytes(len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return AESCBC{block: block, key: key, iv: iv}
}

// PadToMultipleNBytes pads the bytes to the nearest multiple of N.
func PadToMultipleNBytes(text []byte, N int) []byte {
	BytesToAdd := N - (len(text) % N)
	return append(text, bytes.Repeat([]byte{byte(BytesToAdd)}, BytesToAdd)...)
}

// Decrypt decrypts cipher text using CBC mode.
func (c AESCBC) Decrypt(cipherText []byte) []byte {
	// CBC mode always works in whole blocks.
	if len(cipherText)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(c.block, c.iv)

	for i := 0; i < len(cipherText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode.CryptBlocks(cipherText[i*aes.BlockSize:(i+1)*aes.BlockSize], cipherText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return cipherText
}

// Encrypt encrypts the plainText using CBC mode.
func (c AESCBC) Encrypt(plainText []byte) []byte {
	// CBC mode always works in whole blocks.
	plainText = PadToMultipleNBytes(plainText, len(c.key))

	mode := cipher.NewCBCEncrypter(c.block, c.iv)

	for i := 0; i < len(plainText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode.CryptBlocks(plainText[i*aes.BlockSize:(i+1)*aes.BlockSize], plainText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return plainText
}

// PrependAppendEncrypt prepends and appends strings and encrypts the data.
// We cannot allow the user to include a semicolon nor an equal sign.
func (c AESCBC) PrependAppendEncrypt(text []byte) []byte {
	prepended := []byte("comment1=cooking%20MCs;userdata=")
	appended := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	// Get rid of = and ;
	text = bytes.Replace(bytes.Replace(text, []byte("="), []byte(""), -1), []byte(";"), []byte(""), -1)
	return c.Encrypt(append(append(prepended, text...), appended...))
}

// DecryptCheckAdmin uses an AESCBC to decrypt the cipher text and then checks for "admin=true;"
func (c AESCBC) DecryptCheckAdmin(cipherText []byte) bool {
	text := c.Decrypt(cipherText)
	for _, val := range bytes.Split(text, []byte(";")) {
		tuple := bytes.Split(val, []byte("="))
		// If the tuple is of length 2, check if we have admin = true.
		if len(tuple) == 2 && bytes.Equal(tuple[0], []byte("admin")) && bytes.Equal(tuple[1], []byte("true")) {
			return true
		}
	}
	return false
}

// ECBEncryptionOracle is used exactly as described on the cryptopals website.
type ECBEncryptionOracle struct {
	ecb           AESECB
	prepend       []byte
	unknownString []byte
}

// NewECBEncryptionOracle creates a new oracle.
func NewECBEncryptionOracle(prepend, unknownString []byte) ECBEncryptionOracle {
	a := NewAESECB(nil)
	if prepend == nil {
		prepend = RandomBytes(rand.Intn(50) + 1)
	}
	return ECBEncryptionOracle{a, prepend, unknownString}
}

// Encrypt uses the encryption oracle to encryption my string with the prepended string and unknown string.
func (e ECBEncryptionOracle) Encrypt(myString []byte) []byte {
	return e.ecb.Encrypt(append(e.prepend, append(myString, e.unknownString...)...))
}

// GuessBlockSizeOfCipher is an "add on" method that tries to guess the block size of the ECB Encryption Oracle.
func (e ECBEncryptionOracle) GuessBlockSizeOfCipher() int {
	identicalString := make([]byte, 1)
	identicalString[0] = byte(1)
	outputSize := len(e.Encrypt(identicalString))
	for outputSize == len(e.Encrypt(identicalString)) {
		identicalString = append(identicalString, byte(1))
	}
	return len(e.Encrypt(identicalString)) - outputSize
}

// DetectLengthOfRandomBytes is an "add on" method that tries to guess the length of the random bytes prepended
// by the encryption oracle.
func (e ECBEncryptionOracle) DetectLengthOfRandomBytes(blockSize int) int {
	// First we find the total padding for the entire string.
	fillPrependToBlockSize := make([]byte, 0)
	numBlocks := len(e.Encrypt(fillPrependToBlockSize))
	for numBlocks == len(e.Encrypt(append(fillPrependToBlockSize, byte(0)))) {
		fillPrependToBlockSize = append(fillPrependToBlockSize, byte(0))
	}
	totalExtraPadding := len(fillPrependToBlockSize)
	fillPrependToBlockSize = append(fillPrependToBlockSize, make([]byte, 3*blockSize)...)
	encryptedDataToFind := e.Encrypt(fillPrependToBlockSize)
	// Now we know the total padding.
	// Now we back off to find the padding at the end of the string.
	i := 0
	j := -1
	for !bytes.Equal(encryptedDataToFind[i*blockSize:(i+1)*blockSize], encryptedDataToFind[(i+1)*blockSize:(i+2)*blockSize]) {
		i++
	}
	for bytes.Equal(encryptedDataToFind[i*blockSize:(i+1)*blockSize], encryptedDataToFind[(i+1)*blockSize:(i+2)*blockSize]) {
		fillPrependToBlockSize = fillPrependToBlockSize[:len(fillPrependToBlockSize)-1]
		encryptedDataToFind = e.Encrypt(fillPrependToBlockSize)
		j++
	}
	for bytes.Equal(encryptedDataToFind[(i-1)*blockSize:i*blockSize], encryptedDataToFind[i*blockSize:(i+1)*blockSize]) {
		i--
	}
	// Now i contains the total blocks of padding,
	// j is the size of the padding at the end of the string,
	// and there is a error term at the end where the length of the random prepend and the padding
	// at the end of the string could fall to mess things up by one block.
	// The error term takes care of that.
	return i*blockSize - totalExtraPadding + (j % blockSize) - blockSize*(1-j/blockSize)
}

// ProfileAndEncrypt creates a profile for the given email and encrypts it.
func (e AESECB) ProfileAndEncrypt(Email string) string {
	return string(e.Encrypt([]byte(ProfileFor(Email))))
}

// DecryptAndParse decrypts a cookie and parses it.
func (e AESECB) DecryptAndParse(cipherText string) map[string]string {
	return ParsedCookie(string(e.Decrypt([]byte(cipherText))))
}

// RandomBytes generates a random number of bytes.
// Used for things like keys and ivs.
func RandomBytes(numBytes int) []byte {
	key := make([]byte, numBytes)
	// Read random bytes into key.
	n, err := cRand.Read(key)
	if err != nil || n != numBytes {
		fmt.Println("ERROR: could not generate random bytes.")
		return nil
	}
	return key
}

// ECBOrCBCEncryption takes input, appends some random bytes at the beginning and end, and
// encrypts using a random key with CBC half the time and ECB half the time.
func ECBOrCBCEncryption(inputData []byte) ([]byte, int) {
	rand.Seed(time.Now().UTC().UnixNano())
	key := RandomBytes(aes.BlockSize)
	// Append bytes to the beginning.
	inputData = append(RandomBytes(rand.Intn(6)+5), inputData...)
	// Append bytes to the end.
	inputData = append(inputData, RandomBytes(rand.Intn(6)+5)...)
	if rand.Intn(2) == 1 {
		c := NewAESCBC(key, nil)
		return c.Encrypt(inputData), 1
	}
	e := NewAESECB(key)
	return e.Encrypt(inputData), 0
}

// DetectRandomEBCCBCMode passes some carefully chosen input to ECBOrCBCEncryption and guess which mode was
// used to encrypt the data.
func DetectRandomEBCCBCMode() bool {
	blockMatches := 0
	// We create 5 blocks of repeated bytes.
	cipherText, mode := ECBOrCBCEncryption(bytes.Repeat([]byte{byte(rand.Intn(aes.BlockSize))}, aes.BlockSize*5))
	// Now we look to see if those blocks are repeated in the cipher text.
	for i := 0; i < len(cipherText)/aes.BlockSize-1; i++ {
		if bytes.Compare(cipherText[aes.BlockSize*i:aes.BlockSize*(i+1)], cipherText[aes.BlockSize*(i+1):aes.BlockSize*(i+2)]) == 0 {
			blockMatches++
		}
	}
	// If we see the repeated blocks in the cipher text, then we are using ECB mode.
	if blockMatches > 0 {
		return mode == 0
	}
	return mode == 1
}

/*ParsedCookie takes a string of the form foo=bar&baz=qux&zap=sizzle and produces
{
	foo: 'bar',
	baz: 'qux',
	zap: 'sizzle'
  }
*/
func ParsedCookie(cookie string) map[string]string {
	tokens := strings.Split(cookie, "&")
	parsedCookie := make(map[string]string)
	for _, val := range tokens {
		item := strings.Split(val, "=")
		if len(item) != 2 {
			fmt.Println("ERROR: Invalid Cookie")
		} else {
			parsedCookie[item[0]] = item[1]
		}
	}
	return parsedCookie
}

// ProfileFor takes an email and creates a profile cookie, originally for exercise 13
func ProfileFor(Email string) string {
	Email = strings.Replace(Email, "&", "", -1)
	Email = strings.Replace(Email, "=", "", -1)
	return "email=" + Email + "&uid=10&role=user"
}

// VerifyPadding verifies that the text has the proper padding, strips it, and returns the text.
// If we encounter an error, then we return a PaddingError
// Otherwise, the error is nil.
func VerifyPadding(text []byte, blockSize int) ([]byte, PaddingError) {
	// If the last byte text is not an apparent padding byte, we assume everything is good.
	if text[len(text)-1] >= byte(blockSize) {
		return text, nil
	}
	// Now we check that the appropriate bytes are padding bytes.
	paddedByte := text[len(text)-1]
	for i := len(text) - 1; i > len(text)-1-int(paddedByte); i-- {
		if text[i] != paddedByte {
			return text, PaddingError(text)
		}
	}
	return text[:len(text)-1-int(paddedByte)], nil
}

func nonEnglishChars() []byte {
	chars := make([]byte, 0)
	for i := 0; i < 256; i++ {
		if !isEnglishChar(byte(i)) {
			chars = append(chars, byte(i))
		}
	}
	return chars
}
