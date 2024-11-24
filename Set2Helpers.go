package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"strings"
)

// aescbc is used to encrypt and decrypt using CBC mode.
type aescbc struct {
	block cipher.Block
	key   []byte
	iv    []byte
}

// newAESCBC takes a Key and IV and creates a new aescbc.
func newAESCBC(key, iv []byte) (aescbc, error) {
	// If the key is nil, we create a random one.
	if key == nil {
		key = randomBytes(aes.BlockSize)
	}
	// If the IV is nil, then we create a random one.
	if iv == nil {
		iv = randomBytes(len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return aescbc{}, err
	}
	return aescbc{block: block, key: key, iv: iv}, nil
}

// decrypt decrypts cipher text using CBC mode.
func (c aescbc) decrypt(cipherText []byte) ([]byte, error) {
	// CBC mode always works in whole blocks.
	if len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of the block size %d", len(cipherText), aes.BlockSize)
	}

	decryptedText := make([]byte, len(cipherText))
	mode := cipher.NewCBCDecrypter(c.block, c.iv)
	for i := 0; i < len(cipherText)/aes.BlockSize; i++ {
		mode.CryptBlocks(decryptedText[i*aes.BlockSize:(i+1)*aes.BlockSize], cipherText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return decryptedText, nil
}

// encrypt encrypts the plainText using CBC mode.
func (c aescbc) encrypt(plainText []byte) []byte {
	// CBC mode always works in whole blocks.
	plainText = padToMultipleNBytes(plainText, len(c.key))
	encryptedText := make([]byte, len(plainText))

	mode := cipher.NewCBCEncrypter(c.block, c.iv)

	for i := 0; i < len(plainText)/aes.BlockSize; i++ {
		// CryptBlocks can work in-place if the two arguments are the same.
		mode.CryptBlocks(encryptedText[i*aes.BlockSize:(i+1)*aes.BlockSize], plainText[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return encryptedText
}

// prependAppendEncrypt prepends and appends strings and encrypts the data.
// We can't allow the user to include a semicolon nor an equal sign.
func (c aescbc) prependAppendEncrypt(text []byte) []byte {
	prepended := []byte("comment1=cooking%20MCs;userdata=")
	appended := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	// Get rid of = and ;
	text = bytes.ReplaceAll(bytes.ReplaceAll(text, []byte("="), []byte("")), []byte(";"), []byte(""))
	return c.encrypt(append(append(prepended, text...), appended...))
}

// decryptCheckAdmin uses an aescbc to decrypt the cipher text and then checks for "admin=true;"
func (c aescbc) decryptCheckAdmin(cipherText []byte) (bool, error) {
	text, err := c.decrypt(cipherText)
	if err != nil {
		return false, err
	}

	// Split the text into tuples.
	for _, val := range bytes.Split(text, []byte(";")) {
		tuple := bytes.Split(val, []byte("="))
		// If the tuple is of length 2, check if we have admin = true.
		if len(tuple) == 2 && bytes.Equal(tuple[0], []byte("admin")) && bytes.Equal(tuple[1], []byte("true")) {
			return true, nil
		}
	}
	return false, nil
}

// ecbEncryptionOracle is used exactly as described on the cryptopals website.
type ecbEncryptionOracle struct {
	ecb           aesecb
	prepend       []byte
	unknownString []byte
}

// newECBEncryptionOracle creates a new oracle.
func newECBEncryptionOracle(prepend, unknownString []byte) ecbEncryptionOracle {
	a, _ := newAESECB(nil)
	if prepend == nil {
		prepend = randomBytes(rand.Intn(50) + 1)
	}
	return ecbEncryptionOracle{a, prepend, unknownString}
}

// encrypt uses the encryption oracle to encryption my string with the prepended string and unknown string.
func (e ecbEncryptionOracle) encrypt(myString []byte) []byte {
	return e.ecb.encrypt(append(e.prepend, append(myString, e.unknownString...)...))
}

// guessBlockSizeOfCipher tries to guess the block size of the ECB Encryption Oracle.
func guessBlockSizeOfCipher(e ecbEncryptionOracle) int {
	identicalString := make([]byte, 1)
	identicalString[0] = byte(1)
	outputSize := len(e.encrypt(identicalString))
	for outputSize == len(e.encrypt(identicalString)) {
		identicalString = append(identicalString, byte(1))
	}
	return len(e.encrypt(identicalString)) - outputSize
}

// decryptUnknownStringFromOracle will use the given EBC encryptor to decrypt the given ciphertext.
func decryptUnknownStringFromOracle(e ecbEncryptionOracle) []byte {
	blockSize := guessBlockSizeOfCipher(e)
	lengthOfRandomPrepend := detectLengthOfRandomBytes(e, blockSize)
	// We fill so that the prepended portion looks like it ends exactly at a block.
	fillPrependToBlockSize := make([]byte, blockSize-(lengthOfRandomPrepend%blockSize))
	numBlocksForPrepend := (lengthOfRandomPrepend / blockSize) + 1
	numBlocksToFind := len(e.encrypt(fillPrependToBlockSize))/blockSize - numBlocksForPrepend

	var (
		blocksFound       int
		knownPartOfString []byte
	)
	for blocksFound < numBlocksToFind {
		// Following directions, we create a repeated string one smaller than the block size.
		identicalString := bytes.Repeat([]byte{0}, blockSize-1)
		// Now we find the byte that will take the empty spot in the repeated string.
		// We build thisBlock byte by byte.
		thisBlock := make([]byte, 0)
		for j := 0; j < blockSize; j++ {
			thisBlock = append(thisBlock, 0)
			for i := 0; i < 256; i++ {
				thisBlock[j] = byte(i)
				thisTest := e.encrypt(append(append(append(append(fillPrependToBlockSize, identicalString...), knownPartOfString...), thisBlock...), identicalString[:blockSize-j-1]...))[numBlocksForPrepend*blockSize:]
				// Test the appropriate encrypted blocks to see if they're the same.
				// If they are, then we have the next byte.
				if bytes.Equal(thisTest[:blockSize*(blocksFound+1)], thisTest[blockSize*(blocksFound+1):2*(blockSize*(blocksFound+1))]) {
					// If we haven't completed this block, we append to thisBlock, shorten the identicalString
					// and keep going.
					if blockSize-j-2 > -1 {
						identicalString = identicalString[:blockSize-j-2]
					}
					break
				}
			}
		}
		// At this point, we know the next block, so we add it to the end of the known part of the string.
		knownPartOfString = append(knownPartOfString, thisBlock...)
		blocksFound++
	}

	return bytes.Trim(knownPartOfString, string(nonEnglishChars()))
}

// profileAndEncrypt creates a profile for the given email and encrypts it.
func (ecb aesecb) profileAndEncrypt(Email string) string {
	return string(ecb.encrypt([]byte(profileFor(Email))))
}

// decryptAndParse decrypts a cookie and parses it.
func (ecb aesecb) decryptAndParse(cipherText string) (map[string]string, error) {
	output, err := ecb.decrypt([]byte(cipherText))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	parsed, err := parsedCookie(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse: %w", err)
	}

	return parsed, nil
}

// ecbOrCBCEncryption takes input, appends some random bytes at the beginning and end, and
// encrypts using a random key with CBC half the time and ECB half the time.
func ecbOrCBCEncryption(inputData []byte) ([]byte, int, error) {
	key := randomBytes(aes.BlockSize)
	// Append bytes to the beginning.
	inputData = append(randomBytes(rand.Intn(6)+5), inputData...)
	// Append bytes to the end.
	inputData = append(inputData, randomBytes(rand.Intn(6)+5)...)
	if rand.Intn(2) == 1 {
		c, err := newAESCBC(key, nil)
		if err != nil {
			return nil, 0, err
		}
		return c.encrypt(inputData), 1, err
	}

	e, err := newAESECB(key)
	if err != nil {
		return nil, 0, err
	}

	return e.encrypt(inputData), 0, err
}

// detectLengthOfRandomBytes is an "add on" method that tries to guess the length of the random bytes prepended
// by the encryption oracle.
func detectLengthOfRandomBytes(e ecbEncryptionOracle, blockSize int) int {
	// First, we find the total padding for the entire string.
	fillPrependToBlockSize := make([]byte, 0)
	numBlocks := len(e.encrypt(fillPrependToBlockSize))
	for numBlocks == len(e.encrypt(append(fillPrependToBlockSize, 0))) {
		fillPrependToBlockSize = append(fillPrependToBlockSize, 0)
	}
	totalExtraPadding := len(fillPrependToBlockSize)
	fillPrependToBlockSize = append(fillPrependToBlockSize, make([]byte, 3*blockSize)...)
	encryptedDataToFind := e.encrypt(fillPrependToBlockSize)
	// Now we know the total padding.
	// Now we back off to find the padding at the end of the string.
	i := 0
	j := -1
	for !bytes.Equal(encryptedDataToFind[i*blockSize:(i+1)*blockSize], encryptedDataToFind[(i+1)*blockSize:(i+2)*blockSize]) {
		i++
	}
	for bytes.Equal(encryptedDataToFind[i*blockSize:(i+1)*blockSize], encryptedDataToFind[(i+1)*blockSize:(i+2)*blockSize]) {
		fillPrependToBlockSize = fillPrependToBlockSize[:len(fillPrependToBlockSize)-1]
		encryptedDataToFind = e.encrypt(fillPrependToBlockSize)
		j++
	}

	for i > 0 && bytes.Equal(encryptedDataToFind[(i-1)*blockSize:i*blockSize], encryptedDataToFind[i*blockSize:(i+1)*blockSize]) {
		i--
	}
	// Now i contains the total blocks of padding,
	// j is the size of the padding at the end of the string,
	// and there is an error term at the end where the length of the random prepend and the padding
	// at the end of the string could fall to mess things up by one block.
	// The error term takes care of that.
	return i*blockSize - totalExtraPadding + (j % blockSize) - blockSize*(1-j/blockSize)
}

// detectRandomEBCCBCMode will detect whether the cipher text was encrypted with EBC or CBC mode.
func detectRandomEBCCBCMode(cipherText []byte) int {
	for i := 0; i < len(cipherText)/aes.BlockSize-1; i++ {
		if bytes.Equal(cipherText[aes.BlockSize*i:aes.BlockSize*(i+1)], cipherText[aes.BlockSize*(i+1):aes.BlockSize*(i+2)]) {
			// A block matches, so probably EBC mode.
			return 0
		}
	}

	// None of the blocks match, so probably CBC mode.
	return 1
}

/*
parsedCookie takes a string of the form foo=bar&baz=qux&zap=sizzle and produces

	{
		foo: 'bar',
		baz: 'qux',
		zap: 'sizzle'
	  }
*/
func parsedCookie(cookie string) (map[string]string, error) {
	if cookie == "" {
		return nil, nil
	}

	tokens := strings.Split(cookie, "&")
	parsedCookie := make(map[string]string, len(tokens))
	for _, val := range tokens {
		key, val, ok := strings.Cut(val, "=")
		if !ok {
			return nil, fmt.Errorf("invalid cookie: %s", cookie)
		} else {
			parsedCookie[key] = val
		}
	}
	return parsedCookie, nil
}

// profileFor takes an email and creates a profile cookie, originally for exercise 13
func profileFor(email string) string {
	email = strings.ReplaceAll(email, "&", "")
	email = strings.ReplaceAll(email, "=", "")
	return "email=" + email + "&uid=10&role=user"
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
