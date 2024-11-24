package cryptopals

import (
	"bytes"
	"crypto/aes"
	_ "embed"
	"encoding/base64"
	"math/rand"
	"testing"
)

//go:embed set2exercise10input.txt
var exercise10input string

//go:embed set2exercise10output.txt
var exercise10output string

//go:embed set2exercise12input.txt
var exercise12input string

// Title: Implement PKCS#7 padding
// Description: Pad any block to a specific block length, by appending the number of bytes of padding to the end of the block.
func TestExercise9(t *testing.T) {
	output := padToMultipleNBytes([]byte("YELLOW SUBMARINE"), 20)
	if string(output) != "YELLOW SUBMARINE\x04\x04\x04\x04" {
		t.Errorf("unexpected output for exercise 9: %s", output)
	}
}

// Title: Implement CBC mode
// Description: Implement CBC mode by hand by taking the ECB function you wrote earlier.
// The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
func TestExercise10(t *testing.T) {
	e, err := newAESCBC([]byte("YELLOW SUBMARINE"), make([]byte, aes.BlockSize))
	if err != nil {
		t.Fatalf("unexpected error creating CBC: %s", err)
	}

	fileTextAsBytes, err := base64.StdEncoding.DecodeString(exercise10input)
	if err != nil {
		t.Fatalf("unexpected error decoding input for exercise 10: %s", err)
	}

	output, err := e.decrypt(fileTextAsBytes)
	if err != nil {
		t.Errorf("unexpected error decrypting file: %s", err)
	}

	if string(output) != exercise10output {
		t.Errorf("unexpected output for exercise 10: %s", output)
	}
}

// Title: An ECB/CBC detection oracle
// Description: Detect the block cipher mode the function is using each time.
// You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
func TestExercise11(t *testing.T) {
	for range 100 {
		// We create 5 blocks of repeated bytes.
		cipherText, mode, err := ecbOrCBCEncryption(bytes.Repeat([]byte{byte(rand.Intn(aes.BlockSize))}, aes.BlockSize*5))
		if err != nil {
			t.Errorf("unexpected error encrypting: %s", err)
			continue
		}

		guessedMode := detectRandomEBCCBCMode(cipherText)
		if guessedMode != mode {
			t.Errorf("guessed mode %d does not match expected mode %d", guessedMode, mode)
		}
	}
}

// Title: Byte-at-a-time ECB decryption (Simple)
// Description: What you have now is a function that produces: AES-128-ECB(your-string || unknown-string, random-key)
// It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
func TestExercise12(t *testing.T) {
	decodedInput, err := base64.StdEncoding.DecodeString(exercise12input)
	if err != nil {
		t.Fatalf("unexpected error decoding input for exercise 12: %s", err)
	}

	e := newECBEncryptionOracle(make([]byte, 0), decodedInput)
	output := decryptUnknownStringFromOracle(e)
	if !bytes.Equal(output, bytes.TrimSpace(decodedInput)) {
		t.Errorf("unexpected output for exercise 12: %s", output)
	}
}

func TestProfileFor(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedOutput string
	}{
		{
			name:           "empty string",
			input:          "",
			expectedOutput: "email=&uid=10&role=user",
		},
		{
			name:           "standard email",
			input:          "foo@bar.com",
			expectedOutput: "email=foo@bar.com&uid=10&role=user",
		},
		{
			name:           "no email",
			input:          "role=admin",
			expectedOutput: "email=roleadmin&uid=10&role=user",
		},
		{
			name:           "With role=admin",
			input:          "email=foo@bar.com&role=admin",
			expectedOutput: "email=emailfoo@bar.comroleadmin&uid=10&role=user",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := profileFor(test.input)
			if output != test.expectedOutput {
				t.Errorf("unexpected output for %s: %s", test.name, output)
			}
		})
	}
}

func TestParsedCookie(t *testing.T) {
	tests := []struct {
		name    string
		cookie  string
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "single pair",
			cookie:  "foo=bar",
			want:    map[string]string{"foo": "bar"},
			wantErr: false,
		},
		{
			name:    "multiple pairs",
			cookie:  "foo=bar&baz=qux",
			want:    map[string]string{"foo": "bar", "baz": "qux"},
			wantErr: false,
		},
		{
			name:    "invalid format missing value",
			cookie:  "foo",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty string",
			cookie:  "",
			want:    map[string]string{},
			wantErr: false,
		},
		{
			name:    "pairs with missing values",
			cookie:  "foo=&baz=qux",
			want:    map[string]string{"foo": "", "baz": "qux"},
			wantErr: false,
		},
		{
			name:    "pair with '=' in value",
			cookie:  "foo=a=b=c&baz=qux",
			want:    map[string]string{"foo": "a=b=c", "baz": "qux"},
			wantErr: false,
		},
		{
			name:    "complex values",
			cookie:  "user=admin&token=123456&bool=true",
			want:    map[string]string{"user": "admin", "token": "123456", "bool": "true"},
			wantErr: false,
		},
		{
			name:    "invalid format no key",
			cookie:  "=bar",
			want:    map[string]string{"": "bar"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsedCookie(tt.cookie)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsedCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !compareMaps(got, tt.want) {
				t.Errorf("parsedCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func compareMaps(got map[string]string, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}

	for key, value := range got {
		if wantValue, ok := want[key]; !ok || wantValue != value {
			return false
		}
	}

	return true
}

// Title: ECB cut-and-paste
// Description: Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
func TestExercise13(t *testing.T) {
	e, err := newAESECB(nil)
	if err != nil {
		t.Fatalf("unexpected error creating ECB: %s", err)
	}

	email := []byte("thedad@me.")
	// We need admin to be in its own block so we can cut it.
	admin := padToMultipleNBytes([]byte("admin"), aes.BlockSize)
	leftOver := []byte("com")
	encryptedProfile := e.profileAndEncrypt(string(append(email, append(admin, leftOver...)...)))
	// Cut-and-paste part here.
	profile, err := e.decryptAndParse(encryptedProfile[:aes.BlockSize] + encryptedProfile[2*aes.BlockSize:3*aes.BlockSize] + encryptedProfile[aes.BlockSize:2*aes.BlockSize])
	if err != nil {
		t.Fatalf("unexpected error decrypting and parsing profile: %s", err)
	}

	if profile["role"] != "admin" {
		t.Errorf("unexpected role: %s", profile["role"])
	}
}

// Title: Byte-at-a-time ECB decryption (Harder)
// Description: Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext.
// You're now doing: AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
// Same goal: decrypt the target-bytes.
func TestExercise14(t *testing.T) {
	decodedInput, err := base64.StdEncoding.DecodeString(exercise12input)
	if err != nil {
		t.Fatalf("unexpected error decoding input for exercise 12: %s", err)
	}

	// Since there is randomness involved here, test a few times to make sure the randomness doesn't reflect the result.
	for i := 0; i < 25; i++ {
		// Providing nil for the first parameter will generate random bytes to pre-pend to each encryption.
		e := newECBEncryptionOracle(nil, decodedInput)
		output := decryptUnknownStringFromOracle(e)
		if !bytes.Equal(output, bytes.TrimSpace(decodedInput)) {
			t.Errorf("unexpected output for exercise 13: %s", output)
		}
	}
}

// Title: PKCS#7 padding validation
// Description: Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
func TestExercise15(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedOutput string
		expectedValid  bool
	}{
		{
			name:           "empty string",
			input:          "",
			expectedOutput: "",
		},
		{
			name:           "no padding",
			input:          "foo",
			expectedOutput: "foo",
			expectedValid:  false,
		},
		{
			name:           "valid padding",
			input:          "ICE ICE BABY\x04\x04\x04\x04",
			expectedOutput: "ICE ICE BABY",
			expectedValid:  true,
		},
		{
			name:           "invalid padding",
			input:          "ICE ICE BABY\x05\x05\x05\x05",
			expectedOutput: "ICE ICE BABY\x05\x05\x05\x05",
			expectedValid:  false,
		},
		{
			name:           "invalid padding",
			input:          "ICE ICE BABY\x01\x02\x03\x04",
			expectedOutput: "ICE ICE BABY\x01\x02\x03\x04",
			expectedValid:  false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			output, valid := isValidPadding([]byte(test.input), 16)
			if !bytes.Equal(output, []byte(test.expectedOutput)) {
				t.Errorf("unexpected output for %s: %s", test.name, output)
			}
			if valid == nil != test.expectedValid {
				t.Errorf("unexpected valid for %s: %t", test.name, valid)
			}
		})
	}
}

// Title: CBC bitflipping attacks
// Description: Return true or false based on whether admin=true exists.
// If you've written the first function properly,
// it shouldn't be possible to provide user input to it that will generate the string
// the second function is looking for.
// We will have to break the crypto to do that.
// Instead, modify the ciphertext (without knowledge of the AES key) to achieve this.
func TestExercise16(t *testing.T) {
	c, err := newAESCBC(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error creating CBC: %s", err)
	}

	adminText := []byte(";admin=true;a=b")
	firstBlock := []byte("YELLOW SUBMARINE")
	secondBlock := make([]byte, aes.BlockSize)
	encryptedText := c.prependAppendEncrypt(append(firstBlock, secondBlock...))
	for i := 2 * aes.BlockSize; i < 3*aes.BlockSize && i%aes.BlockSize < len(adminText); i++ {
		encryptedText[i] ^= adminText[i%aes.BlockSize]
	}

	if isAdmin, err := c.decryptCheckAdmin(encryptedText); err != nil {
		t.Errorf("unexpected error decrypting and checking admin: %v", err)
	} else if !isAdmin {
		t.Errorf("unexpected output for exercise 16")
	}
}
