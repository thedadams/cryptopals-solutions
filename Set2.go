package crypto

import "bytes"

func PadToNBytes(text []byte, N int) []byte {
	BytesToAdd := N - len(text)
	for i := 0; i < BytesToAdd; i++ {
		text = append(text, bytes.Repeat([]byte{byte(BytesToAdd)}, BytesToAdd)...)
	}
	return text
}
