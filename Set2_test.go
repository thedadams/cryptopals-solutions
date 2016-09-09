package crypto

import "fmt"

func ExamplePadToNBytes() {
	fmt.Println(string(PadToNBytes([]byte("YELLOW SUBMARINE"), 20)))
	// Output: YELLOW SUBMARINE
}
