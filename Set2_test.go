package crypto

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"sort"
)

func ExampleExercise9() {
	fmt.Println(string(Exercise9()))
	// Output: YELLOW SUBMARINE
}

func ExampleExercise10() {
	ExpectedOutput, _ := ioutil.ReadFile("Set2_10Output.txt")
	fmt.Println(bytes.Equal(Exercise10("Set2_10.txt"), ExpectedOutput))
	// Output: true
}

func ExampleExercise11() {
	Exercise11()
	// Output: truetruetruetruetruetruetruetruetruetrue
}

func ExampleExercise12() {
	expectedOutput, _ := ioutil.ReadFile("Set2_12Output.txt")
	expectedOutput = bytes.TrimSpace(expectedOutput)
	fmt.Println(bytes.Equal(Exercise12(expectedOutput), expectedOutput))
	// Output: true
}

func ExampleParsedCookie() {
	Output := ParsedCookie("foo=bar&baz=qux&zap=sizzle")
	keys := []string{}
	for k := range Output {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Print(key + "=" + Output[key] + ",")
	}
	// Output: baz=qux,foo=bar,zap=sizzle,
}

func ExampleProfileFor() {
	fmt.Println(ProfileFor("foo@bar.com"))
	fmt.Println(ProfileFor("foo@bar.com&role=admin"))
	// Output: email=foo@bar.com&uid=10&role=user
	// email=foo@bar.comroleadmin&uid=10&role=user
}

func ExampleExercise13() {
	Exercise13()
	// Output: admin
}

func ExampleExercise14() {
	expectedOutput, _ := ioutil.ReadFile("Set2_12Output.txt")
	expectedOutput = bytes.TrimSpace(expectedOutput)
	fmt.Println(bytes.Equal(Exercise14(expectedOutput), expectedOutput))
	// Output: true
}

func ExampleExercise15() {
	Exercise15()
	// Output: truefalsefalsetrue
}

func ExampleExercise16() {
	Exercise16()
	// Output: true
}
