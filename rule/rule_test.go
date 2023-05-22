package rule

import (
	"fmt"
	"log"
	"testing"
)

// TestHelloName calls greetings.Hello with a name, checking
// for a valid return value.
func TestRuleParse(t *testing.T) {
	result, err := Parse("../testdata/rule.json")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", result)
	fmt.Println(result.CheckAccess("www.google.com"))
}

// TestHelloEmpty calls greetings.Hello with an empty string,
// checking for an error.
