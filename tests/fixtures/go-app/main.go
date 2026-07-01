package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	// Reachable call into a function with a known advisory (GO-2021-0113)
	tags, _, _ := language.ParseAcceptLanguage("en-US,en;q=0.9")
	fmt.Println(tags)
}
