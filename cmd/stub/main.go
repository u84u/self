// Command stub loads a payload sealed by self. It is the inner
// executable of every packed artifact: find the blob, open it with a key
// from the local SSH directory, run the plaintext. Any failure ends in a
// bare crash.
package main

import (
	"os"

	"github.com/u84u/self/internal/unlock"
)

func main() {
	exit, err := unlock.Run()
	if err != nil {
		unlock.Crash()
	}
	os.Exit(exit)
}
