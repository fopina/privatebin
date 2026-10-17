package utils

import "testing"

func TestStripANSI(t *testing.T) {
	input := "\x1b[31mred text\x1b[0m"
	if got, want := StripANSI(input), "red text"; got != want {
		t.Fatalf("StripANSI() = %q, want %q", got, want)
	}
}
