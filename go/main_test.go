package main

import (
	"encoding/hex"
	"testing"
)

func TestHmacSha1(t *testing.T) {
	r := hmacSha1("$3cr3tP4$$", "0")
	got := hex.EncodeToString(r)
	want := []byte("5d1014482edb0afb42101d8d4b5ff9bb5340a683")

	if string(want) != string(got) {
		t.Errorf("want %q got %q", string(want), string(got))
	}
}
