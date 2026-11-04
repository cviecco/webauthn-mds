package jwtlib

import (
	"testing"
)

func TestSplitCompressReassembleRoundTrip(t *testing.T) {
	jwts := []string{
		// Example jwt from rfc7519 section 3.1
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		// Empty payload
		"eyJhbGciOiJub25lIn0..",
	}
	for _, jwt := range jwts {
		header, cpayload, signature, err := SplitCompress(jwt)
		if err != nil {
			t.Fatalf("SplitCompress(%q) failed: %s", jwt, err)
		}
		reassembled, err := Reassemble(header, cpayload, signature)
		if err != nil {
			t.Fatalf("Reassemble failed: %s", err)
		}
		if reassembled != jwt {
			t.Fatalf("round trip mismatch: got %q, want %q", reassembled, jwt)
		}
	}
}

func TestSplitCompressInvalid(t *testing.T) {
	if _, _, _, err := SplitCompress("not-a-jwt"); err == nil {
		t.Fatal("expected error for string without sections")
	}
}

func TestReassembleInvalidPayload(t *testing.T) {
	if _, err := Reassemble("header", []byte("not gzip"), "sig"); err == nil {
		t.Fatal("expected error for non gzip payload")
	}
}
