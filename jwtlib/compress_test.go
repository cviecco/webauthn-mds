package jwtlib

import (
	"io"
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

func TestSplitCompressReassembleReaderRoundTrip(t *testing.T) {
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
		r, err := ReassembleReader(header, cpayload, signature)
		if err != nil {
			t.Fatalf("ReassembleReader failed: %s", err)
		}
		reassembled, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("reading reassembled jwt failed: %s", err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("Close failed: %s", err)
		}
		if string(reassembled) != jwt {
			t.Fatalf("round trip mismatch: got %q, want %q", reassembled, jwt)
		}
	}
}

func TestReassembleReaderCloseEarly(t *testing.T) {
	jwt := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	header, cpayload, signature, err := SplitCompress(jwt)
	if err != nil {
		t.Fatalf("SplitCompress(%q) failed: %s", jwt, err)
	}
	r, err := ReassembleReader(header, cpayload, signature)
	if err != nil {
		t.Fatalf("ReassembleReader failed: %s", err)
	}
	// Read past the header so the payload pipe is in use.
	buf := make([]byte, len(header)+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("partial read failed: %s", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close failed: %s", err)
	}
	if _, err := io.ReadAll(r); err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe after Close, got %v", err)
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
