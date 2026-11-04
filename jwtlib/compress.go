package jwtlib

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

func SplitCompress(jwtString string) (header string,
	cpayload []byte, signature string, err error) {
	sections := strings.SplitN(jwtString, ".", 3)
	if len(sections) != 3 {
		return "", nil, "", fmt.Errorf("Invalid file")
	}
	header = sections[0]
	signature = sections[2]
	payload, err := base64.RawURLEncoding.DecodeString(sections[1])
	if err != nil {
		return "", nil, "", err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err = zw.Write(payload)
	if err != nil {
		return "", nil, "", err
	}
	if err := zw.Close(); err != nil {
		return "", nil, "", err
	}
	return header, buf.Bytes(), signature, nil
}

// Reassemble reverses SplitCompress: it decompresses the payload and
// returns the jwt string made of the header, payload and signature.
func Reassemble(header string, cpayload []byte, signature string) (string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(cpayload))
	if err != nil {
		return "", err
	}
	defer zr.Close()
	payload, err := io.ReadAll(zr)
	if err != nil {
		return "", err
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) +
		"." + signature, nil
}
