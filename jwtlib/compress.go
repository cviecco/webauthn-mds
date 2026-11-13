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

type reassembleReader struct {
	io.Reader
	pr *io.PipeReader
}

// Close stops the goroutine encoding the payload, any pending write to
// the pipe fails with io.ErrClosedPipe.
func (r *reassembleReader) Close() error {
	return r.pr.Close()
}

// ReassembleReader is the streaming version of Reassemble. The caller
// must Close the returned reader to release the payload encoding goroutine.
func ReassembleReader(header string, cpayload []byte, signature string) (io.ReadCloser, error) {
	zr, err := gzip.NewReader(bytes.NewReader(cpayload))
	if err != nil {
		return nil, err
	}
	r1 := strings.NewReader(header)
	r2 := strings.NewReader(".")
	r4 := strings.NewReader(".")
	r5 := strings.NewReader(signature)
	pr, pw := io.Pipe()
	go func() {
		enc := base64.NewEncoder(base64.RawURLEncoding, pw)
		_, err := io.Copy(enc, zr)
		if err == nil {
			err = enc.Close()
		}
		zr.Close()
		pw.CloseWithError(err)
	}()
	return &reassembleReader{
		Reader: io.MultiReader(r1, r2, pr, r4, r5),
		pr:     pr,
	}, nil
}
