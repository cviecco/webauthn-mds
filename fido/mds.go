package fido

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"

	"github.com/go-webauthn/webauthn/metadata"

	"github.com/go-webauthn/webauthn/metadata/providers/memory"
)

//go:embed metadata.jwt.gz
var fidoCompressedBytes []byte

func GetJWTReader() (io.Reader, error) {
	embedReader := bytes.NewReader(fidoCompressedBytes)
	return gzip.NewReader(embedReader)
}

func getBuiltIn() (*metadata.Metadata, error) {
	//mdsReader := bytes.NewReader(fidoMdsBytes)
	//embedReader := bytes.NewReader(fidoCompressedBytes)
	mdsReader, err := GetJWTReader()
	if err != nil {
		return nil, err
	}

	decoder, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return nil, err
	}
	// Decode also does signature verification against the roots built in into
	// the go-webathn library
	payload, err := decoder.Decode(mdsReader)
	if err != nil {
		return nil, err
	}
	return decoder.Parse(payload)
}

func GetProvider() (provider metadata.Provider, err error) {
	builtInMds, err := getBuiltIn()
	if err != nil {
		return nil, err
	}
	return memory.New(
		memory.WithMetadata(builtInMds.ToMap()),
		memory.WithMetadataKeyIdentifiers(builtInMds.ToKeyIdentifierMap()),
		memory.WithValidateEntryKeyIdentifier(true),
	)

}
