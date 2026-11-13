package fido

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"

	"github.com/cviecco/webauthn-mds/jwtlib"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
)

//go:embed fidodata/metadata.jwt.gz
var fidoCompressedBytes []byte

//go:embed fidodata/mds.jwt.header
var mdsHeaderString string

//go:embed fidodata/mds.jwt.payload
var mdsPayLoadBytes []byte

//go:embed fidodata/mds.jwt.sig
var mdsSignatureString string

// GetJWTReader is an experimental interface do
func GetJWTReaderOld() (io.Reader, error) {
	embedReader := bytes.NewReader(fidoCompressedBytes)
	return gzip.NewReader(embedReader)
}

func GetJWTReader() (io.Reader, error) {
	jwtString, err := jwtlib.Reassemble(mdsHeaderString, mdsPayLoadBytes, mdsSignatureString)
	if err != nil {
		return nil, err
	}
	jwtReader := bytes.NewReader([]byte(jwtString))
	return jwtReader, nil
}

func getMetadataFromReader(inreader io.Reader) (*metadata.Metadata, error) {
	decoder, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return nil, err
	}
	// Decode also does signature verification against the roots built in into
	// the go-webathn library
	payload, err := decoder.Decode(inreader)
	if err != nil {
		return nil, err
	}
	return decoder.Parse(payload)
}

func GetProvider() (provider metadata.Provider, err error) {
	jwtReader, err := GetJWTReader()
	if err != nil {
		return nil, err
	}
	return GetProviderFromMetadataReader(jwtReader)

}

// GetProviderFromMetadataReader takes a reader and creates
// a provider to use. This actually validates the reader
// contents against the mds signing roots
// The reader is assumed to be a JWT blob with the official
// fido mds structure
func GetProviderFromMetadataReader(mdsReader io.Reader) (provider metadata.Provider, err error) {
	readMDS, err := getMetadataFromReader(mdsReader)
	if err != nil {
		return nil, err
	}

	return memory.New(
		memory.WithMetadata(readMDS.ToMap()),
		memory.WithMetadataKeyIdentifiers(readMDS.ToKeyIdentifierMap()),
		memory.WithValidateEntryKeyIdentifier(true),
	)

}
