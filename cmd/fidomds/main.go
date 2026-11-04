package main

import (
	"io"
	"os"

	"github.com/cviecco/webauthn-mds/fido"
	"github.com/cviecco/webauthn-mds/jwtlib"
)

func GenerateFiles() error {
	prefix := "mds.jwt"
	jwtReader, err := fido.GetJWTReader()
	if err != nil {
		return err
	}
	return generateFilesFromReader(jwtReader, prefix)
}

func generateFilesFromReader(jwtData io.Reader, outputPrefix string) error {
	dataBytes, err := io.ReadAll(jwtData)
	if err != nil {
		return err
	}
	headerString, payload, signature, err := jwtlib.SplitCompress(string(dataBytes))
	if err != nil {
		return err
	}
	headerFileName := outputPrefix + ".header"
	payloadFilename := outputPrefix + ".payload"
	signatureFilename := outputPrefix + ".sig"
	err = os.WriteFile(headerFileName, []byte(headerString), 0644)
	if err != nil {
		return err
	}
	err = os.WriteFile(payloadFilename, payload, 0644)
	if err != nil {
		return err
	}
	err = os.WriteFile(signatureFilename, []byte(signature), 0644)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	//err := extractPrintHeader(os.Stdout)
	//err := extractPrintJWTSection(2, os.Stdout)
	err := GenerateFiles()
	if err != nil {
		panic(err)
	}
}
