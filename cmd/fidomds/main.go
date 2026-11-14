package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/seekr-osint/wayback-machine-golang/wayback"

	"github.com/cviecco/webauthn-mds/fido"
	"github.com/cviecco/webauthn-mds/jwtlib"
)

type CmdContext struct {
	Debug bool
}

type DownLoadMDS struct {
	OutputFilePath string        `name:"output" default:"metadata.jwt"`
	Timeout        time.Duration `name:"timeout" default:"20s"`
	FetchType      string        `name:"fetcher" default:"direct" enum:"direct,waybackmachine"`
	MDSURL         string        `name:"mdsURL" default:"https://mds.fidoalliance.org"`
}

func getURLDataFromURL(client *http.Client, getURL string) ([]byte, error) {
	resp, err := client.Get(getURL)
	if err != nil {
		return nil, err
	}
	// we always consume the body so that
	// the client can be reused
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("Invalid status code %d", resp.StatusCode)
	}
	return body, nil
}

func donwloadClosestWayback(client *http.Client, targetURL string) ([]byte, error) {
	snapshots, err := wayback.GetSnapshotData(targetURL, client) // the clint argument can also be nil
	if err != nil {
		return nil, err
	}
	fmt.Printf("Snapshot data: %s\n", snapshots)
	closestEntry := snapshots.ArchivedSnapshots.Closest
	if closestEntry.Available != true {
		return nil, fmt.Errorf("closest not available")
	}
	if closestEntry.Status != "200" {
		return nil, fmt.Errorf("Invalid status for closest")
	}
	return getURLDataFromURL(client, closestEntry.URL)
}

func (dms *DownLoadMDS) Run(ctx *CmdContext) error {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}
	var bodyBytes []byte
	targetURL := dms.MDSURL

	switch dms.FetchType {
	case "direct":
		var err error
		bodyBytes, err = getURLDataFromURL(client, targetURL)
		if err != nil {
			log.Printf("getURL failed %w", err)
			return err
		}
	case "waybackmachine":
		var err error
		bodyBytes, err = donwloadClosestWayback(client, targetURL)
		if err != nil {
			return err
		}
		/*
			snapshots, err := wayback.GetSnapshotData(targetURL, client) // the clint argument can also be nil
			if err != nil {
				log.Panic(err)
			}
			fmt.Printf("Snapshot data: %s\n", snapshots)
			return fmt.Errorf("not implementee yet")
		*/
	default:
		return fmt.Errorf("not implemented")
	}
	// TODO: check here if the data is valid before
	// writing the final file
	return os.WriteFile(dms.OutputFilePath, bodyBytes, 0644)
}

type GenerateFilesCmd struct {
	InputFilePath string `name:"input" help:"FileOutputPath." type:"path" default:"metadata.jwt"`
	Prefix        string `name:"prefix" default:"mds.jwt"`
}

func (gc *GenerateFilesCmd) Run(ctx *CmdContext) error {
	input, err := os.Open(gc.InputFilePath)
	if err != nil {
		return err
	}
	return generateFilesFromReader(input, gc.Prefix)
}

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

var cli struct {
	Debug bool `help:"Enable debug mode."`

	Generate    GenerateFilesCmd `cmd:"" help:"Generate Files."`
	Downloadmds DownLoadMDS      `cmd:"" help:"Download MDS "`
}

func main() {

	ctx := kong.Parse(&cli)
	err := ctx.Run(&CmdContext{Debug: cli.Debug})
	ctx.FatalIfErrorf(err)

	/*
		//err := extractPrintHeader(os.Stdout)
		//err := extractPrintJWTSection(2, os.Stdout)
		err := GenerateFiles()
		if err != nil {
			panic(err)
		}
	*/
}
