package clamav

import (
	"bytes"
	"fmt"

	clamd "github.com/dutchcoders/go-clamd"
	"github.com/fsouza/go-dockerclient"

	"github.com/openshift/image-inspector/pkg/api"
)

type ClamScanner struct {
	// Socket is the location of the clamav socket.
	Socket string
}

var _ api.Scanner = &ClamScanner{}

func NewScanner(socket string) api.Scanner {
	return &ClamScanner{
		Socket: socket,
	}
}

// Scan will scan the image
func (s *ClamScanner) Scan(path string, image *docker.Image) error {
	scanner := clamd.NewClamd(s.Socket)

	reader := bytes.NewReader(clamd.EICAR)
	// TODO submit README fix upstream, their example doesn't have the channel
	response, err := scanner.ScanStream(reader, make(chan bool))

	if err != nil {
		return err
	}

	for s := range response {
		fmt.Printf("%v %v\n", s, err)
	}

	//// TODO result channel
	//_, err := scanner.ContScanFile(path)
	return nil
}

// ScannerName is the scanner's name
func (s *ClamScanner) ScannerName() string {
	return "ClamAV"
}

// ResultFileName returns the name of the results file
func (s *ClamScanner) ResultsFileName() string {
	return ""
}

// HtmlResultFileName returns the name of the results file
func (s *ClamScanner) HTMLResultsFileName() string {
	return ""
}
