package clamav

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fsouza/go-dockerclient"
	"github.com/openshift/clam-scanner/pkg/clamav"

	"github.com/openshift/image-inspector/pkg/api"
)

const ScannerName = "clamav"

type ClamScanner struct {
	// Socket is the location of the clamav socket.
	Socket string

	clamd clamav.ClamdSession
}

var _ api.Scanner = &ClamScanner{}

func NewScanner(socket string) api.Scanner {
	scanner := ClamScanner{
		Socket: socket,
	}
	// TODO: Make the ignoreNegatives configurable
	scanner.clamd, _ = clamav.NewClamdSession(scanner.Socket, true)
	return &scanner
}

// Scan will scan the image
func (s *ClamScanner) Scan(path string, image *docker.Image) ([]api.Result, interface{}, error) {
	if s.clamd == nil {
		return nil, nil, fmt.Errorf("unable to start clamd session")
	}
	scanResults := []api.Result{}
	// Useful for debugging
	scanStarted := time.Now()
	defer func() {
		log.Printf("clamav scan took %ds (%d problems found)", int64(time.Since(scanStarted).Seconds()), len(scanResults))
	}()
	if err := s.clamd.ScanPath(path); err != nil {
		return nil, nil, err
	}
	s.clamd.WaitTillDone()
	defer s.clamd.Close()

	clamResults := s.clamd.GetResults()

	for _, r := range clamResults.Files {
		r := api.Result{
			Name:           ScannerName,
			ScannerVersion: "0.99.2", // TODO: this must be returned from clam-scanner
			Timestamp:      scanStarted,
			Reference:      fmt.Sprintf("file://%s", strings.TrimPrefix(r.Filename, path)),
			Description:    r.Result,
		}
		scanResults = append(scanResults, r)
	}

	return scanResults, nil, nil
}

func (s *ClamScanner) Name() string {
	return ScannerName
}
