package openscap

import (
	docker "github.com/fsouza/go-dockerclient"
)

// Scanner is the interface of OpenSCAP scanner
type Scanner interface {
	// Scan will scan the image
	Scan(string, *docker.Image) error
	// ScannerName is the scanner's name
	ScannerName() string
	// ResultFileName returns the name of the results file
	ResultsFileName() string
	// HtmlResultFileName returns the name of the results file
	HTMLResultsFileName() string
}
