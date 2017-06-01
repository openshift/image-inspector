package api

import (
	docker "github.com/fsouza/go-dockerclient"
	"time"
)

// OpenSCAPStatus is the status of openscap scan
type OpenSCAPStatus string

const (
	StatusNotRequested OpenSCAPStatus = "NotRequested"
	StatusSuccess      OpenSCAPStatus = "Success"
	StatusError        OpenSCAPStatus = "Error"
)

type OpenSCAPMetadata struct {
	Status           OpenSCAPStatus // Status of the OpenSCAP scan report
	ErrorMessage     string         // Error message from the openscap
	ContentTimeStamp string         // Timestamp for this data
}

func (osm *OpenSCAPMetadata) SetError(err error) {
	osm.Status = StatusError
	osm.ErrorMessage = err.Error()
	osm.ContentTimeStamp = string(time.Now().Format(time.RFC850))
}

var (
	ScanOptions = []string{"openscap", "clamav"}
)

// InspectorMetadata is the metadata type with information about image-inspector's operation
type InspectorMetadata struct {
	docker.Image // Metadata about the inspected image
	// OpenSCAP describes the state of the OpenSCAP scan
	OpenSCAP *OpenSCAPMetadata
}

// APIVersions holds a slice of supported API versions.
type APIVersions struct {
	// Versions is the supported API versions
	Versions []string `json:"versions"`
}

// Scanner interface that all scanners should define.
type Scanner interface {
	// Scan will scan the image
	Scan(path string, image *docker.Image) error
	// ScannerName is the scanner's name
	ScannerName() string
	// ResultFileName returns the name of the results file
	ResultsFileName() string
	// HtmlResultFileName returns the name of the results file
	HTMLResultsFileName() string
}
