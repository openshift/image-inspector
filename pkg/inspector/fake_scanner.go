package inspector

import (
	"fmt"

	docker "github.com/fsouza/go-dockerclient"
)

// todo move openscap scanner interface to generic location
type FakeScanner struct{}

func (s *FakeScanner) Scan(dstPath string, image *docker.Image) error{
	fmt.Printf("scanning contents at %s", dstPath)
	return nil
}
func (s *FakeScanner) ScannerName() string {
	return "Fake Scanner"
}
func (s *FakeScanner) ResultsFileName() string {
	return "results file name"
}
func (s *FakeScanner) HTMLResultsFileName() string {
	return "html results file name"
}
