package openscap

import (
	"fmt"
	docker "github.com/fsouza/go-dockerclient"
	util "github.com/openshift/image-inspector/pkg/util"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
)

const (
	CPE             = "oval:org.open-scap.cpe.rhel:def:"
	CPEDict         = "/usr/share/openscap/cpe/openscap-cpe-oval.xml"
	CVEUrl          = "https://www.redhat.com/security/data/metrics/ds/"
	DistCVENameFmt  = "com.redhat.rhsa-RHEL%d.ds.xml.bz2"
	StaticCVEFeeds  = "/var/lib/image-inspector/cve_feeds"
	ArfResultFile   = "results-arf.xml"
	TmpDir          = "/tmp"
	Linux           = "Linux"
	OpenSCAP        = "OpenSCAP"
	ImageShortIDLen = 11
	Unknown         = "Unknown"
	LinuxVersionPH  = "Unknown"
)

var (
	RHELDistNumbers = [...]int{5, 6, 7}
	osSetEnv        = os.Setenv
)

// rhelDistFunc provides an injectable way to get the rhel dist for testing.
type rhelDistFunc func() (int, error)

// inputCVEFunc provides an injectable way to get the cve file for testing.
type inputCVEFunc func(int) (string, error)

// chrootOscapFunc provides an injectable way to chroot and execute oscap for testing.
type chrootOscapFunc func(...string) ([]byte, error)

// setEnvFunc provides an injectable way to get the cve file for testing.
type setEnvFunc func() error

type defaultOSCAPScanner struct {
	// DownloadCVEDir is the directory where the CVE file is downloaded and saved
	DownloadCVEDir string
	// ResultsDir is the directory to which the arf report will be written
	ResultsDir string

	// Image is the metadata of the inspected image
	image *docker.Image
	// ImageMountPath is the path where the image to be scanned is mounted
	imageMountPath string

	rhelDist    rhelDistFunc
	inputCVE    inputCVEFunc
	chrootOscap chrootOscapFunc
	setEnv      setEnvFunc
}

// NewDefaultScanner returns a new OpenSCAP scanner
func NewDefaultScanner(cveDir string, resultsDir string) Scanner {
	scanner := &defaultOSCAPScanner{
		DownloadCVEDir: cveDir,
		ResultsDir:     resultsDir,
	}

	scanner.rhelDist = scanner.getRHELDist
	scanner.inputCVE = scanner.getInputCVE
	scanner.chrootOscap = scanner.oscapChroot
	scanner.setEnv = scanner.setOscapChrootEnv

	return scanner
}

func (s *defaultOSCAPScanner) getRHELDist() (int, error) {
	for _, dist := range RHELDistNumbers {
		output, err := s.chrootOscap("oval", "eval", "--id",
			fmt.Sprintf("%s%d", CPE, dist), CPEDict)
		if err != nil {
			return 0, err
		}
		if strings.Contains(string(output), fmt.Sprintf("%s%d: true", CPE, dist)) {
			return dist, nil
		}
	}
	return 0, fmt.Errorf("could not find RHEL dist")
}

func downloadCVE(cveName, downloadDir string) (string, error) {
	cveFileName := path.Join(downloadDir, cveName)

	out, err := os.Create(cveFileName)
	if err != nil {
		return "", fmt.Errorf("Could not create file %s: %v\n", cveFileName, err)
	}
	defer out.Close()

	cveURL, _ := url.Parse(CVEUrl)
	cveURL.Path = path.Join(cveURL.Path, cveName)
	resp, err := http.Get(cveURL.String())
	if err != nil {
		return "", fmt.Errorf("Could not download file %s: %v\n", cveURL, err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	return cveFileName, err
}

func (s *defaultOSCAPScanner) getInputCVE(dist int) (string, error) {
	var err error
	cveName := fmt.Sprintf(DistCVENameFmt, dist)
	cveFileName, downloadErr := downloadCVE(cveName, s.DownloadCVEDir)
	if downloadErr != nil {
		cveFileName = path.Join(StaticCVEFeeds, cveName)
		_, err = os.Stat(cveFileName)
		if os.IsNotExist(err) {
			err = fmt.Errorf("Unable to download the CVE file (%v) or find it in the static files (%v)", downloadErr, err)
		}
	}
	return cveFileName, err
}

func (s *defaultOSCAPScanner) setOscapChrootEnv() error {
	for k, v := range map[string]string{
		"OSCAP_PROBE_ROOT":         s.imageMountPath,
		"OSCAP_PROBE_OS_VERSION":   LinuxVersionPH, // FIXME place holder value
		"OSCAP_PROBE_ARCHITECTURE": util.StrOrDefault(s.image.Architecture, Unknown),
		"OSCAP_PROBE_OS_NAME":      Linux,
		"OSCAP_PROBE_PRIMARY_HOST_NAME": fmt.Sprintf("docker-image-%s",
			s.image.ID[:util.Min(ImageShortIDLen, len(s.image.ID))]),
	} {
		err := osSetEnv(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

// Wrapper function for executing oscap
func (s *defaultOSCAPScanner) oscapChroot(oscapArgs ...string) ([]byte, error) {
	if err := s.setEnv(); err != nil {
		return nil, fmt.Errorf("Unable to set env variables in oscapChroot: %v", err)
	}
	cmd := exec.Command("oscap", oscapArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			if waitStatus.ExitStatus() == 2 {
				// Error code 2 means that OpenSCAP had failed rules
				// For our purpose this means success
				return out, nil
			}
			return out, fmt.Errorf("OpenSCAP error: %d: %v\nInput:\n%s\nOutput:\n%s\n",
				waitStatus.ExitStatus(), err, oscapArgs, string(out))
		}
	}
	return out, err
}

func (s *defaultOSCAPScanner) Scan(mountPath string, image *docker.Image) error {
	fi, err := os.Stat(mountPath)
	if err != nil || os.IsNotExist(err) || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory, error: %v", mountPath, err)
	}
	if image == nil {
		return fmt.Errorf("image cannot be nil")
	}
	s.image = image
	s.imageMountPath = mountPath

	rhelDist, err := s.rhelDist()
	if err != nil {
		return fmt.Errorf("Unable to get RHEL distribution number: %v\n", err)
	}

	cveFileName, err := s.inputCVE(rhelDist)
	if err != nil {
		return fmt.Errorf("Unable to retreive the CVE file: %v\n", err)
	}

	_, err = s.chrootOscap("xccdf", "eval",
		"--results-arf", s.ResultsFileName(),
		cveFileName)
	return err
}

func (s *defaultOSCAPScanner) ScannerName() string {
	return OpenSCAP
}

func (s *defaultOSCAPScanner) ResultsFileName() string {
	return path.Join(s.ResultsDir, ArfResultFile)
}
