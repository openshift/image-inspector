package openscap

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/fsouza/go-dockerclient"
	iiapi "github.com/openshift/image-inspector/pkg/api"
	"github.com/subchen/go-xmldom"
)

const (
	CVEUrl = "https://www.redhat.com/security/data/metrics/ds/"

	cpe             = "oval:org.open-scap.cpe.rhel:def:"
	cpeDict         = "/usr/share/openscap/cpe/openscap-cpe-oval.xml"
	distCVENameFmt  = "com.redhat.rhsa-RHEL%d.ds.xml.bz2"
	arfResultFile   = "results-arf.xml"
	htmlResultFile  = "results.html"
	linux           = "Linux"
	scannerName     = "openscap"
	imageShortIDLen = 11
	unknown         = "Unknown"
	linuxVersionPH  = "Unknown"
	openSCAPVersion = "1.2"
	cveDetailsUrl   = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
)

var (
	distNotFoundErr = fmt.Errorf("could not find RHEL dist")
)

var (
	rhelDistNumbers = []int{5, 6, 7}
)

// OpenSCAPReport holds the both Arf and outputHTML versions of openscap report.
type OpenSCAPReport struct {
	ArfBytes  []byte
	HTMLBytes []byte
}

type defaultOSCAPScanner struct {
	// resultsDir is the directory to which the arf report will be written
	resultsDir string
	// Whether or not to generate an outputHTML report
	outputHTML bool
	// cveDir is the directory where the CVE file is saved
	cveDir string
	// cveUrlAltPath An alternative source for the cve files
	cveUrlAltPath string

	getRHELDistFunc       func(ctx context.Context, mountPath string, image *docker.Image) (int, error)
	getInputCVEFunc       func(dist int, cveDir, cveUrlAltPath string) (string, error)
	oscapCommandFunc      func(ctx context.Context, mountPath string, image *docker.Image, oscapArgs ...string) ([]byte, error)
	setEnvFunc            func(key string, val string) error
	setOscapChrootEnvFunc func(mountPath string, image *docker.Image) error
}

// NewDefaultScanner returns a new OpenSCAP scanner
func NewDefaultScanner(cveDir, resultsDir, cveUrlAltPath string, outputHTML bool) iiapi.Scanner {
	s := &defaultOSCAPScanner{
		resultsDir:    resultsDir,
		outputHTML:    outputHTML,
		cveDir:        cveDir,
		cveUrlAltPath: cveUrlAltPath,
	}
	s.getRHELDistFunc = s.getRHELDist
	s.getInputCVEFunc = getInputCVE
	s.oscapCommandFunc = s.oscapCommand
	s.setEnvFunc = os.Setenv
	s.setOscapChrootEnvFunc = setOscapChrootEnv

	return s
}

func (s *defaultOSCAPScanner) Scan(ctx context.Context, mountPath string, image *docker.Image, filter iiapi.FilesFilter) ([]iiapi.Result, interface{}, error) {
	if err := s.setOscapChrootEnvFunc(mountPath, image); err != nil {
		return nil, nil, fmt.Errorf("unable to set oscap env: %v", err)
	}

	fi, err := os.Stat(mountPath)
	if err != nil || os.IsNotExist(err) || !fi.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory, error: %v", mountPath, err)
	}
	if image == nil {
		return nil, nil, fmt.Errorf("image cannot be nil")
	}

	rhelDist, err := s.getRHELDistFunc(ctx, mountPath, image)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to get RHEL distribution number: %v\n", err)
	}

	cveFileName, err := s.getInputCVEFunc(rhelDist, s.cveDir, s.cveUrlAltPath)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to retreive the CVE file: %v\n", err)
	}

	args := []string{"xccdf", "eval", "--results-arf", path.Join(s.resultsDir, arfResultFile)}

	if s.outputHTML {
		args = append(args, "--report", path.Join(s.resultsDir, htmlResultFile))
	}
	log.Printf("Writing OpenSCAP results to %s", s.resultsDir)

	args = append(args, cveFileName)

	if _, err = s.oscapCommandFunc(ctx, mountPath, image, args...); err != nil {
		return nil, nil, err
	}

	arfBytes, htmlBytes, err := readOpenSCAPReports(s.resultsDir, s.outputHTML)
	if err != nil {
		return nil, nil, err
	}

	return parseResults(arfBytes), OpenSCAPReport{ArfBytes: arfBytes, HTMLBytes: htmlBytes}, nil
}

func (s *defaultOSCAPScanner) Name() string {
	return scannerName
}

func (s *defaultOSCAPScanner) getRHELDist(ctx context.Context, mountPath string, image *docker.Image) (int, error) {
	for _, dist := range rhelDistNumbers {
		output, err := s.oscapCommandFunc(ctx, mountPath, image, "oval", "eval", "--id",
			fmt.Sprintf("%s%d", cpe, dist), cpeDict)
		if err != nil {
			return 0, err
		}
		if strings.Contains(string(output), fmt.Sprintf("%s%d: true", cpe, dist)) {
			return dist, nil
		}
	}
	return 0, distNotFoundErr
}

func getInputCVE(dist int, cveDir, cveUrlAltPath string) (string, error) {
	cveName := fmt.Sprintf(distCVENameFmt, dist)
	cveFileName := path.Join(cveDir, cveName)
	var err error
	var cveURL *url.URL
	if len(cveUrlAltPath) > 0 {
		if cveURL, err = url.Parse(cveUrlAltPath); err != nil {
			return "", fmt.Errorf("Could not parse CVE URL %s: %v\n",
				cveUrlAltPath, err)
		}
	} else {
		cveURL, _ = url.Parse(CVEUrl)
	}
	cveURL.Path = path.Join(cveURL.Path, cveName)

	out, err := os.Create(cveFileName)
	if err != nil {
		return "", fmt.Errorf("Could not create file %s: %v\n", cveFileName, err)
	}
	defer out.Close()

	resp, err := http.Get(cveURL.String())
	if err != nil {
		return "", fmt.Errorf("Could not download file %s: %v\n", cveURL, err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	return cveFileName, err
}

// Wrapper function for executing oscapCommand
func (s *defaultOSCAPScanner) oscapCommand(ctx context.Context, mountPath string, image *docker.Image, oscapArgs ...string) ([]byte, error) {
	if err := s.setOscapChrootEnvFunc(mountPath, image); err != nil {
		return nil, fmt.Errorf("unable to set oscap env: %v", err)
	}
	out, err := exec.CommandContext(ctx, "oscap", oscapArgs...).CombinedOutput()
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

func setOscapChrootEnv(mountPath string, image *docker.Image) error {
	imageArch := image.Architecture
	if len(imageArch) == 0 {
		imageArch = unknown
	}
	maxLen := imageShortIDLen
	if imageNameLen := len(image.ID); imageNameLen < maxLen {
		maxLen = imageNameLen
	}
	for k, v := range map[string]string{
		"OSCAP_PROBE_ROOT":         mountPath,
		"OSCAP_PROBE_OS_VERSION":   linuxVersionPH, // FIXME place holder value
		"OSCAP_PROBE_ARCHITECTURE": imageArch,
		"OSCAP_PROBE_OS_NAME":      linux,
		"OSCAP_PROBE_PRIMARY_HOST_NAME": fmt.Sprintf("docker-image-%s",
			image.ID[:maxLen]),
	} {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	return nil
}

func readOpenSCAPReports(resultsDir string, outputHTML bool) ([]byte, []byte, error) {
	arfResults, err := ioutil.ReadFile(path.Join(resultsDir, arfResultFile))
	if err != nil {
		return nil, nil, err
	}
	if outputHTML {
		htmlResults, err := ioutil.ReadFile(path.Join(resultsDir, htmlResultFile))
		if err != nil {
			return nil, nil, err
		}
		return htmlResults, arfResults, nil
	}
	return arfResults, nil, nil
}

func parseResults(report []byte) []iiapi.Result {
	ret := []iiapi.Result{}
	doc, err := xmldom.ParseXML(string(report))
	if err != nil {
		log.Printf("Error parsing result XML: %v", err)
		return []iiapi.Result{}
	}
	node := xmldom.Must(doc, nil).Root
	for _, c := range node.Query("//rule-result") {
		if !strings.Contains(c.GetChild("result").Text, "fail") {
			continue
		}
		result := iiapi.Result{
			Name:           scannerName,
			ScannerVersion: openSCAPVersion,
			Timestamp:      time.Now(),
			Reference:      fmt.Sprintf("%s=%s", cveDetailsUrl, strings.TrimSpace(c.GetChild("ident").Text)),
		}
		// If we have rule definition, we can provide more details
		if ruleDef := node.QueryOne(fmt.Sprintf("//Benchmark//Rule[@id='%s']", c.GetAttribute("idref").Value)); ruleDef != nil {
			result.Description = strings.TrimSpace(ruleDef.GetChild("title").Text)
			result.Summary = []iiapi.Summary{{Label: iiapi.Severity(ruleDef.GetAttribute("severity").Value)}}
		}
		ret = append(ret, result)
	}
	return ret
}
