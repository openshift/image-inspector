package openscap

import (
	"bytes"
	"compress/bzip2"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fsouza/go-dockerclient"
	"github.com/openshift/image-inspector/pkg/api"
	"github.com/openshift/image-inspector/test"
)

type (
	/*
		// in constructor
		scanner.rhelDist = scanner.getRHELDist
		scanner.inputCVE = scanner.getInputCVE
		scanner.chrootOscap = scanner.oscapChroot
		scanner.setEnv = scanner.setOscapChrootEnv
	*/
	getRHELDistFunc       func(ctx context.Context, mountPath string, image *docker.Image) (int, error)
	getInputCVEFunc       func(dist int, cveDir, cveUrlAltPath string) (string, error)
	oscapCommandFunc      func(ctx context.Context, mountPath string, image *docker.Image, oscapArgs ...string) ([]byte, error)
	setEnvFunc            func(string, string) error
	setOscapChrootEnvFunc func(mountPath string, image *docker.Image) error
)

//errors
var (
	chrootErr     = fmt.Errorf("can't chroot")
	noDistErr     = fmt.Errorf("could not find RHEL dist")
	noInputCVEErr = fmt.Errorf("No Input CVE")
)

// function stubs
var (
	noRHELDist getRHELDistFunc = func(ctx context.Context, mountPath string, image *docker.Image) (int, error) {
		return 0, noDistErr
	}

	rhel7Dist getRHELDistFunc = func(ctx context.Context, mountPath string, image *docker.Image) (int, error) {
		return 7, nil
	}
	noInputCVE getInputCVEFunc = func(dist int, cveDir, cveUrlAltPath string) (string, error) {
		return "", noInputCVEErr
	}
	inputCVEMock getInputCVEFunc = func(dist int, cveDir, cveUrlAltPath string) (string, error) {
		return "cve_file", nil
	}
	unableToChroot oscapCommandFunc = func(ctx context.Context, mountPath string, image *docker.Image, oscapArgs ...string) ([]byte, error) {
		return []byte(""), chrootErr
	}
	okChrootOscap oscapCommandFunc = func(ctx context.Context, mountPath string, image *docker.Image, oscapArgs ...string) ([]byte, error) {
		return []byte(""), nil
	}
	rhel3OscapChroot oscapCommandFunc = func(ctx context.Context, mountPath string, image *docker.Image, oscapArgs ...string) ([]byte, error) {
		return []byte("oval:org.open-scap.cpe.rhel:def:3: true"), nil
	}
	rhel7OscapChroot oscapCommandFunc = func(ctx context.Context, mountPath string, image *docker.Image, oscapArgs ...string) ([]byte, error) {
		if strings.Contains(oscapArgs[3], "7") {
			return []byte("oval:org.open-scap.cpe.rhel:def:7: true"), nil
		}
		return []byte(""), nil
	}
)

func TestGetRhelDist(t *testing.T) {
	ctx := context.Background()

	tsRhel7ItIs := scannerWithStubs(nil, nil, rhel7OscapChroot, nil, nil)
	tsRhel3Always := scannerWithStubs(nil, nil, rhel3OscapChroot, nil, nil)
	tsCantChroot := scannerWithStubs(nil, nil, unableToChroot, nil, nil)

	tests := map[string]struct {
		ts            *defaultOSCAPScanner
		shouldFail    bool
		expectedError error
		expectedDist  int
	}{
		"unable to chroot": {
			ts:            tsCantChroot,
			shouldFail:    true,
			expectedError: chrootErr,
		},
		"Always wrong dist": {
			ts:            tsRhel3Always,
			shouldFail:    true,
			expectedError: noDistErr,
		},
		"happy flow": {
			ts:           tsRhel7ItIs,
			shouldFail:   false,
			expectedDist: 7,
		},
	}

	for k, v := range tests {
		dist, err := v.ts.getRHELDist(ctx, ".", &docker.Image{})
		if v.shouldFail && !strings.Contains(err.Error(), v.expectedError.Error()) {
			t.Errorf("%s expected  to cause error:\n%v\nBut got:\n%v", k, v.expectedError, err)
		}
		if !v.shouldFail && err != nil {
			t.Errorf("%s expected to succeed but failed with %v", k, err)
		}
		if !v.shouldFail && dist != v.expectedDist {
			t.Errorf("%s expected to succeed with dist=%d but got %d",
				k, v.expectedDist, dist)
		}
	}
}

func TestScan(t *testing.T) {
	ctx := context.Background()

	tsNoRhelDist := scannerWithStubs(noRHELDist, nil, nil, nil, nil)
	tsNoInputCVE := scannerWithStubs(rhel7Dist, noInputCVE, nil, nil, nil)
	_, noInputCVEErr := noInputCVE(0, "", "")
	tsCantChroot := scannerWithStubs(rhel7Dist, inputCVEMock, unableToChroot, nil, nil)

	arfResultsDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("unexpected error creating tmp dir: %v", err)
	}
	defer os.RemoveAll(arfResultsDir)
	if err := ioutil.WriteFile(filepath.Join(arfResultsDir, arfResultFile),
		[]byte("<mock><rule-result><result>pass</result></rule-result></mock>"), 0644); err != nil {
		t.Errorf("unexpected error writing arf results file: %v", err)
	}

	tsSuccessMocks := scannerWithStubs(rhel7Dist, inputCVEMock, okChrootOscap, nil, nil)
	tsSuccessMocks.resultsDir = arfResultsDir

	tests := map[string]struct {
		ts            api.Scanner
		shouldFail    bool
		expectedError error
		evalReport    func(interface{}) bool
	}{
		"cant find rhel dist": {
			ts:            tsNoRhelDist,
			shouldFail:    true,
			expectedError: noDistErr,
		},
		"unable to get input cve": {
			ts:            tsNoInputCVE,
			shouldFail:    true,
			expectedError: noInputCVEErr,
		},
		"can't chroot to mountpath": {
			ts:            tsCantChroot,
			shouldFail:    true,
			expectedError: chrootErr,
		},
		"happy flow": {
			ts:         tsSuccessMocks,
			shouldFail: false,
		},
		"happy flow with reports": {
			ts:         tsSuccessMocks,
			shouldFail: false,
			evalReport: func(r interface{}) bool {
				report, ok := r.(OpenSCAPReport)
				if !ok {
					t.Logf("evalReport: unable to convert %#v into OpenSCAPReport", r)
					return false
				}
				if len(report.ArfBytes) == 0 {
					t.Log("evalReport: expected arf results, got empty bytes")
					return false
				}
				return true
			},
		},
	}

	for k, v := range tests {
		_, report, err := v.ts.Scan(ctx, ".", &docker.Image{}, nil)
		if v.shouldFail && !strings.Contains(err.Error(), v.expectedError.Error()) {
			t.Errorf("%s expected to cause error:\n%v\nBut got:\n%v", k, v.expectedError, err)
		}
		if !v.shouldFail && err != nil {
			t.Errorf("%s expected to succeed but failed with %v", k, err)
		}
		if v.evalReport != nil {
			if !v.evalReport(report) {
				t.Errorf("%s expected to succesfully evaluate the report", k)
			}
		}
	}

	for k, v := range map[string]struct {
		mountPath string
		image     *docker.Image
	}{
		"mount path does not exist":     {"nosuchdir", &docker.Image{}},
		"mount path is not a directory": {"openscap.go", &docker.Image{}},
	} {
		if _, _, err := tsSuccessMocks.Scan(ctx, v.mountPath, v.image, nil); err == nil {
			t.Errorf("%s did not fail", k)
		}
	}

}

func notEmptyValue(k, v string) error {
	if len(v) == 0 {
		return fmt.Errorf("the value should'nt be empty for key %s", k)
	}
	return nil
}

func TestSetOscapChrootEnv(t *testing.T) {
	scanner := scannerWithStubs(nil, nil, nil, notEmptyValue, nil)

	okImage := docker.Image{}
	okImage.Architecture = "x86_64"
	okImage.ID = "12345678901234567890"

	noArchImage := okImage
	noArchImage.Architecture = ""

	shortIDImage := okImage
	shortIDImage.ID = "1234"

	noIDImage := okImage
	noIDImage.ID = ""

	for k, v := range map[string]struct {
		ts    *defaultOSCAPScanner
		image *docker.Image
	}{
		"sanity check":       {ts: scanner, image: &okImage},
		"no architecture":    {ts: scanner, image: &noArchImage},
		"short image ID":     {ts: scanner, image: &shortIDImage},
		"no image ID at all": {ts: scanner, image: &noIDImage},
	} {
		err := v.ts.setOscapChrootEnvFunc(".", v.image)
		if err != nil {
			t.Errorf("%s failed but shouldn't have. The error is %v", k, err)
		}
	}
}

const mockOpenscapScript = `#!/bin/bash
echo %s
exit %d
`

const resultsArfXml = `
<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1" xmlns:core="http://scap.nist.gov/schema/reporting-core/1.1" xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1">
          <rule-result idref="xccdf_com.redhat.rhsa_rule_oval-com.redhat.rhsa-def-20171681" time="2017-07-14T19:47:14" severity="high" weight="1.000000">
            <result>fail</result>
            <ident system="http://cve.mitre.org">CVE-2017-9524</ident>
            <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
              <check-content-ref name="oval:com.redhat.rhsa:def:20171681" href="#xccdf1"/>
            </check>
          </rule-result>
</arf:asset-report-collection>
`

// caller is responsible for cleaning up temp dir
// e.g os.RemoveAll(filepath.Dir(file))
func createMockOscap(output string, code int) (string, error) {
	mockOscapDir, err := ioutil.TempDir("", "")
	if err != nil {
		return "", err
	}
	file := filepath.Join(mockOscapDir, "oscap")
	contents := []byte(fmt.Sprintf(mockOpenscapScript, output, code))
	if err := ioutil.WriteFile(file, contents, 0755); err != nil {
		return "", err
	}
	return mockOscapDir, nil
}

func TestIntegrationScan(t *testing.T) {
	// this test modifies PATH variable for the current process
	// defer setting it back
	oldPath := os.Getenv("PATH")
	defer os.Setenv("PATH", oldPath)
	ctx := context.Background()

	for k, v := range map[string]struct {
		ovalEvalOutput        string
		oscapScanOutput       string
		execExitCode          int
		shouldFail            bool
		expectedErrorContains string
		expectedDist          int
		altCveURL             string
	}{
		"unable to chroot": {
			ovalEvalOutput:        "chroot: permission denied",
			execExitCode:          1,
			shouldFail:            true,
			expectedErrorContains: "chroot: permission denied",
		},
		"cant find rhel dist": {
			ovalEvalOutput:        "oval:org.open-scap.cpe.rhel:def:3: true",
			execExitCode:          0,
			shouldFail:            true,
			expectedErrorContains: distNotFoundErr.Error(),
		},
		"unable to get input cve": {
			ovalEvalOutput:        "oval:org.open-scap.cpe.rhel:def:7: true",
			execExitCode:          0,
			altCveURL:             "localhost:1234/doesnotexist",
			shouldFail:            true,
			expectedErrorContains: "Unable to retreive the CVE file",
		},
		"happy flow": {
			ovalEvalOutput:  "oval:org.open-scap.cpe.rhel:def:7: true",
			oscapScanOutput: "chroot: permission denied",
			execExitCode:    0,
			shouldFail:      false,
			expectedDist:    7,
		},
	} {
		mockOscapDir, err := createMockOscap(v.ovalEvalOutput, v.execExitCode)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		defer os.RemoveAll(mockOscapDir)
		//ensure we call our mock oscap file in exec command
		os.Setenv("PATH", mockOscapDir)
		//write scan results file to result dir
		if err := ioutil.WriteFile(filepath.Join(mockOscapDir, arfResultFile), []byte(resultsArfXml), 0644); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		s := NewDefaultScanner(mockOscapDir, mockOscapDir, v.altCveURL, false)
		results, _, err := s.Scan(ctx, mockOscapDir, &docker.Image{}, nil)
		if v.shouldFail && (err == nil || !strings.Contains(err.Error(), v.expectedErrorContains)) {
			t.Errorf("%s: scan did not produce expected error %v", k, v.expectedErrorContains)
		}
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s: scan caused unexpected error %v", k, err)
				continue
			}
			if len(results) < 1 {
				t.Errorf("%s: expected at least 1 result", k)
				continue
			}
			if results[0].Name != "openscap" {
				t.Errorf("%s expected results name openscap, got: %s", k, results[0].Name)
				continue
			}
			if results[0].ScannerVersion != "1.2" {
				t.Errorf("%s expected results scanner version 1.2, got: %s", k, results[0].ScannerVersion)
				continue
			}
			if results[0].Reference != "https://cve.mitre.org/cgi-bin/cvename.cgi?name==CVE-2017-9524" {
				t.Errorf("%s expected results reference, got: %s", k, results[0].Reference)
				continue
			}
		}
	}
}

func TestIntegrationGetInputCVE(t *testing.T) {
	dist := 7
	cveName := fmt.Sprintf(distCVENameFmt, dist)
	cveDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	defer os.RemoveAll(cveDir)

	cveFilename, err := getInputCVE(dist, cveDir, "")
	if err != nil {
		t.Errorf("getInputCVE failed: %v", err)
	}
	if !strings.HasSuffix(cveFilename, cveName) {
		t.Errorf("expected %s to have suffix %s", cveFilename, cveName)
	}
	contents, err := ioutil.ReadFile(cveFilename)
	if err != nil {
		t.Errorf("failed opening downloaded cve file: %v", err)
	}
	decompressed, err := ioutil.ReadAll(bzip2.NewReader(bytes.NewReader(contents)))
	if err != nil {
		t.Errorf("unexpected error decompressing: %v", err)
	}
	t.Logf("%s", cveFilename)
	expectedCVEContents := []byte("Red Hat OVAL Patch Definition Merger")
	if !bytes.Contains(decompressed, expectedCVEContents) {
		t.Errorf("expected downloaded file contents (%v bytes) to contain string %s", len(decompressed), expectedCVEContents)
	}
}

func TestIntegrationSetOscapChrootEnv(t *testing.T) {
	imageMountPath := "."
	for k, test := range map[string]struct {
		imageID   string
		imageArch string
	}{
		"short image id":   {imageID: "aaaa", imageArch: "x86_x64"},
		"long image id":    {imageID: "aaaaaaaaabbbbbbbbbbbbbcccccccccdddddddddddd", imageArch: "x86_x64"},
		"no arch provided": {imageID: "aaaaaaaaabbbbbbbbbbbbbcccccccccdddddddddddd", imageArch: ""},
	} {
		image := &docker.Image{ID: test.imageID, Architecture: test.imageArch}
		if err := setOscapChrootEnv(imageMountPath, image); err != nil {
			t.Errorf("%s: failed to set chroot env: %v", k, err)
		}

		imageArch := image.Architecture
		if imageArch == "" {
			imageArch = unknown
		}
		maxLen := imageShortIDLen
		if imageNameLen := len(image.ID); imageNameLen < maxLen {
			maxLen = imageNameLen
		}

		for k, expectedV := range map[string]string{
			"OSCAP_PROBE_ROOT":         imageMountPath,
			"OSCAP_PROBE_OS_VERSION":   linuxVersionPH,
			"OSCAP_PROBE_ARCHITECTURE": imageArch,
			"OSCAP_PROBE_OS_NAME":      linux,
			"OSCAP_PROBE_PRIMARY_HOST_NAME": fmt.Sprintf("docker-image-%s",
				image.ID[:maxLen]),
		} {
			actualV := os.Getenv(k)
			defer os.Unsetenv(k)
			if actualV != expectedV {
				t.Errorf("%s: env was not set correctly: %s expected, got %s", k, expectedV, actualV)
			}
		}
	}
}

func TestIntegrationOscapCommand(t *testing.T) {
	ctx := context.Background()
	wd, err := test.GetCurrentFileDir()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	fedoraCpePrefix := "oval:org.open-scap.cpe.fedora:def:"

	var cpePrefix string
	var dist int
	//requires fedora or centos distro on host
	distro := test.GetLinuxDistro()
	switch distro {
	case test.Distro_Unknown:
		t.Log("this test must be run on centos or fedora linux")
		t.SkipNow()
	case test.Distro_Centos6:
		cpePrefix, dist = cpe, 6
	case test.Distro_Centos7:
		cpePrefix, dist = cpe, 7
	case test.Distro_Fedora22:
		cpePrefix, dist = fedoraCpePrefix, 22
	case test.Distro_Fedora23:
		cpePrefix, dist = fedoraCpePrefix, 23
	case test.Distro_Fedora24:
		cpePrefix, dist = fedoraCpePrefix, 24
	case test.Distro_Fedora25:
		cpePrefix, dist = fedoraCpePrefix, 25
	case test.Distro_Fedora26:
		cpePrefix, dist = fedoraCpePrefix, 26
	case test.Distro_Fedora27:
		cpePrefix, dist = fedoraCpePrefix, 27
	default:
		t.Errorf("unexpected failure of test.GetLinuxDistro")
	}

	id := fmt.Sprintf("%s%d", cpePrefix, dist)

	args := []string{"oval", "eval", "--id", id, filepath.Join(wd, "test/openscap-cpe-oval.xml")}

	out, err := defaultScanner().oscapCommand(ctx, ".", &docker.Image{}, args...)
	if err != nil {
		if strings.Contains(err.Error(), "Operation not permitted") {
			t.Skipf("unable to test oscap command; requires root privilege")
		}
		t.Errorf("failed executing oscap command %v: %v", args, err)
	}

	if !strings.Contains(string(out), "true") {
		t.Errorf("expected to find oval definition for %s in oscap output %s", id, out)
	}
}

func TestIntegrationGetRhelDist(t *testing.T) {
	ctx := context.Background()
	var expectedDist int
	distro := test.GetLinuxDistro()
	switch distro {
	case test.Distro_Centos6:
		expectedDist = 6
	case test.Distro_Centos7:
		expectedDist = 7
	default:
		t.Logf("must be running on centos 6 or 7")
		t.SkipNow()
	}
	dist, err := defaultScanner().getRHELDist(ctx, ".", &docker.Image{})
	if err != nil {
		t.Errorf("getRHELDist failed (are you running on RHEL?): %v", err)
	}
	if dist != expectedDist {
		t.Errorf("expected rhel version %v but found %v", expectedDist, dist)
	}
}

func defaultScanner() *defaultOSCAPScanner {
	return scannerWithStubs(nil, nil, nil, nil, nil)
}

// zero value scanner with default function types for test
func scannerWithStubs(getRHELDistFunc getRHELDistFunc,
	getInputCVEFunc getInputCVEFunc,
	oscapCommandFunc oscapCommandFunc,
	setEnvFunc setEnvFunc,
	setOscapChrootEnvFunc setOscapChrootEnvFunc) *defaultOSCAPScanner {
	s := NewDefaultScanner("", "", "", false).(*defaultOSCAPScanner)
	if getRHELDistFunc != nil {
		s.getRHELDistFunc = getRHELDistFunc
	}
	if getInputCVEFunc != nil {
		s.getInputCVEFunc = getInputCVEFunc
	}
	if oscapCommandFunc != nil {
		s.oscapCommandFunc = oscapCommandFunc
	}
	if setEnvFunc != nil {
		s.setEnvFunc = setEnvFunc
	}
	if setOscapChrootEnvFunc != nil {
		s.setOscapChrootEnvFunc = setOscapChrootEnvFunc
	}
	return s
}
