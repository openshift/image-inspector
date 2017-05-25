package inspector

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	docker "github.com/fsouza/go-dockerclient"
	iiapi "github.com/openshift/image-inspector/pkg/api"
	iicmd "github.com/openshift/image-inspector/pkg/cmd"
)

type FailMockScanner struct{}
type SuccMockScanner struct {
	FailMockScanner
}
type NoResMockScanner struct {
	SuccMockScanner
}
type SuccWithHTMLMockScanner struct {
	SuccMockScanner
}

func (ms *FailMockScanner) Scan(string, *docker.Image) error {
	return fmt.Errorf("FAIL SCANNER!")
}
func (ms *FailMockScanner) ScannerName() string {
	return "MockScanner"
}
func (ms *FailMockScanner) ResultsFileName() string {
	return "image-inspector_test.go"
}
func (ms *FailMockScanner) HTMLResultsFileName() string {
	return "NoSuchFile"
}

func (ms *SuccWithHTMLMockScanner) HTMLResultsFileName() string {
	return "image-inpector_test.go"
}

func (ms *SuccMockScanner) Scan(string, *docker.Image) error {
	return nil
}

func (ms *NoResMockScanner) ResultsFileName() string {
	return "NoSuchFILE"
}

func TestScanImage(t *testing.T) {
	iiWithHtml := defaultImageInspector{}
	iiWithHtml.opts.OpenScapHTML = true

	for k, v := range map[string]struct {
		ii         defaultImageInspector
		s          iiapi.Scanner
		shouldFail bool
	}{
		"Scanner fails on scan":       {ii: defaultImageInspector{}, s: &FailMockScanner{}, shouldFail: true},
		"Results file does not exist": {ii: defaultImageInspector{}, s: &NoResMockScanner{}, shouldFail: true},
		"Happy Flow":                  {ii: defaultImageInspector{}, s: &SuccMockScanner{}, shouldFail: false},
		"can't read html report":      {ii: iiWithHtml, s: &SuccMockScanner{}, shouldFail: true},
		"Happy Flow with html":        {ii: iiWithHtml, s: &SuccWithHTMLMockScanner{}, shouldFail: true},
	} {
		v.ii.opts.DstPath = "here"
		ii := &v.ii
		report, htmlReport, err := ii.scanImage(v.s)
		if v.shouldFail && err == nil {
			t.Errorf("%s should have failed but it didn't!", k)
		}
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s should have succeeded but failed with %v", k, err)
			} else {
				resultFileContent, err := ioutil.ReadFile(v.s.ResultsFileName())
				if err != nil {
					t.Errorf("%s should have been able to read the"+
						"results file but failed with: %v", k, err)
				}
				if string(resultFileContent) != string(report) {
					t.Errorf("%s The report on disk did not match the "+
						"report from the scanImage: %v", k, err)
					t.Errorf("%s -- The result string read from the "+
						"file is %d characters long.", k, len(resultFileContent))
					t.Errorf("%s -- The result string as read via the "+
						"scan is %d characters long.", k, len(report))
				}
				if ii.opts.OpenScapHTML {
					htmlResultFileContent, err := ioutil.ReadFile(v.s.HTMLResultsFileName())
					if err != nil {
						t.Errorf("%s should have been able to read the"+
							"HTML results file but failed with: %v", k, err)
					}
					if string(htmlResultFileContent) != string(htmlReport) {
						t.Errorf("%s The HTML report on disk did not match the "+
							"report from the scanImage: %v", k, err)
						t.Errorf("%s -- The result string read from the "+
							"file is %d characters long.", k, len(htmlResultFileContent))
						t.Errorf("%s -- The result string as read via the "+
							"scan is %d characters long.", k, len(htmlReport))
					}
				}
			}
		}
	}
}

func TestGetAuthConfigs(t *testing.T) {
	const IMAGE_NAME = "172.30.203.184:5000/hello/world"
	goodNoAuth := iicmd.NewDefaultImageInspectorOptions()

	goodTwoDockerCfg := iicmd.NewDefaultImageInspectorOptions()
	goodTwoDockerCfg.DockerCfg.Values = []string{"test/dockercfg1", "test/dockercfg2"}

	goodUserAndPass := iicmd.NewDefaultImageInspectorOptions()
	goodUserAndPass.Username = "erez"
	goodUserAndPass.Image = IMAGE_NAME
	goodUserAndPass.PasswordFile = "test/passwordFile1"

	badUserAndPass := iicmd.NewDefaultImageInspectorOptions()
	badUserAndPass.Username = "erez"
	badUserAndPass.PasswordFile = "test/nosuchfile"

	badDockerCfgMissing := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgMissing.DockerCfg.Values = []string{"test/dockercfg1", "test/nosuchfile"}

	badDockerCfgWrong := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgWrong.DockerCfg.Values = []string{"test/dockercfg1", "test/passwordFile1"}

	badDockerCfgNoAuth := iicmd.NewDefaultImageInspectorOptions()
	badDockerCfgNoAuth.DockerCfg.Values = []string{"test/dockercfg1", "test/dockercfg3"}

	tests := map[string]struct {
		opts          *iicmd.ImageInspectorOptions
		expectedAuths int
		shouldFail    bool
	}{
		"two dockercfg":               {opts: goodTwoDockerCfg, expectedAuths: 2, shouldFail: false},
		"username and passwordFile":   {opts: goodUserAndPass, expectedAuths: 1, shouldFail: false},
		"two dockercfg, one missing":  {opts: badDockerCfgMissing, expectedAuths: 1, shouldFail: false},
		"two dockercfg, one wrong":    {opts: badDockerCfgWrong, expectedAuths: 1, shouldFail: false},
		"two dockercfg, one no auth":  {opts: badDockerCfgNoAuth, expectedAuths: 1, shouldFail: false},
		"password file doens't exist": {opts: badUserAndPass, expectedAuths: 0, shouldFail: true},
		"no auths, default expected":  {opts: goodNoAuth, expectedAuths: 0, shouldFail: false},
	}

	for k, v := range tests {
		ii := &defaultImageInspector{*v.opts, iiapi.InspectorMetadata{}, nil}
		kr, err := ii.getAuthConfigs()
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s expected to succeed but received %v", k, err)
			}
			var authsLen int = 0
			auths, _ := kr.Lookup(IMAGE_NAME)
			authsLen = len(auths)
			if auths == nil || v.expectedAuths != authsLen {
				t.Errorf("%s expected len to be %d but got %d from %v",
					k, v.expectedAuths, authsLen, kr)
			}
		} else {
			if err == nil {
				t.Errorf("%s should have failed be it didn't", k)
			}
		}
	}
}

func Test_decodeDockerResponse(t *testing.T) {
	no_error_input := "{\"Status\": \"fine\"}"
	one_error := "{\"Status\": \"fine\"}{\"Error\": \"Oops\"}{\"Status\": \"fine\"}"
	decode_error := "{}{}what"
	decode_error_message := "Error decoding json: invalid character 'w' looking for beginning of value"
	tests := map[string]struct {
		readerInput    string
		expectedErrors bool
		errorMessage   string
	}{
		"no error":      {readerInput: no_error_input, expectedErrors: false},
		"error":         {readerInput: one_error, expectedErrors: true, errorMessage: "Oops"},
		"decode errror": {readerInput: decode_error, expectedErrors: true, errorMessage: decode_error_message},
	}

	for test_name, test_params := range tests {
		parsedErrors := make(chan error, 100)
		defer func() { close(parsedErrors) }()

		go func() {
			reader, writer := io.Pipe()
			// handle closing the reader/writer in the method that creates them
			defer reader.Close()
			defer writer.Close()
			go decodeDockerResponse(parsedErrors, reader)
			writer.Write([]byte(test_params.readerInput))
		}()

		select {
		case decodedErrors := <-parsedErrors:
			if decodedErrors == nil && test_params.expectedErrors {
				t.Errorf("Expected to parse an error, but non was parsed in test %s", test_name)
			}
			if decodedErrors != nil {
				if !test_params.expectedErrors {
					t.Errorf("Expected not to get errors in test %s but got: %v", test_name, decodedErrors)
				} else {
					if decodedErrors.Error() != test_params.errorMessage {
						t.Errorf("Expected error message is different than expected in test %s. Expected %v received %v",
							test_name, test_params.errorMessage, decodedErrors.Error())
					}
				}
			}
		}
	}
}

func mkSucc(string, os.FileMode) error {
	return nil
}

func mkFail(string, os.FileMode) error {
	return fmt.Errorf("MKFAIL")
}

func tempSucc(string, string) (string, error) {
	return "tempname", nil
}

func tempFail(string, string) (string, error) {
	return "", fmt.Errorf("TEMPFAIL!")
}

func TestCreateOutputDir(t *testing.T) {
	oldMkdir := osMkdir
	defer func() { osMkdir = oldMkdir }()

	oldTempdir := ioutil.TempDir
	defer func() { ioutilTempDir = oldTempdir }()

	for k, v := range map[string]struct {
		dirName    string
		shouldFail bool
		newMkdir   func(string, os.FileMode) error
		newTempDir func(string, string) (string, error)
	}{
		"good existing dir": {dirName: "/tmp", shouldFail: false, newMkdir: mkSucc},
		"good new dir":      {dirName: "delete_me", shouldFail: false, newMkdir: mkSucc},
		"good temporary":    {dirName: "", shouldFail: false, newMkdir: mkSucc, newTempDir: tempSucc},
		"cant create temp":  {dirName: "", shouldFail: true, newMkdir: mkSucc, newTempDir: tempFail},
		"mkdir fails":       {dirName: "delete_me", shouldFail: true, newMkdir: mkFail},
	} {
		osMkdir = v.newMkdir
		ioutilTempDir = v.newTempDir
		_, err := createOutputDir(v.dirName, "temp-name-")
		if v.shouldFail {
			if err == nil {
				t.Errorf("%s should have failed but it didn't!", k)
			}
		} else {
			if err != nil {
				t.Errorf("%s should have succeeded but failed with %v", k, err)
			}
		}
	}
}
