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

func TestAcquiringInInspect(t *testing.T) {
	for k, v := range map[string]struct {
		ii             defaultImageInspector
		shouldFail     bool
		expectedAcqErr string
	}{
		"Scanner fails on scan": {ii: defaultImageInspector{opts: iicmd.ImageInspectorOptions{DockerSocket: "No such file", Serve: ""}},
			shouldFail:     true,
			expectedAcqErr: "invalid endpoint",
		},
	} {
		err := v.ii.Inspect()
		if v.shouldFail && err == nil {
			t.Errorf("%s should have failed but it didn't!", k)
		}
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s should have succeeded but failed with %v", k, err)
			}
		}
		if v.ii.meta.ImageAcquireError != v.expectedAcqErr {
			t.Errorf("%s acquire error is not matching.\nExtected: %v\nReceived: %v\n", k, v.expectedAcqErr, v.ii.meta.ImageAcquireError)
		}
	}
}

func TestGetAuthConfigs(t *testing.T) {
	goodNoAuth := iicmd.NewDefaultImageInspectorOptions()

	goodTwoDockerCfg := iicmd.NewDefaultImageInspectorOptions()
	goodTwoDockerCfg.DockerCfg.Values = []string{"test/dockercfg1", "test/dockercfg2"}

	goodUserAndPass := iicmd.NewDefaultImageInspectorOptions()
	goodUserAndPass.Username = "erez"
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
		"two dockercfg":               {opts: goodTwoDockerCfg, expectedAuths: 3, shouldFail: false},
		"username and passwordFile":   {opts: goodUserAndPass, expectedAuths: 1, shouldFail: false},
		"two dockercfg, one missing":  {opts: badDockerCfgMissing, expectedAuths: 2, shouldFail: false},
		"two dockercfg, one wrong":    {opts: badDockerCfgWrong, expectedAuths: 2, shouldFail: false},
		"two dockercfg, no auth":      {opts: badDockerCfgNoAuth, expectedAuths: 2, shouldFail: false},
		"password file doens't exist": {opts: badUserAndPass, expectedAuths: 1, shouldFail: true},
		"no auths, default expected":  {opts: goodNoAuth, expectedAuths: 1, shouldFail: false},
	}

	for k, v := range tests {
		ii := &defaultImageInspector{*v.opts, iiapi.InspectorMetadata{}, nil, scanOutputs{}}
		auths, err := ii.getAuthConfigs()
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s expected to succeed but received %v", k, err)
			}
			var authsLen int = 0
			if auths != nil {
				authsLen = len(auths.Configs)
			}
			if auths == nil || v.expectedAuths != authsLen {
				t.Errorf("%s expected len to be %d but got %d from %v",
					k, v.expectedAuths, authsLen, auths)
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
		finished := make(chan bool, 1)
		defer func() {
			<-finished // wait for decodeDockerResponse to finish
			close(finished)
			close(parsedErrors)
		}()

		go func() {
			reader, writer := io.Pipe()
			// handle closing the reader/writer in the method that creates them
			defer reader.Close()
			defer writer.Close()
			go decodeDockerResponse(parsedErrors, reader, finished)
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

type mockDockerRuntimeClient struct{}

func (c mockDockerRuntimeClient) InspectImage(name string) (*docker.Image, error) {
	return nil, fmt.Errorf("mockDockerRuntimeClient FAIL")
}
func (c mockDockerRuntimeClient) ContainerChanges(id string) ([]docker.Change, error) {
	return nil, fmt.Errorf("mockDockerRuntimeClient FAIL")
}
func (c mockDockerRuntimeClient) PullImage(opts docker.PullImageOptions, auth docker.AuthConfiguration) error {
	return fmt.Errorf("mockDockerRuntimeClient FAIL")
}
func (c mockDockerRuntimeClient) CreateContainer(opts docker.CreateContainerOptions) (*docker.Container, error) {
	return nil, fmt.Errorf("mockDockerRuntimeClient FAIL")
}
func (c mockDockerRuntimeClient) RemoveContainer(opts docker.RemoveContainerOptions) error {
	return fmt.Errorf("mockDockerRuntimeClient FAIL")
}
func (c mockDockerRuntimeClient) InspectContainer(id string) (*docker.Container, error) {
	return nil, fmt.Errorf("mockDockerRuntimeClient FAIL")
}
func (c mockDockerRuntimeClient) DownloadFromContainer(id string, opts docker.DownloadFromContainerOptions) error {
	return fmt.Errorf("mockDockerRuntimeClient FAIL")
}

type mockRuntimeClientPullSuccess struct {
	mockDockerRuntimeClient
}

func (c mockRuntimeClientPullSuccess) PullImage(opts docker.PullImageOptions, auth docker.AuthConfiguration) error {
	return nil
}

type mockRuntimeClientInspectSuccess struct {
	mockDockerRuntimeClient
}

func (c mockRuntimeClientInspectSuccess) InspectImage(name string) (*docker.Image, error) {
	return &docker.Image{}, nil
}

type mockDockerRuntimeClientAllSuccess struct{}

func (c mockDockerRuntimeClientAllSuccess) InspectImage(name string) (*docker.Image, error) {
	return &docker.Image{}, nil
}
func (c mockDockerRuntimeClientAllSuccess) ContainerChanges(id string) ([]docker.Change, error) {
	return []docker.Change{}, nil
}
func (c mockDockerRuntimeClientAllSuccess) PullImage(opts docker.PullImageOptions, auth docker.AuthConfiguration) error {
	return nil
}
func (c mockDockerRuntimeClientAllSuccess) CreateContainer(opts docker.CreateContainerOptions) (*docker.Container, error) {
	return &docker.Container{}, nil
}
func (c mockDockerRuntimeClientAllSuccess) RemoveContainer(opts docker.RemoveContainerOptions) error {
	return nil
}
func (c mockDockerRuntimeClientAllSuccess) InspectContainer(id string) (*docker.Container, error) {
	return &docker.Container{}, nil
}
func (c mockDockerRuntimeClientAllSuccess) DownloadFromContainer(id string, opts docker.DownloadFromContainerOptions) error {
	return nil
}

type mockRuntimeClientAllSuccessButContainerChanges struct {
	mockDockerRuntimeClientAllSuccess
}

func (c mockRuntimeClientAllSuccessButContainerChanges) ContainerChanges(id string) ([]docker.Change, error) {
	return []docker.Change{}, fmt.Errorf("mockDockerRuntimeClient FAIL")
}

func TestDockerPullImage(t *testing.T) {
	for k, v := range map[string]struct {
		client      DockerRuntimeClient
		shouldFail  bool
		expectedErr string
	}{
		"With instant pull failing client": {shouldFail: true,
			client:      mockDockerRuntimeClient{},
			expectedErr: "Unable to pull docker image: mockDockerRuntimeClient FAIL"},
		"With instant pull success client": {shouldFail: false,
			client: mockRuntimeClientPullSuccess{}},
	} {
		ii := &defaultImageInspector{iicmd.ImageInspectorOptions{Image: "NoSuchImage!"}, iiapi.InspectorMetadata{}, nil, scanOutputs{}}
		err := ii.dockerPullImage(v.client)
		if v.shouldFail {
			if err == nil {
				t.Errorf("%s should have failed but it didn't", k)
			} else {
				if err.Error() != v.expectedErr {
					t.Errorf("Wrong error message for %s.\nExpected: %s\nReceived: %s\n", k, v.expectedErr, err.Error())
				}
			}
		} else {
			if err != nil {
				t.Errorf("%s should not have failed with: %s", k, err.Error())
			}
		}
	}
}

func TestAcquireImage(t *testing.T) {
	noContainerPullNever := iicmd.ImageInspectorOptions{Image: "noSuchImage", Container: "", PullPolicy: iiapi.PullNever, UseDockerSocket: true}
	noContainerPullAlways := iicmd.ImageInspectorOptions{Image: "noSuchImage", Container: "", PullPolicy: iiapi.PullAlways, UseDockerSocket: true}
	noContainerPullNotPresent := iicmd.ImageInspectorOptions{Image: "noSuchImage", Container: "", PullPolicy: iiapi.PullIfNotPresent, UseDockerSocket: true}

	fromContainer := iicmd.ImageInspectorOptions{Container: "I am a container", ScanContainerChanges: true, UseDockerSocket: true}

	for k, v := range map[string]struct {
		opts        iicmd.ImageInspectorOptions
		client      DockerRuntimeClient
		shouldFail  bool
		expectedErr string
	}{
		"When unable to inspect image and also never pull": {opts: noContainerPullNever, shouldFail: true,
			client: mockDockerRuntimeClient{},
			expectedErr: fmt.Sprintf("Image %s is not available and pull-policy %s doesn't allow pulling",
				noContainerPullNever.Image, noContainerPullNever.PullPolicy)},
		"When unable to inspect or pull image and also always pull": {opts: noContainerPullAlways, shouldFail: true,
			client:      mockDockerRuntimeClient{},
			expectedErr: "Unable to pull docker image: mockDockerRuntimeClient FAIL"},
		"When unable to inspect or pull image and also pull if no present": {opts: noContainerPullNotPresent, shouldFail: true,
			client:      mockDockerRuntimeClient{},
			expectedErr: "Unable to pull docker image: mockDockerRuntimeClient FAIL"},
		"Unable to inspect running container": {opts: fromContainer, shouldFail: true,
			client:      mockDockerRuntimeClient{},
			expectedErr: "Unable to get docker container information: mockDockerRuntimeClient FAIL"},
		"Cannot get container changes": {opts: fromContainer, shouldFail: true,
			client:      mockRuntimeClientAllSuccessButContainerChanges{},
			expectedErr: "Unable to get docker container changes: mockDockerRuntimeClient FAIL"},
		"Success with running Container": {opts: fromContainer, shouldFail: false,
			client: mockDockerRuntimeClientAllSuccess{}},
	} {
		ii := &defaultImageInspector{v.opts, iiapi.InspectorMetadata{}, nil, scanOutputs{}}
		err, _ := ii.acquireImage(v.client)
		if v.shouldFail {
			if err == nil {
				t.Errorf("%s should have failed but it didn't", k)
			} else {
				if err.Error() != v.expectedErr {
					t.Errorf("Wrong error message for %s.\nExpected: %s\nReceived: %s\n", k, v.expectedErr, err.Error())
				}
			}
		} else {
			if err != nil {
				t.Errorf("%s should not have failed with: %s", k, err.Error())
			}
		}
	}
}
