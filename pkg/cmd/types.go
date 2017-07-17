package cmd

import (
	"fmt"

	oscapscanner "github.com/openshift/image-inspector/pkg/openscap"

	iiapi "github.com/openshift/image-inspector/pkg/api"

	"os"

	util "github.com/openshift/image-inspector/pkg/util"
)

const DefaultDockerSocketLocation = "unix:///var/run/docker.sock"

// MultiStringVar is implementing flag.Value
type MultiStringVar []string

func (sv *MultiStringVar) Set(s string) error {
	*sv = append(*sv, s)
	return nil
}

func (sv *MultiStringVar) String() string {
	return fmt.Sprintf("%v", *sv)
}

// ImageInspectorOptions is the main inspector implementation and holds the configuration
// for an image inspector.
type ImageInspectorOptions struct {
	// URI contains the location of the docker daemon socket to connect to.
	URI string
	// Image contains the docker image to inspect.
	Image string
	// Container contains the docker container to inspect.
	Container string
	// ScanContainerChanges controls whether or not whole rootfs will be scanned.
	ScanContainerChanges bool
	// DstPath is the destination path for image files.
	DstPath string
	// Serve holds the host and port for where to serve the image with webdav.
	Serve string
	// Chroot controls whether or not a chroot is excuted when serving the image with webdav.
	Chroot bool
	// DockerCfg is the location of the docker config file.
	DockerCfg MultiStringVar
	// Username is the username for authenticating to the docker registry.
	Username string
	// PasswordFile is the location of the file containing the password for authentication to the
	// docker registry.
	PasswordFile string
	// ScanTypes are the types of scans to be done on the inspected image
	ScanTypes MultiStringVar
	// ScanResultsDir is the directory that will contain the results of the scan
	ScanResultsDir string
	// OpenScapHTML controls whether or not to generate an HTML report
	// TODO: Move this into openscap plugin options.
	OpenScapHTML bool
	// CVEUrlPath An alternative source for the cve files
	// TODO: Move this into openscap plugin options.
	CVEUrlPath string
	// ClamSocket is the location of clamav socket file
	ClamSocket string
	// PostResultURL represents an URL where the image-inspector should post the results of
	// the scan.
	PostResultURL string
	// PostResultTokenFile if specified the content of the file will be added as a token to
	// the result POST URL (eg. http://foo/?token=CONTENT.
	PostResultTokenFile string
	// AuthToken is a Shared Secret used to validate HTTP Requests.
	// AuthToken can be set through AuthTokenFile or ENV
	AuthToken string
	// AuthTokenFile is the path to a file containing the AuthToken
	// If it is not provided, the AuthToken will be read from the ENV
	AuthTokenFile string
	// PullPolicy controls whether we try to pull the inspected image
	PullPolicy string
}

// NewDefaultImageInspectorOptions provides a new ImageInspectorOptions with default values.
func NewDefaultImageInspectorOptions() *ImageInspectorOptions {
	return &ImageInspectorOptions{
		URI:        DefaultDockerSocketLocation,
		DockerCfg:  MultiStringVar{},
		ScanTypes:  MultiStringVar{},
		CVEUrlPath: oscapscanner.CVEUrl,
		PullPolicy: iiapi.PullIfNotPresent,
	}
}

// Validate performs validation on the field settings.
func (i *ImageInspectorOptions) Validate() error {
	if len(i.URI) == 0 {
		return fmt.Errorf("docker socket connection must be specified")
	}
	if len(i.Image) > 0 && len(i.Container) > 0 {
		return fmt.Errorf("options container and image are mutually exclusive")
	}
	if len(i.Image) == 0 && len(i.Container) == 0 {
		return fmt.Errorf("docker image or container must be specified to inspect")
	}
	if i.ScanContainerChanges && len(i.Container) == 0 {
		return fmt.Errorf("please specify docker container")
	}
	if len(i.DockerCfg) > 0 && len(i.Username) > 0 {
		return fmt.Errorf("only specify dockercfg file or username/password pair for authentication")
	}
	if len(i.Username) > 0 && len(i.PasswordFile) == 0 {
		return fmt.Errorf("please specify password-file for the given username")
	}
	if len(i.Serve) == 0 && i.Chroot {
		return fmt.Errorf("change root can be used only when serving the image through webdav")
	}
	if len(i.ScanResultsDir) > 0 && len(i.ScanTypes) == 0 {
		return fmt.Errorf("scan-result-dir can be used only when spacifing scan-type")
	}
	if len(i.ScanResultsDir) > 0 {
		fi, err := os.Stat(i.ScanResultsDir)
		if err == nil && !fi.IsDir() {
			return fmt.Errorf("scan-results-dir %q is not a directory", i.ScanResultsDir)
		}
	}
	if len(i.PostResultTokenFile) > 0 && len(i.PostResultURL) == 0 {
		return fmt.Errorf("post-results-url must be set to use post-results-token-file")
	}
	if i.OpenScapHTML && !util.StringInList("openscap", i.ScanTypes) {
		return fmt.Errorf("openscap-html-report can be used only when specifying scan-type as \"openscap\"")
	}
	for _, fl := range append(i.DockerCfg, i.PasswordFile) {
		if len(fl) > 0 {
			if _, err := os.Stat(fl); os.IsNotExist(err) {
				return fmt.Errorf("%s does not exist", fl)
			}
		}
	}
	if util.StringInList("clamav", i.ScanTypes) && len(i.ClamSocket) == 0 {
		return fmt.Errorf("clam-socket must be set to use clamav scan type")
	}

	// A scan-types must be valid.
	if len(i.ScanTypes) > 0 {
		for _, v := range i.ScanTypes {
			if !util.StringInList(v, iiapi.ScanOptions) {
				return fmt.Errorf("%s is not one of the available scan-types which are %v",
					v, iiapi.ScanOptions)
			}
		}
	}
	if !util.StringInList(i.PullPolicy, iiapi.PullPolicyOptions) {
		return fmt.Errorf("%s is not one of the available pull-policy options which are %v",
			i.PullPolicy, iiapi.PullPolicyOptions)

	}
	return nil
}
