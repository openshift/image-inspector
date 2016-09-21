package cmd

import (
	"fmt"
	"os"
)

var (
	ScanOptions = []string{"openscap"}
)

// MultiStringVar is implementing flag.Value
type MultiStringVar struct {
	Values []string
}

func (sv *MultiStringVar) Set(s string) error {
	sv.Values = append(sv.Values, s)
	return nil
}

func (sv *MultiStringVar) String() string {
	return fmt.Sprintf("%v", sv.Values)
}

// ImageInspectorOptions is the main inspector implementation and holds the configuration
// for an image inspector.
type ImageInspectorOptions struct {
	// URI contains the location of the docker daemon socket to connect to.
	URI string
	// Image contains the docker image to inspect.
	Image string
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
	// ScanType is the type of the scan to be done on the inspected image
	ScanType string
	// ScanResultsDir is the directory that will contain the results of the scan
	ScanResultsDir string
	// OpenScapHTML controls whether or not to generate an HTML report
	OpenScapHTML bool
}

// NewDefaultImageInspectorOptions provides a new ImageInspectorOptions with default values.
func NewDefaultImageInspectorOptions() *ImageInspectorOptions {
	return &ImageInspectorOptions{
		URI:            "unix:///var/run/docker.sock",
		Image:          "",
		DstPath:        "",
		Serve:          "",
		Chroot:         false,
		DockerCfg:      MultiStringVar{[]string{}},
		Username:       "",
		PasswordFile:   "",
		ScanType:       "",
		ScanResultsDir: "",
		OpenScapHTML:   false,
	}
}

// Validate performs validation on the field settings.
func (i *ImageInspectorOptions) Validate() error {
	if len(i.URI) == 0 {
		return fmt.Errorf("Docker socket connection must be specified")
	}
	if len(i.Image) == 0 {
		return fmt.Errorf("Docker image to inspect must be specified")
	}
	if len(i.DockerCfg.Values) > 0 && len(i.Username) > 0 {
		return fmt.Errorf("Only specify dockercfg file or username/password pair for authentication")
	}
	if len(i.Username) > 0 && len(i.PasswordFile) == 0 {
		return fmt.Errorf("Please specify password for the username")
	}
	if len(i.Serve) == 0 && i.Chroot {
		return fmt.Errorf("Change root can be used only when serving the image through webdav")
	}
	if len(i.ScanResultsDir) > 0 && len(i.ScanType) == 0 {
		return fmt.Errorf("scan-result-dir can be used only when spacifing scan-type")
	}
	if len(i.ScanResultsDir) > 0 {
		fi, err := os.Stat(i.ScanResultsDir)
		if err == nil && !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", i.ScanResultsDir)
		}
	}
	if i.OpenScapHTML && (len(i.ScanType) == 0 || i.ScanType != "openscap") {
		return fmt.Errorf("OpenScapHtml can be used only when specifying scan-type as \"openscap\"")
	}
	for _, fl := range append(i.DockerCfg.Values, i.PasswordFile) {
		if len(fl) > 0 {
			if _, err := os.Stat(fl); os.IsNotExist(err) {
				return fmt.Errorf("%s does not exist", fl)
			}
		}
	}
	if len(i.ScanType) > 0 {
		var found bool = false
		for _, opt := range ScanOptions {
			if i.ScanType == opt {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s is not one of the available scan-types which are %v", i.ScanType, ScanOptions)
		}

	}
	return nil
}
