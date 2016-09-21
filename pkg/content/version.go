package content

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

var (
	//ReleaseFiles are the possible files holding release information.  centos-release
	//is typically a soft link to redhat-release, but we'll check for it to help determine
	//the OS type of the container image
	ReleaseFiles = [...]string{"centos-release", "redhat-release", "lsb-release", "os-release"}
)

type defaultVersionInspector struct {

	// ImageMountPath is the path where the image to be scanned is mounted
	imageMountPath string

	versionInfo chrootContentFunc

	contentVersion
}

//ContentVersion holds information about the OS in the container
type contentVersion struct {
	Type  string
	Major string
	Minor string
}

// NewDefaultVersionInspector returns a new Version Inspector
func NewDefaultVersionInspector() Inspector {
	inspector := &defaultVersionInspector{}

	inspector.versionInfo = inspector.getLinuxVersionChroot

	return inspector
}

//processVersion will parse a string from /etc/redhat-release, centos-release
//or lsb-release
func (s *defaultVersionInspector) processVersion(data string) {

	verString := regexp.MustCompile("[0-9]+[\\.[0-9]+]?").FindAllString(data, 1)

	if len(verString) == 0 {
		verString = regexp.MustCompile("[0-9]+").FindAllString(data, 1)
	}

	if strings.Contains(verString[0], ".") {
		splitVer := strings.Split(verString[0], ".")
		s.contentVersion.Major = splitVer[0]

		s.contentVersion.Minor = splitVer[1]
	} else {
		s.contentVersion.Major = verString[0]
	}

}

func (s *defaultVersionInspector) processReleaseData(relFile string) error {

	data, err := ioutil.ReadFile(relFile)

	if err != nil {
		return err
	}

	stringData := string(data)

	if strings.Contains(stringData, "Enterprise Linux Server") {
		s.contentVersion.Type = "Red Hat"
	} else if strings.Contains(stringData, "CentOS") {
		s.contentVersion.Type = "CentOS"
	} else if strings.Contains(stringData, "Ubuntu") {
		s.contentVersion.Type = "Ubuntu"
	} else if strings.Contains(stringData, "Debian") {
		s.contentVersion.Type = "Debian"
	}

	s.processVersion(stringData)
	return nil
}

func (s *defaultVersionInspector) getLinuxVersionChroot(mountPath string) error {

	for _, relFile := range ReleaseFiles {
		_, err := os.Stat(path.Join(mountPath, relFile))
		if err == nil {
			s.processReleaseData(path.Join(mountPath, relFile))
			break
		}
	}

	if s.contentVersion.Type == "" {
		return fmt.Errorf("Could not determine image Linux type.")
	}
	return nil
}

func (s *defaultVersionInspector) Inspect(mountPath string) error {
	fi, err := os.Stat(mountPath)
	if err != nil || os.IsNotExist(err) || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory, error: %v", mountPath, err)
	}
	s.imageMountPath = mountPath
	s.versionInfo(path.Join(s.imageMountPath, DefaultReleasePath))

	return nil

}
