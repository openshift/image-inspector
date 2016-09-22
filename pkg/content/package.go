package content

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
)

type defaultPackageInspector struct {
	packageInfo         chrootContentFunc
	buildPackageCommand chrootCommandFunc
	cmd                 *exec.Cmd

	Packages []packages
}

type packages struct {
	Package     string
	Version     string
	Description string
}

// NewDefaultPackageInspector returns a new Version Inspector
func NewDefaultPackageInspector() Inspector {
	inspector := &defaultPackageInspector{}

	return inspector
}

func buildPathChroot(mountPath string) string {

	pathStr := os.Getenv("PATH")
	pathSlice := strings.Split(pathStr, ":")
	var newPath bytes.Buffer

	newPath.WriteString("PATH=")
	for i, binPath := range pathSlice {
		if i != 0 {
			newPath.WriteString(":")
		}
		newPath.WriteString(path.Join(mountPath, binPath))
	}
	return newPath.String()
}

func (s *defaultPackageInspector) buildDpkgCommandChroot(mountPath string) {
	cmd := exec.Command(path.Join(mountPath, "/usr/bin/dpkg-query"), "-W",
		"-f", "${binary:Package},${Version},${Description}---",
		"--admindir", path.Join(mountPath, "/var/lib/dpkg"))
	cmd.Env = []string{buildPathChroot(mountPath)}
	s.cmd = cmd

}

func (s *defaultPackageInspector) buildRpmCommandChroot(mountPath string) {
	cmd := exec.Command("rpm", "-qa", "--dbpath",
		path.Join(mountPath, "/var/lib/rpm"), "--qf",
		"%{NAME},%{VERSION},%{DESCRIPTION}---")
	cmd.Env = []string{buildPathChroot(mountPath)}
	s.cmd = cmd
}

func (s *defaultPackageInspector) getPackageInformation() error {

	out, err := s.cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("Unable to read package content")
	}
	pkgdata := strings.Replace(string(out), "\n", "", -1)
	pkglist := strings.Split(pkgdata, "---")

	for _, pkg := range pkglist {
		if len(pkg) > 0 {
			parts := strings.Split(pkg, ",")
			pkgDescription := strings.Join(parts[2:], "")

			s.Packages = append(s.Packages, packages{Package: parts[0],
				Version: parts[1], Description: pkgDescription})
		}
	}

	return nil
}

func (s *defaultPackageInspector) Inspect(mountPath string) error {
	_, err := os.Stat(path.Join(mountPath, "/var/lib/rpm"))
	if err == nil {
		log.Println("Determined this is an RPM based image")
		s.buildPackageCommand = s.buildRpmCommandChroot
	}

	_, err = os.Stat(path.Join(mountPath, "/var/lib/dpkg"))
	if err == nil {
		log.Println("Determined this is a DPKG based image")
		s.buildPackageCommand = s.buildDpkgCommandChroot

	}

	if s.buildPackageCommand != nil {
		s.buildPackageCommand(mountPath)

		err = s.getPackageInformation()
		return err
	}

	return fmt.Errorf("Unable to determine package format for image under analysis")
}
