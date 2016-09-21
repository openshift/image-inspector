package content

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
)

type defaultUsersInspector struct {

	// ImageMountPath is the path where the image to be scanned is mounted
	imageMountPath string

	userInfo chrootContentFunc

	Users []user
}

type user struct {
	Name      string
	UID       string
	GID       string
	Directory string
	GECOS     string
	Shell     string
}

// NewDefaultUserInspector returns a new Version Inspector
func NewDefaultUserInspector() Inspector {
	inspector := &defaultUsersInspector{}

	inspector.userInfo = inspector.getUsersChroot

	return inspector
}

func (s *defaultUsersInspector) processUserFile(userFile string) error {

	inFile, err := os.Open(userFile)
	defer inFile.Close()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		userData := strings.Split(scanner.Text(), ":")
		s.Users = append(s.Users, user{Name: userData[0],
			UID:       userData[2],
			GID:       userData[3],
			GECOS:     userData[4],
			Directory: userData[5],
			Shell:     userData[6]})
	}

	return nil
}

func (s *defaultUsersInspector) getUsersChroot(mountPath string) error {

	userFile := path.Join(mountPath, DefaultUserFilePath)

	_, err := os.Stat(userFile)
	if err != nil || os.IsNotExist(err) {
		return fmt.Errorf("Unable to process expected user file %s: %v", userFile, err)
	}

	s.processUserFile(userFile)

	return nil
}

func (s *defaultUsersInspector) Inspect(mountPath string) error {
	s.userInfo(mountPath)
	return nil
}
