package content

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
)

type defaultGroupsInspector struct {

	// ImageMountPath is the path where the image to be scanned is mounted
	imageMountPath string

	groupInfo chrootContentFunc

	Groups []group
}

type group struct {
	Name     string
	GID      string
	UserList string
}

// NewDefaultGroupInspector returns a new Version Inspector
func NewDefaultGroupInspector() Inspector {
	inspector := &defaultGroupsInspector{}

	inspector.groupInfo = inspector.getGroupsChroot

	return inspector
}

func (s *defaultGroupsInspector) processGroupFile(groupFile string) error {

	inFile, err := os.Open(groupFile)
	defer inFile.Close()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		groupData := strings.Split(scanner.Text(), ":")
		s.Groups = append(s.Groups, group{Name: groupData[0],
			GID:      groupData[2],
			UserList: groupData[3]})
	}

	return nil
}

func (s *defaultGroupsInspector) getGroupsChroot(mountPath string) error {

	groupFile := path.Join(mountPath, DefaultGroupFilePath)

	_, err := os.Stat(groupFile)
	if err != nil || os.IsNotExist(err) {
		return fmt.Errorf("Unable to process expected group file %s: %v", groupFile, err)
	}

	s.processGroupFile(groupFile)

	return nil
}

func (s *defaultGroupsInspector) Inspect(mountPath string) error {
	s.groupInfo(mountPath)
	return nil
}
