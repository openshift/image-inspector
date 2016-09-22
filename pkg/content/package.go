package content

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
)

//defaultPackageInspector is the default implementation of the package inspector
type defaultPackageInspector struct {
	buildPackageCommand  chrootCommandFunc
	getPackageBlobChroot chrootGetBlobFunc
	cmd                  *exec.Cmd
	packageBlob          []byte
	packages             []packages
	origPathEnv          string
}

//packages is the struct that defines the package information
type packages struct {
	Name         string //name of the package
	Version      string //version string
	Architecture string //architecture of the package (e.g. x86_64)
	Description  string //description of the package
}

// NewDefaultPackageInspector returns a new Version Inspector
func NewDefaultPackageInspector() Inspector {
	contentInspector := &defaultPackageInspector{}
	contentInspector.getPackageBlobChroot = contentInspector.getPackageBlob
	return contentInspector
}

func (s *defaultPackageInspector) GetPackages() []packages {
	return s.packages
}

//buildPathChroot Builds the new PATH environment variable for executing
//commands
func (s *defaultPackageInspector) buildPathChroot(mountPath string) {
	s.origPathEnv = os.Getenv("PATH")
	pathSlice := strings.Split(s.origPathEnv, ":")
	var newPath bytes.Buffer

	newPath.WriteString("PATH=")
	for i, binPath := range pathSlice {
		if i != 0 {
			newPath.WriteString(":")
		}
		newPath.WriteString(path.Join(mountPath, binPath))
	}
	os.Setenv("PATH", newPath.String())
}

//restorePath Puts the PATH env back the way it was when we are done inspecting
func (s *defaultPackageInspector) restorePath() {
	os.Setenv("PATH", s.origPathEnv)
}

//buildDpkgCommandChroot builds the command for DPKG based images
func (s *defaultPackageInspector) buildDpkgCommandChroot(mountPath string) {
	cmd := exec.Command(path.Join(mountPath, "/usr/bin/dpkg-query"), "-W",
		"-f", "\\{\"Name\": \"${binary:Package}\","+
			"\"Version\": \"${Version}\","+
			"\"Architecture\": \"${Architecture}\","+
			" \"Description\": \"${Description}\"\\}",
		"--admindir", path.Join(mountPath, "/var/lib/dpkg"))
	s.cmd = cmd

}

//buildRpmCommandChroot builds the command for RPM based images
func (s *defaultPackageInspector) buildRpmCommandChroot(mountPath string) {
	cmd := exec.Command("rpm", "-qa", "--dbpath",
		path.Join(mountPath, "/var/lib/rpm"), "--qf",
		"\\{\"Name\": \"%{NAME}\","+
			" \"Version\": \"%{VERSION}\","+
			"\"Architecture\": \"%{ARCH}\","+
			"\"Description\": \"%{DESCRIPTION}\"\\}")
	s.cmd = cmd
}

//getPackageBlob executes the package query command and generates a byte slice
//output
func (s *defaultPackageInspector) getPackageBlob() error {
	out, err := s.cmd.CombinedOutput()
	//Return an error if we can't get the output of the command execution
	if err != nil {
		return fmt.Errorf("Unable to read package content")
	}
	//Set the blob in the inspector struct
	s.packageBlob = []byte{'\x5b'}
	s.packageBlob = append(s.packageBlob, out...)
	s.packageBlob = append(s.packageBlob, []byte{'\x5d'}...)
	//Return no errors
	return nil
}

func (s *defaultPackageInspector) cleanPackageBlob() {
	//First we will remvove all the new lines (e.g. in all the descriptions)
	s.packageBlob = bytes.Replace(s.packageBlob, []byte{'\x0a'}, []byte{'\x20'}, -1)
	//Next we will remvove all the back ticks (e.g. in all the descriptions)
	s.packageBlob = bytes.Replace(s.packageBlob, []byte{'\x60'}, []byte{}, -1)
	//Next we will remvove all the single quotes (e.g. in all the descriptions)
	s.packageBlob = bytes.Replace(s.packageBlob, []byte{'\x27'}, []byte{}, -1)
	//Next we will remvove all the null bytes (e.g. in all the descriptions)
	s.packageBlob = bytes.Replace(s.packageBlob, []byte{'\x00'}, []byte{}, -1)
	//Next we will replace }{ with },{ because we want to process all elements
	s.packageBlob = bytes.Replace(s.packageBlob, []byte{'\x7d', '\x7b'},
		[]byte{'\x7d', '\x2c', '\x7b'}, -1)
}

//processPackageBlob is responsible for unmarshalling the resulting JSON
//structures to structs
func (s *defaultPackageInspector) processPackageBlob() error {

	for {
		//Attempt to decode the string
		dec := json.NewDecoder(strings.NewReader(string(s.packageBlob)))
		err := dec.Decode(&s.packages)
		if err != nil {
			//If there is an error, check if it is a SyntaxError.  If so, then
			//fix the offending byte.
			if ser, ok := err.(*json.SyntaxError); ok {
				offset := ser.Offset
				s.increaseCapacity()
				s.fixJSON(offset)
			} else {
				//If it isn't a SyntaxError, return the error because something else
				//went wrong.
				log.Printf("%s", string(s.packageBlob))
				log.Printf("Something went wrong decoding blob")
				return err
			}
		} else {
			break
		}
	}
	return nil

}

//fixCapacity increases the capacity of the package blob by one
func (s *defaultPackageInspector) increaseCapacity() {
	//First we must grow the slice by one so that we can have room
	//to insert an escape charachter.  We start by creating an empty slice that
	//is one element longer than the capacity of the original package blob
	newSlice := make([]byte, len(s.packageBlob), cap(s.packageBlob)+1)
	//Then we copy the contents of the old blob to the new slice
	copy(newSlice, s.packageBlob)
	//And set the struct field to the value of the new slice which has the
	//original content, and is one bigger.
	s.packageBlob = newSlice
}

func (s *defaultPackageInspector) fixJSON(offset int64) {
	index := offset - 2
	//There should never be a case where there's an invalid character this close
	//to the start of the string, but let's be cautious
	if index >= 0 {
		// Grow the slice by one element.
		s.packageBlob = s.packageBlob[0 : len(s.packageBlob)+1]
		// Use copy to move the upper part of the slice out of the way and open a hole.
		copy(s.packageBlob[index+1:], s.packageBlob[index:])
		s.packageBlob[index] = '\x5c'
	}
}

//isRPMBased uses the PATH environment variable, which has been modified to
//the path for the image under inspection, to find the rpm binary
func isRPMBased() bool {
	_, err := exec.LookPath("rpm")
	if err != nil {
		return false
	}
	return true

}

//isDPKGBased uses the PATH environment variable, which has been modified to
//the path for the image under inspection, to find the dpkg-query binary
func isDPKGBased() bool {
	_, err := exec.LookPath("dpkg-query")
	if err != nil {
		return false
	}
	return true
}

//Inspect is the primary execution entrypoint
func (s *defaultPackageInspector) Inspect(mountPath string) error {
	s.buildPathChroot(mountPath)
	defer s.restorePath()

	if isRPMBased() {
		log.Println("Determined this is an RPM based image")
		s.buildPackageCommand = s.buildRpmCommandChroot
	} else if isDPKGBased() {
		log.Println("Determined this is a DPKG based image")
		s.buildPackageCommand = s.buildDpkgCommandChroot
	} else {
		return fmt.Errorf("Unable to determine packaging type for image under" +
			" inspection.  Skipping package inspection...")
	}

	if s.buildPackageCommand != nil {
		s.buildPackageCommand(mountPath)

		err := s.getPackageBlobChroot()
		if err != nil {
			return err
		}
		s.cleanPackageBlob()

		err = s.processPackageBlob()
		if err != nil {
			return err
		}

		return nil
	}
	return fmt.Errorf("Unable to determine package format for image under analysis")
}
