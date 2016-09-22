package content

import (
	"strings"
	"testing"
)

const (
	TESTPATH = "/test/path"
)

func TestBuildPathPrefix(t *testing.T) {

	testString := buildPathChroot(TESTPATH)
	if !strings.HasPrefix(testString, "PATH=") {
		t.Errorf("testString doesn't have expected prefix \"PATH=\" => %s", testString)
	}

}

func TestBuildPathModify(t *testing.T) {

	testString := strings.Replace(buildPathChroot(TESTPATH), "PATH=", "", -1)

	pathSlice := strings.Split(testString, ":")

	for _, path := range pathSlice {
		if !strings.HasPrefix(path, TESTPATH) {
			t.Errorf("Path string \"%s\" failed to be pre-prended with %s", path, TESTPATH)
		}
	}

}
