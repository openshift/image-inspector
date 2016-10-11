package content

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path"
	"testing"
)

const (
	TESTPATH        = "test/"
	GOODJSONNAME    = "libss"
	GOODJSONVERSION = "1.41.12"
	GOODJSONARCH    = "x86_64"
)

var (
	testLine = []byte{'\x61', '\x22', '\x62', '\x63', '\x64', '\x65'}
	goodJSON = "{\"Name\": \"libss\",\"Version\": \"1.41.12\"," +
		"\"Architecture\": \"x86_64\",\"Description\": \"The cake is a lie\"}"
	okJSON = "{\"Name\": \"libss\",\"Version\": \"1.41.12\"," +
		"\"Architecture\": \"x86_64\",\"Description\": \"The cake is a \"}" +
		string([]byte{'\x22', '\x6c', '\x69', '\x65', '\x22'})
)

func (s *defaultPackageInspector) getRHELBlob() error {
	bytes, err := ioutil.ReadFile(path.Join(TESTPATH, "rhel_7_blob"))
	if err != nil {
		return err
	}
	s.packageBlob = bytes
	return nil
}

func (s *defaultPackageInspector) getRHELSimpleBlob() error {
	bytes, err := ioutil.ReadFile(path.Join(TESTPATH, "rhel_7_simple"))
	if err != nil {
		return err
	}
	s.packageBlob = bytes
	return nil
}

func (s *defaultPackageInspector) getCentOSBlob() error {
	bytes, err := ioutil.ReadFile(path.Join(TESTPATH, "centos_6_blob"))
	if err != nil {
		return err
	}
	s.packageBlob = bytes
	return nil
}

func (s *defaultPackageInspector) getDebianBlob() error {
	bytes, err := ioutil.ReadFile(path.Join(TESTPATH, "debian_8_blob"))
	if err != nil {
		return err
	}
	s.packageBlob = bytes
	return nil
}

func (s *defaultPackageInspector) getUbuntuBlob() error {
	bytes, err := ioutil.ReadFile(path.Join(TESTPATH, "ubuntu_16_04_blob"))
	if err != nil {
		return err
	}
	s.packageBlob = bytes
	return nil
}

func (s *defaultPackageInspector) getNoBlob() error {
	bytes, _ := ioutil.ReadFile(path.Join(TESTPATH, "no_blob"))
	s.packageBlob = bytes
	return fmt.Errorf("No data blob")
}

func NewMockRHELPackageInspector() *defaultPackageInspector {
	contentInspector := &defaultPackageInspector{}
	contentInspector.getPackageBlobChroot = contentInspector.getRHELBlob
	return contentInspector
}

func NewMockRHELSimplePackageInspector() *defaultPackageInspector {
	contentInspector := &defaultPackageInspector{}
	contentInspector.getPackageBlobChroot = contentInspector.getRHELSimpleBlob
	return contentInspector
}

func NewMockCentOSPackageInspector() *defaultPackageInspector {
	contentInspector := &defaultPackageInspector{}
	contentInspector.getPackageBlobChroot = contentInspector.getCentOSBlob
	return contentInspector
}

func NewMockDebianPackageInspector() *defaultPackageInspector {
	contentInspector := &defaultPackageInspector{}
	contentInspector.getPackageBlobChroot = contentInspector.getDebianBlob
	return contentInspector
}

func NewMockUbuntuPackageInspector() *defaultPackageInspector {
	contentInspector := &defaultPackageInspector{}
	contentInspector.getPackageBlobChroot = contentInspector.getUbuntuBlob
	return contentInspector
}

func NewMockBadPackageInspector() *defaultPackageInspector {
	contentInspector := &defaultPackageInspector{}
	contentInspector.getPackageBlobChroot = contentInspector.getNoBlob
	return contentInspector
}

//testHasNilPackages tests if there is a package entry where
//all four values are empty, something went wrong.
func testHasNilPackages(packageList []packages) (int, bool) {
	for i, pkg := range packageList {
		if pkg.Name == "" && pkg.Description == "" &&
			pkg.Architecture == "" && pkg.Version == "" {
			return i, true
		}
	}
	return 0, false
}

func TestGetBlob(t *testing.T) {
	tests := map[string]struct {
		shouldFail    bool
		mockInspector *defaultPackageInspector
	}{
		"Get RHEL Blob":   {mockInspector: NewMockRHELPackageInspector(), shouldFail: false},
		"Get CentOS Blob": {mockInspector: NewMockCentOSPackageInspector(), shouldFail: false},
		"Get Ubuntu Blob": {mockInspector: NewMockUbuntuPackageInspector(), shouldFail: false},
		"Get Debian Blob": {mockInspector: NewMockDebianPackageInspector(), shouldFail: false},
		"Get No Blob":     {mockInspector: NewMockBadPackageInspector(), shouldFail: true},
	}
	for k, v := range tests {
		err := v.mockInspector.getPackageBlobChroot()
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s expected to succeed but received %v", k, err)
			}
		} else {
			if err == nil {
				t.Errorf("%s expected to fail but received no error message: %v", k, err)
			}
		}
	}
}

func TestCleanBlob(t *testing.T) {
	tests := map[string]struct {
		shouldFail    bool
		mockInspector *defaultPackageInspector
	}{
		"Get RHEL Blob":   {mockInspector: NewMockRHELPackageInspector(), shouldFail: false},
		"Get CentOS Blob": {mockInspector: NewMockCentOSPackageInspector(), shouldFail: false},
		"Get Ubuntu Blob": {mockInspector: NewMockUbuntuPackageInspector(), shouldFail: false},
		"Get Debian Blob": {mockInspector: NewMockDebianPackageInspector(), shouldFail: false},
		"Get No Blob":     {mockInspector: NewMockBadPackageInspector(), shouldFail: true},
	}
	for k, v := range tests {
		v.mockInspector.getPackageBlobChroot()
		if !v.shouldFail {
			v.mockInspector.cleanPackageBlob()
			if bytes.Contains(v.mockInspector.packageBlob, []byte{'\x7d', '\x7b'}) {
				t.Errorf("%s failed to clean blob.  Found }{", k)
			}
		} else {
			if !bytes.Contains(v.mockInspector.packageBlob, []byte{'\x7d', '\x7b'}) {
				t.Errorf("%s Should have found }{ because the clean shouldnt have been run", k)
			}
		}
	}
}

func TestIncreaseCapacity(t *testing.T) {
	tests := map[string]struct {
		shouldFail    bool
		mockInspector *defaultPackageInspector
	}{
		"Fix Capacity Success": {mockInspector: NewMockRHELPackageInspector(), shouldFail: false},
	}
	for k, v := range tests {
		v.mockInspector.packageBlob = []byte{'\x20'}
		origCap := cap(v.mockInspector.packageBlob)
		v.mockInspector.increaseCapacity()
		if cap(v.mockInspector.packageBlob) != (origCap + 1) {
			t.Errorf("%s Capacity not increased as expected.  "+
				"Capacity is %d and expected to be %d",
				k, cap(v.mockInspector.packageBlob), (origCap + 1))
		}
	}
}

func TestFixJSON(t *testing.T) {
	tests := map[string]struct {
		shouldFail    bool
		mockInspector *defaultPackageInspector
	}{
		"Fix JSON Success": {mockInspector: NewMockRHELSimplePackageInspector(), shouldFail: false},
	}
	for k, v := range tests {
		v.mockInspector.getPackageBlobChroot()
		if !v.shouldFail {
			v.mockInspector.increaseCapacity()
			v.mockInspector.fixJSON(50)
			if v.mockInspector.packageBlob[48] != '\x5c' {
				t.Errorf("%s Did not insert escape character \\ as expected.  "+
					"Instead found \"%c\"", k, v.mockInspector.packageBlob[48])
			}
		}
	}
}

func TestProcessPackages(t *testing.T) {
	tests := map[string]struct {
		shouldFail    bool
		mockInspector *defaultPackageInspector
	}{
		"RHEL Blob":   {mockInspector: NewMockRHELPackageInspector(), shouldFail: false},
		"CentOS Blob": {mockInspector: NewMockCentOSPackageInspector(), shouldFail: false},
		"Ubuntu Blob": {mockInspector: NewMockUbuntuPackageInspector(), shouldFail: false},
		"Debian Blob": {mockInspector: NewMockDebianPackageInspector(), shouldFail: false},
		"No Blob":     {mockInspector: NewMockBadPackageInspector(), shouldFail: true},
	}
	for k, v := range tests {
		v.mockInspector.getPackageBlobChroot()
		v.mockInspector.cleanPackageBlob()
		if !v.shouldFail {
			err := v.mockInspector.processPackageBlob()
			if err != nil {
				t.Errorf("%s Should have succeeded but failed: %v", k, err)
			}
			index, hasNil := testHasNilPackages(v.mockInspector.GetPackages())
			if hasNil {
				t.Errorf("%s Should have succeeded but an empty "+
					"package value was found at position %d", k, index)
				t.Errorf("%s The last package that succeeded processing was %s",
					k, v.mockInspector.GetPackages()[index-1].Name)
			}
		}
	}
}
