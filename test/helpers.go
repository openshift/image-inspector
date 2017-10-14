package test

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
)

type LinuxDistro int

const (
	Distro_Unknown LinuxDistro = iota
	Distro_Centos6
	Distro_Centos7
	Distro_Fedora22
	Distro_Fedora23
	Distro_Fedora24
	Distro_Fedora25
	Distro_Fedora26
	Distro_Fedora27
)

func GetCurrentFileDir() (string, error) {
	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		return "", errors.New("runtime.Caller failed")
	}
	return filepath.Dir(filename), nil
}

func GetLinuxDistro() LinuxDistro {
	if d := getCentosDistro(); d != Distro_Unknown {
		return d
	}
	return getFedoraDistro()
}

func getCentosDistro() LinuxDistro {
	contents, err := ioutil.ReadFile("/etc/centos-issue")
	if err != nil {
		return Distro_Unknown
	}
	rxp := regexp.MustCompile("[\\d+]+")
	version := rxp.Find(contents)
	if len(version) == 0 {
		return Distro_Unknown
	}
	intVer, err := strconv.Atoi(string(version))
	if err != nil {
		return Distro_Unknown
	}
	switch intVer {
	case 6:
		return Distro_Centos6
	case 7:
		return Distro_Centos7
	}
	return Distro_Unknown
}

func getFedoraDistro() LinuxDistro {
	contents, err := ioutil.ReadFile("/etc/fedora-release")
	if err != nil {
		return Distro_Unknown
	}

	rxp := regexp.MustCompile("[\\d+]+")
	version := rxp.Find(contents)
	if len(version) == 0 {
		return Distro_Unknown
	}
	intVer, err := strconv.Atoi(string(version))
	if err != nil {
		return Distro_Unknown
	}
	switch intVer {
	case 22:
		return Distro_Fedora22
	case 23:
		return Distro_Fedora23
	case 24:
		return Distro_Fedora24
	case 25:
		return Distro_Fedora25
	case 26:
		return Distro_Fedora26
	case 27:
		return Distro_Fedora27
	}
	return Distro_Unknown
}
