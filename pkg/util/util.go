package util

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
)

const (
	DOCKER_TAR_PREFIX = "rootfs/"
	OWNER_PERM_RW     = 0600
)

func StrOrDefault(s string, d string) string {
	if len(s) == 0 { // s || d
		return d
	}
	return s
}

func Min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func HandleTarStream(reader io.ReadCloser, destination string) {
	tr := tar.NewReader(reader)
	if tr != nil {
		err := processTarStream(tr, destination)
		if err != nil {
			log.Print(err)
		}
	} else {
		log.Printf("Unable to create image tar reader")
	}
}

func processTarStream(tr *tar.Reader, destination string) error {
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("Unable to extract container: %v\n", err)
		}

		hdrInfo := hdr.FileInfo()

		dstpath := path.Join(destination, strings.TrimPrefix(hdr.Name, DOCKER_TAR_PREFIX))
		// Overriding permissions to allow writing content
		mode := hdrInfo.Mode() | OWNER_PERM_RW

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(dstpath, mode); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("Unable to create directory: %v", err)
				}
				err = os.Chmod(dstpath, mode)
				if err != nil {
					return fmt.Errorf("Unable to update directory mode: %v", err)
				}
			}
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.OpenFile(dstpath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return fmt.Errorf("Unable to create file: %v", err)
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return fmt.Errorf("Unable to write into file: %v", err)
			}
			file.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, dstpath); err != nil {
				return fmt.Errorf("Unable to create symlink: %v\n", err)
			}
		case tar.TypeLink:
			target := path.Join(destination, strings.TrimPrefix(hdr.Linkname, DOCKER_TAR_PREFIX))
			if err := os.Link(target, dstpath); err != nil {
				return fmt.Errorf("Unable to create link: %v\n", err)
			}
		default:
			// For now we're skipping anything else. Special device files and
			// symlinks are not needed or anyway probably incorrect.
		}

		// maintaining access and modification time in best effort fashion
		os.Chtimes(dstpath, hdr.AccessTime, hdr.ModTime)
	}
}

func UntarGzFile(filename, destination string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	gzf, err := gzip.NewReader(f)
	if err != nil {
		return err
	}

	HandleTarStream(gzf, destination)
	return nil
}
