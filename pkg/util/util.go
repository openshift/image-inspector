package util

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	dockerTarPrefix = "rootfs/"
	ownerPermRW     = 0600

	opaqueWhiteoutFilename = ".wh..wh..opq"
	whiteoutFilePrefix     = ".wh"
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

func StringInList(s string, l []string) bool {
	for _, opt := range l {
		if s == opt {
			return true
		}
	}
	return false
}

func ExtractLayerTar(src io.Reader, destination string) error {
	tr := tar.NewReader(src)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading tar: %v\n", err)
		}

		hdrInfo := hdr.FileInfo()

		dstpath := path.Join(destination, strings.TrimPrefix(hdr.Name, dockerTarPrefix))
		// Overriding permissions to allow writing content
		mode := hdrInfo.Mode() | ownerPermRW

		// opaque whiteout file
		// https://github.com/opencontainers/image-spec/blob/master/layer.md#opaque-whiteout
		if strings.HasSuffix(dstpath, opaqueWhiteoutFilename) {
			dirToClear := filepath.Dir(dstpath)
			filepath.Walk(dirToClear, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if path == dirToClear {
					return nil
				}
				return os.RemoveAll(path)
			})
			continue
		}
		// single whiteout file
		if strings.HasPrefix(filepath.Base(dstpath), whiteoutFilePrefix) {
			os.RemoveAll(dstpath)
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(dstpath, mode); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("creating directory: %v", err)
				}
				err = os.Chmod(dstpath, mode)
				if err != nil {
					return fmt.Errorf("updating directory mode: %v", err)
				}
			}
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.OpenFile(dstpath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return fmt.Errorf("creating file: %v", err)
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return fmt.Errorf("writing into file: %v", err)
			}
			file.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, dstpath); err != nil {
				if os.IsExist(err) {
					continue
				}
				return fmt.Errorf("creating symlink: %v\n", err)
			}
		case tar.TypeLink:
			target := path.Join(destination, strings.TrimPrefix(hdr.Linkname, dockerTarPrefix))
			if err := os.Link(target, dstpath); err != nil {
				if os.IsExist(err) {
					continue
				}
				return fmt.Errorf("creating link: %v\n", err)
			}
		}

		// maintaining access and modification time in best effort fashion
		os.Chtimes(dstpath, hdr.AccessTime, hdr.ModTime)
	}
}

// UntarGzLayer attempts to read filename as a gzipped
// stream of data, processing the decompressed data as
// a tar archive. the contents of the tar archive ar
// extracted to destination directory.
// whiteout files that are encountered are dealt with
// specially (see https://github.com/opencontainers/image-spec/blob/master/layer.md#opaque-whiteout)
func UntarGzLayer(filename, destination string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	gzf, err := gzip.NewReader(f)
	if err != nil {
		return err
	}

	return ExtractLayerTar(gzf, destination)
}
