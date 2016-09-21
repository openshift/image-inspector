package inspector

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"path"
	"strings"
	"syscall"

	"archive/tar"
	"crypto/rand"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/openshift/image-inspector/pkg/openscap"
	"golang.org/x/net/webdav"

	iicmd "github.com/openshift/image-inspector/pkg/cmd"
)

type APIVersions struct {
	Versions []string `json:"versions"`
}

const (
	VERSION_TAG              = "v1"
	DOCKER_TAR_PREFIX        = "rootfs/"
	OWNER_PERM_RW            = 0600
	HEALTHZ_URL_PATH         = "/healthz"
	API_URL_PREFIX           = "/api"
	CONTENT_URL_PREFIX       = API_URL_PREFIX + "/" + VERSION_TAG + "/content/"
	METADATA_URL_PATH        = API_URL_PREFIX + "/" + VERSION_TAG + "/metadata"
	OPENSCAP_URL_PATH        = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap"
	OPENSCAP_REPORT_URL_PATH = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap-report"
	CHROOT_SERVE_PATH        = "/"
	OSCAP_CVE_DIR            = "/tmp"
)

var osMkdir = os.Mkdir
var ioutilTempDir = ioutil.TempDir

// ImageInspector is the interface for all image inspectors.
type ImageInspector interface {
	// Inspect inspects and serves the image based on the ImageInspectorOptions.
	Inspect() error
}

// defaultImageInspector is the default implementation of ImageInspector.
type defaultImageInspector struct {
	opts iicmd.ImageInspectorOptions
	meta InspectorMetadata
}

// NewDefaultImageInspector provides a new default inspector.
func NewDefaultImageInspector(opts iicmd.ImageInspectorOptions) ImageInspector {
	return &defaultImageInspector{opts,
		*NewInspectorMetadata(&docker.Image{})}
}

// Inspect inspects and serves the image based on the ImageInspectorOptions.
func (i *defaultImageInspector) Inspect() error {
	client, err := docker.NewClient(i.opts.URI)
	if err != nil {
		return fmt.Errorf("Unable to connect to docker daemon: %v\n", err)
	}

	if _, err := client.InspectImage(i.opts.Image); err != nil {
		log.Printf("Pulling image %s", i.opts.Image)
		imagePullOption := docker.PullImageOptions{Repository: i.opts.Image}

		var imagePullAuths *docker.AuthConfigurations
		var authCfgErr error
		if imagePullAuths, authCfgErr = i.getAuthConfigs(); authCfgErr != nil {
			return authCfgErr
		}

		// Try all the possible auth's from the config file
		var authErr error
		for _, auth := range imagePullAuths.Configs {
			if authErr = client.PullImage(imagePullOption, auth); authErr == nil {
				break
			}
		}
		if authErr != nil {
			return fmt.Errorf("Unable to pull docker image: %v\n", authErr)
		}
	} else {
		log.Printf("Image %s is available, skipping image pull", i.opts.Image)
	}

	randomName, err := generateRandomName()
	if err != nil {
		return err
	}

	imageMetadata, err := i.createAndExtractImage(client, randomName)
	if err != nil {
		return err
	}
	i.meta.Image = *imageMetadata

	supportedVersions := APIVersions{Versions: []string{VERSION_TAG}}

	var scanReport []byte
	var htmlScanReport []byte
	if i.opts.ScanType == "openscap" {
		if i.opts.ScanResultsDir, err = createOutputDir(i.opts.ScanResultsDir, "image-inspector-scan-results-"); err != nil {
			return err
		}
		scanner := openscap.NewDefaultScanner(OSCAP_CVE_DIR, i.opts.ScanResultsDir, i.opts.OpenScapHTML)
		scanReport, htmlScanReport, err = i.scanImage(scanner)
		if err != nil {
			i.meta.OpenSCAP.SetError(err)
			log.Printf("Unable to scan image: %v", err)
		} else {
			i.meta.OpenSCAP.Status = StatusSuccess
		}
	}

	if len(i.opts.Serve) > 0 {
		servePath := i.opts.DstPath
		if i.opts.Chroot {
			if err := syscall.Chroot(i.opts.DstPath); err != nil {
				return fmt.Errorf("Unable to chroot into %s: %v\n", i.opts.DstPath, err)
			}
			servePath = CHROOT_SERVE_PATH
		} else {
			log.Printf("!!!WARNING!!! It is insecure to serve the image content without changing")
			log.Printf("root (--chroot). Absolute-path symlinks in the image can lead to disclose")
			log.Printf("information of the hosting system.")
		}

		log.Printf("Serving image content %s on webdav://%s%s", i.opts.DstPath, i.opts.Serve, CONTENT_URL_PREFIX)

		http.HandleFunc(HEALTHZ_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok\n"))
		})

		http.HandleFunc(API_URL_PREFIX, func(w http.ResponseWriter, r *http.Request) {
			body, err := json.MarshalIndent(supportedVersions, "", "  ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(body)
		})

		http.HandleFunc(METADATA_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			body, err := json.MarshalIndent(i.meta, "", "  ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(body)
		})

		http.HandleFunc(OPENSCAP_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			if i.opts.ScanType == "openscap" && i.meta.OpenSCAP.Status == StatusSuccess {
				w.Write(scanReport)
			} else {
				if i.meta.OpenSCAP.Status == StatusError {
					http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", i.meta.OpenSCAP.ErrorMessage),
						http.StatusInternalServerError)
				} else {
					http.Error(w, "OpenSCAP option was not chosen", http.StatusNotFound)
				}
			}
		})

		http.HandleFunc(OPENSCAP_REPORT_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			if i.opts.ScanType == "openscap" && i.meta.OpenSCAP.Status == StatusSuccess && i.opts.OpenScapHTML {
				w.Write(htmlScanReport)
			} else {
				if i.meta.OpenSCAP.Status == StatusError {
					http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", i.meta.OpenSCAP.ErrorMessage),
						http.StatusInternalServerError)
				} else {
					http.Error(w, "OpenSCAP option was not chosen", http.StatusNotFound)
				}
			}
		})

		http.Handle(CONTENT_URL_PREFIX, &webdav.Handler{
			Prefix:     CONTENT_URL_PREFIX,
			FileSystem: webdav.Dir(servePath),
			LockSystem: webdav.NewMemLS(),
		})

		return http.ListenAndServe(i.opts.Serve, nil)
	}
	return nil
}

// createAndExtractImage creates a docker container based on the option's image with containerName.
// It will then insepct the container and image and then attempt to extract the image to
// option's destination path.  If the destination path is empty it will write to a temp directory
// and update the option's destination path with a /var/tmp directory.  /var/tmp is used to
// try and ensure it is a non-in-memory tmpfs.
func (i *defaultImageInspector) createAndExtractImage(client *docker.Client, containerName string) (*docker.Image, error) {
	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Name: containerName,
		Config: &docker.Config{
			Image: i.opts.Image,
			// For security purpose we don't define any entrypoint and command
			Entrypoint: []string{""},
			Cmd:        []string{""},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Unable to create docker container: %v\n", err)
	}

	// delete the container when we are done extracting it
	defer func() {
		client.RemoveContainer(docker.RemoveContainerOptions{
			ID: container.ID,
		})
	}()

	containerMetadata, err := client.InspectContainer(container.ID)
	if err != nil {
		return nil, fmt.Errorf("Unable to get docker container information: %v\n", err)
	}

	imageMetadata, err := client.InspectImage(containerMetadata.Image)
	if err != nil {
		return imageMetadata, fmt.Errorf("Unable to get docker image information: %v\n", err)
	}

	if i.opts.DstPath, err = createOutputDir(i.opts.DstPath, "image-inspector-"); err != nil {
		return imageMetadata, err
	}

	reader, writer := io.Pipe()
	// handle closing the reader/writer in the method that creates them
	defer writer.Close()
	defer reader.Close()

	log.Printf("Extracting image %s to %s", i.opts.Image, i.opts.DstPath)

	// start the copy function first which will block after the first write while waiting for
	// the reader to read.
	errorChannel := make(chan error)
	go func() {
		errorChannel <- client.CopyFromContainer(docker.CopyFromContainerOptions{
			Container:    container.ID,
			OutputStream: writer,
			Resource:     "/",
		})
	}()

	// block on handling the reads here so we ensure both the write and the reader are finished
	// (read waits until an EOF or error occurs).
	handleTarStream(reader, i.opts.DstPath)

	// capture any error from the copy, ensures both the handleTarStream and CopyFromContainer
	// are done.
	err = <-errorChannel
	if err != nil {
		return imageMetadata, fmt.Errorf("Unable to extract container: %v\n", err)
	}

	return imageMetadata, nil
}

func handleTarStream(reader io.ReadCloser, destination string) {
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

func generateRandomName() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return "", fmt.Errorf("Unable to generate random container name: %v\n", err)
	}
	return fmt.Sprintf("image-inspector-%016x", n), nil
}

func appendDockerCfgConfigs(dockercfg string, cfgs *docker.AuthConfigurations) error {
	var imagePullAuths *docker.AuthConfigurations
	reader, err := os.Open(dockercfg)
	if err != nil {
		return fmt.Errorf("Unable to open docker config file: %v\n", err)
	}
	defer reader.Close()
	if imagePullAuths, err = docker.NewAuthConfigurations(reader); err != nil {
		return fmt.Errorf("Unable to parse docker config file: %v\n", err)
	}
	if len(imagePullAuths.Configs) == 0 {
		return fmt.Errorf("No auths were found in the given dockercfg file\n")
	}
	for name, ac := range imagePullAuths.Configs {
		cfgs.Configs[fmt.Sprintf("%s/%s", dockercfg, name)] = ac
	}
	return nil
}

func (i *defaultImageInspector) getAuthConfigs() (*docker.AuthConfigurations, error) {
	imagePullAuths := &docker.AuthConfigurations{
		map[string]docker.AuthConfiguration{"": {}}}
	if len(i.opts.DockerCfg.Values) > 0 {
		for _, dcfgFile := range i.opts.DockerCfg.Values {
			if err := appendDockerCfgConfigs(dcfgFile, imagePullAuths); err != nil {
				log.Printf("WARNING: Unable to read docker configuration from %s. Error: %v", dcfgFile, err)
			}
		}
	}

	if i.opts.Username != "" {
		token, err := ioutil.ReadFile(i.opts.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("Unable to read password file: %v\n", err)
		}
		imagePullAuths = &docker.AuthConfigurations{
			map[string]docker.AuthConfiguration{"": {Username: i.opts.Username, Password: string(token)}}}
	}

	return imagePullAuths, nil
}

func (i *defaultImageInspector) scanImage(s openscap.Scanner) ([]byte, []byte, error) {
	log.Printf("%s scanning %s. Placing results in %s",
		s.ScannerName(), i.opts.DstPath, i.opts.ScanResultsDir)
	err := s.Scan(i.opts.DstPath, &i.meta.Image)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to run %s: %v\n", s.ScannerName(), err)
	}
	scanReport, err := ioutil.ReadFile(s.ResultsFileName())
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to read %s result file: %v\n", s.ScannerName(), err)
	}

	htmlScanReport, err := ioutil.ReadFile(s.HTMLResultsFileName())
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to read %s HTML result file: %v\n", s.ScannerName(), err)
	}

	return scanReport, htmlScanReport, nil
}

func createOutputDir(dirName string, tempName string) (string, error) {
	if len(dirName) > 0 {
		err := osMkdir(dirName, 0755)
		if err != nil {
			if !os.IsExist(err) {
				return "", fmt.Errorf("Unable to create destination path: %v\n", err)
			}
		}
	} else {
		// forcing to use /var/tmp because often it's not an in-memory tmpfs
		var err error
		dirName, err = ioutilTempDir("/var/tmp", tempName)
		if err != nil {
			return "", fmt.Errorf("Unable to create temporary path: %v\n", err)
		}
	}
	return dirName, nil
}
