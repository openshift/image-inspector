package inspector

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"strings"
	"time"

	"crypto/rand"

	"github.com/containers/image/copy"
	"github.com/containers/image/manifest"
	"github.com/containers/image/signature"
	"github.com/containers/image/transports/alltransports"
	"github.com/containers/image/types"
	"github.com/opencontainers/go-digest"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/openshift/image-inspector/pkg/openscap"

	iicmd "github.com/openshift/image-inspector/pkg/cmd"
	"github.com/openshift/image-inspector/pkg/util"

	iiapi "github.com/openshift/image-inspector/pkg/api"
	apiserver "github.com/openshift/image-inspector/pkg/imageserver"
)

const (
	VERSION_TAG              = "v1"
	HEALTHZ_URL_PATH         = "/healthz"
	API_URL_PREFIX           = "/api"
	CONTENT_URL_PREFIX       = API_URL_PREFIX + "/" + VERSION_TAG + "/content/"
	METADATA_URL_PATH        = API_URL_PREFIX + "/" + VERSION_TAG + "/metadata"
	OPENSCAP_URL_PATH        = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap"
	OPENSCAP_REPORT_URL_PATH = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap-report"
	CHROOT_SERVE_PATH        = "/"
	OSCAP_CVE_DIR            = "/tmp"
	PULL_LOG_INTERVAL_SEC    = 10
	DOCKER_CERTS_DIR         = "/etc/docker/certs.d"
	DEFAULT_SIGN_POLICY      = "{\"default\":[{\"type\": \"insecureAcceptAnything\" }]}"
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
	meta iiapi.InspectorMetadata
	// an optional image server that will server content for inspection.
	imageServer apiserver.ImageServer
}

// NewInspectorMetadata returns a new InspectorMetadata out of *docker.Image
// The OpenSCAP status will be NotRequested
func NewInspectorMetadata(imageMetadata *docker.Image) iiapi.InspectorMetadata {
	return iiapi.InspectorMetadata{
		Image: *imageMetadata,
		OpenSCAP: &iiapi.OpenSCAPMetadata{
			Status:           iiapi.StatusNotRequested,
			ErrorMessage:     "",
			ContentTimeStamp: string(time.Now().Format(time.RFC850)),
		},
	}
}

// NewDefaultImageInspector provides a new default inspector.
func NewDefaultImageInspector(opts iicmd.ImageInspectorOptions) ImageInspector {
	inspector := &defaultImageInspector{
		opts: opts,
		meta: NewInspectorMetadata(&docker.Image{}),
	}

	// if serving then set up an image server
	if len(opts.Serve) > 0 {
		imageServerOpts := apiserver.ImageServerOptions{
			ServePath:         opts.Serve,
			HealthzURL:        HEALTHZ_URL_PATH,
			APIURL:            API_URL_PREFIX,
			APIVersions:       iiapi.APIVersions{Versions: []string{VERSION_TAG}},
			MetadataURL:       METADATA_URL_PATH,
			ContentURL:        CONTENT_URL_PREFIX,
			ImageServeURL:     opts.DstPath,
			ScanType:          opts.ScanType,
			ScanReportURL:     OPENSCAP_URL_PATH,
			HTMLScanReport:    opts.OpenScapHTML,
			HTMLScanReportURL: OPENSCAP_REPORT_URL_PATH,
		}
		inspector.imageServer = apiserver.NewWebdavImageServer(imageServerOpts, opts.Chroot)
	}
	return inspector
}

// Inspect inspects and serves the image based on the ImageInspectorOptions.
func (i *defaultImageInspector) Inspect() error {
	if i.opts.UseDockDaemon {
		client, err := docker.NewClient(i.opts.DockerSocket)
		if err != nil {
			return fmt.Errorf("Unable to connect to docker daemon: %v\n", err)
		}

		if err = i.dockerPullImage(client); err != nil {
			return err
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
	} else {
		inspectInfo, imageDigest, err := i.pullExtractAndInspectImage()
		if err != nil {
			return err
		}
		i.meta.Image = *inspectInfoToDockerImage(inspectInfo, imageDigest)
	}

	var err error
	var scanReport []byte
	var htmlScanReport []byte
	if i.opts.ScanType == "openscap" {
		if i.opts.ScanResultsDir, err = createOutputDir(i.opts.ScanResultsDir, "image-inspector-scan-results-"); err != nil {
			return err
		}
		scanner := openscap.NewDefaultScanner(OSCAP_CVE_DIR, i.opts.ScanResultsDir, i.opts.CVEUrlPath, i.opts.OpenScapHTML)
		scanReport, htmlScanReport, err = i.scanImage(scanner)
		if err != nil {
			i.meta.OpenSCAP.SetError(err)
			log.Printf("Unable to scan image: %v", err)
		} else {
			i.meta.OpenSCAP.Status = iiapi.StatusSuccess
		}
	}

	if i.imageServer != nil {
		return i.imageServer.ServeImage(&i.meta,
			scanReport, htmlScanReport)
	}
	return nil
}

// aggregateBytesAndReport sums the numbers recieved from its input channel
// bytesChan and prints them to the log every PULL_LOG_INTERVAL_SEC seconds.
// It will exit after bytesChan is closed.
func aggregateBytesAndReport(bytesChan chan int) {
	var bytesDownloaded int = 0
	ticker := time.NewTicker(PULL_LOG_INTERVAL_SEC * time.Second)
	defer ticker.Stop()
	for {
		select {
		case bytes, open := <-bytesChan:
			if !open {
				log.Printf("Finished Downloading Image (%dKb downloaded)", bytesDownloaded/1024)
				return
			}
			bytesDownloaded += bytes
		case <-ticker.C:
			log.Printf("Downloading Image (%dKb downloaded)", bytesDownloaded/1024)
		}
	}
}

// decodeDockerPullMessages will parse the docker pull messages received
// from reader and will push the difference of bytes downloaded to
// bytesChan. After reader is closed it will close bytesChan and exit.
func decodeDockerPullMessages(bytesChan chan int, reader io.Reader) {
	type progressDetailType struct {
		Current, Total int
	}
	type pullMessage struct {
		Status, Id     string
		ProgressDetail progressDetailType
	}
	defer func() { close(bytesChan) }()           // Closing the channel to end the other routine
	layersBytesDownloaded := make(map[string]int) // bytes downloaded per layer
	dec := json.NewDecoder(reader)                // decoder for the json messages
	for {
		var v pullMessage
		if err := dec.Decode(&v); err != nil {
			if err != io.ErrClosedPipe {
				log.Printf("Error decoding json: %v", err)
			}
			break
		}
		// decoding
		if v.Status == "Downloading" {
			bytes := v.ProgressDetail.Current
			last, existed := layersBytesDownloaded[v.Id]
			if !existed {
				last = 0
			}
			layersBytesDownloaded[v.Id] = bytes
			bytesChan <- (bytes - last)
		}
	}
}

// pullImage pulls the inspected image using the given client.
// It will try to use all the given authentication methods and will fail
// only if all of them failed.
func (i *defaultImageInspector) dockerPullImage(client *docker.Client) error {
	log.Printf("Pulling image %s", i.opts.Image)

	var imagePullAuths *docker.AuthConfigurations
	var authCfgErr error
	if imagePullAuths, authCfgErr = i.getAuthConfigs(); authCfgErr != nil {
		return authCfgErr
	}

	reader, writer := io.Pipe()
	// handle closing the reader/writer in the method that creates them
	defer writer.Close()
	defer reader.Close()
	imagePullOption := docker.PullImageOptions{
		Repository:    i.opts.Image,
		OutputStream:  writer,
		RawJSONStream: true,
	}

	bytesChan := make(chan int)
	go aggregateBytesAndReport(bytesChan)
	go decodeDockerPullMessages(bytesChan, reader)

	// Try all the possible auth's from the config file
	var authErr error
	for name, auth := range imagePullAuths.Configs {
		if authErr = client.PullImage(imagePullOption, auth); authErr == nil {
			return nil
		}
		log.Printf("Authentication with %s failed: %v", name, authErr)
	}
	return fmt.Errorf("Unable to pull docker image: %v\n", authErr)
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
		errorChannel <- client.DownloadFromContainer(
			container.ID,
			docker.DownloadFromContainerOptions{
				OutputStream: writer,
				Path:         "/",
			})
	}()

	// block on handling the reads here so we ensure both the write and the reader are finished
	// (read waits until an EOF or error occurs).
	util.HandleTarStream(reader, i.opts.DstPath)

	// capture any error from the copy, ensures both the handleTarStream and DownloadFromContainer
	// are done.
	err = <-errorChannel
	if err != nil {
		return imageMetadata, fmt.Errorf("Unable to extract container: %v\n", err)
	}

	return imageMetadata, nil
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
		map[string]docker.AuthConfiguration{"Default Empty Authentication": {}}}
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
	var htmlScanReport []byte
	err := s.Scan(i.opts.DstPath, &i.meta.Image)
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to run %s: %v\n", s.ScannerName(), err)
	}
	scanReport, err := ioutil.ReadFile(s.ResultsFileName())
	if err != nil {
		return []byte(""), []byte(""), fmt.Errorf("Unable to read %s result file: %v\n", s.ScannerName(), err)
	}

	if i.opts.OpenScapHTML {
		htmlScanReport, err = ioutil.ReadFile(s.HTMLResultsFileName())
		if err != nil {
			return []byte(""), []byte(""), fmt.Errorf("Unable to read %s HTML result file: %v\n", s.ScannerName(), err)
		}
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

// pullExtractAndInspectImage will use containers/image library to pull extract and get the image to be scanned
// and will inspect it for its metadata.
// Assumes the image to be pulled is with a transport prefix
// or if not attempts to add the "docker://" prefix to the image.
func (i *defaultImageInspector) pullExtractAndInspectImage() (*types.ImageInspectInfo, digest.Digest, error) {

	policy, err := signature.NewPolicyFromBytes([]byte(DEFAULT_SIGN_POLICY))
	if err != nil {
		return nil, "", err
	}
	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return nil, "", err
	}
	defer policyContext.Destroy()

	srcRef, err := alltransports.ParseImageName(i.opts.Image)
	if err != nil {
		// try adding "docker://"
		i.opts.Image = "docker://" + i.opts.Image
		srcRef, err = alltransports.ParseImageName(i.opts.Image)
		if err != nil {
			return nil, "", fmt.Errorf("Invalid source name %s: %v", i.opts.Image, err)
		}
	}

	certPath, err := i.certPath(i.opts.Image)
	if err != nil {
		return nil, "", err
	}
	sourceCtx := &types.SystemContext{
		DockerAuthConfig: nil,
		DockerCertPath:   certPath,
	}

	if i.opts.DstPath, err = createOutputDir(i.opts.DstPath, "image-inspector-"); err != nil {
		return nil, "", err
	}
	destRef, err := alltransports.ParseImageName(fmt.Sprintf("dir://%s", i.opts.DstPath))
	if err != nil {
		return nil, "", fmt.Errorf("Invalid destination name %s: %v", i.opts.DstPath, err)
	}

	imagePullAuths, err := i.getAuthConfigs()
	if err != nil {
		return nil, "", err
	}

	// Try all the possible auth's from the config file
	var authErr error
	log.Println("Copying image")
	for name, auth := range imagePullAuths.Configs {
		sourceCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: auth.Username,
			Password: auth.Password,
		}
		authErr = copy.Image(policyContext, destRef, srcRef, &copy.Options{
			RemoveSignatures: false,
			SignBy:           "",
			ReportWriter:     os.Stdout,
			SourceCtx:        sourceCtx,
			DestinationCtx:   nil,
			ProgressInterval: PULL_LOG_INTERVAL_SEC,
		})
		if authErr == nil {
			break
		}
		log.Printf("Authentication with %s failed: %v", name, authErr)
	}

	if authErr != nil {
		return nil, "", fmt.Errorf("Unable to pull docker image: %v\n", authErr)
	}

	img, err := srcRef.NewImage(sourceCtx)
	if err != nil {
		return nil, "", err
	}

	log.Println("Inspecting image")
	rawManifest, _, err := img.Manifest()
	if err != nil {
		return nil, "", fmt.Errorf("Error while reading image manifest: %v\n", err)
	}
	imageDigest, err := manifest.Digest(rawManifest)
	if err != nil {
		return nil, "", fmt.Errorf("Error while parsing image manifest: %v\n", err)
	}

	inspectInfo, err := img.Inspect()
	if err != nil {
		return inspectInfo, "", fmt.Errorf("Error while inspecting copied image Manifest: %v\n", err)
	}

	err = i.extractDownloadedImage(inspectInfo)
	if err != nil {
		return nil, "", fmt.Errorf("Error while extracting downloaded image: %v\n", err)
	}

	return inspectInfo, imageDigest, nil
}

// extractDownloadedImage will untar all the layer tar files specified in 'info'
// assuming those files exist in i.opts.DstPath .
func (i *defaultImageInspector) extractDownloadedImage(info *types.ImageInspectInfo) error {
	for _, layer := range info.Layers {
		filename := i.opts.DstPath + "/" + strings.SplitN(layer, ":", 2)[1] + ".tar"
		log.Printf("Untar %s\n", filename)
		if err := util.UntarGzFile(filename, i.opts.DstPath); err != nil {
			return err
		}
	}
	return nil
}

// dockerCertPath will try to extract the registry name from the image and return
// "/etc/docker/certs.d/<RERGISTRY_NAME>" if this path exists or nil otherwise.
func (i *defaultImageInspector) certPath(fullImageName string) (string, error) {
	if len(i.opts.RegistryCertPath) > 0 {
		return i.opts.RegistryCertPath, nil
	}

	// try to find certificates from docker
	source_name := strings.SplitN(fullImageName, "://", 2)
	name := source_name[len(source_name)-1]
	names := strings.SplitN(name, "/", 2)
	certsPath := DOCKER_CERTS_DIR + "/" + names[0]
	_, err := os.Stat(certsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return certsPath, nil
}

// inspectInfoToDockerImage will convert the information in info of type ImageInspectInfo to
// imageDigest which is of type Digest.
func inspectInfoToDockerImage(info *types.ImageInspectInfo, imageDigest digest.Digest) *docker.Image {
	return &docker.Image{
		ID:            "",
		RepoDigests:   []string{string(imageDigest)},
		RepoTags:      []string{info.Tag},
		Created:       info.Created,
		Architecture:  info.Architecture,
		DockerVersion: info.DockerVersion,
	}
}
