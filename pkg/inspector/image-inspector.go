package inspector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containers/image/copy"
	"github.com/containers/image/directory"
	"github.com/containers/image/manifest"
	"github.com/containers/image/signature"
	"github.com/containers/image/transports/alltransports"
	"github.com/containers/image/types"
	docker "github.com/fsouza/go-dockerclient"
	"github.com/opencontainers/go-digest"
	iiapi "github.com/openshift/image-inspector/pkg/api"
	"github.com/openshift/image-inspector/pkg/clamav"
	iicmd "github.com/openshift/image-inspector/pkg/cmd"
	apiserver "github.com/openshift/image-inspector/pkg/imageserver"
	"github.com/openshift/image-inspector/pkg/openscap"
	"github.com/openshift/image-inspector/pkg/util"
)

const (
	// TODO: Make this const golang style
	VERSION_TAG              = "v1"
	HEALTHZ_URL_PATH         = "/healthz"
	API_URL_PREFIX           = "/api"
	RESULT_API_URL_PATH      = "/results"
	CONTENT_URL_PREFIX       = API_URL_PREFIX + "/" + VERSION_TAG + "/content/"
	METADATA_URL_PATH        = API_URL_PREFIX + "/" + VERSION_TAG + "/metadata"
	OPENSCAP_URL_PATH        = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap"
	OPENSCAP_REPORT_URL_PATH = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap-report"
	OSCAP_CVE_DIR            = "/tmp"
	PULL_LOG_INTERVAL_SEC    = 10 * time.Second
	DOCKER_CERTS_DIR         = "/etc/docker/certs.d"
)

var osMkdir = os.Mkdir
var ioutilTempDir = ioutil.TempDir

type containerMeta struct {
	Container *docker.Container
	Image     *docker.Image
}

// ImageInspector is the interface for all image inspectors.
type ImageInspector interface {
	// Inspect inspects and serves the image based on the ImageInspectorOptions.
	Inspect() error
}

// scanOutputs is a struct to hold all the scan outputs that needs to be served
type scanOutputs struct {
	ScanReport     []byte
	HtmlScanReport []byte
	ScanResults    iiapi.ScanResult
}

// defaultImageInspector is the default implementation of ImageInspector.
type defaultImageInspector struct {
	opts iicmd.ImageInspectorOptions
	meta iiapi.InspectorMetadata
	// an optional image server that will server content for inspection.
	imageServer apiserver.ImageServer

	scanOutputs scanOutputs
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
			ResultAPIUrlPath:  RESULT_API_URL_PATH,
			APIVersions:       iiapi.APIVersions{Versions: []string{VERSION_TAG}},
			MetadataURL:       METADATA_URL_PATH,
			ContentURL:        CONTENT_URL_PREFIX,
			ScanType:          opts.ScanType,
			ScanReportURL:     OPENSCAP_URL_PATH,
			HTMLScanReport:    opts.OpenScapHTML,
			HTMLScanReportURL: OPENSCAP_REPORT_URL_PATH,
			AuthToken:         opts.AuthToken,
			Chroot:            opts.Chroot,
		}
		inspector.imageServer = apiserver.NewWebdavImageServer(imageServerOpts)
	}

	inspector.scanOutputs.ScanResults = iiapi.ScanResult{
		APIVersion: iiapi.DefaultResultsAPIVersion,
		ImageName:  inspector.opts.Image,
		Results:    []iiapi.Result{},
	}

	return inspector
}

type DockerRuntimeClient interface {
	InspectImage(name string) (*docker.Image, error)
	ContainerChanges(id string) ([]docker.Change, error)
	PullImage(opts docker.PullImageOptions, auth docker.AuthConfiguration) error
	CreateContainer(opts docker.CreateContainerOptions) (*docker.Container, error)
	RemoveContainer(opts docker.RemoveContainerOptions) error
	InspectContainer(id string) (*docker.Container, error)
	DownloadFromContainer(id string, opts docker.DownloadFromContainerOptions) error
}

// Inspect inspects and serves the image based on the ImageInspectorOptions.
func (i *defaultImageInspector) Inspect() error {
	err := i.acquireAndScan()
	if err != nil {
		i.meta.ImageAcquireError = err.Error()
	}

	if i.imageServer != nil {
		return i.imageServer.ServeImage(&i.meta, i.opts.DstPath, i.scanOutputs.ScanResults, i.scanOutputs.ScanReport, i.scanOutputs.HtmlScanReport)
	}

	return err
}

// AcquireAndScan acquires and scans the image based on the ImageInspectorOptions.
func (i *defaultImageInspector) acquireAndScan() error {
	var (
		scanner iiapi.Scanner

		filterFn iiapi.FilesFilter
	)

	ctx := context.Background()

	client, err := docker.NewClient(i.opts.DockerSocket)
	if err != nil {
		i.meta.ImageAcquireError = err.Error()
		return err
	} else {
		err, filterFn = i.acquireImage(client)
		if err != nil {
			i.meta.ImageAcquireError = err.Error()
			return err
		}
	}

	switch i.opts.ScanType {
	case "openscap":
		var err error
		if i.opts.ScanResultsDir, err = createOutputDir(i.opts.ScanResultsDir, "image-inspector-scan-results-"); err != nil {
			return err
		}
		var (
			results   []iiapi.Result
			reportObj interface{}
		)
		scanner = openscap.NewDefaultScanner(OSCAP_CVE_DIR, i.opts.ScanResultsDir, i.opts.CVEUrlPath, i.opts.OpenScapHTML)
		results, reportObj, err = scanner.Scan(ctx, i.opts.DstPath, &i.meta.Image, filterFn)
		if err != nil {
			i.meta.OpenSCAP.SetError(err)
			log.Printf("DEBUG: Unable to scan image %q with OpenSCAP: %v", i.opts.Image, err)
		} else {
			i.meta.OpenSCAP.Status = iiapi.StatusSuccess
			report := reportObj.(openscap.OpenSCAPReport)
			i.scanOutputs.ScanReport = report.ArfBytes
			i.scanOutputs.HtmlScanReport = report.HTMLBytes
			i.scanOutputs.ScanResults.Results = append(i.scanOutputs.ScanResults.Results, results...)
		}

	case "clamav":
		scanner, err := clamav.NewScanner(i.opts.ClamSocket)
		if err != nil {
			return fmt.Errorf("failed to initialize clamav scanner: %v", err)
		}
		results, _, err := scanner.Scan(ctx, i.opts.DstPath, &i.meta.Image, filterFn)
		if err != nil {
			log.Printf("DEBUG: Unable to scan image %q with ClamAV: %v", i.opts.Image, err)
			return err
		}
		i.scanOutputs.ScanResults.Results = append(i.scanOutputs.ScanResults.Results, results...)

	default:
		return fmt.Errorf("unsupported scan type: %s", i.opts.ScanType)
	}

	if len(i.opts.PostResultURL) > 0 {
		if err := i.postResults(i.scanOutputs.ScanResults); err != nil {
			log.Printf("Error posting results: %v", err)
			return err
		}
	}

	return nil
}

func (i *defaultImageInspector) postTokenContent() string {
	if len(i.opts.PostResultTokenFile) == 0 {
		return ""
	}
	token, err := ioutil.ReadFile(i.opts.PostResultTokenFile)
	if err != nil {
		log.Printf("WARNING: Unable to read the %q token file: %v (no token will be used)", i.opts.PostResultTokenFile, err)
		return ""
	}
	return fmt.Sprintf("?token=%s", strings.TrimSpace(string(token)))
}

func (i *defaultImageInspector) postResults(scanResults iiapi.ScanResult) error {
	url := i.opts.PostResultURL + i.postTokenContent()
	log.Printf("Posting results to %q ...", url)
	resultJSON, err := json.Marshal(scanResults)
	if err != nil {
		return err
	}
	client := http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewReader(resultJSON))
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	log.Printf("DEBUG: Success: %v", resp)
	return nil
}

// aggregateBytesAndReport sums the numbers recieved from its input channel
// bytesChan and prints them to the log every PULL_LOG_INTERVAL_SEC seconds.
// It will exit after bytesChan is closed.
func aggregateBytesAndReport(bytesChan chan int) {
	var bytesDownloaded int = 0
	ticker := time.NewTicker(PULL_LOG_INTERVAL_SEC)
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

// decodeDockerResponse will parse the docker pull messages received
// from reader. It will start aggregateBytesAndReport with bytesChan
// and will push the difference of bytes downloaded to bytesChan.
// Errors encountered during parsing are reported to parsedErrors channel.
// After reader is closed it will send nil on parsedErrors, close bytesChan and send true on finished.
func decodeDockerResponse(parsedErrors chan error, reader io.Reader, finished chan bool) {
	type progressDetailType struct {
		Current, Total int
	}
	type pullMessage struct {
		Status, Id     string
		ProgressDetail progressDetailType
		Error          string
	}
	bytesChan := make(chan int, 100)
	defer func() { close(bytesChan) }()           // Closing the channel to end the other routine
	layersBytesDownloaded := make(map[string]int) // bytes downloaded per layer
	dec := json.NewDecoder(reader)                // decoder for the json messages

	var startedDownloading = false
	for {
		var v pullMessage
		if err := dec.Decode(&v); err != nil {
			if err != io.ErrClosedPipe && err != io.EOF {
				log.Printf("Error decoding json: %v", err)
				parsedErrors <- fmt.Errorf("Error decoding json: %v", err)
			} else {
				parsedErrors <- nil
			}
			break
		}
		// decoding
		if v.Error != "" {
			parsedErrors <- fmt.Errorf(v.Error)
			break
		}
		if v.Status == "Downloading" {
			if !startedDownloading {
				go aggregateBytesAndReport(bytesChan)
				startedDownloading = true
			}
			bytes := v.ProgressDetail.Current
			last, existed := layersBytesDownloaded[v.Id]
			if !existed {
				last = 0
			}
			layersBytesDownloaded[v.Id] = bytes
			bytesChan <- (bytes - last)
		}
	}

	finished <- true
}

func (i *defaultImageInspector) getContainerMeta(client DockerRuntimeClient) (*containerMeta, error) {
	var err error
	result := &containerMeta{}

	result.Container, err = client.InspectContainer(i.opts.Container)
	if err != nil {
		return nil, fmt.Errorf("Unable to get docker container information: %v", err)
	}

	result.Image, err = client.InspectImage(result.Container.Image)
	if err != nil {
		return nil, fmt.Errorf("Unable to get docker image information: %v", err)
	}

	return result, nil
}

func (i *defaultImageInspector) getContainerChanges(client DockerRuntimeClient, meta *containerMeta) (map[string]struct{}, error) {
	rootPath := i.opts.DstPath

	containerChanges, err := client.ContainerChanges(i.opts.Container)
	if err != nil {
		return nil, fmt.Errorf("Unable to get docker container changes: %v", err)
	}

	// We don't want to scan anything if the containerChanges is empty.
	filter := make(map[string]struct{})

	for _, change := range containerChanges {
		switch change.Kind {
		case docker.ChangeAdd, docker.ChangeModify:
			filter[rootPath+change.Path] = struct{}{}
		}
	}

	return filter, nil
}

// dockerPullImage pulls the inspected image through the docker socket
// using the given client.
// It will try to use all detected authentication methods and will fail
// only if all of them failed.
func (i *defaultImageInspector) dockerPullImage(client DockerRuntimeClient) error {
	log.Printf("Pulling image %s", i.opts.Image)

	var imagePullAuths *docker.AuthConfigurations
	var authCfgErr error
	if imagePullAuths, authCfgErr = i.getAuthConfigs(); authCfgErr != nil {
		return authCfgErr
	}

	// Try all the possible auth's from the config file
	var err error
	for name, auth := range imagePullAuths.Configs {
		parsedErrors := make(chan error, 100)
		finished := make(chan bool, 1)

		defer func() {
			<-finished
			close(finished)
			close(parsedErrors)
		}()

		go func() {
			reader, writer := io.Pipe()
			defer writer.Close()
			defer reader.Close()
			imagePullOption := docker.PullImageOptions{
				Repository:    i.opts.Image,
				OutputStream:  writer,
				RawJSONStream: true,
			}
			go decodeDockerResponse(parsedErrors, reader, finished)

			if err = client.PullImage(imagePullOption, auth); err != nil {
				parsedErrors <- err
			}
		}()

		if parsedError := <-parsedErrors; parsedError != nil {
			log.Printf("Pulling image with authentication %s failed: %v", name, parsedError)
		} else {
			return nil
		}
	}
	return fmt.Errorf("Unable to pull docker image: %v", err)
}

// extractImageFromContainer creates a docker container based on the option's image with containerName.
// It will then insepct the container and image and then attempt to extract the image to
// option's destination path.  If the destination path is empty it will write to a temp directory
// and update the option's destination path with a /var/tmp directory.  /var/tmp is used to
// try and ensure it is a non-in-memory tmpfs.
func (i *defaultImageInspector) extractImageFromContainer(client DockerRuntimeClient, containerName string) (*docker.Image, error) {
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
		return nil, fmt.Errorf("creating docker container: %v\n", err)
	}

	// delete the container when we are done extracting it
	defer func() {
		client.RemoveContainer(docker.RemoveContainerOptions{
			ID: container.ID,
		})
	}()

	containerMetadata, err := client.InspectContainer(container.ID)
	if err != nil {
		return nil, fmt.Errorf("getting docker container information: %v\n", err)
	}

	imageMetadata, err := client.InspectImage(containerMetadata.Image)
	if err != nil {
		return imageMetadata, fmt.Errorf("getting docker image information: %v\n", err)
	}

	if i.opts.DstPath, err = createOutputDir(i.opts.DstPath, "image-inspector-"); err != nil {
		return imageMetadata, fmt.Errorf("creating output dir: %v", err)
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
	if err := util.ExtractLayerTar(reader, i.opts.DstPath); err != nil {
		return nil, err
	}

	// capture any error from the copy, ensures both the handleTarStream and DownloadFromContainer
	// are done.
	err = <-errorChannel
	if err != nil {
		return imageMetadata, fmt.Errorf("extracting container: %v\n", err)
	}

	return imageMetadata, nil
}

func generateRandomName() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return "", fmt.Errorf("generating random container name: %v\n", err)
	}
	return fmt.Sprintf("image-inspector-%016x", n), nil
}

func appendDockerCfgConfigs(dockercfg string, cfgs *docker.AuthConfigurations) error {
	var imagePullAuths *docker.AuthConfigurations
	reader, err := os.Open(dockercfg)
	if err != nil {
		return fmt.Errorf("opening docker config file: %v\n", err)
	}
	defer reader.Close()
	if imagePullAuths, err = docker.NewAuthConfigurations(reader); err != nil {
		return fmt.Errorf("parsing docker config file: %v\n", err)
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
	imagePullAuths := &docker.AuthConfigurations{Configs: map[string]docker.AuthConfiguration{"Default Empty Authentication": {}}}
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
			return nil, fmt.Errorf("unable to read password file: %v\n", err)
		}
		imagePullAuths = &docker.AuthConfigurations{Configs: map[string]docker.AuthConfiguration{"": {Username: i.opts.Username, Password: string(token)}}}
	}

	return imagePullAuths, nil
}

func createOutputDir(dirName string, tempName string) (string, error) {
	if len(dirName) > 0 {
		err := osMkdir(dirName, 0755)
		if err != nil {
			if !os.IsExist(err) {
				return "", fmt.Errorf("creating destination path: %v\n", err)
			}
		}
	} else {
		// forcing to use /var/tmp because often it's not an in-memory tmpfs
		var err error
		dirName, err = ioutilTempDir("/var/tmp", tempName)
		if err != nil {
			return "", fmt.Errorf("creating temporary path: %v\n", err)
		}
	}
	return dirName, nil
}

// acquireImage returns error and iiapi.FilesFilter for this image.
func (i *defaultImageInspector) acquireImage(client DockerRuntimeClient) (error, iiapi.FilesFilter) {
	var err error
	if len(i.opts.Container) == 0 {
		if i.opts.UseDockerSocket {
			imageMetaBefore, inspectErrBefore := client.InspectImage(i.opts.Image)
			if i.opts.PullPolicy == iiapi.PullNever && inspectErrBefore != nil {
				return fmt.Errorf("Image %s is not available and pull-policy %s doesn't allow pulling",
					i.opts.Image, i.opts.PullPolicy), nil
			}

			if i.opts.PullPolicy == iiapi.PullAlways ||
				(i.opts.PullPolicy == iiapi.PullIfNotPresent && inspectErrBefore != nil) {
				if err = i.dockerPullImage(client); err != nil {
					return err, nil
				}
			}

			imageMetaAfter, inspectErrAfter := client.InspectImage(i.opts.Image)
			if inspectErrBefore == nil && inspectErrAfter == nil &&
				imageMetaBefore.ID == imageMetaAfter.ID {
				log.Printf("Image %s was already available", i.opts.Image)
			}

			randomName, err := generateRandomName()
			if err != nil {
				return err, nil
			}

			imageMetadata, err := i.extractImageFromContainer(client, randomName)
			if err != nil {
				return err, nil
			}
			i.meta.Image = *imageMetadata

			return nil, nil
		} else {
			inspectInfo, imageDigest, err := i.containersPullImage()
			if err != nil {
				return err, nil
			}

			if err := i.extractDownloadedImage(inspectInfo.Layers); err != nil {
				return fmt.Errorf("extracting downloaded image: %v ", err), nil
			}

			i.meta.Image = inspectInfoToDockerImage(inspectInfo, imageDigest)
			return nil, nil
		}
	} else {
		meta, err := i.getContainerMeta(client)
		if err != nil {
			return err, nil
		}
		i.meta.Image = *meta.Image
		i.scanOutputs.ScanResults.ContainerID = meta.Container.ID

		var filterInclude map[string]struct{}

		if i.opts.ScanContainerChanges {
			filterInclude, err = i.getContainerChanges(client, meta)
			if err != nil {
				return err, nil
			}
		}

		i.opts.DstPath = fmt.Sprintf("/proc/%d/root/", meta.Container.State.Pid)

		excludePrefixes := []string{
			i.opts.DstPath + "proc",
			i.opts.DstPath + "sys",
		}

		filterFn := func(path string, fileInfo os.FileInfo) bool {
			if filterInclude != nil {
				if _, ok := filterInclude[path]; !ok {
					return false
				}
			}

			for _, prefix := range excludePrefixes {
				if strings.HasPrefix(path, prefix) {
					return false
				}
			}

			return true
		}
		return nil, filterFn
	}
}

// containersPullImage pulls the image using containers/image library
// to directly connect to the docker registry
// and will return its metadata (*types.ImageInspectInfo).
// Assumes the image to be pulled is with a transport prefix
// or if not attempts to add the "docker://" prefix to the image.
func (i *defaultImageInspector) containersPullImage() (*types.ImageInspectInfo, digest.Digest, error) {
	policy := &signature.Policy{
		Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()},
	}
	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		return nil, "", fmt.Errorf("creating context for policy %v: %v", policy, err)
	}
	defer policyContext.Destroy()

	imageURL, err := url.Parse(i.opts.Image)
	if err != nil {
		return nil, "", fmt.Errorf("parsing image name %s: %v", i.opts.Image, err)
	}
	if "" == imageURL.Scheme {
		imageURL.Scheme = "docker"
		i.opts.Image = imageURL.String()
	}

	srcRef, err := alltransports.ParseImageName(i.opts.Image)
	if err != nil {
		return nil, "", fmt.Errorf("invalid source name %s: %v", i.opts.Image, err)
	}

	certPath, err := i.certPath(i.opts.Image)
	if err != nil {
		return nil, "", fmt.Errorf("finding certificate path: %v", err)
	}
	sourceCtx := &types.SystemContext{
		DockerCertPath: certPath,
	}

	if i.opts.DstPath, err = createOutputDir(i.opts.DstPath, "image-inspector-"); err != nil {
		return nil, "", fmt.Errorf("creating output dir: %v", err)
	}
	destRef, err := directory.NewReference(i.opts.DstPath)
	if err != nil {
		return nil, "", fmt.Errorf("invalid destination name %s: %v", i.opts.DstPath, err)
	}

	imagePullAuths, err := i.getAuthConfigs()
	if err != nil {
		return nil, "", fmt.Errorf("getting registry auth config: %v", err)
	}

	// Try all the possible auths from the config file
	log.Println("Pulling image ...")
	for name, auth := range imagePullAuths.Configs {
		sourceCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: auth.Username,
			Password: auth.Password,
		}
		reportReader, reportWriter := io.Pipe()
		// print progress from reportWriter
		go func() {
			lineReader := bufio.NewReader(reportReader)
			buffered := []byte{}
			last := time.Now()
			for {
				b, err := lineReader.ReadByte()
				if err != nil {
					return
				}
				if b == byte('\n') {
					log.Printf("%s", buffered)
					buffered = []byte{}
				}
				buffered = append(buffered, b)
				if b == byte(']') {
					if time.Since(last) > PULL_LOG_INTERVAL_SEC {
						log.Printf("%s", buffered)
						last = time.Now()
					}
					buffered = []byte{}
				}
			}
		}()
		err = copy.Image(policyContext, destRef, srcRef, &copy.Options{
			RemoveSignatures: false,
			SignBy:           "",
			ReportWriter:     reportWriter,
			SourceCtx:        sourceCtx,
			DestinationCtx:   nil,
			ProgressInterval: PULL_LOG_INTERVAL_SEC,
		})
		reportWriter.Close()
		if err == nil {
			break
		}
		log.Printf("Authentication with %s failed: %v", name, err)
	}

	if err != nil {
		return nil, "", fmt.Errorf("pulling docker image: %v\n", err)
	}

	img, err := srcRef.NewImage(sourceCtx)
	if err != nil {
		return nil, "", fmt.Errorf(": %v", err)
	}

	log.Println("Inspecting image...")
	rawManifest, _, err := img.Manifest()
	if err != nil {
		return nil, "", fmt.Errorf("reading image manifest: %v ", err)
	}
	imageDigest, err := manifest.Digest(rawManifest)
	if err != nil {
		return nil, "", fmt.Errorf("parsing image manifest: %v ", err)
	}

	inspectInfo, err := img.Inspect()
	if err != nil {
		return nil, "", fmt.Errorf("inspecting copied image Manifest: %v ", err)
	}

	return inspectInfo, imageDigest, nil
}

// extractDownloadedImage will untar all the layer tar files specified in 'info'
func (i *defaultImageInspector) extractDownloadedImage(layers []string) error {
	for _, layer := range layers {
		split := strings.SplitN(layer, ":", 2)
		if len(split) < 2 {
			return fmt.Errorf("invalid format for layer name: %s", layer)
		}
		baseName := split[1]
		filename := filepath.Join(i.opts.DstPath, baseName+".tar")
		destDir := i.opts.DstPath
		log.Printf("Untar %s\n", filename)
		if err := util.UntarGzLayer(filename, destDir); err != nil {
			return fmt.Errorf("extracting gzipped layer tarball: %v", err)
		}
	}
	return nil
}

// certPath will try to extract the registry name from the image and return
// "/etc/docker/certs.d/<REGISTRY_NAME>" if this path exists or nil otherwise.
func (i *defaultImageInspector) certPath(fullImageName string) (string, error) {
	if len(i.opts.RegistryCertPath) > 0 {
		return i.opts.RegistryCertPath, nil
	}

	// try to find certificates from docker
	sourceName := strings.SplitN(fullImageName, "://", 2)
	name := sourceName[len(sourceName)-1]
	names := strings.SplitN(name, "/", 2)
	certsPath := filepath.Join(DOCKER_CERTS_DIR, names[0])
	if _, err := os.Stat(certsPath); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return certsPath, nil
}

// inspectInfoToDockerImage will convert the information in info of type ImageInspectInfo to
// imageDigest which is of type Digest.
func inspectInfoToDockerImage(info *types.ImageInspectInfo, imageDigest digest.Digest) docker.Image {
	return docker.Image{
		ID:            "",
		RepoDigests:   []string{string(imageDigest)},
		RepoTags:      []string{info.Tag},
		Created:       info.Created,
		Architecture:  info.Architecture,
		DockerVersion: info.DockerVersion,
	}
}
