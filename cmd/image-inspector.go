package main

import (
	"flag"
	"fmt"
	"log"

	iicmd "github.com/openshift/image-inspector/pkg/cmd"
	ii "github.com/openshift/image-inspector/pkg/inspector"
)

func main() {
	inspectorOptions := iicmd.NewDefaultImageInspectorOptions()

	flag.StringVar(&inspectorOptions.URI, "docker", inspectorOptions.URI, "Daemon socket to connect to")
	flag.StringVar(&inspectorOptions.Image, "image", inspectorOptions.Image, "Docker image to inspect")
	flag.StringVar(&inspectorOptions.DstPath, "path", inspectorOptions.DstPath, "Destination path for the image files")
	flag.StringVar(&inspectorOptions.Serve, "serve", inspectorOptions.Serve, "Host and port where to serve the image with webdav")
	flag.BoolVar(&inspectorOptions.Chroot, "chroot", inspectorOptions.Chroot, "Change root when serving the image with webdav")
	flag.Var(&inspectorOptions.DockerCfg, "dockercfg", "Location of the docker configuration files. May be specified more than once")
	flag.StringVar(&inspectorOptions.Username, "username", inspectorOptions.Username, "username for authenticating with the docker registry")
	flag.StringVar(&inspectorOptions.PasswordFile, "password-file", inspectorOptions.PasswordFile, "Location of a file that contains the password for authentication with the docker registry")
	flag.StringVar(&inspectorOptions.ScanType, "scan-type", inspectorOptions.ScanType, fmt.Sprintf("The type of the scan to be done on the inspected image. Available scan types are: %v", iicmd.ScanOptions))
	flag.StringVar(&inspectorOptions.ScanResultsDir, "scan-results-dir", inspectorOptions.ScanResultsDir, "The directory that will contain the results of the scan")
	flag.BoolVar(&inspectorOptions.OpenScapHTML, "openscap-html-report", inspectorOptions.OpenScapHTML, "Generate an OpenScap HTML report in addition to the ARF formatted report")

	flag.Parse()

	if err := inspectorOptions.Validate(); err != nil {
		log.Fatal(err)
	}

	inspector := ii.NewDefaultImageInspector(*inspectorOptions)
	if err := inspector.Inspect(); err != nil {
		log.Fatalf("Error inspecting image: %v", err)
	}
}
