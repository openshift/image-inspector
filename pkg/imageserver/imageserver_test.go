package imageserver

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"

	"github.com/fsouza/go-dockerclient"
	"github.com/ilackarms/webdavclnt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/openshift/image-inspector/pkg/api"
)

const (
	versionTag             = "v1"
	healthzPath            = "/healthz"
	apiPrefix              = "/api"
	contentPath            = apiPrefix + "/" + versionTag + "/content/"
	metadataPath           = apiPrefix + "/" + versionTag + "/metadata"
	openscapReportPath     = apiPrefix + "/" + versionTag + "/openscap"
	openScapHTMLReportPath = apiPrefix + "/" + versionTag + "/openscap-report"
	scanType               = "openscap"
	authToken              = "12345"
)

var _ = Describe("ImageServer", func() {
	var (
		server           *httptest.Server
		options          ImageServerOptions
		dstPath          string
		dummyScanResults = api.ScanResult{
			APIVersion: api.DefaultResultsAPIVersion,
			Results:    []api.Result{},
		}
		dummyMetadata = &api.InspectorMetadata{
			Image: docker.Image{
				ID: "dummy",
			},
			OpenSCAP: &api.OpenSCAPMetadata{
				Status: api.StatusSuccess,
			},
		}
		dummyScanReport     = []byte("this is a dummy scan report")
		dummyHTMLScanReport = []byte("this is a dummy HTML scan report")
		apiVersions         = api.APIVersions{Versions: []string{versionTag}}
	)
	JustBeforeEach(func() {
		var err error
		dstPath, err = ioutil.TempDir("", "")
		Expect(err).NotTo(HaveOccurred())
		options = ImageServerOptions{
			HealthzURL:        healthzPath,
			APIURL:            apiPrefix,
			APIVersions:       apiVersions,
			MetadataURL:       metadataPath,
			ContentURL:        contentPath,
			ScanType:          scanType,
			ScanReportURL:     openscapReportPath,
			HTMLScanReport:    true,
			HTMLScanReportURL: openScapHTMLReportPath,
			AuthToken:         authToken,
			Chroot:            false,
		}
		handler, err := NewWebdavImageServer(options).(*webdavImageServer).GetHandler(dummyMetadata, dstPath, dummyScanResults, dummyScanReport, dummyHTMLScanReport)
		Expect(err).NotTo(HaveOccurred())
		server = httptest.NewServer(handler)
	})
	AfterEach(func() {
		server.Close()
		os.RemoveAll(dstPath)
	})
	Describe("Endpoints:", func() {
		var u *url.URL
		JustBeforeEach(func() {
			var err error
			u, err = url.Parse(server.URL)
			Expect(err).NotTo(HaveOccurred())
		})
		Describe("Healthz", func() {
			JustBeforeEach(func() {
				u.Path = healthzPath
			})
			Context("valid auth token", func() {
				It("returns 200 and the text \"ok\\n\"", func() {
					status, body, err := getWithAuth(u, authToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(status).To(Equal(http.StatusOK))
					Expect(body).To(Equal([]byte("ok\n")))
				})
			})
			Context("invalid auth token", func() {
				It("returns 401", func() {
					status, _, err := getWithAuth(u, "asdf")
					Expect(err).NotTo(HaveOccurred())
					Expect(status).To(Equal(http.StatusUnauthorized))
				})
			})
		})
		Describe(apiPrefix, func() {
			JustBeforeEach(func() {
				u.Path = apiPrefix
			})
			It("returns a list of available api versions", func() {
				status, body, err := getWithAuth(u, authToken)
				Expect(err).NotTo(HaveOccurred())
				Expect(status).To(Equal(http.StatusOK))
				var returnedVersions api.APIVersions
				err = json.Unmarshal(body, &returnedVersions)
				Expect(err).NotTo(HaveOccurred())
				Expect(returnedVersions).To(Equal(apiVersions))
			})
		})
		Describe(metadataPath, func() {
			JustBeforeEach(func() {
				u.Path = metadataPath
			})
			It("returns the metadata the server was initialized with", func() {
				status, body, err := getWithAuth(u, authToken)
				Expect(err).NotTo(HaveOccurred())
				Expect(status).To(Equal(http.StatusOK))
				var metadata api.InspectorMetadata
				err = json.Unmarshal(body, &metadata)
				Expect(err).NotTo(HaveOccurred())
				Expect(metadata.ID).To(Equal(dummyMetadata.ID))
				Expect(metadata.OpenSCAP.Status).To(Equal(dummyMetadata.OpenSCAP.Status))
			})
		})

		Describe(openscapReportPath, func() {
			JustBeforeEach(func() {
				u.Path = openscapReportPath
			})
			Context("OpenSCAP scan succeeded", func() {
				BeforeEach(func() {
					dummyMetadata.OpenSCAP.Status = api.StatusSuccess
				})
				It("should return 200 with the scan report", func() {
					status, body, err := getWithAuth(u, authToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(status).To(Equal(http.StatusOK))
					Expect(body).To(Equal(dummyScanReport))
				})
			})
			Context("OpenSCAP scan errored", func() {
				BeforeEach(func() {
					dummyMetadata.OpenSCAP.Status = api.StatusError
					dummyMetadata.OpenSCAP.ErrorMessage = "dummy error message"
				})
				It("should return 500 with the scan error message", func() {
					status, body, err := getWithAuth(u, authToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(status).To(Equal(http.StatusInternalServerError))
					Expect(string(body)).To(ContainSubstring(dummyMetadata.OpenSCAP.ErrorMessage))
				})
			})
		})

		Describe(openScapHTMLReportPath, func() {
			JustBeforeEach(func() {
				u.Path = openScapHTMLReportPath
			})
			Context("OpenSCAP scan succeeded", func() {
				BeforeEach(func() {
					dummyMetadata.OpenSCAP.Status = api.StatusSuccess
				})
				It("should return 200 with the scan report", func() {
					status, body, err := getWithAuth(u, authToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(status).To(Equal(http.StatusOK))
					Expect(body).To(Equal(dummyHTMLScanReport))
				})
			})
			Context("OpenSCAP scan errored", func() {
				BeforeEach(func() {
					dummyMetadata.OpenSCAP.Status = api.StatusError
					dummyMetadata.OpenSCAP.ErrorMessage = "dummy error message"
				})
				It("should return 500 with the scan error message", func() {
					status, body, err := getWithAuth(u, authToken)
					Expect(err).NotTo(HaveOccurred())
					Expect(status).To(Equal(http.StatusInternalServerError))
					Expect(string(body)).To(ContainSubstring(dummyMetadata.OpenSCAP.ErrorMessage))
				})
			})
		})
		Describe("webdav content serving", func() {
			var files map[string]string
			JustBeforeEach(func() {
				var err error
				files, err = addFiles(dstPath, 3)
				Expect(err).NotTo(HaveOccurred())
			})
			Describe("an HTTP GET of an expected file from "+contentPath, func() {
				It("should return status 200 and the contents of the file", func() {
					for filename, contents := range files {
						u.Path = contentPath + filepath.Base(filename)
						status, body, err := getWithAuth(u, authToken)
						Expect(err).NotTo(HaveOccurred())
						Expect(status).To(Equal(http.StatusOK))
						Expect(string(body)).To(Equal(contents))
					}
				})
			})
			Describe("list content root via webdav client", func() {
				It("should list the contents of "+dstPath, func() {
					client := webdavclnt.NewClient(u.Host).SetWrapRequest(func(req *http.Request) {
						req.Header.Set(authTokenHeader, authToken)
					})
					prop, err := client.AllPropFind(contentPath)
					Expect(err).NotTo(HaveOccurred())
					for filename := range files {
						Expect(prop).To(HaveKey(contentPath + filepath.Base(filename)))
					}
				})
			})
		})
	})
})

func getWithAuth(u *url.URL, token string) (int, []byte, error) {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set(authTokenHeader, token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	resp.Body.Close()
	return resp.StatusCode, body, nil
}

func addFiles(dstPath string, quantity int) (map[string]string, error) {
	fileContents := make(map[string]string)
	for i := 0; i < quantity; i++ {
		contents := fmt.Sprintf("i am file number %v", i)
		tmpFile, err := ioutil.TempFile(dstPath, "")
		if err != nil {
			return nil, err
		}
		_, err = tmpFile.WriteString(contents)
		if err != nil {
			return nil, err
		}
		defer tmpFile.Close()
		fileContents[tmpFile.Name()] = contents
	}
	return fileContents, nil
}
