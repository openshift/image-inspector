package imageserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"syscall"

	"golang.org/x/net/webdav"

	iiapi "github.com/openshift/image-inspector/pkg/api"
)

const (
	// CHROOT_SERVE_PATH is the path to server if we are performing a chroot
	// this probably does not belong here.
	CHROOT_SERVE_PATH = "/"
	// AUTH_TOKEN_HEADER is the custom HTTP Header used
	// to authenticate to image inspector.
	// We use a custom auth header instead of Authorization
	// because Kubernetes Proxy strips the default Auth Header
	// from requests
	AUTH_TOKEN_HEADER = "X-Auth-Token"
)

// webdavImageServer implements ImageServer.
type webdavImageServer struct {
	opts   ImageServerOptions
	chroot bool
}

// ensures this always implements the interface or fail compilation.
var _ ImageServer = &webdavImageServer{}

// NewWebdavImageServer creates a new webdav image server.
func NewWebdavImageServer(opts ImageServerOptions, chroot bool) ImageServer {
	return &webdavImageServer{
		opts:   opts,
		chroot: chroot,
	}
}

// ServeImage Serves the image.
func (s *webdavImageServer) ServeImage(meta *iiapi.InspectorMetadata,
	results iiapi.ScanResult,
	scanReport []byte,
	htmlScanReport []byte,
) error {

	servePath := s.opts.ImageServeURL
	if s.chroot {
		if err := syscall.Chroot(s.opts.ImageServeURL); err != nil {
			return fmt.Errorf("Unable to chroot into %s: %v\n", s.opts.ImageServeURL, err)
		}
		servePath = CHROOT_SERVE_PATH
	} else {
		log.Printf("!!!WARNING!!! It is insecure to serve the image content without changing")
		log.Printf("root (--chroot). Absolute-path symlinks in the image can lead to disclose")
		log.Printf("information of the hosting system.")
	}

	log.Printf("Serving image content %s on webdav://%s%s", s.opts.ImageServeURL, s.opts.ServePath, s.opts.ContentURL)

	http.Handle(s.opts.HealthzURL, s.checkAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	}))

	http.Handle(s.opts.APIURL, s.checkAuth(func(w http.ResponseWriter, r *http.Request) {
		body, err := json.MarshalIndent(s.opts.APIVersions, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	}))

	http.Handle(s.opts.MetadataURL, s.checkAuth(func(w http.ResponseWriter, r *http.Request) {
		body, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	}))

	http.HandleFunc(s.opts.ResultAPIUrlPath, s.checkAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		resultJSON, err := json.Marshal(results)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(resultJSON)
	}))

	http.Handle(s.opts.ScanReportURL, s.checkAuth(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.ScanType != "" && meta.OpenSCAP.Status == iiapi.StatusSuccess {
			w.Write(scanReport)
		} else {
			if meta.OpenSCAP.Status == iiapi.StatusError {
				http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", meta.OpenSCAP.ErrorMessage),
					http.StatusInternalServerError)
			} else {
				http.Error(w, "OpenSCAP option was not chosen", http.StatusNotFound)
			}
		}
	}))

	http.Handle(s.opts.HTMLScanReportURL, s.checkAuth(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.ScanType != "" && meta.OpenSCAP.Status == iiapi.StatusSuccess && s.opts.HTMLScanReport {
			w.Write(htmlScanReport)
		} else {
			if meta.OpenSCAP.Status == iiapi.StatusError {
				http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", meta.OpenSCAP.ErrorMessage),
					http.StatusInternalServerError)
			} else {
				http.Error(w, "OpenSCAP option was not chosen", http.StatusNotFound)
			}
		}
	}))

	http.Handle(s.opts.ContentURL, s.checkAuth((&webdav.Handler{
		Prefix:     s.opts.ContentURL,
		FileSystem: webdav.Dir(servePath),
		LockSystem: webdav.NewMemLS(),
	}).ServeHTTP))

	return http.ListenAndServe(s.opts.ServePath, nil)
}

//middleware handler for checking auth
func (s *webdavImageServer) checkAuth(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	authToken := s.opts.AuthToken
	// allow running without authorization
	if len(authToken) == 0 {
		log.Printf("!!!WARNING!!! It is insecure to serve the image content without setting")
		log.Printf("an auth token. Please set INSPECTOR_AUTH_TOKEN in your environment.")
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next(w, req)
		})
	}

	return func(w http.ResponseWriter, req *http.Request) {
		if err := func() error {
			token := req.Header.Get(AUTH_TOKEN_HEADER)
			if len(token) == 0 {
				return fmt.Errorf("must provide %s header with this request", AUTH_TOKEN_HEADER)
			}
			if token != authToken {
				return fmt.Errorf("invalid auth token provided")
			}
			return nil
		}(); err != nil {
			http.Error(w, fmt.Sprintf("Authorization failed: %s", err.Error()), http.StatusUnauthorized)
		} else {
			next(w, req)
		}
	}
}
