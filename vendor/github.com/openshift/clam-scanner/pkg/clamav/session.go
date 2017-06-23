package clamav

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/golang/glog"
)

// ClamdSession is the interface for a Clamav session.
type ClamdSession interface {
	// ScanPath scans all files under the specified path.
	ScanPath(path string) error

	// WaitTillDone blocks until responses have been received for all the
	// files submitted for scanning.
	WaitTillDone()

	// Close closes the clamd session.
	Close() error

	// GetResults returns the scan results.
	GetResults() ClamdScanResult
}

// clamdSession keeps track of Clamav session data.
type clamdSession struct {
	// conn is the Unix domain socket connection to clamd.
	conn ClamdConn

	// partialResponse holds any partial response in case a response is
	// split across multiple reads.
	partialResponse []byte

	// closeChan is a channel by which pollResponses signals to WaitTillDone
	// that all responses have been received.
	closeChan chan bool

	// allFilesSubmitted indicates whether all files have been submitted to
	// clamd for scanning.
	allFilesSubmitted bool

	// numFilesSubmitted is the number of files that have been submitted to
	// clamd for scanning.
	numFilesSubmitted int

	// numResponsesReceived is the number of responses that have been
	// received from clamd.  There should be one response for each file
	// submitted for scanning.
	numResponsesReceived int

	// requestIDToFilename maps request ID to filename.
	// requestIDToFilename[1] is the filename of the first file submitted
	// for scanning, requestIDToFilename[2] is the filename of the second
	// file submitted, and so on.
	requestIDToFilename map[int]string

	// requestIDToFilenameMutex is a lock protecting requestIDToFilename.
	requestIDToFilenameMutex sync.Mutex

	// ignoreNegatives indicates whether negative ("OK") scan results should
	// be omitted from the results.
	ignoreNegatives bool

	// results holds the results of the scan.  It is built incrementally as
	// responses (or errors) are received from clamd.
	results ClamdScanResult
}

// ClamdScanResult holds the results of a scan.
type ClamdScanResult struct {
	// Files holds scan results for individual files.
	Files []ClamdFileResult `json:"results"`

	// Errors holds error responses received from clamd or logged internally
	// during the scan.
	Errors []string `json:"errors"`
}

// ClamdFileResult holds the scan result for a file.
type ClamdFileResult struct {
	// Filename is the name of the file.
	Filename string `json:"filename"`

	// Result is the response received from clamd for the file.
	Result string `json:"result"`

	// Errors holds any errors that arose while submitting the file to clamd
	// for scanning or reading the response from clamd.
	Errors []string `json:"errors"`
}

// IsNegative returns a Boolean value indicating whether the scan result was
// negative ("OK") or not.
func (fileResult *ClamdFileResult) IsNegative() bool {
	return fileResult.Result == "OK"
}

// NewClamdSession opens a connection to clamd, starts a session, and returns
// a session object for that session.
func NewClamdSession(socket string, ignoreNegatives bool) (ClamdSession, error) {
	conn, err := NewClamdConn(socket)
	if err != nil {
		return nil, err
	}

	err = conn.Write([]byte("zIDSESSION\000"), nil)
	if err != nil {
		return nil, err
	}

	closeChan := make(chan bool)
	requestIDToFilename := make(map[int]string)

	ses := &clamdSession{
		closeChan:                closeChan,
		conn:                     conn,
		requestIDToFilename:      requestIDToFilename,
		requestIDToFilenameMutex: sync.Mutex{},
		ignoreNegatives:          ignoreNegatives,
		results: ClamdScanResult{
			Files: []ClamdFileResult{},
		},
	}

	go ses.pollResponses()

	return ses, nil
}

// Close ends the session with clamd and closes the connection.
func (ses *clamdSession) Close() error {
	err := ses.conn.Write([]byte("zEND\000"), nil)
	if err != nil {
		ses.conn.Close()
		return err
	}

	return ses.conn.Close()
}

// WaitTillDone waits for all responses for each file submitted to clamd to be
// received.  It should be called only after all files have been submitted.
func (ses *clamdSession) WaitTillDone() {
	ses.allFilesSubmitted = true

	for {
		select {
		case <-ses.closeChan:
			return
		default:
		}
	}
}

// GetResults returns the scan results.
func (ses *clamdSession) GetResults() ClamdScanResult {
	return ses.results
}

// pollResponses polls clamd for responses, reads them, and handles them.  It
// closes closeChan and returns once all files have been submitted and all
// responses received, or when the connection to clamd is closed.
func (ses *clamdSession) pollResponses() {
	defer close(ses.closeChan)

	for {
		if ses.allFilesSubmitted && ses.numFilesSubmitted == ses.numResponsesReceived {
			return
		}

		buf, err := ses.conn.Read()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}

			ses.log(err)

			if err == io.EOF {
				return
			}

			continue
		}

		ses.handleResponses(buf)
	}
}

// handleResponses takes a buffer that may contain 1 or more responses from
// clamd and handles those responses individually.
func (ses *clamdSession) handleResponses(buf []byte) {
	buf = append(ses.partialResponse, buf...)
	ses.partialResponse = nil

	for {
		end := bytes.IndexByte(buf, '\x00')
		if end <= 0 {
			ses.partialResponse = buf
			return
		}

		response := string(buf[:end])
		buf = buf[end+1:]

		glog.V(6).Infof("Parsed response:\n  %#v\nremaining buffer:\n  %#v\n", response, string(buf))

		ses.handleResponse(response)
	}
}

// handleResponse takes a response that was received from clamd and handles it.
func (ses *clamdSession) handleResponse(response string) {
	errors := []string{}

	requestID, requestResult, err := parseClamdResponse(response)
	if err != nil {
		errors = append(errors, err.Error())
	}

	path := "<unknown>"
	if requestID != 0 {
		var ok bool

		ses.requestIDToFilenameMutex.Lock()
		path, ok = ses.requestIDToFilename[requestID]
		ses.requestIDToFilenameMutex.Unlock()
		if !ok {
			errors = append(errors, fmt.Sprintf("request not recognized: %d", requestID))
		}

		ses.numResponsesReceived++
	}

	result := ClamdFileResult{
		Filename: path,
		Result:   requestResult,
		Errors:   errors,
	}

	glog.V(6).Infof("Received scan result for request %d out of %d submitted:\n  %#v\n",
		requestID, ses.numFilesSubmitted, result)

	if !ses.ignoreNegatives || !result.IsNegative() {
		ses.results.Files = append(ses.results.Files, result)
	}
}

// parseClamdResponse takes a response that was received from clamd and parses it.
func parseClamdResponse(response string) (int, string, error) {
	glog.V(6).Infof("Parsing clamd response: %q\n", response)

	parts := strings.SplitN(response, ": ", 3)
	if len(parts) < 3 {
		return 0, "", fmt.Errorf("unexpected response from clamd: %s", response)
	}

	// Response should have the form "<requestID>: fd[<fd>]: <response>"
	// where requestID is an integer, fd[<fd>] is the file descriptor on
	// clamd's side (which is useless to us), and response is the result of
	// the clamd scan on that file descriptor.

	requestID, err := strconv.ParseInt(parts[0], 10, 0)
	if err != nil {
		return 0, "", fmt.Errorf("strconv.ParseInt failed: %s", response)
	}

	result := parts[2]

	return int(requestID), result, nil
}

// log appends an error to the scan results.
func (ses *clamdSession) log(err error) {
	ses.results.Errors = append(ses.results.Errors, err.Error())
}

// ScanPath performs a scan on a path by walking the path and submitting files
// to clamd.  Recoverable errors are added to the scan result.  In the case of a
// non-recoverable error, an error is returned instead.
func (ses *clamdSession) ScanPath(path string) error {
	walkFn := func(path string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			ses.log(err)
			return nil
		}

		if fileInfo.Mode().IsRegular() {
			err := ses.scanFile(path)
			if err != nil {
				ses.log(err)
			}
		}

		return nil
	}

	err := filepath.Walk(path, walkFn)
	if err != nil {
		return err
	}

	return nil
}

// scanFile submits a file to clamd for scanning.
func (ses *clamdSession) scanFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	rights := syscall.UnixRights(int(f.Fd()))
	msg := []byte("zFILDES\000\000")

	err = ses.conn.Write(msg, rights)
	if err != nil {
		return err
	}

	ses.numFilesSubmitted++
	ses.requestIDToFilenameMutex.Lock()
	ses.requestIDToFilename[ses.numFilesSubmitted] = path
	ses.requestIDToFilenameMutex.Unlock()

	return nil
}
