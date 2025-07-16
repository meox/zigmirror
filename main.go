package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"zigmirror/registry"

	log "github.com/sirupsen/logrus"
)

const ZigMirrorRelease = "https://ziglang.org/download/"
const ZigMirrorBuilds = "https://ziglang.org/builds/"

type zigVersion struct {
	maj   uint32
	min   uint32
	patch uint32
	dev   bool
}

var repoPathBuilds = "/tmp/zig_repo/builds"
var repoPathRelease = "/tmp/zig_repo/release"

type page struct {
	Data []byte
}

var pool = sync.Pool{
	New: func() any {
		return &page{
			Data: make([]byte, 1*1024*1024),
		}
	},
}

var (
	address string
	port    int
)

func init() {
	// Only log the warning severity or above.
	log.SetLevel(log.DebugLevel)

	flag.StringVar(&address, "address", "localhost", "listen address")
	flag.IntVar(&port, "port", 5000, "listen port")
}

func main() {
	flag.Parse()

	buildDirRepo()

	reg := registry.Init()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{filename}", func(w http.ResponseWriter, r *http.Request) {
		fileName := r.PathValue("filename")
		if !validFormat(fileName) {
			// return 404
			log.Warnf("reject request for invalid format: filename = %s", fileName)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		version, err := getVersion(fileName)
		if err != nil {
			log.Warnf("request %s with a bad version: %v", fileName, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// check older than 0.5.0
		if version.maj == 0 && (version.min < 5 || (version.min == 5 && version.patch == 0)) {
			// too old
			log.Warnf("request discarded because the file is too old: %s", fileName)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		handleFileRequest(reg, fileName, version, w)
	})

	listenAddr := fmt.Sprintf("%s:%d", address, port)
	log.Infof("serving request at: %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func handleFileRequest(reg *registry.SafeDownload, fileName string, v zigVersion, w http.ResponseWriter) {
	var filePath string
	var url string

	hash := getSHA256(fileName)
	log.Debugf("request %s: (sha256=%s, version: %d.%d.%d) (dev: %t)\n", fileName, hash, v.maj, v.min, v.patch, v.dev)

	if v.dev {
		url = fmt.Sprintf("%s/%s", ZigMirrorBuilds, fileName)
		filePath = repoPathBuilds
	} else {
		url = fmt.Sprintf("%s/%d.%d.%d/%s", ZigMirrorRelease, v.maj, v.min, v.patch, fileName)
		filePath = repoPathRelease
	}
	filePath = path.Join(filePath, hash)

	// check if the file is in the repo
	if _, err := os.Stat(filePath); err == nil {
		log.Debugf("file %s present", filePath)

		// serve the file
		err = serveFile(filePath, w)
		if err != nil {
			log.Errorf("cannot serve the file: %v", err)
		}
		log.Debugf("file %s served!", fileName)
	} else if errors.Is(err, os.ErrNotExist) {
		log.Debugf("file not present, downloading: %s", fileName)

		if !reg.StartDownload(fileName) {
			log.Warnf("downloading in progress for file: %s", fileName)
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		defer reg.DownloadComplete(fileName)

		// download and serve
		err := downloadServe(url, filePath, w)
		if err != nil {
			log.Errorf("cannot download: %s, %v", fileName, err)
		}
		log.Debugf("file %s served!", fileName)
	} else {
		log.Errorf("reject request for error: %v", err)
		w.WriteHeader(http.StatusNotFound)
	}
}

func getSHA256(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func validFormat(fileName string) bool {
	var acceptedFormat = []string{
		".zip",
		".tar.xz",
		".zip.minisig",
		".tar.xz.minisig",
	}

	for _, format := range acceptedFormat {
		if strings.HasSuffix(fileName, format) {
			return true
		}
	}
	return false
}

func getVersion(fileName string) (zigVersion, error) {
	const versionRegex = `(\d+)\.(\d+)\.(\d+)(-dev\.\d+\+[0-9a-f]+)?`

	// Compile the regex pattern
	re := regexp.MustCompile(versionRegex)

	// Find matches in the filename
	matches := re.FindStringSubmatch(fileName)

	if len(matches) < 4 {
		// Return zero version if no match found
		return zigVersion{}, fmt.Errorf("invalid version")
	}

	// Parse major, minor, patch versions
	maj, err := strconv.ParseUint(matches[1], 10, 32)
	if err != nil {
		return zigVersion{}, err
	}

	min, err := strconv.ParseUint(matches[2], 10, 32)
	if err != nil {
		return zigVersion{}, err
	}

	patch, err := strconv.ParseUint(matches[3], 10, 32)
	if err != nil {
		return zigVersion{}, err
	}

	// Check if it's a dev version
	isDev := matches[4] != "" && strings.Contains(matches[4], "-dev")

	return zigVersion{
		maj:   uint32(maj),
		min:   uint32(min),
		patch: uint32(patch),
		dev:   isDev,
	}, nil
}

func serveFile(filePath string, w http.ResponseWriter) error {
	w.WriteHeader(http.StatusOK)
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close()

	buff := pool.Get().(*page)
	defer pool.Put(buff)

	_, err = io.CopyBuffer(w, fd, buff.Data)
	return err
}

func downloadServe(url string, dstFile string, w http.ResponseWriter) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		tmpFile, err := os.CreateTemp(os.TempDir(), "zigmirror-")
		if err != nil {
			return err
		}

		buff := pool.Get().(*page)
		defer pool.Put(buff)

		r := io.TeeReader(resp.Body, w)
		_, errCopy := io.CopyBuffer(tmpFile, r, buff.Data)
		if errCopy == nil {
			err = tmpFile.Sync()
			if err != nil {
				log.Debugf("cannot sync file to disk")
			}
		}

		err = tmpFile.Close()
		if err != nil {
			log.Debugf("cannot close file to disk")
		}

		if errCopy != nil {
			os.Remove(tmpFile.Name())
			return errCopy
		}

		// rename the file
		log.Debugf("renaming: %s -> %s", tmpFile.Name(), dstFile)
		return os.Rename(tmpFile.Name(), dstFile)
	} else {
		w.WriteHeader(http.StatusNotFound)
		log.Warnf("downloading file failed due to: %s", resp.Status)
	}
	return nil
}

func buildDirRepo() {
	if _, err := os.Stat(repoPathBuilds); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		err = os.MkdirAll(repoPathBuilds, 0700)
		if err != nil {
			log.Fatalf("Cannot create repo path: %s, reason: %v", repoPathBuilds, err)
		}
	}
	if _, err := os.Stat(repoPathRelease); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		err = os.MkdirAll(repoPathRelease, 0700)
		if err != nil {
			log.Fatalf("Cannot create repo path: %s, reason: %v", repoPathRelease, err)
		}
	}
}
