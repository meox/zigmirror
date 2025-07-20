package main

import (
	"crypto/sha256"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"log"
	"zigmirror/registry"

	"go.uber.org/zap"
)

const PubKey = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U"
const ZigMirrorRelease = "https://ziglang.org/download"
const ZigMirrorBuilds = "https://ziglang.org/builds"

//go:embed favicon.ico
var favicon embed.FS

type zigVersion struct {
	maj   uint32
	min   uint32
	patch uint32
	dev   bool
}

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
	mirrorPath string
	address    string
	port       int
)
var (
	repoBase        = "/tmp/zig_repo/"
	repoPathBuilds  = repoBase + "/builds"
	repoPathRelease = repoBase + "/release"
	repoPathTmp     = repoBase + "/tmp"
)

func init() {
	flag.StringVar(&mirrorPath, "mirror-path", "/tmp/zig_repo", "base mirror path")
	flag.StringVar(&address, "address", "localhost", "listen address")
	flag.IntVar(&port, "port", 5000, "listen port")
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("cannot create logger: %v", err)
	}
	defer logger.Sync() // flushes buffer, if any

	flag.Parse()

	buildDirRepo()

	reg := registry.Init()

	mux := http.NewServeMux()
	mux.Handle("GET /favicon.ico", http.FileServer(http.FS(favicon)))
	mux.HandleFunc("GET /{filename}", func(w http.ResponseWriter, r *http.Request) {
		fileName := r.PathValue("filename")
		sugar := logger.Sugar().With("filename", fileName)

		defer sugar.Sync()

		if !validFormat(fileName) {
			// return 404
			sugar.Warn("reject request for invalid format")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		version, err := getVersion(fileName)
		if err != nil {
			sugar.Warnf("request with a bad version: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// check older than 0.5.0
		if version.maj == 0 && (version.min < 5 || (version.min == 5 && version.patch == 0)) {
			// too old
			sugar.Warn("request discarded because the file is too old")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		handleFileRequest(sugar, reg, fileName, version, w)
	})

	listenAddr := fmt.Sprintf("%s:%d", address, port)
	sugar := logger.Sugar()
	sugar.Infof("serving request at: %s, repo path: %s", listenAddr, mirrorPath)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func handleFileRequest(sugar *zap.SugaredLogger, reg *registry.SafeDownload, fileName string, v zigVersion, w http.ResponseWriter) {
	var filePath string
	var url string

	hash := getSHA256(fileName)

	if v.dev {
		url = fmt.Sprintf("%s/%s", ZigMirrorBuilds, fileName)
		filePath = repoPathBuilds
	} else {
		url = fmt.Sprintf("%s/%d.%d.%d/%s", ZigMirrorRelease, v.maj, v.min, v.patch, fileName)
		filePath = repoPathRelease
	}
	filePath = path.Join(filePath, hash)

	sugar = sugar.With(
		"file_path", filePath,
		"sha256", hash,
		"version", fmt.Sprintf("%d.%d.%d", v.maj, v.min, v.patch),
		"dev", v.dev,
	)

	// check if the file is in the repo
	if _, err := os.Stat(filePath); err == nil {
		t_now := time.Now()

		// serve the file
		err = serveFile(filePath, w)
		if err != nil {
			sugar.Errorf("cannot serve the file: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sugar.Infow("file served!", "present", true, "elapsed_ms", time.Since(t_now).Milliseconds())
	} else if errors.Is(err, os.ErrNotExist) {
		sugarU := sugar.With("url", url, "present", false)

		if !reg.StartDownload(fileName) {
			sugarU.Warn("downloading from main mirror already in progress")
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer reg.DownloadComplete(fileName)

		// download and serve
		err := downloadServe(sugarU, url, filePath, w)
		if err != nil {
			sugarU.Errorf("cannot download: %v", err)
			return
		}
	} else {
		sugar.Errorf("reject request for error: %v", err)
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

func serveFile(filePath string, w http.ResponseWriter) error {
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close()

	w.WriteHeader(http.StatusOK)

	buff := pool.Get().(*page)
	defer pool.Put(buff)

	_, err = io.CopyBuffer(w, fd, buff.Data)
	return err
}

func downloadServe(sugar *zap.SugaredLogger, url string, dstFile string, w http.ResponseWriter) error {
	t_now := time.Now()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second, // Connection timeout
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			IdleConnTimeout:       20 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
		},
		Timeout: 60 * time.Second, // Overall request timeout
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNotFound {
		w.WriteHeader(resp.StatusCode)
		sugar.Warnf("downloading file failed due to: %s", resp.Status)
		return fmt.Errorf("%v not found", url)
	}

	tmpFile, err := os.CreateTemp(repoPathTmp, "f-*")
	if err != nil {
		return err
	}
	sugar = sugar.With("tmp_file", tmpFile.Name(), "dest_file", dstFile)

	buff := pool.Get().(*page)
	defer pool.Put(buff)

	r := io.TeeReader(resp.Body, w)
	written, errCopy := io.CopyBuffer(tmpFile, r, buff.Data)
	if errCopy == nil {
		err = tmpFile.Sync()
		if err != nil {
			sugar = sugar.With("sync_error", true)
		}
	}

	err = tmpFile.Close()
	if err != nil {
		sugar = sugar.With("close_error", true)
	}

	if errCopy != nil {
		os.Remove(tmpFile.Name())
		return errCopy
	}

	// rename the file
	err = os.Rename(tmpFile.Name(), dstFile)
	if err != nil {
		sugar.Errorf("cannot rename: %s -> %s, reason: %v", tmpFile.Name(), dstFile, err)
		return err
	}

	sugar.With(
		"renamed", true,
		"written", written,
		"elapsed_ms", time.Since(t_now).Milliseconds(),
	).Info("file served!")
	return nil
}

func buildDirRepo() {
	repoPathBuilds = path.Join(mirrorPath, "builds")
	repoPathRelease = path.Join(mirrorPath, "release")
	repoPathTmp = path.Join(mirrorPath, "tmp")

	paths := []string{
		repoPathBuilds,
		repoPathRelease,
		repoPathTmp,
	}

	for _, p := range paths {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			err = os.MkdirAll(p, 0700)
			if err != nil {
				log.Fatalf("Cannot create repo path: %s, reason: %v", p, err)
			}
		}
	}
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
