// Package febbox implements a backend for Febbox Cloud Storage.
package febbox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/rest"
)

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "febbox",
		Description: "Febbox Cloud Storage",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "cookies",
			Help:     "ALL cookies from browser (PHPSESSID, ui, cf_clearance, etc.)",
			Required: true,
		}, {
			Name:     "share_key",
			Help:     "Share key from Febbox share URL",
			Required: true,
		}},
	})
}

// Options defines the configuration options for the Fs.
type Options struct {
	Cookies  string `config:"cookies"`
	ShareKey string `config:"share_key"`
}

// FileItem represents a file item from Febbox API.
type FileItem struct {
	FID           int64  `json:"fid"`
	FileName      string `json:"file_name"`
	FileSize      string `json:"file_size"`
	FileSizeBytes int64  `json:"file_size_bytes"`
	IsDir         int    `json:"is_dir"`
	Ext           string `json:"ext"`
	AddTime       string `json:"add_time"`
	UpdateTime    int64  `json:"update_time"`
	OssFID        int64  `json:"oss_fid"`
	Hash          string `json:"hash"`
	HashType      string `json:"hash_type"`
}

// Response represents the response from Febbox file listing API.
type Response struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		FileList []FileItem `json:"file_list"`
	} `json:"data"`
}

// DownloadResponse represents the response from Febbox download API.
type DownloadResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data []struct {
		Error       int    `json:"error"`
		DownloadURL string `json:"download_url"`
		Hash        string `json:"hash"`
		HashType    string `json:"hash_type"`
		FID         int64  `json:"fid"`
		FileName    string `json:"file_name"`
		FileSize    int64  `json:"file_size"`
		Ext         string `json:"ext"`
		QualityList []struct {
			Quality     string `json:"quality"`
			DownloadURL string `json:"download_url"`
			OssFID      int64  `json:"oss_fid"`
			FileSize    int64  `json:"file_size"`
			Bitrate     string `json:"bitrate"`
			Runtime     int    `json:"runtime"`
			Is265       int    `json:"is_265"`
		} `json:"quality_list"`
	} `json:"data"`
}

// Fs represents a connection to Febbox.
type Fs struct {
	name      string
	root      string
	opt       Options
	features  *fs.Features
	api       *rest.Client
	shareKey  string
	cookieJar *cookiejar.Jar
}

// Object represents a file in Febbox.
type Object struct {
	fs       *Fs
	remote   string
	fid      int64
	ossFid   int64
	hash     string
	hashType string
	name     string
	size     int64
	modTime  time.Time
	isDir    bool
	mimeType string
}

// StreamingResponse wraps the HTTP response for streaming.
type StreamingResponse struct {
	io.ReadCloser
	size   int64
	offset int64
}

// Read implements io.Reader.
func (sr *StreamingResponse) Read(p []byte) (n int, err error) {
	return sr.ReadCloser.Read(p)
}

// NewFs creates a new connection to Febbox.
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return nil, err
	}

	if opt.Cookies == "" {
		return nil, fmt.Errorf("cookies are required - get them from browser dev tools")
	}
	if opt.ShareKey == "" {
		return nil, fmt.Errorf("share_key is required - get it from the share URL")
	}

	root = strings.Trim(root, "/")
	f := &Fs{
		name:     name,
		root:     root,
		opt:      *opt,
		shareKey: opt.ShareKey,
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}
	f.cookieJar = jar

	cookies := parseCookieString(opt.Cookies)
	febboxURL, _ := url.Parse("https://www.febbox.com")
	jar.SetCookies(febboxURL, cookies)

	httpClient := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}

	f.api = rest.NewClient(httpClient).SetRoot("https://www.febbox.com")

	f.api.SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	f.api.SetHeader("X-Requested-With", "XMLHttpRequest")
	f.api.SetHeader("Cookie", opt.Cookies)
	f.api.SetHeader("Referer", "https://www.febbox.com/console")
	f.api.SetHeader("Origin", "https://www.febbox.com")

	var apiResp Response
	opts := rest.Opts{
		Method: "GET",
		Path:   fmt.Sprintf("/file/file_share_list?share_key=%s&parent_id=0&is_html=0", f.shareKey),
	}

	_, err = f.api.CallJSON(ctx, &opts, nil, &apiResp)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Febbox: %w", err)
	}

	if apiResp.Code != 1 {
		return nil, fmt.Errorf("febbox API error (code %d): %s", apiResp.Code, apiResp.Msg)
	}

	f.features = (&fs.Features{
		CaseInsensitive:         true,
		ReadMimeType:            true,
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	return f, nil
}

// Name returns the name of the remote Fs.
func (f *Fs) Name() string { return f.name }

// Root returns the root for the filesystem.
func (f *Fs) Root() string { return f.root }

// String returns a description of the Fs.
func (f *Fs) String() string { return fmt.Sprintf("Febbox share '%s'", f.shareKey) }

// Precision returns the precision of timestamps.
func (f *Fs) Precision() time.Duration { return time.Second }

// Hashes returns the supported hash types.
func (f *Fs) Hashes() hash.Set { return hash.Set(hash.None) }

// Features returns the optional features of this Fs.
func (f *Fs) Features() *fs.Features { return f.features }

// getFileList gets the list of files from Febbox.
func (f *Fs) getFileList(ctx context.Context, parentID string) ([]FileItem, error) {
	var apiResp Response
	opts := rest.Opts{
		Method: "GET",
		Path:   fmt.Sprintf("/file/file_share_list?share_key=%s&parent_id=%s&is_html=0", f.shareKey, parentID),
	}

	_, err := f.api.CallJSON(ctx, &opts, nil, &apiResp)
	if err != nil {
		return nil, err
	}

	if apiResp.Code != 1 {
		return nil, fmt.Errorf("API error (code %d): %s", apiResp.Code, apiResp.Msg)
	}

	return apiResp.Data.FileList, nil
}

// NewObject finds the Object for remote.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	remote = strings.TrimPrefix(remote, "/")
	if remote == "" {
		return nil, fs.ErrorIsDir
	}

	fileList, err := f.getFileList(ctx, "0")
	if err != nil {
		return nil, err
	}

	for _, item := range fileList {
		if item.FileName == remote {
			modTime, _ := time.Parse("Jan 2,2006 15:04", item.AddTime)
			if modTime.IsZero() {
				modTime = time.Now()
			}

			return &Object{
				fs:       f,
				remote:   remote,
				fid:      item.FID,
				ossFid:   item.OssFID,
				hash:     item.Hash,
				hashType: item.HashType,
				name:     item.FileName,
				size:     item.FileSizeBytes,
				modTime:  modTime,
				isDir:    item.IsDir == 1,
				mimeType: getMimeType(item.Ext),
			}, nil
		}
	}

	return nil, fs.ErrorObjectNotFound
}

// List the objects and directories in dir into entries.
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	if dir != "" && dir != "." {
		return nil, fs.ErrorNotImplemented
	}

	fileList, err := f.getFileList(ctx, "0")
	if err != nil {
		return nil, err
	}

	var entries fs.DirEntries
	for _, item := range fileList {
		modTime, _ := time.Parse("Jan 2,2006 15:04", item.AddTime)
		if modTime.IsZero() {
			modTime = time.Now()
		}

		if item.IsDir == 1 {
			entries = append(entries, fs.NewDir(item.FileName, modTime))
		} else {
			entries = append(entries, &Object{
				fs:       f,
				remote:   item.FileName,
				fid:      item.FID,
				ossFid:   item.OssFID,
				hash:     item.Hash,
				hashType: item.HashType,
				name:     item.FileName,
				size:     item.FileSizeBytes,
				modTime:  modTime,
				isDir:    false,
				mimeType: getMimeType(item.Ext),
			})
		}
	}

	return entries, nil
}

// getDownloadURL returns the download URL for a file.
func (f *Fs) getDownloadURL(ctx context.Context, fid int64) (string, error) {
	fidsJSON := fmt.Sprintf(`["%d"]`, fid)
	encodedFids := url.QueryEscape(fidsJSON)

	var downloadResp DownloadResponse
	opts := rest.Opts{
		Method: "GET",
		Path:   fmt.Sprintf("/console/file_download?fids=%s&share=", encodedFids),
	}

	_, err := f.api.CallJSON(ctx, &opts, nil, &downloadResp)
	if err != nil {
		return "", fmt.Errorf("failed to get download URL: %w", err)
	}

	if downloadResp.Code != 1 || len(downloadResp.Data) == 0 {
		return "", fmt.Errorf("API error (code %d): %s", downloadResp.Code, downloadResp.Msg)
	}

	if downloadResp.Data[0].Error != 0 {
		return "", fmt.Errorf("download error: %d", downloadResp.Data[0].Error)
	}

	downloadURL := downloadResp.Data[0].DownloadURL
	if downloadURL == "" && len(downloadResp.Data[0].QualityList) > 0 {
		downloadURL = downloadResp.Data[0].QualityList[0].DownloadURL
	}

	if downloadURL == "" {
		return "", fmt.Errorf("no download URL found")
	}

	return downloadURL, nil
}

// getMimeType returns the MIME type for a file extension.
func getMimeType(ext string) string {
	ext = strings.ToLower(strings.TrimPrefix(ext, "."))

	switch ext {
	case "mp4", "m4v":
		return "video/mp4"
	case "mkv":
		return "video/x-matroska"
	case "avi":
		return "video/x-msvideo"
	case "mov":
		return "video/quicktime"
	case "wmv":
		return "video/x-ms-wmv"
	case "flv":
		return "video/x-flv"
	case "webm":
		return "video/webm"
	case "m3u8":
		return "application/x-mpegURL"
	case "mp3":
		return "audio/mpeg"
	case "wav":
		return "audio/wav"
	case "flac":
		return "audio/flac"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "png":
		return "image/png"
	case "gif":
		return "image/gif"
	default:
		return "application/octet-stream"
	}
}

// parseCookieString parses a cookie string into []*http.Cookie.
func parseCookieString(cookieStr string) []*http.Cookie {
	var cookies []*http.Cookie
	parts := strings.Split(cookieStr, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		name := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		if name == "" || value == "" {
			continue
		}

		cookies = append(cookies, &http.Cookie{
			Name:  name,
			Value: value,
		})
	}

	return cookies
}

// Fs returns the parent Fs.
func (o *Object) Fs() fs.Info { return o.fs }

// Remote returns the remote path.
func (o *Object) Remote() string { return o.remote }

// String returns a description of the Object.
func (o *Object) String() string { return o.remote }

// ModTime returns the modification time of the object.
func (o *Object) ModTime(ctx context.Context) time.Time { return o.modTime }

// Size returns the size of an object in bytes.
func (o *Object) Size() int64 { return o.size }

// Storable returns whether this object is storable.
func (o *Object) Storable() bool { return !o.isDir }

// Hash returns the hash of an object.
func (o *Object) Hash(ctx context.Context, ht hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// SetModTime sets the modification time of the object.
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorNotImplemented
}

// Update updates the object with the contents of in.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	return fs.ErrorNotImplemented
}

// Remove removes the object.
func (o *Object) Remove(ctx context.Context) error {
	return fs.ErrorNotImplemented
}

// Open opens the object for reading.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	downloadURL, err := o.fs.getDownloadURL(ctx, o.fid)
	if err != nil {
		return nil, fmt.Errorf("failed to get download URL: %w", err)
	}

	client := &http.Client{
		Jar:     o.fs.cookieJar,
		Timeout: 0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header = via[0].Header.Clone()
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://www.febbox.com/console")
	req.Header.Set("Origin", "https://www.febbox.com")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Cookie", o.fs.opt.Cookies)

	var rangeHeader string
	var start, end int64 = 0, o.size - 1
	var seekOffset int64

	for _, option := range options {
		switch opt := option.(type) {
		case *fs.SeekOption:
			start = opt.Offset
			seekOffset = opt.Offset
			if start < 0 {
				start = 0
				seekOffset = 0
			}
			if start > o.size {
				start = o.size
				seekOffset = o.size
			}
			end = o.size - 1
			rangeHeader = fmt.Sprintf("bytes=%d-", start)
		case *fs.RangeOption:
			start = opt.Start
			end = opt.End
			if start < 0 {
				start = 0
			}
			if end < 0 || end >= o.size {
				end = o.size - 1
			}
			rangeHeader = fmt.Sprintf("bytes=%d-%d", start, end)
		}
	}

	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	status := resp.StatusCode
	if status != http.StatusOK && status != http.StatusPartialContent {
		_ = resp.Body.Close()

		if status == http.StatusRequestedRangeNotSatisfiable || status == http.StatusForbidden {
			retryReq, _ := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
			retryReq.Header = req.Header.Clone()
			retryReq.Header.Del("Range")

			retryResp, err := client.Do(retryReq)
			if err != nil {
				return nil, fmt.Errorf("download failed: %s", resp.Status)
			}

			if retryResp.StatusCode == http.StatusOK {
				if retryResp.Header.Get("Content-Type") == "" {
					retryResp.Header.Set("Content-Type", o.mimeType)
				}
				if retryResp.Header.Get("Accept-Ranges") == "" {
					retryResp.Header.Set("Accept-Ranges", "bytes")
				}

				return &StreamingResponse{
					ReadCloser: retryResp.Body,
					size:       o.size,
					offset:     seekOffset,
				}, nil
			}
			_ = retryResp.Body.Close()
		}

		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}

	if resp.Header.Get("Content-Type") == "" {
		resp.Header.Set("Content-Type", o.mimeType)
	}

	if resp.Header.Get("Accept-Ranges") == "" {
		resp.Header.Set("Accept-Ranges", "bytes")
	}

	if resp.Header.Get("Content-Length") == "" && o.size > 0 {
		if status == http.StatusPartialContent {
			contentLength := end - start + 1
			resp.Header.Set("Content-Length", strconv.FormatInt(contentLength, 10))
			resp.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, o.size))
		} else {
			resp.Header.Set("Content-Length", strconv.FormatInt(o.size, 10))
		}
	}

	return &StreamingResponse{
		ReadCloser: resp.Body,
		size:       o.size,
		offset:     seekOffset,
	}, nil
}

// Put creates or updates an object.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return nil, fs.ErrorNotImplemented
}

// Mkdir creates a directory.
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return fs.ErrorNotImplemented
}

// Rmdir removes a directory.
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return fs.ErrorNotImplemented
}
