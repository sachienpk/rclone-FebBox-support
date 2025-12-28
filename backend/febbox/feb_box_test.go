// Package feb_box_test contains tests for the feb_box package.
package febbox

import (
	"testing"

	"github.com/rclone/rclone/fs"
	"github.com/stretchr/testify/assert"
)

func TestRegistration(t *testing.T) {
	var backend *fs.RegInfo
	for _, b := range fs.Registry {
		if b.Name == "febbox" {
			backend = b
			break
		}
	}

	assert.NotNil(t, backend, "febbox backend should be registered")
	assert.Equal(t, "febbox", backend.Name)
	assert.Equal(t, "Febbox Cloud Storage", backend.Description)
}

func TestGetMimeType(t *testing.T) {
	tests := []struct {
		ext      string
		expected string
	}{
		{"mp4", "video/mp4"},
		{"mkv", "video/x-matroska"},
		{"m3u8", "application/x-mpegURL"},
		{"mp3", "audio/mpeg"},
		{"jpg", "image/jpeg"},
		{"png", "image/png"},
		{"pdf", "application/octet-stream"},
		{"unknown", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			result := getMimeType(tt.ext)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseCookieString(t *testing.T) {
	tests := []struct {
		name      string
		cookieStr string
		expected  int
	}{
		{
			name:      "multiple cookies",
			cookieStr: "PHPSESSID=abc; ui=def; cf_clearance=ghi",
			expected:  3,
		},
		{
			name:      "single cookie",
			cookieStr: "ui=abc123",
			expected:  1,
		},
		{
			name:      "empty cookies",
			cookieStr: "",
			expected:  0,
		},
		{
			name:      "malformed cookie",
			cookieStr: "ui=abc; broken; name=value",
			expected:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookies := parseCookieString(tt.cookieStr)
			assert.Equal(t, tt.expected, len(cookies))
		})
	}
}
