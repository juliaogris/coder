package chatfiles

import (
	"bytes"
	"encoding/xml"
	"mime"
	"net/http"
	"strings"
)

var (
	utf8BOM       = []byte{0xEF, 0xBB, 0xBF}
	webpMagicRIFF = []byte("RIFF")
	webpMagicWEBP = []byte("WEBP")
)

// DetectContentType detects the MIME type of the given file contents.
// It extends http.DetectContentType with support for WebP, which Go's
// standard sniffer does not recognize.
func DetectContentType(data []byte) string {
	if len(data) >= 12 &&
		bytes.Equal(data[0:4], webpMagicRIFF) &&
		bytes.Equal(data[8:12], webpMagicWEBP) {
		return "image/webp"
	}
	return http.DetectContentType(data)
}

// BaseMediaType strips parameters from a media type.
func BaseMediaType(mediaType string) string {
	if parsed, _, err := mime.ParseMediaType(mediaType); err == nil {
		return parsed
	}
	return mediaType
}

// IsSVGContent reports whether the provided file bytes decode to an SVG root
// element. This catches SVG content even when generic sniffers only classify it
// as text or XML.
func IsSVGContent(data []byte) bool {
	data = bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
	if len(data) == 0 {
		return false
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		return strings.EqualFold(start.Name.Local, "svg")
	}
}

// NormalizeMediaType strips parameters and normalizes text/* media types
// to text/plain so browsers render them safely and consistently.
func NormalizeMediaType(mediaType string) string {
	mediaType = BaseMediaType(mediaType)
	if strings.HasPrefix(mediaType, "text/") {
		return "text/plain"
	}
	return mediaType
}

// IsInlineSafe reports whether files of the given MIME type should be
// rendered inline in the browser rather than downloaded as attachments.
func IsInlineSafe(mediaType string) bool {
	mediaType = NormalizeMediaType(mediaType)
	switch {
	case mediaType == "image/svg+xml":
		return false
	case strings.HasPrefix(mediaType, "image/"):
		return true
	case mediaType == "text/plain":
		return true
	case mediaType == "application/json":
		return true
	case mediaType == "application/pdf":
		return true
	default:
		return false
	}
}
