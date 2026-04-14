package chatfiles

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"mime"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

const (
	PromptReadableKindUnsupported = "unsupported"
	PromptReadableKindText        = "text"
	PromptReadableKindImage       = "image"
	PromptReadableKindDocument    = "document"
)

type mediaTypePolicy struct {
	allowStorage       bool
	inlineSafe         bool
	promptReadableKind string
}

var (
	utf8BOM = []byte{0xEF, 0xBB, 0xBF}

	mediaTypePolicies = map[string]mediaTypePolicy{
		"image/png": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindImage,
		},
		"image/jpeg": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindImage,
		},
		"image/gif": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindImage,
		},
		"image/webp": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindImage,
		},
		"text/plain": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindText,
		},
		"text/markdown": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindText,
		},
		"text/csv": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindText,
		},
		"application/json": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindText,
		},
		"application/pdf": {
			allowStorage:       true,
			inlineSafe:         true,
			promptReadableKind: PromptReadableKindDocument,
		},
	}
)

// DetectMediaType detects the base media type of the given file contents.
func DetectMediaType(data []byte) string {
	return BaseMediaType(mimetype.Detect(data).String())
}

// BaseMediaType strips parameters from a media type.
func BaseMediaType(mediaType string) string {
	if parsed, _, err := mime.ParseMediaType(mediaType); err == nil {
		return parsed
	}
	return mediaType
}

// AllowedStoredMediaTypes returns the supported durable chat file media types.
func AllowedStoredMediaTypes() []string {
	types := make([]string, 0, len(mediaTypePolicies))
	for mediaType, policy := range mediaTypePolicies {
		if !policy.allowStorage {
			continue
		}
		types = append(types, mediaType)
	}
	slices.Sort(types)
	return types
}

// AllowedStoredMediaTypesString returns the supported durable chat file media
// types as a comma-separated list.
func AllowedStoredMediaTypesString() string {
	return strings.Join(AllowedStoredMediaTypes(), ", ")
}

// IsAllowedStoredMediaType reports whether the media type is supported for
// durable chat file storage.
func IsAllowedStoredMediaType(mediaType string) bool {
	policy, ok := mediaTypePolicies[BaseMediaType(mediaType)]
	return ok && policy.allowStorage
}

// PromptReadableKind reports how the stored media type should be surfaced to a
// model prompt.
func PromptReadableKind(mediaType string) string {
	policy, ok := mediaTypePolicies[BaseMediaType(mediaType)]
	if !ok {
		return PromptReadableKindUnsupported
	}
	return policy.promptReadableKind
}

// IsCompatibleUploadMediaType reports whether an upload request that declared
// declaredMediaType may be stored as storedMediaType after byte classification.
// Exact matches are always compatible; the compatibility table only covers
// explicit refinements like text/plain uploads that safely store as richer text
// subtypes.
func IsCompatibleUploadMediaType(declaredMediaType, storedMediaType string) bool {
	declaredMediaType = BaseMediaType(declaredMediaType)
	storedMediaType = BaseMediaType(storedMediaType)
	if declaredMediaType == storedMediaType {
		return true
	}
	if declaredMediaType != "text/plain" {
		return false
	}
	return PromptReadableKind(storedMediaType) == PromptReadableKindText
}

// HasSVGRootElement reports whether the provided file bytes decode to an SVG
// root element. This catches SVG content even when generic sniffers classify it
// as text or XML.
func HasSVGRootElement(data []byte) bool {
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

// ClassifyStoredMediaType returns the media type that durable chat storage
// would use for the given filename and bytes. Unsupported or blocked content is
// returned as its detected media type so callers can report the specific type.
func ClassifyStoredMediaType(name string, data []byte) string {
	if HasSVGRootElement(data) {
		return "image/svg+xml"
	}

	mediaType := DetectMediaType(data)
	switch mediaType {
	case "image/png", "image/jpeg", "image/gif", "image/webp",
		"text/markdown", "text/csv", "application/json",
		"application/pdf", "application/xml", "text/xml":
		return mediaType
	case "text/plain":
		return refineTextMediaType(name, data)
	default:
		if strings.HasPrefix(mediaType, "text/") {
			return "text/plain"
		}
		return mediaType
	}
}

func refineTextMediaType(name string, data []byte) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		if json.Valid(data) {
			return "application/json"
		}
	case ".md", ".markdown":
		return "text/markdown"
	case ".csv":
		return "text/csv"
	}
	return "text/plain"
}

// IsInlineSafe reports whether files of the given media type should be rendered
// inline in the browser rather than downloaded as attachments.
func IsInlineSafe(mediaType string) bool {
	policy, ok := mediaTypePolicies[BaseMediaType(mediaType)]
	return ok && policy.inlineSafe
}
