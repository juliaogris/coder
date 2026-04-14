package chatfiles_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/coder/v2/coderd/chatfiles"
)

func TestDetectMediaType_WebP(t *testing.T) {
	t.Parallel()

	data := append([]byte("RIFF"), []byte{0x24, 0x00, 0x00, 0x00}...)
	data = append(data, []byte("WEBPVP8 ")...)
	require.Equal(t, "image/webp", chatfiles.DetectMediaType(data))
}

func TestBaseMediaType(t *testing.T) {
	t.Parallel()

	require.Equal(t, "text/plain", chatfiles.BaseMediaType("text/plain; charset=utf-8"))
	require.Equal(t, "application/json", chatfiles.BaseMediaType("application/json"))
}

func TestAllowedStoredMediaTypes(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{
		"application/json",
		"application/pdf",
		"image/gif",
		"image/jpeg",
		"image/png",
		"image/webp",
		"text/csv",
		"text/markdown",
		"text/plain",
	}, chatfiles.AllowedStoredMediaTypes())
}

func TestPromptReadableKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mediaType string
		want      string
	}{
		{
			name:      "Text",
			mediaType: "text/plain; charset=utf-8",
			want:      chatfiles.PromptReadableKindText,
		},
		{
			name:      "JSON",
			mediaType: "application/json",
			want:      chatfiles.PromptReadableKindText,
		},
		{
			name:      "Image",
			mediaType: "image/png",
			want:      chatfiles.PromptReadableKindImage,
		},
		{
			name:      "Document",
			mediaType: "application/pdf",
			want:      chatfiles.PromptReadableKindDocument,
		},
		{
			name:      "Unsupported",
			mediaType: "text/html",
			want:      chatfiles.PromptReadableKindUnsupported,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, chatfiles.PromptReadableKind(tt.mediaType))
		})
	}
}

func TestClassifyStoredMediaType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fileName string
		data     []byte
		want     string
	}{
		{
			name:     "PlainText",
			fileName: "build.log",
			data:     []byte("build succeeded\n"),
			want:     "text/plain",
		},
		{
			name:     "MarkdownFromExtension",
			fileName: "notes.md",
			data:     []byte("# Release notes\n"),
			want:     "text/markdown",
		},
		{
			name:     "CSVFromDetector",
			fileName: "report.txt",
			data:     []byte("name,count\nwidgets,3\n"),
			want:     "text/csv",
		},
		{
			name:     "JSONFromDetector",
			fileName: "payload.txt",
			data:     []byte(`{"ok":true}`),
			want:     "application/json",
		},
		{
			name:     "PDF",
			fileName: "report.pdf",
			data:     []byte("%PDF-1.7\n"),
			want:     "application/pdf",
		},
		{
			name:     "HTMLFallsBackToTextPlain",
			fileName: "snippet.txt",
			data:     []byte("<!DOCTYPE html><html><body>hello</body></html>"),
			want:     "text/plain",
		},
		{
			name:     "XMLStaysBlocked",
			fileName: "note.xml",
			data:     []byte(`<?xml version="1.0"?><note><to>Tove</to></note>`),
			want:     "text/xml",
		},
		{
			name:     "SVGBlockedEvenWhenNamedText",
			fileName: "notes.txt",
			data:     []byte(`<svg xmlns="http://www.w3.org/2000/svg"><text>Hello</text></svg>`),
			want:     "image/svg+xml",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, chatfiles.ClassifyStoredMediaType(tt.fileName, tt.data))
		})
	}
}

func TestIsCompatibleUploadMediaType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		declared string
		stored   string
		want     bool
	}{
		{
			name:     "TextPlainMayRefineToJSON",
			declared: "text/plain; charset=utf-8",
			stored:   "application/json",
			want:     true,
		},
		{
			name:     "TextPlainMayRefineToCSV",
			declared: "text/plain",
			stored:   "text/csv",
			want:     true,
		},
		{
			name:     "TextPlainMayNotRefineToPNG",
			declared: "text/plain",
			stored:   "image/png",
			want:     false,
		},
		{
			name:     "JSONMustStillMatchExactly",
			declared: "application/json",
			stored:   "text/plain",
			want:     false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, chatfiles.IsCompatibleUploadMediaType(tt.declared, tt.stored))
		})
	}
}

func TestIsInlineSafe(t *testing.T) {
	t.Parallel()

	require.True(t, chatfiles.IsInlineSafe("text/plain; charset=utf-8"))
	require.True(t, chatfiles.IsInlineSafe("text/markdown"))
	require.True(t, chatfiles.IsInlineSafe("text/csv"))
	require.True(t, chatfiles.IsInlineSafe("application/json"))
	require.True(t, chatfiles.IsInlineSafe("application/pdf"))
	require.True(t, chatfiles.IsInlineSafe("image/png"))
	require.False(t, chatfiles.IsInlineSafe("image/svg+xml"))
	require.False(t, chatfiles.IsInlineSafe("image/avif"))
	require.False(t, chatfiles.IsInlineSafe("application/zip"))
}

func TestHasSVGRootElement(t *testing.T) {
	t.Parallel()

	require.True(t, chatfiles.HasSVGRootElement([]byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`)))
	require.True(t, chatfiles.HasSVGRootElement([]byte("\xef\xbb\xbf<svg></svg>")))
	require.False(t, chatfiles.HasSVGRootElement([]byte("<html><body>not svg</body></html>")))
}
