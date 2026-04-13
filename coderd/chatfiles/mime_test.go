package chatfiles_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/coder/v2/coderd/chatfiles"
)

func TestDetectContentType_WebP(t *testing.T) {
	t.Parallel()

	data := append([]byte("RIFF"), []byte{0x24, 0x00, 0x00, 0x00}...)
	data = append(data, []byte("WEBPVP8 ")...)
	require.Equal(t, "image/webp", chatfiles.DetectContentType(data))
}

func TestBaseMediaType(t *testing.T) {
	t.Parallel()

	require.Equal(t, "text/plain", chatfiles.BaseMediaType("text/plain; charset=utf-8"))
	require.Equal(t, "application/json", chatfiles.BaseMediaType("application/json"))
}

func TestNormalizeMediaType(t *testing.T) {
	t.Parallel()

	require.Equal(t, "text/plain", chatfiles.NormalizeMediaType("text/markdown; charset=utf-8"))
	require.Equal(t, "application/json", chatfiles.NormalizeMediaType("application/json"))
}

func TestIsInlineSafe(t *testing.T) {
	t.Parallel()

	require.True(t, chatfiles.IsInlineSafe("text/markdown"))
	require.True(t, chatfiles.IsInlineSafe("application/json"))
	require.True(t, chatfiles.IsInlineSafe("application/pdf"))
	require.False(t, chatfiles.IsInlineSafe("image/svg+xml"))
	require.False(t, chatfiles.IsInlineSafe("application/zip"))
}

func TestIsSVGContent(t *testing.T) {
	t.Parallel()

	require.True(t, chatfiles.IsSVGContent([]byte("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")))
	require.True(t, chatfiles.IsSVGContent([]byte("\xef\xbb\xbf<svg></svg>")))
	require.False(t, chatfiles.IsSVGContent([]byte("<html><body>not svg</body></html>")))
}
