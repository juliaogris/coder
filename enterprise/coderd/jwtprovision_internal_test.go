package coderd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSynthesizeJWTEmail(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		username string
		issuer   string
		want     string
	}{
		{
			name:     "bare hostname issuer (Teleport)",
			username: "juliaogris",
			issuer:   "julia-coder-iap.devteleport.com",
			want:     "juliaogris@julia-coder-iap.devteleport.com",
		},
		{
			name:     "URL issuer gets narrowed to host",
			username: "alice",
			issuer:   "https://accounts.example.com/",
			want:     "alice@accounts.example.com",
		},
		{
			name:     "empty issuer falls back to reserved TLD",
			username: "bob",
			issuer:   "",
			want:     "bob@" + jwtEmailFallbackDomain,
		},
		{
			name:     "issuer without scheme is used verbatim",
			username: "carol",
			issuer:   "iss.example.test",
			want:     "carol@iss.example.test",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, synthesizeJWTEmail(tc.username, tc.issuer))
		})
	}
}
