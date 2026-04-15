package terraform

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/coder/coder/v2/provisionersdk/proto"
)

func TestProvisionEnv_UserSecrets(t *testing.T) {
	t.Parallel()

	t.Run("EnvSecret", func(t *testing.T) {
		t.Parallel()
		secrets := []*proto.UserSecretValue{
			{EnvName: "MY_TOKEN", Value: []byte("secret-value")},
		}
		env, err := provisionEnv(&proto.Config{}, &proto.Metadata{}, nil, nil, nil, secrets)
		require.NoError(t, err)

		want := "CODER_SECRET_ENV_MY_TOKEN=secret-value"
		assert.Contains(t, env, want)
	})

	t.Run("FileSecret", func(t *testing.T) {
		t.Parallel()
		filePath := "~/.ssh/id_rsa"
		secrets := []*proto.UserSecretValue{
			{FilePath: filePath, Value: []byte("key-data")},
		}
		env, err := provisionEnv(&proto.Config{}, &proto.Metadata{}, nil, nil, nil, secrets)
		require.NoError(t, err)

		hexPath := hex.EncodeToString([]byte(filePath))
		want := "CODER_SECRET_FILE_" + hexPath + "=key-data"
		assert.Contains(t, env, want)
	})

	t.Run("BothEnvAndFile", func(t *testing.T) {
		t.Parallel()
		filePath := "/tmp/secret.txt"
		secrets := []*proto.UserSecretValue{
			{EnvName: "DUAL", FilePath: filePath, Value: []byte("both-value")},
		}
		env, err := provisionEnv(&proto.Config{}, &proto.Metadata{}, nil, nil, nil, secrets)
		require.NoError(t, err)

		wantEnv := "CODER_SECRET_ENV_DUAL=both-value"
		hexPath := hex.EncodeToString([]byte(filePath))
		wantFile := "CODER_SECRET_FILE_" + hexPath + "=both-value"
		assert.Contains(t, env, wantEnv)
		assert.Contains(t, env, wantFile)
	})

	t.Run("NilSecrets", func(t *testing.T) {
		t.Parallel()
		env, err := provisionEnv(&proto.Config{}, &proto.Metadata{}, nil, nil, nil, nil)
		require.NoError(t, err)

		for _, e := range env {
			assert.False(t, strings.HasPrefix(e, "CODER_SECRET_"),
				"unexpected secret env var: %s", e)
		}
	})

	t.Run("EmptyEnvAndFile", func(t *testing.T) {
		t.Parallel()
		secrets := []*proto.UserSecretValue{
			{EnvName: "", FilePath: "", Value: []byte("ignored")},
		}
		env, err := provisionEnv(&proto.Config{}, &proto.Metadata{}, nil, nil, nil, secrets)
		require.NoError(t, err)

		for _, e := range env {
			assert.False(t, strings.HasPrefix(e, "CODER_SECRET_"),
				"unexpected secret env var: %s", e)
		}
	})
}
