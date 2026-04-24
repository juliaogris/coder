package coderd_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/coder/coder/v2/coderd/coderdtest"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/enterprise/coderd/coderdenttest"
	"github.com/coder/serpent"
)

// TestJWTAuth_UsersMe wires the JWT middleware end-to-end and asserts
// that a request carrying only the configured header - no Coder
// session token - is authenticated as the user named in the JWT's
// username claim.
func TestJWTAuth_UsersMe(t *testing.T) {
	t.Parallel()

	const (
		header   = "Teleport-Jwt-Assertion"
		audience = "https://coder.test"
	)

	key, kid := newJWTSigningKey(t)
	jwksURL := startJWKSServer(t, key, kid)

	dv := coderdtest.DeploymentValues(t, func(dv *codersdk.DeploymentValues) {
		dv.JWTAuth.Header = serpent.String(header)
		dv.JWTAuth.JWKSURL = serpent.String(jwksURL)
		dv.JWTAuth.Audience = serpent.String(audience)
		dv.JWTAuth.AllowHTTP = serpent.Bool(true)
	})

	client, firstUser := coderdenttest.New(t, &coderdenttest.Options{
		Options: &coderdtest.Options{
			DeploymentValues: dv,
		},
		LicenseOptions: &coderdenttest.LicenseOptions{AllFeatures: true},
	})

	token := signJWT(t, key, kid, jwt.Claims{
		Subject:  coderdtest.FirstUserParams.Username,
		Issuer:   "https://teleport.test",
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		ID:       "integration-test",
	}, coderdtest.FirstUserParams.Username)

	// Raw HTTP request so the Coder session token that the test client
	// holds does not leak into the call. Only the JWT header is set.
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		client.URL.String()+"/api/v2/users/me", nil,
	)
	require.NoError(t, err)
	req.Header.Set(header, token)

	resp, err := client.HTTPClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "body: %s", body)

	var got codersdk.User
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, coderdtest.FirstUserParams.Username, got.Username)
	require.Equal(t, firstUser.UserID, got.ID)
}

// TestJWTAuth_UsersMe_NoHeader confirms the middleware does not alter
// behavior when the JWT header is absent. The request must reach the
// unauthenticated path and return 401, not fall through to a stale
// prechecked result.
func TestJWTAuth_UsersMe_NoHeader(t *testing.T) {
	t.Parallel()

	const (
		header   = "Teleport-Jwt-Assertion"
		audience = "https://coder.test"
	)

	key, kid := newJWTSigningKey(t)
	jwksURL := startJWKSServer(t, key, kid)

	dv := coderdtest.DeploymentValues(t, func(dv *codersdk.DeploymentValues) {
		dv.JWTAuth.Header = serpent.String(header)
		dv.JWTAuth.JWKSURL = serpent.String(jwksURL)
		dv.JWTAuth.Audience = serpent.String(audience)
		dv.JWTAuth.AllowHTTP = serpent.Bool(true)
	})

	client, _ := coderdenttest.New(t, &coderdenttest.Options{
		Options: &coderdtest.Options{
			DeploymentValues: dv,
		},
		LicenseOptions: &coderdenttest.LicenseOptions{AllFeatures: true},
	})

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		client.URL.String()+"/api/v2/users/me", nil,
	)
	require.NoError(t, err)

	resp, err := client.HTTPClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestJWTAuth_UsersMe_UnknownUser confirms that a valid JWT whose
// username claim does not match any user in the database falls through
// to the normal unauthenticated path.
func TestJWTAuth_UsersMe_UnknownUser(t *testing.T) {
	t.Parallel()

	const (
		header   = "Teleport-Jwt-Assertion"
		audience = "https://coder.test"
	)

	key, kid := newJWTSigningKey(t)
	jwksURL := startJWKSServer(t, key, kid)

	dv := coderdtest.DeploymentValues(t, func(dv *codersdk.DeploymentValues) {
		dv.JWTAuth.Header = serpent.String(header)
		dv.JWTAuth.JWKSURL = serpent.String(jwksURL)
		dv.JWTAuth.Audience = serpent.String(audience)
		dv.JWTAuth.AllowHTTP = serpent.Bool(true)
	})

	client, _ := coderdenttest.New(t, &coderdenttest.Options{
		Options: &coderdtest.Options{
			DeploymentValues: dv,
		},
		LicenseOptions: &coderdenttest.LicenseOptions{AllFeatures: true},
	})

	token := signJWT(t, key, kid, jwt.Claims{
		Subject:  "nobody",
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		ID:       "unknown-user",
	}, "nobody")

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		client.URL.String()+"/api/v2/users/me", nil,
	)
	require.NoError(t, err)
	req.Header.Set(header, token)

	resp, err := client.HTTPClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestJWTAuth_UsersMe_BadSignature signs a JWT with a private key that
// does not match the key published by the JWKS, so the middleware must
// reject it and the request must receive a normal 401, never a 200.
// Without this, a wiring regression that seeded the prechecked result
// before signature verification would slip past unit tests.
func TestJWTAuth_UsersMe_BadSignature(t *testing.T) {
	t.Parallel()

	const (
		header   = "Teleport-Jwt-Assertion"
		audience = "https://coder.test"
	)

	goodKey, kid := newJWTSigningKey(t)
	jwksURL := startJWKSServer(t, goodKey, kid)

	// Sign with a different key but advertise the same kid.
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	dv := coderdtest.DeploymentValues(t, func(dv *codersdk.DeploymentValues) {
		dv.JWTAuth.Header = serpent.String(header)
		dv.JWTAuth.JWKSURL = serpent.String(jwksURL)
		dv.JWTAuth.Audience = serpent.String(audience)
		dv.JWTAuth.AllowHTTP = serpent.Bool(true)
	})

	client, _ := coderdenttest.New(t, &coderdenttest.Options{
		Options: &coderdtest.Options{
			DeploymentValues: dv,
		},
		LicenseOptions: &coderdenttest.LicenseOptions{AllFeatures: true},
	})

	token := signJWT(t, attackerKey, kid, jwt.Claims{
		Subject:  coderdtest.FirstUserParams.Username,
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		ID:       "bad-sig",
	}, coderdtest.FirstUserParams.Username)

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet,
		client.URL.String()+"/api/v2/users/me", nil,
	)
	require.NoError(t, err)
	req.Header.Set(header, token)

	resp, err := client.HTTPClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a JWT signed by an untrusted key must not authenticate")
}

// ---- Test helpers ----

func newJWTSigningKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key, "jwtauth-integration"
}

func startJWKSServer(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	keys := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, base jwt.Claims, username string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	require.NoError(t, err)

	type claims struct {
		jwt.Claims
		Username string `json:"username"`
	}
	payload, err := json.Marshal(claims{Claims: base, Username: username})
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)
	out, err := signed.CompactSerialize()
	require.NoError(t, err)
	return out
}

