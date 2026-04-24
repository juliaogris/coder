package httpmw

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"cdr.dev/slog/v3"
	"cdr.dev/slog/v3/sloggers/slogtest"
	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/database/dbgen"
	"github.com/coder/coder/v2/coderd/database/dbmock"
	"github.com/coder/coder/v2/coderd/database/dbtestutil"
	agplhttpmw "github.com/coder/coder/v2/coderd/httpmw"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/testutil"
	"github.com/coder/quartz"
)

const (
	testAudience = "https://coder.t.tp"
	testHeader   = "Teleport-Jwt-Assertion"
	testUsername = "julia"
)

type fixture struct {
	t *testing.T

	signingKeyID string
	signingKey   *rsa.PrivateKey

	jwksServer  *httptest.Server
	jwksFetches *atomic.Int64
	// jwksKeys holds the JWKS payload as a mutable pointer so tests
	// can rotate the key between requests without restarting the
	// server.
	jwksKeys *atomic.Value // *jose.JSONWebKeySet
	// jwksBody lets a test override the raw body served at /.well-known/jwks.json
	// (for oversize and malformed-response cases).
	jwksBody *atomic.Value // []byte
	// jwksStatus lets a test force a non-200 response.
	jwksStatus *atomic.Int32

	clock *quartz.Mock
	db    database.Store
	opts  Options
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, kid := genRSAKey(t)

	var (
		fetches atomic.Int64
		keys    atomic.Value
		body    atomic.Value
		status  atomic.Int32
	)
	keys.Store(jwksFromKey(key, kid))
	body.Store([]byte(nil))
	status.Store(int32(http.StatusOK))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if s := status.Load(); s != http.StatusOK {
			w.WriteHeader(int(s))
			return
		}
		if b, _ := body.Load().([]byte); len(b) > 0 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
			return
		}
		current, _ := keys.Load().(*jose.JSONWebKeySet)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(current)
	}))
	t.Cleanup(srv.Close)

	clock := quartz.NewMock(t)
	clock.Set(time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC))

	db, _ := dbtestutil.NewDB(t)

	f := &fixture{
		t:            t,
		signingKeyID: kid,
		signingKey:   key,
		jwksServer:   srv,
		jwksFetches:  &fetches,
		jwksKeys:     &keys,
		jwksBody:     &body,
		jwksStatus:   &status,
		clock:        clock,
		db:           db,
		opts: Options{
			Logger:    slogtest.Make(t, nil).Leveled(slog.LevelDebug),
			Header:    testHeader,
			JWKSURL:   srv.URL,
			Audience:  testAudience,
			AllowHTTP: true,
			Database:  db,
			Clock:     clock,
		},
	}
	return f
}

// auth constructs the internal jwtAuth directly so tests can exercise
// unexported methods without going through the HTTP middleware path.
func (f *fixture) auth() *jwtAuth {
	return &jwtAuth{
		logger:   f.opts.Logger,
		header:   f.opts.Header,
		audience: f.opts.Audience,
		db:       f.db,
		clock:    f.clock,
		jwks: &jwksClient{
			url:        f.opts.JWKSURL,
			httpClient: http.DefaultClient,
			clock:      f.clock,
			unknownKid: make(map[string]time.Time),
		},
	}
}

// authWithDB lets tests substitute a custom database.Store (usually a
// dbmock) to drive error paths without touching a live Postgres.
func (f *fixture) authWithDB(db database.Store) *jwtAuth {
	a := f.auth()
	a.db = db
	return a
}

// sign returns a JWT signed by the fixture's current key with the
// given claims merged on top of sensible defaults.
func (f *fixture) sign(overrides jwtClaims) string {
	f.t.Helper()
	return f.signWithKey(f.signingKeyID, f.signingKey, overrides)
}

func (f *fixture) signWithKey(kid string, key *rsa.PrivateKey, overrides jwtClaims) string {
	f.t.Helper()
	now := f.clock.Now()
	c := jwtClaims{
		Claims: jwt.Claims{
			Subject:   testUsername,
			Issuer:    "https://teleport.t.tp",
			Audience:  jwt.Audience{testAudience},
			NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)),
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "jti-" + kid,
		},
		Username: testUsername,
	}
	// Apply overrides on non-zero fields.
	if overrides.Subject != "" {
		c.Subject = overrides.Subject
	}
	if overrides.Issuer != "" {
		c.Issuer = overrides.Issuer
	}
	if len(overrides.Audience) > 0 {
		c.Audience = overrides.Audience
	}
	if overrides.NotBefore != nil {
		c.NotBefore = overrides.NotBefore
	}
	if overrides.Expiry != nil {
		c.Expiry = overrides.Expiry
	}
	if overrides.IssuedAt != nil {
		c.IssuedAt = overrides.IssuedAt
	}
	if overrides.ID != "" {
		c.ID = overrides.ID
	}
	if overrides.Username != "" {
		c.Username = overrides.Username
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	require.NoError(f.t, err)
	payload, err := json.Marshal(c)
	require.NoError(f.t, err)
	signed, err := signer.Sign(payload)
	require.NoError(f.t, err)
	token, err := signed.CompactSerialize()
	require.NoError(f.t, err)
	return token
}

func (f *fixture) rotateKey() {
	f.t.Helper()
	newKey, newKID := genRSAKey(f.t)
	f.signingKey = newKey
	f.signingKeyID = newKID
	f.jwksKeys.Store(jwksFromKey(newKey, newKID))
}

func genRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	// Short random kid; the full hex would be noise in log output.
	var kidBytes [8]byte
	_, err = rand.Read(kidBytes[:])
	require.NoError(t, err)
	return key, hex.EncodeToString(kidBytes[:])
}

func base64URL(t *testing.T, b []byte) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(b)
}

func marshalClaims(t *testing.T, c jwtClaims) []byte {
	t.Helper()
	b, err := json.Marshal(c)
	require.NoError(t, err)
	return b
}

func jwksFromKey(key *rsa.PrivateKey, kid string) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &key.PublicKey,
				KeyID:     kid,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
		},
	}
}

func TestNew_UnconfiguredReturnsNoOp(t *testing.T) {
	t.Parallel()

	mw := New(Options{Logger: slogtest.Make(t, nil)})
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Teleport-Jwt-Assertion", "anything")
	h.ServeHTTP(httptest.NewRecorder(), req)
	require.True(t, called, "no-op middleware must still call next")
}

// TestNew_RequiresAllFields pins the activation check: the middleware
// must be a no-op when any of Header, JWKSURL, Audience, or Database
// is missing. Without this, a refactor that removes one of the four
// checks would pass CI; the non-table-driven siblings only cover
// "everything empty" and "missing Database".
func TestNew_RequiresAllFields(t *testing.T) {
	t.Parallel()

	db, _ := dbtestutil.NewDB(t)
	full := Options{
		Logger:   slogtest.Make(t, nil),
		Header:   testHeader,
		JWKSURL:  "https://example.com/jwks",
		Audience: testAudience,
		Database: db,
	}

	cases := []struct {
		name string
		mut  func(*Options)
	}{
		{"MissingHeader", func(o *Options) { o.Header = "" }},
		{"MissingJWKSURL", func(o *Options) { o.JWKSURL = "" }},
		{"MissingAudience", func(o *Options) { o.Audience = "" }},
		{"MissingDatabase", func(o *Options) { o.Database = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := full
			tc.mut(&opts)

			mw := New(opts)
			called := false
			h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(testHeader, "anything")
			h.ServeHTTP(httptest.NewRecorder(), req)
			require.True(t, called, "no-op middleware must call next")
		})
	}
}

func TestNew_RejectsHTTPURLWhenNotAllowed(t *testing.T) {
	t.Parallel()

	db, _ := dbtestutil.NewDB(t)
	mw := New(Options{
		Logger:   slogtest.Make(t, &slogtest.Options{IgnoreErrors: true}),
		Header:   testHeader,
		JWKSURL:  "http://example.com/jwks",
		Audience: testAudience,
		Database: db,
	})
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, "anything")
	h.ServeHTTP(httptest.NewRecorder(), req)
	require.True(t, called, "invalid scheme should disable middleware but still call next")
}

func TestNew_MissingDatabaseReturnsNoOp(t *testing.T) {
	t.Parallel()

	mw := New(Options{
		Logger:   slogtest.Make(t, nil),
		Header:   testHeader,
		JWKSURL:  "https://example.com/jwks",
		Audience: testAudience,
	})
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, "anything")
	h.ServeHTTP(httptest.NewRecorder(), req)
	require.True(t, called, "missing Database must disable middleware but still call next")
}

func TestMiddleware_HeaderMissing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	mw := New(f.opts)
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, called)
	require.Zero(t, f.jwksFetches.Load(), "absent header must not trigger a JWKS fetch")
}

// TestMiddleware_ValidJWTTriggersJWKSFetch asserts that a syntactically
// valid JWT whose username does not resolve to a DB user reaches the
// JWKS fetch path exactly once. The "next handler still runs" property
// is covered by the no-header and unconfigured tests; the unique thing
// here is the fetch count.
func TestMiddleware_ValidJWTTriggersJWKSFetch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	token := f.sign(jwtClaims{})
	mw := New(f.opts)
	called := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	h.ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, called)
	require.EqualValues(t, 1, f.jwksFetches.Load())
}

func TestVerify_BadFormat(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	_, err := f.auth().verify(ctx, "not-a-jwt")
	require.Error(t, err)
	require.ErrorIs(t, err, errJWTParse)
}

func TestVerify_BadSignature(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	// Sign with a different key but the same kid the fixture uses.
	wrongKey, _ := genRSAKey(t)
	token := f.signWithKey(f.signingKeyID, wrongKey, jwtClaims{})

	_, err := f.auth().verify(ctx, token)
	require.Error(t, err)
	require.ErrorIs(t, err, errJWTSignature)
}

// TestVerify_RejectsHS256 pins the algorithm allowlist against the
// classic HMAC-confusion attack: sign a token with HS256 using the
// RSA public key bytes as the shared secret, and confirm the
// middleware rejects it at parse time before any key lookup happens.
func TestVerify_RejectsHS256(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	// Any byte string works as an HS256 secret; using the RSA public
	// key's modulus bytes is the canonical "HMAC confusion" shape.
	secret := f.signingKey.PublicKey.N.Bytes()

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       secret,
	}, (&jose.SignerOptions{}).WithHeader("kid", f.signingKeyID))
	require.NoError(t, err)
	payload, err := json.Marshal(jwtClaims{
		Claims: jwt.Claims{
			Audience: jwt.Audience{testAudience},
			Expiry:   jwt.NewNumericDate(f.clock.Now().Add(5 * time.Minute)),
			IssuedAt: jwt.NewNumericDate(f.clock.Now()),
		},
		Username: testUsername,
	})
	require.NoError(t, err)
	signed, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := signed.CompactSerialize()
	require.NoError(t, err)

	_, err = f.auth().verify(ctx, token)
	require.ErrorIs(t, err, errJWTParse,
		"HS256 must be rejected by ParseSigned before key lookup")
}

// TestVerify_RejectsAlgNone pins the allowlist against unsigned tokens.
// A token with alg: none has no signature, so any party can fabricate
// one that otherwise looks well-formed.
func TestVerify_RejectsAlgNone(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	// Hand-build a JWS with alg: none and an empty signature segment.
	header := base64URL(t, []byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64URL(t, marshalClaims(t, jwtClaims{
		Claims: jwt.Claims{
			Audience: jwt.Audience{testAudience},
			Expiry:   jwt.NewNumericDate(f.clock.Now().Add(5 * time.Minute)),
			IssuedAt: jwt.NewNumericDate(f.clock.Now()),
		},
		Username: testUsername,
	}))
	token := header + "." + payload + "."

	_, err := f.auth().verify(ctx, token)
	require.ErrorIs(t, err, errJWTParse,
		"alg: none must be rejected by ParseSigned")
}

func TestVerify_Expired(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	token := f.sign(jwtClaims{
		Claims: jwt.Claims{
			Expiry: jwt.NewNumericDate(f.clock.Now().Add(-1 * time.Hour)),
		},
	})

	_, err := f.auth().verify(ctx, token)
	require.Error(t, err)
	require.ErrorIs(t, err, errJWTExpired)
}

func TestVerify_NotYetValid(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	token := f.sign(jwtClaims{
		Claims: jwt.Claims{
			NotBefore: jwt.NewNumericDate(f.clock.Now().Add(1 * time.Hour)),
			Expiry:    jwt.NewNumericDate(f.clock.Now().Add(2 * time.Hour)),
		},
	})

	_, err := f.auth().verify(ctx, token)
	require.Error(t, err)
	require.ErrorIs(t, err, errJWTNotYet)
}

func TestVerify_ClockSkewExpBoundary(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	auth := f.auth()

	// exp = now-29s passes (within 30s leeway).
	tokenInside := f.sign(jwtClaims{
		Claims: jwt.Claims{Expiry: jwt.NewNumericDate(f.clock.Now().Add(-29 * time.Second))},
	})
	_, err := auth.verify(ctx, tokenInside)
	require.NoError(t, err)

	// exp = now-31s fails.
	tokenOutside := f.sign(jwtClaims{
		Claims: jwt.Claims{Expiry: jwt.NewNumericDate(f.clock.Now().Add(-31 * time.Second))},
	})
	_, err = auth.verify(ctx, tokenOutside)
	require.ErrorIs(t, err, errJWTExpired)
}

func TestVerify_ClockSkewNbfBoundary(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	auth := f.auth()

	// nbf = now+29s passes.
	tokenInside := f.sign(jwtClaims{
		Claims: jwt.Claims{
			NotBefore: jwt.NewNumericDate(f.clock.Now().Add(29 * time.Second)),
			Expiry:    jwt.NewNumericDate(f.clock.Now().Add(1 * time.Hour)),
		},
	})
	_, err := auth.verify(ctx, tokenInside)
	require.NoError(t, err)

	// nbf = now+31s fails.
	tokenOutside := f.sign(jwtClaims{
		Claims: jwt.Claims{
			NotBefore: jwt.NewNumericDate(f.clock.Now().Add(31 * time.Second)),
			Expiry:    jwt.NewNumericDate(f.clock.Now().Add(1 * time.Hour)),
		},
	})
	_, err = auth.verify(ctx, tokenOutside)
	require.ErrorIs(t, err, errJWTNotYet)
}

func TestVerify_IssuerMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	// Configure a fixed issuer and then sign a token whose iss claim
	// does not match. The issuer field defaults to empty, which means
	// "accept any", so tests that do not care about this path are
	// unaffected.
	auth := f.auth()
	auth.issuer = "https://teleport.t.tp"

	token := f.sign(jwtClaims{
		Claims: jwt.Claims{Issuer: "https://evil.example.com"},
	})
	_, err := auth.verify(ctx, token)
	require.ErrorIs(t, err, errJWTIssuer)
}

func TestVerify_IssuerMatches(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	auth := f.auth()
	auth.issuer = "https://teleport.t.tp"

	token := f.sign(jwtClaims{}) // default issuer is https://teleport.t.tp
	_, err := auth.verify(ctx, token)
	require.NoError(t, err)
}

func TestVerify_IssuerUncheckedWhenEmpty(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	// Default fixture has no issuer set; any iss claim passes.
	token := f.sign(jwtClaims{
		Claims: jwt.Claims{Issuer: "https://whatever.example.com"},
	})
	_, err := f.auth().verify(ctx, token)
	require.NoError(t, err)
}

func TestVerify_AudienceMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	token := f.sign(jwtClaims{
		Claims: jwt.Claims{Audience: jwt.Audience{"https://grafana.t.tp"}},
	})

	_, err := f.auth().verify(ctx, token)
	require.ErrorIs(t, err, errJWTAudience)
}

func TestVerify_Success(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	token := f.sign(jwtClaims{Username: "alice"})
	claims, err := f.auth().verify(ctx, token)
	require.NoError(t, err)
	require.Equal(t, "alice", claims.Username)
	require.Equal(t, jwt.Audience{testAudience}, claims.Audience)
}

func TestJWKS_CacheHit(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	auth := f.auth()
	for range 5 {
		token := f.sign(jwtClaims{})
		_, err := auth.verify(ctx, token)
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, f.jwksFetches.Load(), "5 verifies should share a single cached JWKS")
}

func TestJWKS_CacheTTLExpires(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	auth := f.auth()

	token := f.sign(jwtClaims{})
	_, err := auth.verify(ctx, token)
	require.NoError(t, err)
	require.EqualValues(t, 1, f.jwksFetches.Load())

	// Advance past the 5 minute TTL.
	f.clock.Advance(6 * time.Minute).MustWait(ctx)

	// Resign under the new clock so exp is still in the future.
	token2 := f.sign(jwtClaims{})
	_, err = auth.verify(ctx, token2)
	require.NoError(t, err)
	require.EqualValues(t, 2, f.jwksFetches.Load(), "expired cache should trigger a second fetch")
}

func TestJWKS_KeyRotation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	auth := f.auth()

	// Prime the cache with the original key.
	_, err := auth.verify(ctx, f.sign(jwtClaims{}))
	require.NoError(t, err)
	require.EqualValues(t, 1, f.jwksFetches.Load())

	// Rotate: the server now serves a new public key with a new kid.
	f.rotateKey()

	// Token signed with the new key should trigger a forced refresh
	// and then succeed.
	token := f.sign(jwtClaims{})
	_, err = auth.verify(ctx, token)
	require.NoError(t, err)
	require.EqualValues(t, 2, f.jwksFetches.Load(), "unknown kid must force a second fetch")
}

func TestJWKS_FetchError(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	f.jwksStatus.Store(int32(http.StatusInternalServerError))

	_, err := f.auth().verify(ctx, f.sign(jwtClaims{}))
	require.Error(t, err)
	require.ErrorIs(t, err, errJWKSFetch)
}

func TestJWKS_OversizeBody(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	// Serve a body > 1 MB. The payload is not valid JSON but that
	// does not matter; the size check runs before json.Unmarshal.
	oversized := make([]byte, jwksMaxBodyBytes+1)
	for i := range oversized {
		oversized[i] = 'x'
	}
	f.jwksBody.Store(oversized)

	_, err := f.auth().verify(ctx, f.sign(jwtClaims{}))
	require.Error(t, err)
	require.ErrorIs(t, err, errJWKSFetch)
	require.Contains(t, err.Error(), "exceeds")
}

func TestRedactToken(t *testing.T) {
	t.Parallel()

	require.Equal(t, "<invalid>", redactToken("one"))
	require.Equal(t, "<invalid>", redactToken("header.payload"))
	redacted := redactToken("header.payload.signature")
	require.Equal(t, "header.payload.<redacted>", redacted)
	require.False(t, strings.Contains(redacted, "signature"))
}

// TestErrorsJoinMatchesSentinels pins the failure-mode dispatch in
// logVerifyError to the contract of errors.Join: each sentinel must
// still be reachable via errors.Is after being joined with an
// underlying error.
func TestErrorsJoinMatchesSentinels(t *testing.T) {
	t.Parallel()

	joined := errors.Join(errJWTParse, errors.New("underlying"))
	require.ErrorIs(t, joined, errJWTParse)
}

func TestApiKeyIDFromJTI(t *testing.T) {
	t.Parallel()

	require.Len(t, apiKeyIDFromJTI("abc"), 10)
	require.Equal(t, "abc0000000", apiKeyIDFromJTI("abc"))
	require.Equal(t, "0123456789", apiKeyIDFromJTI("0123456789abcdef"))
	require.Equal(t, "0000000000", apiKeyIDFromJTI(""))
}

// captureContext returns a handler and a pointer that will hold the
// request.Context at the moment next is called. The prechecked API key
// is stored under a private key in coderd/httpmw, so the test reads it
// indirectly through the same package's accessor.
func captureContext() (http.Handler, *context.Context) {
	var captured context.Context
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r.Context()
	})
	return h, &captured
}

func TestMiddleware_UserFound_Active(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	user := dbgen.User(f.t, f.db, database.User{
		Username: testUsername,
		Status:   database.UserStatusActive,
	})

	token := f.sign(jwtClaims{Username: testUsername})
	handler, captured := captureContext()
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, *captured, "next must have been called")
	pc, ok := agplhttpmw.APIKeyPrecheckedFromContext(*captured)
	require.True(t, ok, "prechecked result must be set on context")
	require.Nil(t, pc.Err, "prechecked error must be nil on success")
	require.NotNil(t, pc.Result)
	require.Equal(t, user.ID, pc.Result.Key.UserID)
	require.Equal(t, user.Status, pc.Result.UserStatus)
	require.Equal(t, database.LoginTypeToken, pc.Result.Key.LoginType)
	require.Equal(t, database.APIKeyScopes{database.ApiKeyScopeCoderAll}, pc.Result.Key.Scopes)
	require.Equal(t, user.ID.String(), pc.Result.Subject.ID)
}

func TestMiddleware_UserFound_Suspended(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	dbgen.User(f.t, f.db, database.User{
		Username: testUsername,
		Status:   database.UserStatusSuspended,
	})

	token := f.sign(jwtClaims{Username: testUsername})
	handler, captured := captureContext()
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, *captured)
	_, ok := agplhttpmw.APIKeyPrecheckedFromContext(*captured)
	require.False(t, ok, "suspended users must not populate a prechecked result")
}

func TestMiddleware_UserFound_Dormant(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	dbgen.User(f.t, f.db, database.User{
		Username: testUsername,
		Status:   database.UserStatusDormant,
	})

	token := f.sign(jwtClaims{Username: testUsername})
	handler, captured := captureContext()
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, *captured)
	_, ok := agplhttpmw.APIKeyPrecheckedFromContext(*captured)
	require.False(t, ok, "dormant users must not populate a prechecked result")
}

func TestMiddleware_UserNotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// No user created in the DB.
	token := f.sign(jwtClaims{Username: "ghost"})
	handler, captured := captureContext()
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, *captured)
	_, ok := agplhttpmw.APIKeyPrecheckedFromContext(*captured)
	require.False(t, ok, "unknown user must not populate a prechecked result")
}

// TestMiddleware_EmailColumnCollision confirms the middleware looks up
// users by the username column only. If the JWT carried a string that
// matches an email column belonging to a different user, that other
// user must not be returned.
func TestMiddleware_EmailColumnCollision(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Alice owns alice@example.com.
	dbgen.User(f.t, f.db, database.User{
		Username: "alice",
		Email:    "alice@example.com",
		Status:   database.UserStatusActive,
	})

	// JWT carries alice@example.com as the username. Since there is no
	// user whose username is alice@example.com, the lookup must miss.
	token := f.sign(jwtClaims{Username: "alice@example.com"})
	handler, captured := captureContext()
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, *captured)
	_, ok := agplhttpmw.APIKeyPrecheckedFromContext(*captured)
	require.False(t, ok, "username lookup must not fall back to the email column")
}

func TestMiddleware_DBLookupError(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctrl := gomock.NewController(t)
	mock := dbmock.NewMockStore(ctrl)
	mock.EXPECT().
		GetUserByEmailOrUsername(gomock.Any(), gomock.Any()).
		Return(database.User{}, errors.New("boom"))

	auth := f.authWithDB(mock)

	token := f.sign(jwtClaims{Username: testUsername})
	ctx := testutil.Context(t, testutil.WaitShort)
	claims, err := auth.verify(ctx, token)
	require.NoError(t, err)

	_, ok := auth.setPrecheckedResult(ctx, claims)
	require.False(t, ok, "db error must not produce a prechecked result")
}

// TestMiddleware_RBACSubjectError pins the error path where the user
// lookup succeeds but the RBAC subject build fails. Without this,
// a regression that attached a prechecked result anyway would grant
// unauthenticated access to an unauthorized user.
func TestMiddleware_RBACSubjectError(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	ctrl := gomock.NewController(t)
	mock := dbmock.NewMockStore(ctrl)
	mock.EXPECT().
		GetUserByEmailOrUsername(gomock.Any(), gomock.Any()).
		Return(database.User{
			Username: testUsername,
			Status:   database.UserStatusActive,
		}, nil)
	mock.EXPECT().
		GetAuthorizationUserRoles(gomock.Any(), gomock.Any()).
		Return(database.GetAuthorizationUserRolesRow{}, errors.New("roles lookup failed"))

	auth := f.authWithDB(mock)
	// The middleware logs at Error when the RBAC subject build fails;
	// that is the expected behaviour here, so the test logger should
	// not treat it as a test failure.
	auth.logger = slogtest.Make(t, &slogtest.Options{IgnoreErrors: true}).Leveled(slog.LevelDebug)

	token := f.sign(jwtClaims{Username: testUsername})
	ctx := testutil.Context(t, testutil.WaitShort)
	claims, err := auth.verify(ctx, token)
	require.NoError(t, err)

	_, ok := auth.setPrecheckedResult(ctx, claims)
	require.False(t, ok, "rbac subject error must not produce a prechecked result")
}

func TestMiddleware_JTIDerivedID(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	dbgen.User(f.t, f.db, database.User{
		Username: testUsername,
		Status:   database.UserStatusActive,
	})

	longJTI := "abcdef0123456789deadbeef"
	token := f.sign(jwtClaims{
		Claims:   jwt.Claims{ID: longJTI},
		Username: testUsername,
	})
	handler, captured := captureContext()
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	mw(handler).ServeHTTP(httptest.NewRecorder(), req)

	pc, ok := agplhttpmw.APIKeyPrecheckedFromContext(*captured)
	require.True(t, ok)
	require.Equal(t, longJTI[:10], pc.Result.Key.ID)
}

func TestMiddleware_StripsSessionToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	dbgen.User(f.t, f.db, database.User{
		Username: testUsername,
		Status:   database.UserStatusActive,
	})

	token := f.sign(jwtClaims{Username: testUsername})

	// Capture what the downstream handler actually sees. The full set
	// of token inputs matches APITokenFromRequest so that handlers
	// which call it directly (workspace-app issuance, debug, mcp_http)
	// cannot see a caller identity that diverges from the JWT.
	var (
		seenHeader      string
		seenCookie      string
		seenQuery       string
		seenAuth        string
		seenAccessToken string
	)
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get(codersdk.SessionTokenHeader)
		if c, err := r.Cookie(codersdk.SessionTokenCookie); err == nil {
			seenCookie = c.Value
		}
		seenQuery = r.URL.Query().Get(codersdk.SessionTokenCookie)
		seenAuth = r.Header.Get("Authorization")
		seenAccessToken = r.URL.Query().Get("access_token")
	})
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet,
		"/?"+codersdk.SessionTokenCookie+"=stale-query&access_token=stale-access&keep=me", nil)
	req.Header.Set(testHeader, token)
	req.Header.Set(codersdk.SessionTokenHeader, "stale-header")
	req.Header.Set("Authorization", "Bearer stale-bearer")
	req.AddCookie(&http.Cookie{Name: codersdk.SessionTokenCookie, Value: "stale-cookie"})
	req.AddCookie(&http.Cookie{Name: "other", Value: "keep-me"})

	mw(next).ServeHTTP(httptest.NewRecorder(), req)

	require.Empty(t, seenHeader, "session-token header must be stripped")
	require.Empty(t, seenCookie, "session-token cookie must be stripped")
	require.Empty(t, seenQuery, "session-token query parameter must be stripped")
	require.Empty(t, seenAuth, "Authorization: Bearer credential must be stripped")
	require.Empty(t, seenAccessToken, "access_token query parameter must be stripped")

	// Other cookies and unrelated query parameters must survive.
	other, err := req.Cookie("other")
	require.NoError(t, err)
	require.Equal(t, "keep-me", other.Value)
	require.Equal(t, "me", req.URL.Query().Get("keep"))
}

// TestStripSessionToken_PreservesNonBearerAuthorization confirms the
// middleware only drops the Bearer variant of an Authorization header.
// Other schemes are not treated as session tokens by
// APITokenFromRequest, so leaving them in place is correct.
func TestStripSessionToken_PreservesNonBearerAuthorization(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	stripSessionToken(req)

	require.Equal(t, "Basic dXNlcjpwYXNz", req.Header.Get("Authorization"))
}

func TestMiddleware_DoesNotStripSessionOnJWTFailure(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// A signature failure happens before any DB lookup, so the
	// downstream chain must see the caller's original session token
	// and get a chance to authenticate normally.
	wrongKey, _ := genRSAKey(t)
	token := f.signWithKey(f.signingKeyID, wrongKey, jwtClaims{})

	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get(codersdk.SessionTokenHeader)
	})
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	req.Header.Set(codersdk.SessionTokenHeader, "keep-me")

	mw(next).ServeHTTP(httptest.NewRecorder(), req)

	require.Equal(t, "keep-me", seen, "JWT failure must not strip the session token")
}

// TestMiddleware_SystemUserImpersonation pins the system-user guard in
// setPrecheckedResult. Migration 000308_system_user inserts an active
// user named "prebuilds" with is_system=true, and
// GetUserByEmailOrUsername does not filter on that column, so without
// the guard an IdP misconfiguration that minted a JWT for that
// username would install an APIKeyPrechecked under the prebuilds
// system account's RBAC subject.
func TestMiddleware_SystemUserImpersonation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	const sysUsername = "prebuilds-like"

	ctrl := gomock.NewController(t)
	mock := dbmock.NewMockStore(ctrl)
	mock.EXPECT().
		GetUserByEmailOrUsername(gomock.Any(), gomock.Any()).
		Return(database.User{
			Username: sysUsername,
			Status:   database.UserStatusActive,
			IsSystem: true,
		}, nil)

	auth := f.authWithDB(mock)

	token := f.sign(jwtClaims{Username: sysUsername})
	ctx := testutil.Context(t, testutil.WaitShort)
	claims, err := auth.verify(ctx, token)
	require.NoError(t, err)

	_, ok := auth.setPrecheckedResult(ctx, claims)
	require.False(t, ok, "system users must never receive a prechecked result")
}

func TestMiddleware_ServiceAccountImpersonation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	const svcUsername = "admin-svc"

	ctrl := gomock.NewController(t)
	mock := dbmock.NewMockStore(ctrl)
	mock.EXPECT().
		GetUserByEmailOrUsername(gomock.Any(), gomock.Any()).
		Return(database.User{
			Username:         svcUsername,
			Status:           database.UserStatusActive,
			IsServiceAccount: true,
		}, nil)

	auth := f.authWithDB(mock)

	token := f.sign(jwtClaims{Username: svcUsername})
	ctx := testutil.Context(t, testutil.WaitShort)
	claims, err := auth.verify(ctx, token)
	require.NoError(t, err)

	_, ok := auth.setPrecheckedResult(ctx, claims)
	require.False(t, ok, "admin-managed service accounts must never receive a prechecked result")
}

// TestJWKS_UnknownKidNegativeCache pins the forced-refresh-amplification
// guard. Repeated unknown kids must fall into the negative cache so
// concurrent attacker-chosen kids cannot drive an unbounded number of
// outbound JWKS fetches.
func TestJWKS_UnknownKidNegativeCache(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	auth := f.auth()

	// Prime the cache.
	_, err := auth.verify(ctx, f.sign(jwtClaims{}))
	require.NoError(t, err)
	require.EqualValues(t, 1, f.jwksFetches.Load())

	// Sign with a fresh key whose kid is not in the JWKS. The first
	// such token forces a refresh (second fetch). Subsequent tokens
	// with the same unknown kid must be short-circuited by the
	// negative cache and must NOT trigger any further fetches.
	badKey, badKID := genRSAKey(t)
	tok := f.signWithKey(badKID, badKey, jwtClaims{})

	_, err = auth.verify(ctx, tok)
	require.ErrorIs(t, err, errJWTSignature)
	require.EqualValues(t, 2, f.jwksFetches.Load(), "first unknown kid forces a refresh")

	for range 10 {
		_, err = auth.verify(ctx, tok)
		require.ErrorIs(t, err, errJWTSignature)
	}
	require.EqualValues(t, 2, f.jwksFetches.Load(),
		"negative cache must suppress further JWKS refetches for a known-unknown kid")
}

// TestMiddleware_AutoProvisionsUnknownUser asserts the AutoProvisionUser
// hook is invoked when the JWT's username is not in the database, and
// that the resulting user is installed on the prechecked context so
// downstream handlers see the JWT identity.
func TestMiddleware_AutoProvisionsUnknownUser(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	const newUser = "fresh-user"

	var called int
	f.opts.AutoProvisionUser = func(ctx context.Context, provisioned ProvisionedUser) (database.User, error) {
		called++
		require.Equal(t, newUser, provisioned.Username)
		require.Equal(t, "https://teleport.t.tp", provisioned.Issuer,
			"issuer must be forwarded so the hook can derive the email domain")
		return dbgen.User(t, f.db, database.User{
			Username: provisioned.Username,
			Status:   database.UserStatusActive,
		}), nil
	}

	token := f.sign(jwtClaims{Username: newUser})

	var sawPrechecked bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, sawPrechecked = agplhttpmw.APIKeyPrecheckedFromContext(r.Context())
	})
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	mw(next).ServeHTTP(httptest.NewRecorder(), req)

	require.Equal(t, 1, called, "auto-provision must be called exactly once for an unknown user")
	require.True(t, sawPrechecked, "prechecked result must be installed after auto-provision succeeds")
}

// TestMiddleware_AutoProvisionReactivatesDormantUser covers the
// follow-up path where the user already exists but is dormant (the
// camscale case from the PoC instance). The hook gets a chance to
// flip the user back to active, and the prechecked result is then
// installed for the outer request.
func TestMiddleware_AutoProvisionReactivatesDormantUser(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	const dormant = "dormant-user"
	dbgen.User(f.t, f.db, database.User{
		Username: dormant,
		Status:   database.UserStatusDormant,
	})

	var called int
	f.opts.AutoProvisionUser = func(ctx context.Context, provisioned ProvisionedUser) (database.User, error) {
		called++
		// Mimic what the real provisioner does: flip the row back to
		// active and return the updated user.
		user, err := f.db.GetUserByEmailOrUsername(ctx, database.GetUserByEmailOrUsernameParams{
			Username: provisioned.Username,
		})
		require.NoError(t, err)
		user.Status = database.UserStatusActive
		return user, nil
	}

	token := f.sign(jwtClaims{Username: dormant})

	var sawPrechecked bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, sawPrechecked = agplhttpmw.APIKeyPrecheckedFromContext(r.Context())
	})
	mw := New(f.opts)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(testHeader, token)
	mw(next).ServeHTTP(httptest.NewRecorder(), req)

	require.Equal(t, 1, called, "auto-provision must run for a dormant user")
	require.True(t, sawPrechecked, "prechecked result must be installed after reactivation")
}

// TestJWKS_UnknownKidNegativeCacheExpires confirms the negative entry
// is not permanent: after the TTL elapses, the same kid is tried again
// (so a genuine key rotation is still observable).
func TestJWKS_UnknownKidNegativeCacheExpires(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := testutil.Context(t, testutil.WaitShort)

	auth := f.auth()

	// Prime.
	_, err := auth.verify(ctx, f.sign(jwtClaims{}))
	require.NoError(t, err)
	require.EqualValues(t, 1, f.jwksFetches.Load())

	badKey, badKID := genRSAKey(t)
	tok := f.signWithKey(badKID, badKey, jwtClaims{})

	// First unknown kid: refresh happens.
	_, err = auth.verify(ctx, tok)
	require.ErrorIs(t, err, errJWTSignature)
	require.EqualValues(t, 2, f.jwksFetches.Load())

	// While the negative cache is hot, no further fetch.
	_, err = auth.verify(ctx, tok)
	require.ErrorIs(t, err, errJWTSignature)
	require.EqualValues(t, 2, f.jwksFetches.Load())

	// Advance past the negative TTL but stay inside the main cache
	// TTL, so only the forced refresh on unknown kid can fire.
	f.clock.Advance(unknownKidNegativeTTL + time.Second).MustWait(ctx)

	// Resign under the advanced clock so exp is still in the future.
	tok2 := f.signWithKey(badKID, badKey, jwtClaims{})
	_, err = auth.verify(ctx, tok2)
	require.ErrorIs(t, err, errJWTSignature)
	require.EqualValues(t, 3, f.jwksFetches.Load(),
		"after negative TTL expires, an unknown kid is re-checked against the JWKS")
}
