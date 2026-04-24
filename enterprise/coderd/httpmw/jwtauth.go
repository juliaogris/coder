package httpmw

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/sync/singleflight"
	"golang.org/x/xerrors"

	"cdr.dev/slog/v3"
	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/database/dbauthz"
	"github.com/coder/coder/v2/coderd/database/dbtime"
	agplhttpmw "github.com/coder/coder/v2/coderd/httpmw"
	"github.com/coder/coder/v2/coderd/rbac"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/quartz"
)

const (
	jwksCacheTTL     = 5 * time.Minute
	jwksFetchTimeout = 10 * time.Second
	jwksMaxBodyBytes = 1 << 20
	skewTolerance    = 30 * time.Second
	// unknownKidNegativeTTL suppresses forced JWKS refetches for a kid
	// that the upstream JWKS just confirmed it does not have. Without
	// this guard, an attacker who can reach the proxy can fabricate
	// unlimited tokens with random kid header values and drive one
	// outbound JWKS request per incoming request, amplifying any
	// validation load into a DoS against the IdP.
	unknownKidNegativeTTL = 30 * time.Second
)

// allowedAlgorithms restricts the JWT signing algorithms the
// middleware accepts. Locking the list down prevents an attacker who
// controls the JWT header from downgrading to a weaker algorithm. RS256
// is what Teleport's HTTP app service signs with today; the rest of the
// list covers other modern asymmetric algorithms so alternative IdPs
// still work.
var allowedAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// Options configures the JWTAuth middleware.
type Options struct {
	Logger slog.Logger
	// Header is the HTTP header carrying the JWT (for example
	// "Teleport-Jwt-Assertion").
	Header string
	// JWKSURL is the absolute URL of the JWKS endpoint used to verify
	// the JWT signature. Must be https unless AllowHTTP is set. The
	// URL is operator-supplied; if the deployment allows it to point
	// at a private address (for example cloud metadata endpoints like
	// 169.254.169.254), that is a configuration concern outside the
	// middleware's control.
	JWKSURL string
	// Audience must appear in the JWT aud claim.
	Audience string
	// Issuer, when non-empty, must match the JWT iss claim. Leaving it
	// empty accepts any issuer and is only appropriate when the JWKS
	// is single-tenant and the Audience alone pins the relying party.
	Issuer string
	// AllowHTTP permits a non-https JWKSURL for dev and demos.
	AllowHTTP bool
	// Database is used to look up the user identified by the JWT
	// username claim. It is required for the middleware to run; if nil
	// the middleware turns off.
	Database database.Store
	// AutoProvisionUser is an optional hook that creates a Coder user
	// when a valid JWT arrives for a username not yet present in the
	// database, and reactivates a dormant user whose name matches the
	// JWT. Leaving it nil turns auto-provisioning off; the middleware
	// then refuses to install a prechecked result for unknown or
	// dormant users, and callers have to sign up through whichever
	// sign-up path the deployment configures. The hook is called with
	// a system-restricted context, so it has the authority to create
	// and mutate users directly. The ProvisionedUser carries the
	// verified username and issuer from the JWT so the hook can derive
	// deployment-specific fields such as the email domain.
	AutoProvisionUser func(ctx context.Context, user ProvisionedUser) (database.User, error)
	// Clock is optional and defaults to quartz.NewReal().
	Clock quartz.Clock
	// HTTPClient is optional and defaults to a client with the fetch
	// timeout applied.
	HTTPClient *http.Client
}

// New returns an HTTP middleware that validates a JWT present in the
// configured header against a JWKS and, on success, populates a
// prechecked API key result in the request context so that downstream
// PrecheckAPIKey / ExtractAPIKeyMW short-circuit as if a normal
// session token had been presented.
//
// If Header, JWKSURL, Audience, or Database are unset, the feature is
// off and New returns a no-op middleware.
func New(opts Options) func(http.Handler) http.Handler {
	if opts.Header == "" || opts.JWKSURL == "" || opts.Audience == "" || opts.Database == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	u, err := url.Parse(opts.JWKSURL)
	// A JWKS URL must be https, or http when the operator has
	// explicitly opted into the insecure mode. Reading it as a single
	// positive condition avoids the De Morgan'd chain of negations.
	schemeOK := err == nil && (u.Scheme == "https" || (u.Scheme == "http" && opts.AllowHTTP))
	if !schemeOK {
		opts.Logger.Error(context.Background(),
			"jwt auth disabled: JWKS URL must use https (or set --dangerous-jwt-auth-allow-http)",
			slog.F("jwks_url", opts.JWKSURL))
		return func(next http.Handler) http.Handler { return next }
	}

	clock := opts.Clock
	if clock == nil {
		clock = quartz.NewReal()
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: jwksFetchTimeout}
	}

	a := &jwtAuth{
		logger:        opts.Logger,
		header:        opts.Header,
		audience:      opts.Audience,
		issuer:        opts.Issuer,
		db:            opts.Database,
		autoProvision: opts.AutoProvisionUser,
		clock:         clock,
		jwks: &jwksClient{
			url:        opts.JWKSURL,
			httpClient: httpClient,
			clock:      clock,
			unknownKid: make(map[string]time.Time),
		},
	}
	return a.middleware
}

type jwtAuth struct {
	logger        slog.Logger
	header        string
	audience      string
	issuer        string
	db            database.Store
	autoProvision func(ctx context.Context, user ProvisionedUser) (database.User, error)
	clock         quartz.Clock
	jwks          *jwksClient
}

// ProvisionedUser carries the verified JWT fields that AutoProvisionUser
// needs to create or reactivate a Coder account. Only claims the
// middleware has already checked are exposed here, so a hook
// implementation cannot accidentally pick up an unverified value from
// the raw token.
type ProvisionedUser struct {
	// Username is the value of the JWT's username claim.
	Username string
	// Issuer is the value of the JWT's iss claim. The hook is free to
	// use it as the email domain for a synthesized placeholder email,
	// which for a Teleport-signed JWT gives the proxy's FQDN.
	Issuer string
}

// jwtClaims holds the fields we read from the JWT. Only the registered
// RFC 7519 claims and username are extracted; traits and roles are
// intentionally ignored so they cannot leak into logs.
type jwtClaims struct {
	jwt.Claims
	Username string `json:"username"`
}

func (a *jwtAuth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawToken := r.Header.Get(a.header)
		if rawToken == "" {
			next.ServeHTTP(w, r)
			return
		}
		claims, err := a.verify(r.Context(), rawToken)
		if err != nil {
			a.logVerifyError(r.Context(), rawToken, err)
			next.ServeHTTP(w, r)
			return
		}

		ctx, ok := a.setPrecheckedResult(r.Context(), claims)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		// Strip any cookie or header identity the caller might also
		// have presented so that the JWT-derived identity is the only
		// one visible to the rest of the chain. Without this a stale
		// Coder session cookie could win ahead of the JWT result.
		r = r.WithContext(ctx)
		stripSessionToken(r)
		next.ServeHTTP(w, r)
	})
}

// setPrecheckedResult looks up the user named in claims.Username,
// rejects non-active users, builds a synthetic APIKeyPrechecked value,
// and attaches it to the context. The returned bool is false when the
// lookup fails or the user is not active, in which case the caller
// should let the request continue unauthenticated.
func (a *jwtAuth) setPrecheckedResult(ctx context.Context, claims *jwtClaims) (context.Context, bool) {
	// The DB call uses the system-restricted actor because the
	// caller is not yet authenticated. Email is intentionally set to
	// the empty string so the OR branch against the email column
	// cannot fire and collide with a different user that happens to
	// have this value in their email.
	user, err := a.db.GetUserByEmailOrUsername(
		dbauthz.AsSystemRestricted(ctx),
		database.GetUserByEmailOrUsernameParams{
			Username: claims.Username,
			Email:    "",
		},
	)
	// When AutoProvisionUser is configured, trust the verified JWT
	// claim as the signal to create a Coder account for a new user or
	// reactivate a dormant one. The upstream proxy is the identity
	// source of truth in IAP deployments; forcing every caller through
	// Coder's own login flow to seed an account would defeat that.
	if a.autoProvision != nil {
		needsProvision := errors.Is(err, sql.ErrNoRows) ||
			(err == nil && user.Status == database.UserStatusDormant)
		if needsProvision {
			user, err = a.autoProvision(dbauthz.AsSystemRestricted(ctx), ProvisionedUser{
				Username: claims.Username,
				Issuer:   claims.Issuer,
			})
			if err != nil {
				a.logger.Error(ctx, "jwt auto-provision failed",
					slog.F("username", claims.Username),
					slog.Error(err))
				return ctx, false
			}
		}
	}
	if err != nil {
		a.logger.Debug(ctx, "jwt user lookup failed",
			slog.F("username", claims.Username),
			slog.Error(err))
		return ctx, false
	}
	// System users (for example the "prebuilds" account inserted by
	// migration 000308_system_user) and admin-managed service accounts
	// cannot log in through any normal path. Reject them here so a
	// misconfigured IdP that mints a JWT with one of their usernames
	// cannot install an APIKeyPrechecked under their RBAC subject.
	if user.IsSystem || user.IsServiceAccount {
		a.logger.Warn(ctx, "jwt rejected: username resolves to non-human user",
			slog.F("username", user.Username),
			slog.F("is_system", user.IsSystem),
			slog.F("is_service_account", user.IsServiceAccount))
		return ctx, false
	}
	if user.Status != database.UserStatusActive {
		a.logger.Warn(ctx, "jwt user not active",
			slog.F("username", user.Username),
			slog.F("status", string(user.Status)))
		return ctx, false
	}

	subject, _, err := agplhttpmw.UserRBACSubject(ctx, a.db, user.ID, rbac.ScopeAll)
	if err != nil {
		a.logger.Error(ctx, "jwt rbac subject lookup failed",
			slog.F("username", user.Username),
			slog.Error(err))
		return ctx, false
	}

	now := a.clock.Now()
	apiKey := database.APIKey{
		ID:              apiKeyIDFromJTI(claims.ID),
		UserID:          user.ID,
		LastUsed:        dbtime.Time(now),
		ExpiresAt:       dbtime.Time(now.Add(time.Hour)),
		CreatedAt:       dbtime.Time(now),
		UpdatedAt:       dbtime.Time(now),
		LoginType:       database.LoginTypeToken,
		LifetimeSeconds: int64(time.Hour / time.Second),
		Scopes:          database.APIKeyScopes{database.ApiKeyScopeCoderAll},
	}

	ctx = agplhttpmw.SetPrecheckedResult(ctx, agplhttpmw.APIKeyPrechecked{
		Result: &agplhttpmw.ValidateAPIKeyResult{
			Key:        apiKey,
			Subject:    subject,
			UserStatus: user.Status,
		},
		// The identity came from a verified JWT header, not a session
		// token. Tagging the source here lets downstream ExtractAPIKey
		// calls with a custom SessionTokenFunc (for example workspace
		// app / terminal token issuance) consume this prechecked
		// result instead of treating it as a potentially-stale
		// top-level session-token precheck.
		Source: agplhttpmw.APIKeyPrecheckedSourceExternal,
	})

	a.logger.Debug(ctx, "jwt verified",
		slog.F("username", user.Username),
		slog.F("aud", []string(claims.Audience)),
		slog.F("exp", claims.Expiry),
		slog.F("jti", claims.ID))
	return ctx, true
}

// apiKeyIDFromJTI derives a stable, well-formed API key ID from the
// JWT ID claim. The database column for api_keys.id is a 10-character
// string, so we truncate or pad the raw jti value accordingly. The
// returned value never escapes the request; it exists only to
// populate the synthetic APIKey struct used by dbauthz and logging.
func apiKeyIDFromJTI(jti string) string {
	const size = 10
	if len(jti) >= size {
		return jti[:size]
	}
	return jti + strings.Repeat("0", size-len(jti))
}

// stripSessionToken removes every input that APITokenFromRequest would
// treat as a session token: the Coder-Session-Token header, the
// Coder-Session-Token cookie, the coder_session_token query parameter,
// an RFC 6750 Authorization: Bearer header, and the access_token query
// parameter. Handlers that bypass the prechecked context (for example
// workspace-app issuance in coderd/workspaceapps/cookies.go, the debug
// endpoint in coderd/debug.go, and the MCP endpoint in
// coderd/mcp_http.go) call APITokenFromRequest directly, so any of
// these inputs left in place would let the caller's non-JWT identity
// diverge from the JWT identity the middleware installed.
func stripSessionToken(r *http.Request) {
	r.Header.Del(codersdk.SessionTokenHeader)

	// Drop an Authorization: Bearer ... credential. Other schemes
	// (Basic, Digest, ...) are left alone; only the Bearer form is
	// treated as a session token by APITokenFromRequest.
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			r.Header.Del("Authorization")
		}
	}

	cookies := r.Cookies()
	hasSessionCookie := false
	for _, c := range cookies {
		if c.Name == codersdk.SessionTokenCookie {
			hasSessionCookie = true
			break
		}
	}
	if hasSessionCookie {
		// net/http does not expose a single-cookie delete, so rebuild
		// the Cookie header without the session cookie.
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name == codersdk.SessionTokenCookie {
				continue
			}
			r.AddCookie(c)
		}
	}

	q := r.URL.Query()
	changed := false
	if q.Has(codersdk.SessionTokenCookie) {
		q.Del(codersdk.SessionTokenCookie)
		changed = true
	}
	if q.Has("access_token") {
		q.Del("access_token")
		changed = true
	}
	if changed {
		r.URL.RawQuery = q.Encode()
	}
}

// Sentinel errors let callers and tests match failure modes without
// pattern-matching on free-form wrapped messages.
var (
	errJWTParse     = xerrors.New("parse JWT")
	errJWTSignature = xerrors.New("bad signature")
	errJWTExpired   = xerrors.New("expired")
	errJWTNotYet    = xerrors.New("not yet valid")
	errJWTAudience  = xerrors.New("audience mismatch")
	errJWTIssuer    = xerrors.New("issuer mismatch")
	errJWKSFetch    = xerrors.New("fetch JWKS")
)

// verify parses the token, verifies the signature against the JWKS,
// and validates exp, nbf, and aud with a 30 second skew tolerance. It
// refreshes the JWKS once if the token's kid is not present, which
// handles key rotation without requiring a server restart.
func (a *jwtAuth) verify(ctx context.Context, token string) (*jwtClaims, error) {
	parsed, err := jwt.ParseSigned(token, allowedAlgorithms)
	if err != nil {
		return nil, errors.Join(errJWTParse, err)
	}
	if len(parsed.Headers) != 1 {
		return nil, errors.Join(errJWTParse, xerrors.New("expected exactly one JWS header"))
	}
	kid := parsed.Headers[0].KeyID

	keys, err := a.jwks.Fetch(ctx, false)
	if err != nil {
		return nil, errors.Join(errJWKSFetch, err)
	}
	key, ok := pickKey(keys, kid)
	if !ok {
		// Honor the negative cache before forcing a refresh so an
		// attacker cannot bypass the 5 minute TTL with a fresh random
		// kid on every request.
		if a.jwks.recentlyUnknown(kid) {
			return nil, errors.Join(errJWTSignature, xerrors.Errorf("no key with id %q (recently unknown)", kid))
		}
		keys, err = a.jwks.Fetch(ctx, true)
		if err != nil {
			return nil, errors.Join(errJWKSFetch, err)
		}
		key, ok = pickKey(keys, kid)
		if !ok {
			a.jwks.markUnknown(kid)
			return nil, errors.Join(errJWTSignature, xerrors.Errorf("no key with id %q", kid))
		}
	}

	var c jwtClaims
	if err := parsed.Claims(key.Key, &c); err != nil {
		return nil, errors.Join(errJWTSignature, err)
	}

	expected := jwt.Expected{
		AnyAudience: jwt.Audience{a.audience},
		Issuer:      a.issuer,
		Time:        a.clock.Now(),
	}
	err = c.ValidateWithLeeway(expected, skewTolerance)
	switch {
	case errors.Is(err, jwt.ErrExpired):
		return nil, errors.Join(errJWTExpired, err)
	case errors.Is(err, jwt.ErrNotValidYet):
		return nil, errors.Join(errJWTNotYet, err)
	case errors.Is(err, jwt.ErrInvalidAudience):
		return nil, errors.Join(errJWTAudience, err)
	case errors.Is(err, jwt.ErrInvalidIssuer):
		return nil, errors.Join(errJWTIssuer, err)
	case err != nil:
		return nil, err
	}
	return &c, nil
}

// pickKey returns the JWK that matches kid, or the sole key in the set
// if the token did not name a kid and exactly one key is available.
func pickKey(keys *jose.JSONWebKeySet, kid string) (jose.JSONWebKey, bool) {
	if keys == nil {
		return jose.JSONWebKey{}, false
	}
	if kid != "" {
		for _, k := range keys.Keys {
			if k.KeyID == kid {
				return k, true
			}
		}
		return jose.JSONWebKey{}, false
	}
	if len(keys.Keys) == 1 {
		return keys.Keys[0], true
	}
	return jose.JSONWebKey{}, false
}

// logVerifyError maps validation errors to log levels. Parse and
// time-window failures are expected whenever an unauthenticated caller
// hits the proxy, so they log at Debug. Signature, audience, and
// issuer failures are rarer and worth Warn. JWKS fetch failures are
// Error because they indicate the deployment cannot verify any JWT
// until the upstream IdP is reachable again. The raw token is redacted
// before it lands in a log line so a replayable signature never leaves
// memory.
func (a *jwtAuth) logVerifyError(ctx context.Context, token string, err error) {
	fields := []slog.Field{
		slog.F("token", redactToken(token)),
		slog.Error(err),
	}
	switch {
	case errors.Is(err, errJWTParse):
		a.logger.Debug(ctx, "jwt parse failed", fields...)
	case errors.Is(err, errJWTExpired), errors.Is(err, errJWTNotYet):
		a.logger.Debug(ctx, "jwt time window rejected", fields...)
	case errors.Is(err, errJWTSignature):
		a.logger.Warn(ctx, "jwt signature invalid", fields...)
	case errors.Is(err, errJWTAudience):
		a.logger.Warn(ctx, "jwt audience mismatch", fields...)
	case errors.Is(err, errJWTIssuer):
		a.logger.Warn(ctx, "jwt issuer mismatch", fields...)
	case errors.Is(err, errJWKSFetch):
		a.logger.Error(ctx, "jwt JWKS fetch failed", fields...)
	default:
		a.logger.Warn(ctx, "jwt validation failed", fields...)
	}
}

// redactToken returns the header and payload segments of a JWT with
// the signature elided. Keeping the first two segments makes parse
// failures diagnosable (the claims are visible) without logging a
// token anyone can replay within its validity window.
func redactToken(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "<invalid>"
	}
	return parts[0] + "." + parts[1] + ".<redacted>"
}

// jwksClient fetches and caches a JSON Web Key Set from a URL with a
// 5-minute TTL, a 10-second fetch timeout, and a 1 MB response cap.
// Callers can request a forced refresh to handle key rotation.
//
// Concurrent fetches are coalesced through a singleflight group, and a
// short negative cache records kids that the upstream JWKS just
// confirmed it does not have. Together these stop an attacker who can
// reach the proxy from amplifying syntactically-valid tokens with
// random kid headers into unbounded outbound JWKS requests.
type jwksClient struct {
	url        string
	httpClient *http.Client
	clock      quartz.Clock

	sf singleflight.Group

	mu         sync.Mutex
	cached     *cachedJWKS
	unknownKid map[string]time.Time
}

type cachedJWKS struct {
	keys    *jose.JSONWebKeySet
	fetched time.Time
}

// recentlyUnknown reports whether kid is in the negative cache and has
// not yet expired. It prunes stale entries on the fly so the map does
// not grow unboundedly with attacker-chosen values.
func (c *jwksClient) recentlyUnknown(kid string) bool {
	if kid == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.unknownKid[kid]
	if !ok {
		return false
	}
	if c.clock.Now().Sub(at) >= unknownKidNegativeTTL {
		delete(c.unknownKid, kid)
		return false
	}
	return true
}

// markUnknown records that a kid is absent from the current JWKS. The
// entry is cleared automatically the next time recentlyUnknown prunes
// it, or when the kid starts appearing in a fresh JWKS response.
func (c *jwksClient) markUnknown(kid string) {
	if kid == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unknownKid[kid] = c.clock.Now()
}

func (c *jwksClient) Fetch(ctx context.Context, forceRefresh bool) (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	cached := c.cached
	c.mu.Unlock()
	if !forceRefresh && cached != nil && c.clock.Now().Sub(cached.fetched) < jwksCacheTTL {
		return cached.keys, nil
	}

	// Coalesce concurrent fetchers onto one outbound request. Without
	// this, N simultaneous unknown-kid requests would issue N HTTP
	// round-trips (each capped at 1 MB) against the upstream JWKS.
	key := "fetch"
	if forceRefresh {
		key = "refresh"
	}
	v, err, _ := c.sf.Do(key, func() (any, error) {
		return c.fetchUncoalesced(ctx)
	})
	if err != nil {
		return nil, err
	}
	return v.(*jose.JSONWebKeySet), nil
}

func (c *jwksClient) fetchUncoalesced(ctx context.Context) (*jose.JSONWebKeySet, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, xerrors.Errorf("new request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBodyBytes+1))
	if err != nil {
		return nil, xerrors.Errorf("read body: %w", err)
	}
	if len(body) > jwksMaxBodyBytes {
		return nil, xerrors.Errorf("JWKS response exceeds %d bytes", jwksMaxBodyBytes)
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, xerrors.Errorf("unmarshal JWKS: %w", err)
	}

	c.mu.Lock()
	c.cached = &cachedJWKS{keys: &keys, fetched: c.clock.Now()}
	// A kid that appears in the fresh response is no longer unknown.
	for _, k := range keys.Keys {
		delete(c.unknownKid, k.KeyID)
	}
	c.mu.Unlock()
	return &keys, nil
}
