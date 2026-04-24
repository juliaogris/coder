package coderd

import (
	"context"
	"database/sql"
	"errors"
	"net/url"

	"github.com/google/uuid"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd"
	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/database/dbauthz"
	"github.com/coder/coder/v2/coderd/database/dbtime"
	"github.com/coder/coder/v2/coderd/rbac"
	"github.com/coder/coder/v2/coderd/util/ptr"
	"github.com/coder/coder/v2/codersdk"
	entmw "github.com/coder/coder/v2/enterprise/coderd/httpmw"
)

// jwtEmailFallbackDomain is used when the JWT does not carry a usable
// issuer. ".local" is reserved by RFC 6762 so a synthesized address
// here cannot accidentally resolve on the public internet.
const jwtEmailFallbackDomain = "jwt.iap.local"

// jwtAutoProvisionFn returns the JWT middleware callback that creates
// or reactivates a Coder user on first sign-in. The upstream proxy's
// signed JWT claim is treated as the identity source of truth, so a
// verified JWT for a username that is absent from the database causes
// that user to be created with active status, and a JWT for a dormant
// user flips the user back to active. Suspended users are left alone
// and the middleware refuses to install a prechecked result for them.
//
// api is captured by reference so the closure can reach
// api.AGPL.CreateUser; api.AGPL is populated by the coderd.New call
// that runs immediately after the middleware is registered, so the
// closure sees a non-nil AGPL API by the time the first HTTP request
// arrives.
func jwtAutoProvisionFn(api *API) func(ctx context.Context, user entmw.ProvisionedUser) (database.User, error) {
	return func(ctx context.Context, user entmw.ProvisionedUser) (database.User, error) {
		return jwtAutoProvisionUser(ctx, api, user)
	}
}

func jwtAutoProvisionUser(ctx context.Context, api *API, claim entmw.ProvisionedUser) (database.User, error) {
	if api.AGPL == nil {
		return database.User{}, xerrors.New("coder API not yet initialized")
	}
	// Read the current row so we can tell "missing" from "dormant"
	// from "already active". The lookup is intentionally username-only
	// so the OR branch against email cannot collide with a different
	// user whose email happens to match this username.
	user, err := api.Database.GetUserByEmailOrUsername(
		dbauthz.AsSystemRestricted(ctx),
		database.GetUserByEmailOrUsernameParams{Username: claim.Username},
	)
	switch {
	case err == nil && user.Status == database.UserStatusDormant:
		return activateDormantJWTUser(ctx, api, user)
	case err == nil:
		return user, nil
	case errors.Is(err, sql.ErrNoRows):
		return createJWTUser(ctx, api, claim)
	default:
		return database.User{}, xerrors.Errorf("look up user %q: %w", claim.Username, err)
	}
}

func createJWTUser(ctx context.Context, api *API, claim entmw.ProvisionedUser) (database.User, error) {
	sysCtx := dbauthz.AsSystemRestricted(ctx)
	defaultOrg, err := api.Database.GetDefaultOrganization(sysCtx)
	if err != nil {
		return database.User{}, xerrors.Errorf("get default organization: %w", err)
	}
	// Coder requires a unique email per user. The upstream JWT does not
	// carry an email claim today, so synthesize one by combining the
	// username with the JWT issuer. For a Teleport-signed JWT the
	// issuer is the cluster's bare proxy hostname, so the email ends
	// up looking like juliaogris@julia-coder-iap.devteleport.com. The
	// user can edit it from the Coder UI once signed in.
	var rbacRoles []string
	// Mirror the OAuth first-user behaviour: if there are no users in
	// the deployment yet, promote the very first JWT-provisioned user
	// to Owner so the deployment is not locked out of its own admin
	// surface after a fresh stand-up or a DB reset.
	count, err := api.Database.GetUserCount(sysCtx, false)
	if err != nil {
		return database.User{}, xerrors.Errorf("count users: %w", err)
	}
	if count == 0 {
		rbacRoles = append(rbacRoles, rbac.RoleOwner().String())
	}
	return api.AGPL.CreateUser(sysCtx, api.Database, coderd.CreateUserRequest{
		CreateUserRequestWithOrgs: codersdk.CreateUserRequestWithOrgs{
			Username:        claim.Username,
			Email:           synthesizeJWTEmail(claim.Username, claim.Issuer),
			OrganizationIDs: []uuid.UUID{defaultOrg.ID},
			UserStatus:      ptr.Ref(codersdk.UserStatusActive),
		},
		LoginType:         database.LoginTypeNone,
		RBACRoles:         rbacRoles,
		SkipNotifications: true,
	})
}

// synthesizeJWTEmail derives a placeholder email address from the JWT
// username and issuer claims. Issuers that look like URLs are narrowed
// to their host, which accommodates IdPs that publish iss as
// "https://issuer.example.com" while keeping Teleport's bare-hostname
// issuer form intact. Unusable issuers fall back to the reserved
// ".local" TLD so a synthesized address cannot resolve on the public
// internet.
func synthesizeJWTEmail(username, issuer string) string {
	domain := jwtEmailFallbackDomain
	if issuer != "" {
		if u, err := url.Parse(issuer); err == nil && u.Host != "" {
			domain = u.Host
		} else {
			domain = issuer
		}
	}
	return username + "@" + domain
}

func activateDormantJWTUser(ctx context.Context, api *API, user database.User) (database.User, error) {
	updated, err := api.Database.UpdateUserStatus(
		dbauthz.AsSystemRestricted(ctx),
		database.UpdateUserStatusParams{
			ID:         user.ID,
			Status:     database.UserStatusActive,
			UpdatedAt:  dbtime.Now(),
			UserIsSeen: true,
		},
	)
	if err != nil {
		return database.User{}, xerrors.Errorf("activate dormant user: %w", err)
	}
	return updated, nil
}
