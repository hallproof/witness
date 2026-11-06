package authsome

import (
	"context"
	"errors"
	"fmt"
	"time"

	authsome "github.com/xraph/authsome"
	"github.com/xraph/authsome/appclientconfig"
	"github.com/xraph/authsome/settings"
	"github.com/xraph/authsome/store"

	"github.com/hallproof/witness/collect"
)

func (a *Adapter) authPolicy() collect.Snapshot {
	return collect.Snapshot{
		Key:         "authsome.auth-policy",
		Title:       "Sign-in policy",
		Description: "The platform app's MFA, password, session and lockout settings as Authsome enforces them.",
		Tests:       []string{"mfa-enforced", "password-policy"},
		Every:       every,
		Collect:     a.collectAuthPolicy,
	}
}

// collectAuthPolicy picks named fields only. Config also holds the token
// encryption keys and the API key pepper, and some settings are secrets, so
// nothing here is marshalled whole.
func (a *Adapter) collectAuthPolicy(ctx context.Context) (map[string]any, error) {
	app, err := a.appID(ctx)
	if err != nil {
		return nil, err
	}
	cfg := a.eng.Config()
	s := map[string]any{
		"app_id":                     app.String(),
		"mfa_plugin":                 a.mfaPlugin() != nil,
		"mfa_enabled":                nil,
		"mfa_required":               nil,
		"mfa_methods":                nil,
		"require_email_verification": a.eng.EmailVerificationRequired(ctx, app),
	}

	cc, err := a.eng.Store().GetAppClientConfig(ctx, app)
	switch {
	case errors.Is(err, appclientconfig.ErrNotFound), errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, fmt.Errorf("witness/authsome: read the app client config: %w", err)
	default:
		s["mfa_enabled"] = optBool(cc.MFAEnabled)
		s["mfa_required"] = optBool(cc.MFARequired)
		if cc.MFAMethods != nil {
			s["mfa_methods"] = sorted(cc.MFAMethods)
		}
	}

	pw := cfg.Password
	s["password_min_length"] = pw.MinLength
	s["password_require_uppercase"] = pw.RequireUppercase
	s["password_require_lowercase"] = pw.RequireLowercase
	s["password_require_digit"] = pw.RequireDigit
	s["password_require_special"] = pw.RequireSpecial
	s["password_check_breached"] = pw.CheckBreached
	s["password_history_count"] = pw.HistoryCount
	s["password_max_age_days"] = pw.MaxAgeDays
	algorithm := pw.Algorithm
	if algorithm == "" {
		algorithm = "bcrypt"
	}
	s["password_algorithm"] = algorithm

	sc := a.eng.SessionConfigForApp(ctx, app)
	s["session_token_ttl_seconds"] = seconds(sc.TokenTTL)
	s["session_refresh_ttl_seconds"] = seconds(sc.RefreshTokenTTL)
	s["session_max_active"] = sc.MaxActiveSessions
	s["session_rotate_refresh"] = sc.RotateRefreshToken
	s["session_absolute_lifetime_seconds"] = seconds(a.eng.AbsoluteLifetimeFor(ctx, app))
	s["session_inactivity_enforced"] = a.opts.InactivityEnforced
	opts := settings.ResolveOpts{AppID: app.String()}
	for key, def := range map[string]settings.DefinitionTyped[bool]{
		"session_bind_to_ip":     authsome.SettingBindToIP,
		"session_bind_to_device": authsome.SettingBindToDevice,
	} {
		v, serr := setting(ctx, a.eng.Settings(), def, opts)
		if serr != nil {
			return nil, serr
		}
		s[key] = v
	}
	inactivity, err := setting(ctx, a.eng.Settings(), authsome.SettingInactivityTimeoutSeconds, opts)
	if err != nil {
		return nil, err
	}
	s["session_inactivity_timeout_seconds"] = inactivity

	lo := cfg.Lockout
	s["lockout_enabled"] = a.eng.Lockout() != nil
	s["lockout_max_attempts"] = lo.MaxAttempts
	s["lockout_duration_seconds"] = seconds(lo.LockoutDuration())
	s["lockout_reset_after_seconds"] = seconds(lo.ResetAfter())
	return s, nil
}

// setting resolves one setting for the app, or nil when the engine has no
// settings manager.
func setting[T any](ctx context.Context, m *settings.Manager, def settings.DefinitionTyped[T], opts settings.ResolveOpts) (any, error) {
	if m == nil {
		return nil, nil
	}
	v, err := settings.Get(ctx, m, def, opts)
	if err != nil {
		return nil, fmt.Errorf("witness/authsome: read setting %s: %w", def.Def.Key, err)
	}
	return v, nil
}

func seconds(d time.Duration) int64 { return int64(d / time.Second) }
