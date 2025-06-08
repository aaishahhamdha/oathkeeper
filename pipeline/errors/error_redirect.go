package errors

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/aaishahhamdha/oathkeeper/pipeline/authn"
	"github.com/aaishahhamdha/oathkeeper/pipeline/session_store"
	"github.com/aaishahhamdha/oathkeeper/x"
	"github.com/pkg/errors"
)

var _ Handler = new(ErrorRedirect)

const (
	xForwardedProto = "X-Forwarded-Proto"
	xForwardedHost  = "X-Forwarded-Host"
	xForwardedUri   = "X-Forwarded-Uri"
)

type (
	ErrorRedirectConfig struct {
		To                    string `json:"to"`
		Code                  int    `json:"code"`
		ReturnToQueryParam    string `json:"return_to_query_param"`
		Type                  string `json:"type"`
		OidcLogoutUrl         string `json:"oidc_logout_url"`
		PostLogoutRedirectUrl string `json:"post_logout_redirect_url"`
	}
	ErrorRedirect struct {
		c configuration.Provider
		d ErrorRedirectDependencies
	}
	ErrorRedirectDependencies interface {
		x.RegistryWriter
		x.RegistryLogger
	}
)

func NewErrorRedirect(
	c configuration.Provider,
	d ErrorRedirectDependencies,
) *ErrorRedirect {
	return &ErrorRedirect{c: c, d: d}
}

// ContextKeySession is the key used to store the authentication session in the request context
var ContextKeySession = struct{}{}

func (a *ErrorRedirect) Handle(w http.ResponseWriter, r *http.Request, s *authn.AuthenticationSession, config json.RawMessage, rule pipeline.Rule, err error) error {
	c, err := a.Config(config)
	if err != nil {
		return err
	}

	r.URL.Scheme = x.OrDefaultString(r.Header.Get(xForwardedProto), r.URL.Scheme)
	r.URL.Host = x.OrDefaultString(r.Header.Get(xForwardedHost), r.URL.Host)
	r.URL.Path = x.OrDefaultString(r.Header.Get(xForwardedUri), r.URL.Path)

	if c.Type == "auth" {
		a.d.Logger().Debug("Redirect type: auth")
		// Generate a random state for CSRF protection
		state, err := GenerateState(64)
		if err != nil {
			return err
		}
		// Store the state in the session store with client info
		var upStreamURL string
		if rule != nil {
			upStreamURL = rule.GetUpstreamURL()
		}
		cleanURL := func(u *url.URL) string {
			parsed, err := url.Parse(u.String())
			if err != nil {
				return u.String()
			}
			q := parsed.Query()
			q.Del("state")
			parsed.RawQuery = q.Encode()
			return parsed.String()
		}(r.URL)

		session_store.GlobalStore.AddStateEntry(state, r.UserAgent(), cleanURL, upStreamURL)
		redirectURL := a.RedirectURL(r.URL, c, s) + "&state=" + state
		http.Redirect(w, r, redirectURL, c.Code)
		a.d.Logger().WithFields(map[string]interface{}{
			"redirect_url": redirectURL,
			"state":        state,
		}).Info("Redirecting to auth URL with state")
	} else if c.Type == "logout" {

		a.d.Logger().Debug("Redirect type: logout")
		if c.OidcLogoutUrl == "" {
			return errors.New("oidc_logout_url is required")
		}
		if c.PostLogoutRedirectUrl == "" {
			return errors.New("post_logout_redirect_url is required")
		}

		// Get session ID from cookie
		sessionCookie, err := r.Cookie("IG_SESSION_ID")
		var idTokenHint string
		if err == nil && sessionCookie != nil {
			a.d.Logger().WithField("session_id", sessionCookie.Value).Debug("Logout: Found session cookie")

			if _, exists := session_store.GlobalStore.GetSession(sessionCookie.Value); exists {
				a.d.Logger().Debug("Session exists in store, proceeding with logout")
			} else {
				a.d.Logger().WithField("session_id", sessionCookie.Value).Warn("Logout: Session not found in store")
			}

			idTokenHint, _ = session_store.GlobalStore.GetField(sessionCookie.Value, "id_token")
			if idTokenHint != "" {
				a.d.Logger().Debug("Logout: ID token hint found for OIDC logout")
			} else {
				a.d.Logger().WithField("session_id", sessionCookie.Value).Debug("Logout: No ID token found for session")
			}

			session_store.GlobalStore.DeleteSession(sessionCookie.Value)
			a.d.Logger().WithField("session_id", sessionCookie.Value).Info("Logout: Successfully deleted session from store")

			deletedSession, exists := session_store.GlobalStore.GetSession(sessionCookie.Value)
			a.d.Logger().WithFields(map[string]interface{}{
				"session_exists": exists,
				"session_data":   deletedSession,
			}).Debug("Logout verification: Session deletion status")
			session_store.GlobalStore.CleanExpired()

			// Remove the IG_SESSION_ID cookie
			a.clearSessionCookie(w)
			a.d.Logger().Info("Logout: Cleared IG_SESSION_ID cookie from client")
		} else {
			a.d.Logger().Info("Logout: No session cookie found in request")
		}

		state, err := GenerateState(64)
		if err != nil {
			return errors.WithStack(err)
		}

		// Construct logout URL
		logoutURL, err := url.Parse(c.OidcLogoutUrl)
		if err != nil {
			return errors.WithStack(err)
		}
		params := url.Values{}
		params.Set("post_logout_redirect_uri", c.PostLogoutRedirectUrl)
		params.Set("state", state)
		params.Set("id_token_hint", idTokenHint)

		logoutURL.RawQuery = params.Encode()
		logoutURLString := logoutURL.String()

		a.d.Logger().WithField("logout_url", logoutURLString).Info("Logout: Calling OIDC logout URL")
		http.Redirect(w, r, logoutURLString, c.Code)
		a.d.Logger().WithField("redirect_url", logoutURLString).Info("Redirecting to logout URL")
		a.d.Logger().Info("Logout: Successfully completed logout process")
	} else {
		a.d.Logger().Debug("Redirect type: none")
		// Type is "none" or any other value - just do a simple redirect
		redirectURL := a.RedirectURL(r.URL, c, s)
		http.Redirect(w, r, redirectURL, c.Code)
		a.d.Logger().WithField("redirect_url", redirectURL).Info("Redirecting to default URL")
	}

	return nil
}

func (a *ErrorRedirect) Validate(config json.RawMessage) error {
	if !a.c.ErrorHandlerIsEnabled(a.GetID()) {
		return NewErrErrorHandlerNotEnabled(a)
	}
	_, err := a.Config(config)
	return err
}

func (a *ErrorRedirect) Config(config json.RawMessage) (*ErrorRedirectConfig, error) {
	var c ErrorRedirectConfig
	if err := a.c.ErrorHandlerConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrErrorHandlerMisconfigured(a, err)
	}

	if c.Code < 301 || c.Code > 302 {
		c.Code = http.StatusFound
	}

	return &c, nil
}

func (a *ErrorRedirect) GetID() string {
	return "redirect"
}

func (a *ErrorRedirect) RedirectURL(uri *url.URL, c *ErrorRedirectConfig, session *authn.AuthenticationSession) string {
	if c.ReturnToQueryParam == "" {
		return c.To
	}

	// Check if c.To contains a template variable like {{key}}
	to := c.To
	var key string
	start := strings.Index(to, "{{")
	end := strings.Index(to, "}}")
	if start != -1 && end != -1 && end > start+2 {
		key = strings.TrimSpace(to[start+2 : end])
		// Try to get value from session.Extra
		if session != nil && session.Extra != nil {
			if val, ok := session.Extra[key]; ok {
				to = to[:start] + fmt.Sprintf("%v", val) + to[end+2:]
			}
		}
		return to
	}

	u, err := url.Parse(to)
	if err != nil {
		return to
	}

	q := u.Query()
	q.Set(c.ReturnToQueryParam, uri.String())
	u.RawQuery = q.Encode()
	return u.String()
}

// clearSessionCookie removes the IG_SESSION_ID cookie from the client's browser
func (a *ErrorRedirect) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "IG_SESSION_ID",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

func GenerateState(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
