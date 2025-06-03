package authn_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aaishahhamdha/oathkeeper/helper"
	"github.com/aaishahhamdha/oathkeeper/internal"
	. "github.com/aaishahhamdha/oathkeeper/pipeline/authn"
)

func TestAuthenticatorLogout(t *testing.T) {
	t.Parallel()
	conf := internal.NewConfigurationWithDefaults()
	reg := internal.NewRegistry(conf)

	a, err := reg.PipelineAuthenticator("logout")
	require.NoError(t, err)
	assert.Equal(t, "logout", a.GetID())

	t.Run("method=authenticate", func(t *testing.T) {
		testCases := []struct {
			name           string
			request        *http.Request
			config         json.RawMessage
			expectErr      bool
			expectExactErr error
		}{
			{
				name: "empty request",
				request: &http.Request{
					Method: "GET",
					Header: http.Header{},
				},
				config:         json.RawMessage(`{}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
			{
				name: "with Authorization header",
				request: &http.Request{
					Method: "POST",
					Header: http.Header{"Authorization": {"Bearer token"}},
				},
				config:         json.RawMessage(`{}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
			{
				name: "with session cookie",
				request: func() *http.Request {
					req := &http.Request{
						Method: "GET",
						Header: http.Header{},
					}
					req.AddCookie(&http.Cookie{
						Name:  "session_id",
						Value: "some_session",
					})
					return req
				}(),
				config:         json.RawMessage(`{}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
			{
				name: "with custom config",
				request: &http.Request{
					Method: "POST",
					Header: http.Header{"Content-Type": {"application/json"}},
				},
				config:         json.RawMessage(`{"oidc_logout_url": "https://provider.com/logout"}`),
				expectErr:      true,
				expectExactErr: helper.ErrUnauthorized,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				sess := new(AuthenticationSession)
				err := a.Authenticate(tc.request, sess, tc.config, nil)

				if tc.expectErr {
					require.Error(t, err)
					if tc.expectExactErr != nil {
						assert.ErrorIs(t, err, tc.expectExactErr)
					}
				} else {
					require.NoError(t, err)
				}

				assert.Empty(t, sess.Subject)
				assert.Empty(t, sess.Extra)
			})
		}
	})

	t.Run("method=GetID", func(t *testing.T) {
		assert.Equal(t, "logout", a.GetID())
	})
}
