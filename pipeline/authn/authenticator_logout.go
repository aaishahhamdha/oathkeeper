// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"encoding/json"
	"net/http"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/helper"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/pkg/errors"
)

type AuthenticatorLogout struct {
	c configuration.Provider
}

func NewAuthenticatorLogout(c configuration.Provider) *AuthenticatorLogout {
	return &AuthenticatorLogout{c: c}
}

func (a *AuthenticatorLogout) GetID() string {
	return "logout"
}

func (a *AuthenticatorLogout) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	if err := a.c.AuthenticatorConfig(a.GetID(), config, nil); err != nil {
		return NewErrAuthenticatorMisconfigured(a, err)
	}
	return nil
}

func (a *AuthenticatorLogout) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, rule pipeline.Rule) error {
	// Always fail with unauthorized error
	return errors.WithStack(helper.ErrUnauthorized)
}
