package oidc

import (
	"encoding/base64"
	"encoding/json"
)

type OidcState struct {
	Action      string `json:"action"`
	RedirectUrl string `json:"redirect_url"`

	// Set when this login was triggered by UnauthorizedBehavior's Challenge (an authorization
	// re-check that failed), as opposed to a plain unauthenticated login. Carried through the
	// callback so the resulting session can be marked as having already attempted a challenge,
	// regardless of which middleware instance's rules end up handling the callback.
	IsChallenge bool `json:"is_challenge"`
}

func EncodeState(state *OidcState) (string, error) {
	stateBytes, err := json.Marshal(state)

	if err != nil {
		return "", err
	}

	stateBase64 := base64.RawURLEncoding.EncodeToString(stateBytes)
	return stateBase64, nil
}

func DecodeState(base64State string) (*OidcState, error) {
	stateBytes, err := base64.RawURLEncoding.DecodeString(base64State)

	if err != nil {
		return nil, err
	}

	var state OidcState
	err2 := json.Unmarshal(stateBytes, &state)
	if err2 != nil {
		return nil, err2
	}

	return &state, nil
}
