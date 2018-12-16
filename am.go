package amrest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// User contains information needed for the basic authorisation of a request
type User struct {
	Username string
	Password string
}

func (u User) String() string {
	return fmt.Sprintf("{u: %s, p: %s}", u.Username, u.Password)
}

// OAuth2IDTokenInfoRequest creates a request to get information about the OAuth2 token
func OAuth2IDTokenInfoRequest(baseURL, realm string, user User, idToken string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/oauth2/idtokeninfo?realm=%s", baseURL, realm),
		strings.NewReader(fmt.Sprintf("id_token=%s", idToken)))

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(user.Username, user.Password)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// AuthenticateResponse is the response to a Authenticate request
type AuthenticateResponse struct {
	TokenID string `json:"tokenId"`
}

// AuthenticateRequest creates a request that authenticates a User
func AuthenticateRequest(baseURL, realm string, user User) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/json/authenticate?realm=%s", baseURL, realm),
		nil)

	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept-API-Version", "resource=2.0, protocol=1.0")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-OpenAM-Username", user.Username)
	req.Header.Add("X-OpenAM-Password", user.Password)
	req.Header.Add("cache-control", "no-cache")

	return req, nil
}

// Policies describes an action
type Policies struct {
	Resources   []string `json:"resources"`
	Application string   `json:"application"`
	Subject     struct {
		Claims json.RawMessage `json:"claims,omitempty"`
	} `json:"subject"`
}

// NewPolicies creates a new set of policies
// An additional method call will be needed to add subject(s) to the Policies
func NewPolicies(resources []string, application string) *Policies {
	return &Policies{Resources: resources, Application: application}
}

// AddClaims adds JWT claims to the Policies
func (p *Policies) AddClaims(c []byte) *Policies {
	p.Subject.Claims = c
	return p
}

// A map of action names to bool values that indicate whether the action is allowed or denied for the specified
// resource
type actions map[string]bool

func (a actions) String() string {
	s := "{ "
	for k, v := range a {
		s += fmt.Sprintf(" %s:%t,", k, v)
	}
	s += "}"
	return s
}

// PolicyEvaluation is a policy evaluation response for a single resource
type PolicyEvaluation struct {
	Resource string  `json:"resource"`
	Actions  actions `json:"actions"`
}

// PoliciesEvaluateRequest creates a request that evaluates the given policies
func PoliciesEvaluateRequest(baseURL, realm, cookieName, ssoToken string, policies *Policies) (*http.Request, error) {
	// The value passed to json.Marshal must be a pointer for json.RawMessage to work properly
	b, err := json.Marshal(policies)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/json/policies?_action=evaluate&realm=%s", baseURL, realm),
		bytes.NewReader(b))

	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Cookie", fmt.Sprintf("%s=%s", cookieName, ssoToken))
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("Accept-API-Version", "resource=2.0, protocol=1.0")

	return req, nil
}
