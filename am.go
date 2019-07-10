package amrest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// OAuth2Client represents an AM OAuth2 client
type OAuth2Client struct {
	baseURL string
	realm   string
	id      string
	secret  string
}

// NewOAuth2ClientWithSecret creates a new OAuth2 client that uses the supplied secret to authenticate itself
func NewOAuth2ClientWithSecret(baseURL, realm, id, secret string) OAuth2Client {
	return OAuth2Client{baseURL: baseURL, realm: realm, id: id, secret: secret}
}

// Introspect creates a request to introspect the given OAuth2 token
func (o OAuth2Client) Introspect(token string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/oauth2/realms/root/realms%s/introspect", o.baseURL, o.realm),
		strings.NewReader(fmt.Sprintf("token=%s", token)))

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(o.id, o.secret)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// IDTokenInfo creates a request to request information about the OAuth2 id token
func (o OAuth2Client) IDTokenInfo(idToken string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/oauth2/idtokeninfo?realm=%s", o.baseURL, o.realm),
		strings.NewReader(fmt.Sprintf("id_token=%s", idToken)))

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(o.id, o.secret)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// IntrospectionResponse contains the data returned by the server to an introspection request
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	Username  string `json:"username"`
	TokenType string `json:"token_type"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	Nbf       int64  `json:"nbf"`
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	Iss       string `json:"iss"`
	Jti       string `json:"jti"`
}

// User contains information needed for the basic authorisation of a request
type User struct {
	Username string
	Password string
}

func (u User) String() string {
	return fmt.Sprintf("{u: %s, p: %s}", u.Username, u.Password)
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
