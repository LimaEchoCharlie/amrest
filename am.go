package amrest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

// Doer is an interface that represents a http client
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// StatusCodeError indicate that an unexpected status code has been returned by the server
type StatusCodeError int

func (e StatusCodeError) Error() string {
	return fmt.Sprintf("received status code %d", e)
}

// OAuth2IDTokenInfo requests information about the OAuth2 token
func OAuth2IDTokenInfo(client Doer, baseURL, realm string, user User, idToken string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/oauth2/idtokeninfo?realm=%s", baseURL, realm),
		strings.NewReader(fmt.Sprintf("id_token=%s", idToken)))

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(user.Username, user.Password)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return body, StatusCodeError(resp.StatusCode)
	}
	return body, nil
}

// AuthenticateResponse is the response to a Authenticate request
type AuthenticateResponse struct {
	TokenID string `json:"tokenId"`
}

// Authenticate sends a request to authenticate the User
func Authenticate(client Doer, baseURL, realm string, user User) ([]byte, error) {
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

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}

	if resp.StatusCode != http.StatusOK {
		return body, StatusCodeError(resp.StatusCode)
	}
	return body, nil
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

// PoliciesEvaluate evaluates the given resources
func PoliciesEvaluate(client Doer, baseURL, realm, cookieName, ssoToken string, policies *Policies) ([]byte, error) {
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

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return body, StatusCodeError(resp.StatusCode)
	}
	return body, nil
}
