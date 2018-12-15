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

// Printfer is an interface that represents a logger, enabling the caller to control where debug information is sent
type Printfer interface {
	Printf(format string, v ...interface{})
}

type nullPrintfer struct{}

func (nullPrintfer) Printf(string, ...interface{}) {
	return
}

// NullPrintfer is a no-op Printfer
var NullPrintfer = &nullPrintfer{}

type Actions map[string]bool

func (a Actions) String() string {
	s := "{ "
	for k, v := range a {
		s += fmt.Sprintf(" %s:%t, ", k, v)
	}
	s += "}"
	return s
}

// StatusCodeError indicate that an unexpected status code has been returned by the server
type StatusCodeError int

func (e StatusCodeError) Error() string {
	return fmt.Sprintf("received status code %d", e)
}

// OAuth2IDTokenInfo requests information about the OAuth2 token
func OAuth2IDTokenInfo(client Doer, baseURL, realm string, user User, idToken string, logger Printfer) (info []byte, err error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/oauth2/idtokeninfo?realm=%s", baseURL, realm),
		strings.NewReader(fmt.Sprintf("id_token=%s", idToken)))

	if err != nil {
		return info, err
	}

	req.SetBasicAuth(user.Username, user.Password)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}

	if resp.StatusCode != http.StatusOK {
		logger.Printf("status %d, body: %s", resp.StatusCode, string(body))
		return info, StatusCodeError(resp.StatusCode)
	}

	return body, nil
}

// Authenticate sends a request to authenticate the User
func Authenticate(client Doer, baseURL, realm string, user User, logger Printfer) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/json/realms/root/realms/%s/authenticate", baseURL, realm),
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
		logger.Printf("status %d, body: %s", resp.StatusCode, string(body))
		return body, err
	}

	if resp.StatusCode != http.StatusOK {
		return body, StatusCodeError(resp.StatusCode)
	}

	return body, nil
}

// PoliciesEvaluate evaluates the given resources
func PoliciesEvaluate(client Doer, baseURL, realm, app, cookieName, ssoToken string, idTokenInfo []byte, recources []string, logger Printfer) ([]byte, error) {
	type subject struct {
		Claims json.RawMessage `json:"claims"`
	}
	payloadData := struct {
		Resources   []string `json:"resources"`
		Application string   `json:"application"`
		Subject     subject  `json:"subject"`
	}{
		Resources:   recources,
		Application: app,
		Subject:     subject{Claims: idTokenInfo},
	}
	// The value passed to json.Marshal must be a pointer for json.RawMessage to work properly
	b, err := json.Marshal(&payloadData)
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
		logger.Printf("status %d, body: %s", resp.StatusCode, string(body))
		return body, StatusCodeError(resp.StatusCode)
	}
	return body, nil
}
