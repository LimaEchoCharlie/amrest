package amrest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type User struct {
	Username string
	Password string
}

func (u User) String() string {
	return fmt.Sprintf("{u: %s, p: %s}", u.Username, u.Password)
}

type Actions map[string]bool

type statusResponseError int

func (e statusResponseError) Error() string {
	return fmt.Sprintf("received status code %d", e)
}

// OAuth2IDTokenInfo requests information about the OAuth2 token
func OAuth2IDTokenInfo(baseURL, realm string, user User, idToken string) (info []byte, err error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/oauth2/idtokeninfo?realm=%s", baseURL, realm),
		strings.NewReader(fmt.Sprintf("id_token=%s", idToken)))

	if err != nil {
		return info, err
	}

	req.SetBasicAuth(user.Username, user.Password)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return info, err
	}
	if resp.StatusCode != http.StatusOK {
		return info, statusResponseError(resp.StatusCode)
	}

	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}
	return resBody, nil
}

// Authenticate sends a request to authenticate the User
func Authenticate(baseURL, realm string, user User) (string, error) {
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/json/realms/root/realms/%s/authenticate", baseURL, realm),
		nil)

	if err != nil {
		return "", err
	}

	req.Header.Add("Accept-API-Version", "resource=2.0, protocol=1.0")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-OpenAM-Username", user.Username)
	req.Header.Add("X-OpenAM-Password", user.Password)
	req.Header.Add("cache-control", "no-cache")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", statusResponseError(resp.StatusCode)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	info := struct {
		TokenID string `json:"tokenId"`
	}{}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", err
	}
	return info.TokenID, nil
}

// PoliciesEvaluate evaluates the given resources
func PoliciesEvaluate(baseURL, realm, app, cookieName, ssoToken string, idTokenInfo json.RawMessage, recources []string) (Actions, error) {
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
	b, err := json.Marshal(payloadData)
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusResponseError(resp.StatusCode)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var evaluation []struct {
		Actions Actions
	}

	if err := json.Unmarshal(body, &evaluation); err != nil {
		return nil, err
	}
	if len(evaluation) != 1 {
		return nil, fmt.Errorf("expected only one resource; got %d", len(evaluation))
	}
	return evaluation[0].Actions, nil
}
