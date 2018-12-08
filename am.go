package amrest

import (
	"fmt"
	"strings"
	"net/http"
	"io/ioutil"
	"bytes"
	"errors"
	"encoding/json"
)

type User struct {
	Username string
	Password string
}

type Actions map[string]bool

// OAuth2IDTokenInfo requests information about the OAuth2 token
func OAuth2IDTokenInfo(baseURL, realm string, user User, idToken string) (info []byte, err error) {
	url := fmt.Sprintf("%s/oauth2/idtokeninfo?realm=%s", baseURL, realm)

	reqBody := strings.NewReader(fmt.Sprintf("id_token=%s", idToken))
	req, err := http.NewRequest(http.MethodPost, url, reqBody)
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return info, errors.New(fmt.Sprintf("Status %s", resp.Status))
	}

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}
	return resBody, nil
}

// Authenticate sends a request to authenticate the User
func Authenticate(baseURL, realm string, user User) (string, error) {
	url := fmt.Sprintf("%s/json/realms/root/realms/%s/authenticate", baseURL, realm)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Accept-API-Version", "resource=2.0, protocol=1.0")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-OpenAM-Username", user.Username)
	req.Header.Add("X-OpenAM-Password", user.Password)
	req.Header.Add("cache-control", "no-cache")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("Status %s", res.Status))
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	response := struct {
		TokenID string `json:"tokenId"`
	}{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}
	return response.TokenID, nil
}

// PoliciesEvaluate evaluates the given resources
func PoliciesEvaluate(baseURL, realm, app string, idTokenInfo json.RawMessage, SSOToken string, recources []string) (Actions, error) {
	url := fmt.Sprintf("%s/json/policies?_action=evaluate&realm=%s", baseURL, realm)
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

	payload := bytes.NewReader(b)
	req, _ := http.NewRequest(http.MethodPost, url, payload)

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Cookie", fmt.Sprintf("iPlanetDirectoryPro=%s", SSOToken))
	req.Header.Add("cache-control", "no-cache")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var response []struct {
		Actions Actions
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if len(response) != 1 {
		return nil, fmt.Errorf("expected only one resource; got %d", len(response))
	}
	return response[0].Actions, nil

}
