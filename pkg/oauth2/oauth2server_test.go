/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * openFuyao is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package oauth2

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"openfuyao/oauth-server/cmd/oauth-server/app/config"
	"openfuyao/oauth-server/pkg/constants"
	"openfuyao/oauth-server/pkg/fuyaostore"
	"openfuyao/oauth-server/pkg/sessions"
)

// TestFuyaoAuthorizeServerOAuthAuthorizeHandlerSucceed test http handler for /oauth/authorize
func TestFuyaoAuthorizeServerOAuthAuthorizeHandlerSucceed(t *testing.T) {
	// prepare query parameters
	redirectUri := "http://192.168.100.48:9036/rest/auth/callback"
	query := url.Values{}
	query.Add("client_id", "console")
	query.Add("identity_provider", "fuyaoPasswordProvider")
	query.Add("redirect_uri", redirectUri)
	query.Add("response_type", "code")
	query.Add("state", "10a4d3a9")
	req, err := http.NewRequest("GET", constants.FuyaoOAuthAuthorizeEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.RawQuery = query.Encode()
	fakeCookie := &http.Cookie{
		Name:    "idpLogin",
		Value:   "MTcxNjYzMjc5Mnxsa2NwY055UUxRdVUwTjcyVUNRRzUtTE5FMW1VOC05TWtTdGZrYXhKRVYxLUtDcXplcjJBTm1ITXFrSlBOZnkzWVBiZ2FFM0t5Y1V3VTlFMkZuNWJFRTJvcmJwTjk5UXJpSTNqbGdLZllvTFRpRWFZSU4zNXh0TmNLZ2NEYUZWcm5id3RDVTZ3QmRDd3JWSm9lRUpTOWdxZk9FaVpsS3hmbWJBTU9NZlRKLXB6REZUVUdwM0FHZUkzeC1seEZ3RmZiX1gyZWFIYUxJRmlONDloRFVOZHJaRXVFazFGZzlhQnNnTHotRHJJUnlEZHVUVW13VW81bDJVdHJWWmlwSFc0VUFhWHZfeUVNRXl5T1JFbXB1WkUzYWRyZ0VoRWhjYXprRmt0NjVvYXJBcTRYeUFOZ1VxaEZ3bWZ0aW9lM2tMQy1teGdQUVNPbk40UkFVZU5OZm80NUdXS29YOXZYS0dUOFpWTmhKdElpRy1mZmRma1JVeXhpOUlxamJWVmVxeVJ6VllaYTdzNERad2NJOFNzeldHYm9xTnAxZW5hQjNjNlV3N01QVGxMeTM3YWM5MVc1aTZoRnJiZGxWUkFHOC05SmRjei1qVjhBanViSWc9PXzDmy8u3Jdey5SMnWC9vwYlO_biv4GPXk9wJbyrAeC3Mw==",
		Expires: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	req.AddCookie(fakeCookie)

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Minute * 5,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)

	rr := httptest.NewRecorder()
	testFuyaoOAuthServer.OAuthAuthorizeHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}

	location := redirectUri + "?code="
	if !strings.HasPrefix(rr.Header().Get("Location"), location) {
		t.Errorf("Expected location prefix %s; get %s", location, rr.Header().Get("Location"))
	}
}

// TestFuyaoAuthorizeServerOAuthAuthorizeHandlerNoSession test http handler for /oauth/authorize
func TestFuyaoAuthorizeServerOAuthAuthorizeHandlerNoSession(t *testing.T) {
	// prepare query parameters
	query := url.Values{}
	query.Add("client_id", "console")
	query.Add("identity_provider", "fuyaoPasswordProvider")
	query.Add("redirect_uri", "http://192.168.100.48:9036/rest/auth/callback")
	query.Add("response_type", "code")
	query.Add("state", "10a4d3a9")
	req, err := http.NewRequest("GET", constants.FuyaoOAuthAuthorizeEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.RawQuery = query.Encode()

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Minute * 5,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)

	rr := httptest.NewRecorder()
	testFuyaoOAuthServer.OAuthAuthorizeHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}

	cookieSet := rr.Header().Get("Set-Cookie")
	if !strings.HasPrefix(cookieSet, "idpLogin=") {
		t.Errorf("Expected cookie set but it didn't")
	}

	location := constants.FuyaoLoginEndpoint + "?then=" + url.QueryEscape(req.URL.String())
	if rr.Header().Get("Location") != location {
		t.Errorf("Expected locatin %s; get %s", location, rr.Header().Get("Location"))
	}
}

// TestFuyaoAuthorizeServerOAuthAuthorizeHandlerFirstLogin test http handler for /oauth/authorize
func TestFuyaoAuthorizeServerOAuthAuthorizeHandlerFirstLogin(t *testing.T) {
	// prepare query parameters
	query := url.Values{}
	query.Add("client_id", "console")
	query.Add("identity_provider", "fuyaoPasswordProvider")
	query.Add("redirect_uri", "http://192.168.100.48:9036/rest/auth/callback")
	query.Add("response_type", "code")
	query.Add("state", "10a4d3a9")
	req, err := http.NewRequest("GET", constants.FuyaoOAuthAuthorizeEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.RawQuery = query.Encode()
	fakeCookie := &http.Cookie{
		Name:    "idpLogin",
		Value:   "MTcxNjc0NDE3NXxUb2p2d0JsalhFU0Zrc2tkWkZnQUN5ckVlX2hoYU5QZFNUeTJQX1c2THdmeVhBYklqRkg2Rk1yYlhVelNXelQwRnRkRHMyUDhPbVA3Qncta3RLZWhxeU9TTzZXWWgwSXhiNE42ZXhIWmZFcTBpVV9WZ01ORzdJcENnZzE3amMzbllaLTBubVFNOHFPTFA3WTRrVGdlOXRjeS1pSE1hYS1qYXFGbnFBUVRXeENCT19wOE1NNmktbHBvQjdKMjdYYjBjZ2wtX0xhcXlhMHFWWEowSUZfdzFJbGkzMUh3YUlDUXhodjdzLUtRamE2bzhMamNEeXh6bTFMeVAxaWtXZy04Q3FvUDc4QWtZS1NKRUJFX0NUU2ZFamNlanpnakRydkxrRXRQQ2lfZEZTN0J5TUR2a3NTdXk4NGp3WkVLaGllVnM4bGRGQXo2ZjFtVXhjWHFiMWsySm5sbllKQ3BKaDd2TGlfUm9YRVdVblJ3YUctMk8yNUp6cmxTcGtHY2I2RXFxQTdHUXNHS3pVSGdTYzgwYm5kNjJMZHZzeERibFJCbEtBdTJBV2lDQ1dKVm5MZlBnMDFCQXUwaWtSc3hWLUhEcldxMG16azNYZG83TXc9PXxZxTOclZv7gL1dnb7Co329a3GuvJCJmaN28kQ481F4_Q==",
		Expires: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	req.AddCookie(fakeCookie)

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Minute * 5,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)

	rr := httptest.NewRecorder()
	testFuyaoOAuthServer.OAuthAuthorizeHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}

	location := constants.FuyaoLoginEndpoint + "?then=" + url.QueryEscape(req.URL.String())
	if rr.Header().Get("Location") != location {
		t.Errorf("Expected location %s; get %s", location, rr.Header().Get("Location"))
	}
}

// TestFuyaoAuthorizeServerOAuthTokenHandlerCodeExpired test http handler for /oauth/token
func TestFuyaoAuthorizeServerOAuthTokenHandlerCodeExpired(t *testing.T) {
	// with correct code
	// prepare form parameters
	form := url.Values{}
	testCode := "zjhjoddimwutyzjkni0zzwe3lwfhngutothkmwy0ngzjnmjj"
	testOAuthServerSessionID := "testIDPSessionID"
	form.Add("code", testCode)
	form.Add("grant_type", "authorization_code")
	form.Add("logout_endpoint", "https://192.168.100.9091/oauth/logout")
	form.Add("redirect_uri", "https://192.168.100.48:9091/oauth/callback")
	form.Add("session_id", "testsessionidtryme")
	form.Add("client_id", "oauth-proxy")
	form.Add("client_secret", "SECRETTS")

	// prepare request
	req, err := http.NewRequest("POST", constants.FuyaoOAuthTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// prepare authcode secret
	testCodeSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.CodePrefix + testCode,
			Namespace: "oauth-code-token",
		},
		Data: map[string][]byte{
			"userinfo": []byte(`{"ClientID":"oauth-proxy","UserID":"admin","RedirectURI":"https://192.168.100.48:9091/oauth/callback","Scope":"user:info user:check-access","Code":"zjhjoddimwutyzjkni0zzwe3lwfhngutothkmwy0ngzjnmjj","CodeChallenge":"","CodeChallengeMethod":"","CodeCreateAt":"2024-05-27T10:34:51.973738633+08:00","CodeExpiresIn":300000000000,"Access":"","AccessCreateAt":"0001-01-01T00:00:00Z","AccessExpiresIn":0,"Refresh":"","RefreshCreateAt":"0001-01-01T00:00:00Z","RefreshExpiresIn":0}`),
		},
	}
	fakeClient := fake.NewSimpleClientset(testCodeSecret)
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Hour * 8760,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)
	testFuyaoOAuthServer.authCode2SessionID = map[string]string{testCode: testOAuthServerSessionID}
	testFuyaoOAuthServer.oauthProxyStore = make(map[string]map[string]string)

	// run test
	rr := httptest.NewRecorder()
	testFuyaoOAuthServer.OAuthTokenHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d; got %d", http.StatusUnauthorized, rr.Code)
	}

	body, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	bodyStr := string(body)
	expectedBodyStr := `{"error":"invalid_grant","error_description":"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client"}` + "\n"
	if bodyStr != expectedBodyStr {
		t.Errorf("Expected return body %s; got %s", expectedBodyStr, bodyStr)
	}
}

// TestFuyaoAuthorizeServerOAuthTokenHandlerSucceed test http handler for /oauth/token
func TestFuyaoAuthorizeServerOAuthTokenHandlerSucceed(t *testing.T) {
	// prepare form parameters
	form := url.Values{}
	testCode := "oda1mthhmtutmgfknc0zyjdllwe5ztetzmi5mwm0owuyzjbm"
	testOAuthServerSessionID := "testIDPSessionID"
	form.Add("code", testCode)
	form.Add("grant_type", "authorization_code")
	form.Add("logout_endpoint", "https://192.168.100.9091/oauth/logout")
	form.Add("redirect_uri", "https://192.168.100.48:9091/oauth/callback")
	form.Add("session_id", "testsessionidtryme")
	form.Add("client_id", "oauth-proxy")
	form.Add("client_secret", "SECRETTS")

	// prepare request
	req, err := http.NewRequest("POST", constants.FuyaoOAuthTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// prepare authcode secret
	testCodeSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.CodePrefix + testCode,
			Namespace: "oauth-code-token",
		},
		Data: map[string][]byte{
			"userinfo": []byte(`{"ClientID":"oauth-proxy","UserID":"admin","RedirectURI":"https://192.168.100.48:9091/oauth/callback","Scope":"user:info user:check-access","Code":"oda1mthhmtutmgfknc0zyjdllwe5ztetzmi5mwm0owuyzjbm","CodeChallenge":"","CodeChallengeMethod":"","CodeCreateAt":"2024-05-27T11:29:35.378162227+08:00","CodeExpiresIn":315360000000000000,"Access":"","AccessCreateAt":"0001-01-01T00:00:00Z","AccessExpiresIn":0,"Refresh":"","RefreshCreateAt":"0001-01-01T00:00:00Z","RefreshExpiresIn":0}`),
		},
	}
	fakeClient := fake.NewSimpleClientset(testCodeSecret)
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Hour * 8760,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)
	testFuyaoOAuthServer.authCode2SessionID = map[string]string{testCode: testOAuthServerSessionID}
	testFuyaoOAuthServer.oauthProxyStore = make(map[string]map[string]string)

	// run test
	rr := httptest.NewRecorder()
	testFuyaoOAuthServer.OAuthTokenHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d; got %d", http.StatusOK, rr.Code)
	}

	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	var returnedToken oauth2.Token
	if err = json.Unmarshal(body, &returnedToken); err != nil {
		t.Fatal(err)
	}

	if returnedToken.AccessToken == "" || returnedToken.TokenType != "Bearer" {
		t.Errorf("Expected return token is invalid")
	}

}

// TestFuyaoAuthorizeServerSingleLogoutHandlerSucceed test http handler for /auth/logout
func TestFuyaoAuthorizeServerSingleLogoutHandlerSucceed(t *testing.T) {
	// prepare form parameters
	redirectUri := "https://192.168.100.48:9036/rest/auth/login"
	query := url.Values{}
	proxyLogoutEndpoint := "https://192.168.100.48:9091/oauth/logout"
	query.Add("redirect_uri", redirectUri)

	// prepare request
	req, err := http.NewRequest("POST", constants.FuyaoLogoutEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.RawQuery = query.Encode()

	fakeCookie := &http.Cookie{
		Name:    "idpLogin",
		Value:   "MTcxNjc4MjIwMXxxelZzUWlXcXViR1F3Um84TU5KZjhoZXNaSk1rN2wzeGFRbml3b0MxYVR5ZEMtRG5IeVZRX3B6VllwX3EyeEZVU0dlRm1STHQ5b2RfdW1CMjVhUDlKQ21feXZuSUtkNXJiamo0eEkzNzRIb1Etb3dyZ0lXcHcwTlhqaUNnM1hBNnhyS2lLLXMtYXI2VXNydDhjYWJBZDV2U3BTYWQxaHVTME91M3poWk0yMTRWNHczME96XzdsSUVMNnZnNWFKWVhKVTZrdHRxa0JidFRzb253bVpXaXFOd3QzSHE0aWxDc0xya0kxZFhLcGhCYVdhdGtfUWNrVzlDSFZ5ZENJdTVRT1lGNV9GVDFNZy14WFU4ZDg2RERVeFRrUVROSDJsT0kzczNyRUo0SWhpdUVVb1ZQWHdFY21zZTFXSFRqdHRYVFlCYTJYUUhsVjlxOW04X0NlWHh6X1lLVTRKb0UxYk1XcWNBOHU2LTBNRkdaY1pDdlVveGE5b2JfQ2pubUljSjZ2eTREajNCSEo2V2x4NlZSNkl0czhJdE5WQjctQU9VV2k4QWpqVGh1V1Mzd0xvQ211cEVRUVh3VHFWQkFDcHdKVUtXX091eDNodGxxYWg0PXzZzou4XjM-YH1ki-UhtByIdt0dzoPjyxgnbZCm3GHL3Q==",
		Expires: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	req.AddCookie(fakeCookie)

	testOAuthServerSessionID := "ztnp2wrui7vf3v9vf8qd1it4rj2v9cqe"
	testOAuthPRoxySessionID := "test-session-id"
	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Hour * 8760,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)
	testFuyaoOAuthServer.oauthProxyStore[testOAuthServerSessionID] = map[string]string{testOAuthPRoxySessionID: proxyLogoutEndpoint}

	// run test
	rr := httptest.NewRecorder()
	testFuyaoOAuthServer.SingleLogoutHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}

	if !strings.HasPrefix(rr.Header().Get("Location"), redirectUri) {
		t.Errorf("Expected location prefix %s; get %s", redirectUri, rr.Header().Get("Location"))
	}

	cookieSet := rr.Header().Get("Set-Cookie")
	if !strings.HasPrefix(cookieSet, "idpLogin=") {
		t.Errorf("Expected cookie set but it didn't")
	}
}

// TestFuyaoAuthorizeServerSingleLogoutHandlerNoServerSession test http handler for /auth/logout
func TestFuyaoAuthorizeServerSingleLogoutHandlerNoServerSession(t *testing.T) {
	// prepare form parameters
	query := url.Values{}
	redirectUri := "https://192.168.100.48:9036/rest/auth/login"
	query.Add("redirect_uri", redirectUri)

	// prepare request
	req, err := http.NewRequest("POST", constants.FuyaoLogoutEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.RawQuery = query.Encode()

	fakeCookie := &http.Cookie{
		Name:    "idpLogin",
		Value:   "MTcxNjc0NDE3NXxUb2p2d0JsalhFU0Zrc2tkWkZnQUN5ckVlX2hoYU5QZFNUeTJQX1c2THdmeVhBYklqRkg2Rk1yYlhVelNXelQwRnRkRHMyUDhPbVA3Qncta3RLZWhxeU9TTzZXWWgwSXhiNE42ZXhIWmZFcTBpVV9WZ01ORzdJcENnZzE3amMzbllaLTBubVFNOHFPTFA3WTRrVGdlOXRjeS1pSE1hYS1qYXFGbnFBUVRXeENCT19wOE1NNmktbHBvQjdKMjdYYjBjZ2wtX0xhcXlhMHFWWEowSUZfdzFJbGkzMUh3YUlDUXhodjdzLUtRamE2bzhMamNEeXh6bTFMeVAxaWtXZy04Q3FvUDc4QWtZS1NKRUJFX0NUU2ZFamNlanpnakRydkxrRXRQQ2lfZEZTN0J5TUR2a3NTdXk4NGp3WkVLaGllVnM4bGRGQXo2ZjFtVXhjWHFiMWsySm5sbllKQ3BKaDd2TGlfUm9YRVdVblJ3YUctMk8yNUp6cmxTcGtHY2I2RXFxQTdHUXNHS3pVSGdTYzgwYm5kNjJMZHZzeERibFJCbEtBdTJBV2lDQ1dKVm5MZlBnMDFCQXUwaWtSc3hWLUhEcldxMG16azNYZG83TXc9PXxZxTOclZv7gL1dnb7Co329a3GuvJCJmaN28kQ481F4_Q==",
		Expires: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	req.AddCookie(fakeCookie)

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Hour * 8760,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)

	// run test
	rr := httptest.NewRecorder()
	testFuyaoOAuthServer.SingleLogoutHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}

	if !strings.HasPrefix(rr.Header().Get("Location"), redirectUri) {
		t.Errorf("Expected location prefix %s; get %s", redirectUri, rr.Header().Get("Location"))
	}

	cookieSet := rr.Header().Get("Set-Cookie")
	if !strings.HasPrefix(cookieSet, "idpLogin=") {
		t.Errorf("Expected cookie set but it didn't")
	}
}

// TestNewOAuthServer test initializing OAuthServer
func TestNewOAuthServer(t *testing.T) {
	type args struct {
		idpLoginStore *sessions.CookieStore
		tokenStore    *fuyaostore.K8sSecretStore
		cfg           *config.OAuthServerConfig
	}
	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Minute * 5,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      "i_am_the_secrets",
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	fakeManager := manage.NewDefaultManager()
	tgt := NewFuyaoAuthorizeServer(server.NewConfig(), fakeManager, fakeIdpLoginStore, fakeTokenStore)
	tests := []struct {
		name string
		args args
		want *FuyaoAuthorizeServer
	}{
		{
			"successfully initialized",
			args{
				idpLoginStore: fakeIdpLoginStore,
				tokenStore:    fakeTokenStore,
				cfg:           cfg,
			},
			tgt,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewOAuthServer(tt.args.idpLoginStore, tt.args.tokenStore, tt.args.cfg); !reflect.DeepEqual(got.Config, tt.want.Config) {
				t.Errorf("NewOAuthServer() = %v, want %v", got, tt.want)
			}
		})
	}
}
