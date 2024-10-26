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
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"bou.ke/monkey"
	"golang.org/x/oauth2"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/server"
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
	redirectUri := "/rest/auth/callback"
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
		JWTPrivateKey:      []byte("i_am_the_secrets"),
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)
	// Mock AuthorizeThroughSession 方法
	monkey.PatchInstanceMethod(reflect.TypeOf(testFuyaoOAuthServer), "AuthorizeThroughSession", func(_ *FuyaoAuthorizeServer, w http.ResponseWriter, r *http.Request) (*authenticator.Response, constants.LoginStatus, error) {
		return &authenticator.Response{
			User: &user.DefaultInfo{
				Name:   "admin",
				UID:    "",
				Groups: []string{},
				Extra:  nil,
			},
		}, constants.LoggedIn, nil
	})

	defer monkey.UnpatchAll() // 确保在测试结束时还原补丁
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
	query.Add("redirect_uri", "/rest/auth/callback")
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
		JWTPrivateKey:      []byte("i_am_the_secrets"),
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
	query.Add("redirect_uri", "/rest/auth/callback")
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
		JWTPrivateKey:      []byte("i_am_the_secrets"),
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
		JWTPrivateKey:      []byte("i_am_the_secrets"),
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
		JWTPrivateKey:      []byte("i_am_the_secrets"),
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
		Value:   "MTczMDExNjg2MXxWSjJDaWhGTk1KQVpRS3RPOXhKQS1IMV9zR05OTzRjQ1RmRWt0ZDI2OWo0STJPUWN6U0tfdzhmbkgyOE4xSDFUYnE1NUJBdGNmTDlsQ19iYnpFemFpal96TG5KcUtzVmx1UXFVNlRmWlBOVG5RNWQ0OXdjLXM2eEZCUjBRNTNOVzlrNFpCN3h6akFFejhEaHpFaDItRVQtSTNEelUxVXpxN3ZXZk9UeEtjQXNaMHRpQ0RqcGU2TWVXV3FkcFUwcDZINHRMZmlDUUVhNmp1TkU5NmE1M3JQT3BQVFpleXVwNHVyTW43YVdQYnU4djBNQm9nbXc5cW1pelp5NllkRnJzR2JRT1RuZW1VOEFPZXYzdDJ4aUZsYXhRLXNTRDZKQ3Z4WGFVTGwzWENraWVLUWE1QmtvOTk1OU4wV3lRQi1VN05CT05sc0FIOXI1UW5zVEVObmlPVU9SU2hpcHRycnM1OE9OenJhb0htWkhacXNRbEZlSVhHUVg1S01ZR0p3ajVCNDlRZXUtcGVBNk4wa0FGSE53WTNMbHpYMmgtcUFxblctdndoT0hULTlMSUFlRnZVbmRPQ3BaTEZzU2h3UjR1U2ZjakR3RlJXU3dlRU1BcEtVaUhNb1Z5Rmc9PXyuo9OPqM568EZLy5Xw8dOogXsmhxFbkmyJuCrdFkf8rw==",
		Expires: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	req.AddCookie(fakeCookie)

	testOAuthServerSessionID := "ztnp2wrui7vf3v9vf8qd1it4rj2v9cqe"
	testOAuthPRoxySessionID := "test-session-id"
	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("ez9iuWcPd3wyqzSoW3cb3fDK0HwCH1oGj1rbzqp1gAk="), []byte("ZAh1t2uOJcv44OOmOqq8zlXHlshbse7TghtCJN5wxWU="))
	cfg := &config.OAuthServerConfig{
		CodeTokenNamespace: "oauth-code-token",
		AuthCodeExp:        time.Hour * 8760,
		AccessTokenExp:     time.Hour * 2,
		RefreshTokenExp:    time.Hour * 2,
		IsGenerateRefresh:  false,
		JWTKeyID:           "access_token_sign_key",
		JWTPrivateKey:      []byte("i_am_the_secrets"),
		ClientMapper: map[string]string{
			"console":     "console-password",
			"oauth-proxy": "SECRETTS",
		},
	}
	// 使用 gou.ke monkey 进行补丁

	testFuyaoOAuthServer := NewOAuthServer(fakeIdpLoginStore, fakeTokenStore, cfg)
	testFuyaoOAuthServer.oauthProxyStore[testOAuthServerSessionID] = map[string]string{testOAuthPRoxySessionID: proxyLogoutEndpoint}
	// 使用 monkey 进行补丁
	monkey.PatchInstanceMethod(reflect.TypeOf(testFuyaoOAuthServer.idpLoginStore), "Get", func(_ *sessions.CookieStore, r *http.Request) sessions.Values {
		return sessions.Values{
			constants.UserExtra: map[string][]string{constants.OAuthServerSessionID: {testOAuthServerSessionID}},
		}
	})

	// Mock Put 方法
	monkey.PatchInstanceMethod(reflect.TypeOf(testFuyaoOAuthServer.idpLoginStore), "Put", func(_ *sessions.CookieStore, w http.ResponseWriter, values sessions.Values) error {
		return nil // 模拟成功
	})

	// Mock Put 方法
	monkey.PatchInstanceMethod(reflect.TypeOf(sessions.Values{}), "GetExtraByKey", func(_ sessions.Values, key string) ([]string, bool) {
		return []string{testOAuthServerSessionID}, true // 模拟返回值
	})

	// 确保在测试结束时恢复补丁
	defer monkey.UnpatchAll()

	// run test
	rr := httptest.NewRecorder()
	testFuyaoOAuthServer.SingleLogoutHandler(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status code %d; got %d", http.StatusNoContent, rr.Code)
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
		JWTPrivateKey:      []byte("i_am_the_secrets"),
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
