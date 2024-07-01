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

package fuyaopassword

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"openfuyao/oauth-server/cmd/oauth-server/app/config"
	"openfuyao/oauth-server/pkg/authenticators"
	"openfuyao/oauth-server/pkg/constants"
	"openfuyao/oauth-server/pkg/fuyaostore"
	"openfuyao/oauth-server/pkg/protector"
	"openfuyao/oauth-server/pkg/sessions"
)

// TestLoginHandlerGetSucceed tests the successful condition for getting login page
func TestLoginHandlerGetSucceed(t *testing.T) {
	req, err := http.NewRequest("GET", constants.FuyaoLoginEndpoint+"?then=/", nil)
	if err != nil {
		t.Fatal(err)
	}

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}
	rr := httptest.NewRecorder()
	testLogin.LoginHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d; got %d", http.StatusOK, rr.Code)
	}
}

// TestLoginHandlerPostSucceed tests the successful condition for logging in
func TestLoginHandlerPostSucceed(t *testing.T) {
	form := url.Values{}
	form.Add("username", "admin")
	form.Add("password", "Soup4@LL")
	form.Add("csrf_token", "")
	form.Add("then", "/oauth2/oauth/authorize?client_id=console&identity_provider=fuyaoPasswordProvider&redirect_uri=https%3A%2F%2F192.168.100.48%3A31616%2Frest%2Fauth%2Fcallback&response_type=code&state=d7e6a4b3")
	req, err := http.NewRequest("POST", constants.FuyaoLoginEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	testUserSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin",
			Namespace: "oauth-user",
		},
		Data: map[string][]byte{
			"username":           []byte("admin"),
			"groups":             []byte("system:admin"),
			"extra":              []byte(`{"first-login":["false"]}`),
			"encrypted-password": []byte("lXc1sa8Y/6AWFg5LXUBo+iccNxwvcwot3rXlOaY40nvSW9+3pp+EXY7pypWnVdLh3wOrds1UOUjr8BhlyycPqNUbqSvGOQi6nqcEJc7T9zQ="),
		},
	}
	fakeClient := fake.NewSimpleClientset(testUserSecret)
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}
	rr := httptest.NewRecorder()
	testLogin.LoginHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}
}

// TestLoginHandlerPostFail tests the failed condition for logging in
func TestLoginHandlerPostFail(t *testing.T) {
	form := url.Values{}
	then := "/oauth2/oauth/authorize?client_id=console&identity_provider=fuyaoPasswordProvider&redirect_uri=https%3A%2F%2F192.168.100.48%3A31616%2Frest%2Fauth%2Fcallback&response_type=code&state=d7e6a4b3"
	form.Add("username", "admin")
	form.Add("password", "Soup4@LLL")
	form.Add("csrf_token", "")
	form.Add("then", then)
	req, err := http.NewRequest("POST", constants.FuyaoLoginEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	testUserSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin",
			Namespace: "oauth-user",
		},
		Data: map[string][]byte{
			"username":           []byte("admin"),
			"groups":             []byte("system:admin"),
			"extra":              []byte(`{"first-login":["false"]}`),
			"encrypted-password": []byte("lXc1sa8Y/6AWFg5LXUBo+iccNxwvcwot3rXlOaY40nvSW9+3pp+EXY7pypWnVdLh3wOrds1UOUjr8BhlyycPqNUbqSvGOQi6nqcEJc7T9zQ="),
		},
	}
	fakeClient := fake.NewSimpleClientset(testUserSecret)
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}
	rr := httptest.NewRecorder()
	testLogin.LoginHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}

	if rr.Header().Get("Location")[:20] != "/oauth2/auth/login/fuyaoPasswordProvider"[:20] {
		t.Errorf("Expected Location %s; got %s", then, rr.Header().Get("Location"))
	}
}

// TestLoginHandlerUnknownMethod tests the successful condition for logging in
func TestLoginHandlerUnknownMethod(t *testing.T) {
	req, err := http.NewRequest("PATCH", constants.FuyaoLoginEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}
	rr := httptest.NewRecorder()
	testLogin.LoginHandler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d; got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

// TestLoginPasswordConfirmHandlerGetSucceed tests the successful condition for password confirmation
func TestLoginPasswordConfirmHandlerGetSucceed(t *testing.T) {
	req, err := http.NewRequest("GET", constants.FuyaoPasswordConfirmEndpoint+`?then=/`, nil)
	if err != nil {
		t.Fatal(err)
	}
	fakeCookie := &http.Cookie{
		Name:    "idpLogin",
		Value:   "MTcxOTgxODEyN3x1Sy1JSmRWTGF6S20wekFjenAzbXpQMnBwdkczd19QYzRfbTNxWWxOVUJEV2xEU1BIS0xNeTV3Wk82T0JPY04zNmhyZGJVcDZZb1Q3bmdLRE5YN1pQLTlkMnhZTTFTX2RqWkJQMTI3TUNqSk9SalZ0Nk1BZDNRX0ZmaGFtRDctWlBEdk94RXB4NjNKWnhsZUZRZ3o2a1NFQmp5akl2Z2tLdEVPTmNGWno1eGNVbFExOUNFSzBmc0xTT2pTNFJoMDhmNGkycVJpbmZma0g3aV9NZFZQakV5alF4d2pLTHg1NDB6TW83UFZpd2txOTBKMjFSZUNNblpFYl9ORnlYdFFrQy1lYUZ4Y0ROc19YM2hVTldldV9pSzJLZnFaU1lCdTJEdnFzemoxLWVybkJaQ1FWRDZVQzg4bl83NjFFOEdzNXFLV3Z0Y0JiRUtoVHJKdTZmdWgzZHNwWGxrQzZVRnQtVy1DbktGdy0tN09zZ3RSWVlLY2VkeFRpUlJqTmdacVRHYkRaaHh2SnlFRl9KTWNwdGxiTVRscVdNQ3JEMUw3V3ZFYWFFTVJocHhSLXlhZF9oWlByWDBWUV90WVJORmpqeVpWaGhHb2RxUjNvfIVeE2zLQq3m_hK9Is9cGn1moYm6OYuD_Q7yuqgYKVCG",
		Expires: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	req.AddCookie(fakeCookie)

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}
	rr := httptest.NewRecorder()
	testLogin.PasswordConfirmHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d; got %d", http.StatusOK, rr.Code)
	}
}

// TestLoginPasswordConfirmHandlerPostSucceed tests the successful condition for password confirmation
func TestLoginPasswordConfirmHandlerPostSucceed(t *testing.T) {
	// prepare forms
	form := url.Values{}
	form.Add("new_password", "soup4@LL")
	then := "/oauth2/oauth/authorize?client_id=console&identity_provider=fuyaoPasswordProvider&redirect_uri=https%3A%2F%2F192.168.100.48%3A31616%2Frest%2Fauth%2Fcallback&response_type=code&state=d7e6a4b3"
	form.Add("then", then)
	req, err := http.NewRequest("POST", constants.FuyaoPasswordConfirmEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fakeCookie := &http.Cookie{
		Name:    "idpLogin",
		Value:   "MTcxOTgxODEyN3x1Sy1JSmRWTGF6S20wekFjenAzbXpQMnBwdkczd19QYzRfbTNxWWxOVUJEV2xEU1BIS0xNeTV3Wk82T0JPY04zNmhyZGJVcDZZb1Q3bmdLRE5YN1pQLTlkMnhZTTFTX2RqWkJQMTI3TUNqSk9SalZ0Nk1BZDNRX0ZmaGFtRDctWlBEdk94RXB4NjNKWnhsZUZRZ3o2a1NFQmp5akl2Z2tLdEVPTmNGWno1eGNVbFExOUNFSzBmc0xTT2pTNFJoMDhmNGkycVJpbmZma0g3aV9NZFZQakV5alF4d2pLTHg1NDB6TW83UFZpd2txOTBKMjFSZUNNblpFYl9ORnlYdFFrQy1lYUZ4Y0ROc19YM2hVTldldV9pSzJLZnFaU1lCdTJEdnFzemoxLWVybkJaQ1FWRDZVQzg4bl83NjFFOEdzNXFLV3Z0Y0JiRUtoVHJKdTZmdWgzZHNwWGxrQzZVRnQtVy1DbktGdy0tN09zZ3RSWVlLY2VkeFRpUlJqTmdacVRHYkRaaHh2SnlFRl9KTWNwdGxiTVRscVdNQ3JEMUw3V3ZFYWFFTVJocHhSLXlhZF9oWlByWDBWUV90WVJORmpqeVpWaGhHb2RxUjNvfIVeE2zLQq3m_hK9Is9cGn1moYm6OYuD_Q7yuqgYKVCG",
		Expires: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	req.AddCookie(fakeCookie)

	testUserSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin",
			Namespace: "oauth-user",
		},
		Data: map[string][]byte{
			"username":           []byte("admin"),
			"groups":             []byte("system:admin"),
			"extra":              []byte(`{"first-login":["true"]}`),
			"encrypted-password": []byte("lXc1sa8Y/6AWFg5LXUBo+iccNxwvcwot3rXlOaY40nvSW9+3pp+EXY7pypWnVdLh3wOrds1UOUjr8BhlyycPqNUbqSvGOQi6nqcEJc7T9zQ="),
		},
	}
	fakeClient := fake.NewSimpleClientset(testUserSecret)
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}
	rr := httptest.NewRecorder()
	testLogin.PasswordConfirmHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Errorf("Expected Set-Cookie key in header but it does show up")
	}

	if rr.Header().Get("Location") != then {
		t.Errorf("Expected Location %s; got %s", then, rr.Header().Get("Location"))
	}
}

// TestLoginPasswordResetHandlerPostSucceed tests the successful condition for password reset
func TestLoginPasswordResetHandlerPostSucceed(t *testing.T) {
	// 构造请求体
	requestBody := PasswordResetRequest{
		Username:         "admin",
		OriginalPassword: "Soup4@LL",
		NewPassword:      "soup4@LL",
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}
	req, err := http.NewRequest("POST", constants.FuyaoPasswordModifyEndpoint, bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	// 设置请求头
	req.Header.Set("Content-Type", "application/json")

	// add token header
	bearerToken := "test-test"
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	// add fake secrets
	testUserSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin",
			Namespace: "oauth-user",
		},
		Data: map[string][]byte{
			"username":           []byte("admin"),
			"groups":             []byte("system:admin"),
			"extra":              []byte(`{"first-login":["false"]}`),
			"encrypted-password": []byte("lXc1sa8Y/6AWFg5LXUBo+iccNxwvcwot3rXlOaY40nvSW9+3pp+EXY7pypWnVdLh3wOrds1UOUjr8BhlyycPqNUbqSvGOQi6nqcEJc7T9zQ="),
		},
	}

	fakeClient := fake.NewSimpleClientset(testUserSecret)
	// 定义自定义的反应函数，模拟 TokenReview 的 Create 方法
	fakeClient.Fake.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction := action.(k8stesting.CreateAction)
		tokenReview := createAction.GetObject().(*authenticationv1.TokenReview)
		// 模拟返回结果
		tokenReview.Status = authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1.UserInfo{
				Username: "admin",
				UID:      "12345",
			},
		}
		return true, tokenReview, nil
	})

	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}
	rr := httptest.NewRecorder()
	testLogin.PasswordResetHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}

	if rr.Header().Get("Set-Cookie") == "" {
		t.Errorf("Expected Set-Cookie key in header but it does show up")
	}

	redirect := constants.FuyaoLoginEndpoint
	if rr.Header().Get("Location") != redirect {
		t.Errorf("Expected Location %s; got %s", redirect, rr.Header().Get("Location"))
	}
}

// TestLoginPasswordConfirmHandlerRevertSucceed tests the reverting condition for password confirmation
func TestLoginPasswordConfirmHandlerRevertSucceed(t *testing.T) {
	req, err := http.NewRequest("DELETE", constants.FuyaoPasswordConfirmEndpoint+`?then=/`, nil)
	if err != nil {
		t.Fatal(err)
	}
	fakeCookie := &http.Cookie{
		Name:    "idpLogin",
		Value:   "MTcxOTgxODEyN3x1Sy1JSmRWTGF6S20wekFjenAzbXpQMnBwdkczd19QYzRfbTNxWWxOVUJEV2xEU1BIS0xNeTV3Wk82T0JPY04zNmhyZGJVcDZZb1Q3bmdLRE5YN1pQLTlkMnhZTTFTX2RqWkJQMTI3TUNqSk9SalZ0Nk1BZDNRX0ZmaGFtRDctWlBEdk94RXB4NjNKWnhsZUZRZ3o2a1NFQmp5akl2Z2tLdEVPTmNGWno1eGNVbFExOUNFSzBmc0xTT2pTNFJoMDhmNGkycVJpbmZma0g3aV9NZFZQakV5alF4d2pLTHg1NDB6TW83UFZpd2txOTBKMjFSZUNNblpFYl9ORnlYdFFrQy1lYUZ4Y0ROc19YM2hVTldldV9pSzJLZnFaU1lCdTJEdnFzemoxLWVybkJaQ1FWRDZVQzg4bl83NjFFOEdzNXFLV3Z0Y0JiRUtoVHJKdTZmdWgzZHNwWGxrQzZVRnQtVy1DbktGdy0tN09zZ3RSWVlLY2VkeFRpUlJqTmdacVRHYkRaaHh2SnlFRl9KTWNwdGxiTVRscVdNQ3JEMUw3V3ZFYWFFTVJocHhSLXlhZF9oWlByWDBWUV90WVJORmpqeVpWaGhHb2RxUjNvfIVeE2zLQq3m_hK9Is9cGn1moYm6OYuD_Q7yuqgYKVCG",
		Expires: time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	req.AddCookie(fakeCookie)

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}
	rr := httptest.NewRecorder()
	testLogin.PasswordConfirmHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Expected status code %d; got %d", http.StatusFound, rr.Code)
	}
}

func TestNewLogin(t *testing.T) {
	type args struct {
		idpLoginStore    *sessions.CookieStore
		k8sClient        kubernetes.Interface
		tokenStore       *fuyaostore.K8sSecretStore
		loginIPProtector *protector.LoginIPProtector
		loginConfig      *config.LoginConfig
	}

	fakeClient := fake.NewSimpleClientset()
	fakeTokenStore := fuyaostore.NewK8sSecretStore(fakeClient, "oauth-code-token")
	fakeAuthenticator := authenticators.NewFuyaoPasswordAuthenticator(fakeClient, "oauth-user")
	fakeIdpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	fakeLoginIPProtector := protector.NewLoginIPProtector(&config.IPProtectorConfig{
		FailTimes:    5,
		FailDuration: time.Minute * 5,
		LockDuration: time.Minute * 20,
	})

	testLogin := &Login{
		Provider:         "fuyaoPasswordProvider",
		K8sClient:        fakeClient,
		TokenStore:       fakeTokenStore,
		Authenticator:    fakeAuthenticator,
		idpLoginStore:    fakeIdpLoginStore,
		loginIPProtector: fakeLoginIPProtector,
	}

	tests := []struct {
		name string
		args args
		want *Login
	}{
		{
			"successfully init",
			args{
				idpLoginStore:    fakeIdpLoginStore,
				k8sClient:        fakeClient,
				tokenStore:       fakeTokenStore,
				loginIPProtector: fakeLoginIPProtector,
				loginConfig: &config.LoginConfig{
					Provider:      "fuyaoPasswordProvider",
					UserNamespace: "oauth-user",
				},
			},
			testLogin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewLogin(tt.args.idpLoginStore, tt.args.k8sClient, tt.args.tokenStore, tt.args.loginIPProtector, tt.args.loginConfig)
			if !reflect.DeepEqual(got.idpLoginStore, tt.want.idpLoginStore) || !reflect.DeepEqual(got.TokenStore, tt.want.TokenStore) || !reflect.DeepEqual(got.loginIPProtector, tt.want.loginIPProtector) {
				t.Errorf("NewLogin() = %v, want %v", got, tt.want)
			}
		})
	}
}
