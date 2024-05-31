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
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	req, err := http.NewRequest("GET", constants.FuyaoLoginEndpoint, nil)
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

	expectedBody := `<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>

<body>
    <div id="root">
        <div class="form-block">
            <h3>欢迎登录openFuyao</h3    >
            <form id="login-form" autocomplete="off" action="" method="POST">
              <div class="error-placeholder">
                
              </div>
                <label class="form-label required-label" for="username">用户名</label>
                <div class="form-input-line">
                    <input id="username" name="username" type="text" value="" required="">
                </div>
                <div class="alert-line hidden-alert">请输入用户名!</div>
                <label class="form-label required-label" for="password">密码</label>
                <div class="form-input-line">
                    <span role="img" tabindex="-1" class="password-input-icon" onclick="togglePassword(this)">

                        <svg viewBox="64 64 896 896" focusable="false" width="1em" height="1em" fill="currentColor">
                            <path
                                d="M942.2 486.2Q889.47 375.11 816.7 305l-50.88 50.88C807.31 395.53 843.45 447.4 874.7 512 791.5 684.2 673.4 766 512 766q-72.67 0-133.87-22.38L323 798.75Q408 838 512 838q288.3 0 430.2-300.3a60.29 60.29 0 000-51.5zm-63.57-320.64L836 122.88a8 8 0 00-11.32 0L715.31 232.2Q624.86 186 512 186q-288.3 0-430.2 300.3a60.3 60.3 0 000 51.5q56.69 119.4 136.5 191.41L112.48 835a8 8 0 000 11.31L155.17 889a8 8 0 0011.31 0l712.15-712.12a8 8 0 000-11.32zM149.3 512C232.6 339.8 350.7 258 512 258c54.54 0 104.13 9.36 149.12 28.39l-70.3 70.3a176 176 0 00-238.13 238.13l-83.42 83.42C223.1 637.49 183.3 582.28 149.3 512zm246.7 0a112.11 112.11 0 01146.2-106.69L401.31 546.2A112 112 0 01396 512z">
                            </path>
                            <path
                                d="M508 624c-3.46 0-6.87-.16-10.25-.47l-52.82 52.82a176.09 176.09 0 00227.42-227.42l-52.82 52.82c.31 3.38.47 6.79.47 10.25a111.94 111.94 0 01-112 112z">
                            </path>
                            <path style="display: none;"
                                d="M942.2 486.2C847.4 286.5 704.1 186 512 186c-192.2 0-335.4 100.5-430.2 300.3a60.3 60.3 0 000 51.5C176.6 737.5 319.9 838 512 838c192.2 0 335.4-100.5 430.2-300.3 7.7-16.2 7.7-35 0-51.5zM512 766c-161.3 0-279.4-81.8-362.7-254C232.6 339.8 350.7 258 512 258c161.3 0 279.4 81.8 362.7 254C791.5 684.2 673.4 766 512 766zm-4-430c-97.2 0-176 78.8-176 176s78.8 176 176 176 176-78.8 176-176-78.8-176-176-176zm0 288c-61.9 0-112-50.1-112-112s50.1-112 112-112 112 50.1 112 112-50.1 112-112 112z">
                            </path>
                        </svg>
                    </span>
                    <input class="password-input" id="password" name="password" type="password" required="">

                </div>
                <div class="alert-line hidden-alert">请输入密码!</div>
                <div><input id="csrf_token" name="csrf_token" type="text" value="" hidden=""></div>
                <div><input id="then" name="then" type="text" value="/" hidden=""></div>

                <div class="btn-block"><button type="submit" id="login-btn" class="btn-primary login-btn" formnovalidate=""><span>登录</span></button>
                  </div>
            </form>
        </div>
    </div>
    <script>
        const togglePassword = (element) => {
            // Toggle visibility of the SVG paths
            element.querySelectorAll('path').forEach((path) => {
                path.style.display = (path.style.display === 'none') ? '' : 'none';
            });
            const input = element.nextElementSibling;
            if (input.type === 'password') {
                input.type = 'text';
            } else {
                input.type = 'password';
            }
        }

        let usernameValid = false;
        let passwordValid = false;
        const usernameAlert = document.getElementsByClassName("alert-line")[0]
        const passwordAlert = document.getElementsByClassName("alert-line")[1]

        const switchAlertVisibility = (inputAlert, testRes) => {
            if (testRes) {
                inputAlert.classList.add("hidden-alert");
            } else {
                inputAlert.classList.remove("hidden-alert");
            }
        }

        document.getElementById("username").addEventListener("input", (event) => {
            usernameValid = event.target.value.length > 0
            switchAlertVisibility(usernameAlert, usernameValid)
        })

        document.getElementById("password").addEventListener("input", (event) => {
            passwordValid = event.target.value.length > 0
            switchAlertVisibility(passwordAlert, passwordValid)
        })

        document.getElementById("login-btn").addEventListener("click", (event) => {
            switchAlertVisibility(usernameAlert, usernameValid)
            switchAlertVisibility(passwordAlert, passwordValid)
            if (!usernameValid || !passwordValid) {
                event.preventDefault()
            }
        })
    </script>
    <style>
        body,html{margin:0;padding:0;font-size:14px;font-family:'Montserrat',sans-serif;box-sizing:border-box}
        input,button,.password-input-icon{outline:0;transition:all .2s cubic-bezier(0.645,0.045,0.355,1)}
        #root{background:linear-gradient(70deg,#256cba,#a9d2f0);width:100vw;height:100vh;display:flex;align-items:center;justify-content:center}
        .form-block{margin-left:500px;padding:0 64px;width:500px;height:500px;display:flex;flex-direction:column;justify-content:center;border-radius:4px;background:#fff;box-shadow:0 3px 10px rgba(51,51,51,0.1);box-sizing:border-box}
        .form-block h3{margin:0;font-size:24px;margin:24px 0;color:#333;font-weight:normal}
        .prompt-line{color:#89939b;margin:.25em 0;position:relative;margin-left:1.5em}
        .prompt-default::before{content:"";display:inline-block;width:1em;height:1em;position:absolute;top:.25em;left:-1.25em;margin-right:1em}
        .prompt-default.prompt-info::before{background-image:url("data:image/svg+xml,%3Csvgxmlns='http://www.w3.org/2000/svg'viewBox='6464896896'fill='%234b8bea'%3E%3Cpathd='M51264C264.66464264.664512s200.6448448448448-200.6448-448S759.46451264zm32664c04.4-3.68-88h-48c-4.40-8-3.6-8-8V456c0-4.43.6-88-8h48c4.4083.688v272zm-32-344a48.0148.010010-9648.0148.01001096z'%3E%3C/path%3E%3C/svg%3E")}
        .prompt-default.prompt-inactive::before{background-image:url("data:image/svg+xml,%3Csvgxmlns='http://www.w3.org/2000/svg'viewBox='6464896896'fill='%23cccccc'%3E%3Cpathd='M51264C264.66464264.664512s200.6448448448448-200.6448-448S759.46451264zm193.5301.7l-210.6292a31.831.8001-51.70L318.5484.9c-3.8-5.30-12.76.5-12.7h46.9c10.2019.94.925.913.3l71.298.8157.2-218c6-8.315.6-13.325.9-13.3H699c6.5010.37.46.512.7z'%3E%3C/path%3E%3C/svg%3E")}
        .prompt-default.prompt-ok::before{background-image:url("data:image/svg+xml,%3Csvgxmlns='http://www.w3.org/2000/svg'viewBox='6464896896'fill='%2320c41a'%3E%3Cpathd='M51264C264.66464264.664512s200.6448448448448-200.6448-448S759.46451264zm193.5301.7l-210.6292a31.831.8001-51.70L318.5484.9c-3.8-5.30-12.76.5-12.7h46.9c10.2019.94.925.913.3l71.298.8157.2-218c6-8.315.6-13.325.9-13.3H699c6.5010.37.46.512.7z'%3E%3C/path%3E%3C/svg%3E")}
        .prompt-default.prompt-error::before{background-image:url("data:image/svg+xml,%3Csvgxmlns='http://www.w3.org/2000/svg'viewBox='6464896896'fill='%23e94547'%3E%3Cpathd='M51264c247.40448200.6448448S759.496051296064759.464512264.66451264zm127.98274.82h-.04l-.08.06L512466.75384.14338.88c-.04-.05-.06-.06-.08-.06a.12.12000-.070c-.030-.05.01-.09.05l-45.0245.02a.2.2000-.05.09.12.120000.07v.02a.27.27000.06.06L466.75512338.88639.86c-.05.04-.06.06-.06.08a.12.120000.07c0.03.01.05.05.09l45.0245.02a.2.2000.09.05.12.12000.070c.020.04-.01.08-.05L512557.25l127.86127.87c.04.04.06.05.08.05a.12.12000.070c.030.05-.01.09-.05l45.02-45.02a.2.2000.05-.09.12.120000-.07v-.02a.27.27000-.05-.06L557.25512l127.87-127.86c.04-.04.05-.06.05-.08a.12.120000-.07c0-.03-.01-.05-.05-.09l-45.02-45.02a.2.2000-.09-.05.12.12000-.070z'%3E%3C/path%3E%3C/svg%3E")}
        .form-block form{display:flex;flex-direction:column}
        .form-label{color:#666;max-width:100%;margin:.25em 0}
        .alert-line{color:#ff4d4f;max-width:100%;margin:.25em 0;transition:all .2s cubic-bezier(0.645,0.045,0.355,1)}
        .alert-line.hidden-alert{opacity:0}
        .form-block .required-label::before{margin-inline-end:.25em;color:#ff4d4f;font-family:SimSun,sans-serif;content:"*"}
        .form-block input{box-sizing:border-box;padding:0 .5em;line-height:22px;height:32px;width:100%;border-radius:2px;background:#fff;border:1px solid #d9d9d9}
        .form-input-line{position:relative}
        .form-input-line .password-input{padding-right:7%}
        .password-input-icon{position:absolute;top:50%;right:2.5%;transform:translateY(-50%);display:flex;align-items:center;cursor:pointer;outline:0;color:#939393}
        .password-input-icon:hover{color:#2c2c2c}
        .password-input-icon:hover+input,.form-block input:hover{border:1px solid #4096ff}
        .form-block input:focus{border:1px solid #1677ff;box-shadow:0 0 0 2px rgba(5,145,255,0.1)}
        .btn-block{margin-top:24px;display:flex;gap:1em;justify-content:right}
        .btn-block button{width:96px;height:32px;border:0;border-radius:2px;cursor:pointer}
        .btn-primary{color:white;background-color:#356ac4}
        .btn-primary:hover{background-color:#4b8bea}
        .btn-primary:active{background-color:#234c9e}
        .login-btn{height:40px!important;width:100%!important;box-shadow:0 2px 0 rgba(5,145,255,0.1)}
        .cancel-btn{background-color:#fff!important;color:black;border:1px solid #ccc!important}
        .cancel-btn:hover{background-color:#f8f8f8!important}
        .cancel-btn:active{background-color:#e8e8e8!important}
        .error-placeholder {fill: #fff2f0;}
        .pf-m-error__icon {stroke: #e94547;}
    </style>
</body>

</html>`
	if rr.Body.String() != expectedBody {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expectedBody)
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
	req, err := http.NewRequest("GET", constants.FuyaoPasswordConfirmEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	fakeCookie := &http.Cookie{
		Name:    "idpLogin",
		Value:   "MTcxNjYzMjc5Mnxsa2NwY055UUxRdVUwTjcyVUNRRzUtTE5FMW1VOC05TWtTdGZrYXhKRVYxLUtDcXplcjJBTm1ITXFrSlBOZnkzWVBiZ2FFM0t5Y1V3VTlFMkZuNWJFRTJvcmJwTjk5UXJpSTNqbGdLZllvTFRpRWFZSU4zNXh0TmNLZ2NEYUZWcm5id3RDVTZ3QmRDd3JWSm9lRUpTOWdxZk9FaVpsS3hmbWJBTU9NZlRKLXB6REZUVUdwM0FHZUkzeC1seEZ3RmZiX1gyZWFIYUxJRmlONDloRFVOZHJaRXVFazFGZzlhQnNnTHotRHJJUnlEZHVUVW13VW81bDJVdHJWWmlwSFc0VUFhWHZfeUVNRXl5T1JFbXB1WkUzYWRyZ0VoRWhjYXprRmt0NjVvYXJBcTRYeUFOZ1VxaEZ3bWZ0aW9lM2tMQy1teGdQUVNPbk40UkFVZU5OZm80NUdXS29YOXZYS0dUOFpWTmhKdElpRy1mZmRma1JVeXhpOUlxamJWVmVxeVJ6VllaYTdzNERad2NJOFNzeldHYm9xTnAxZW5hQjNjNlV3N01QVGxMeTM3YWM5MVc1aTZoRnJiZGxWUkFHOC05SmRjei1qVjhBanViSWc9PXzDmy8u3Jdey5SMnWC9vwYlO_biv4GPXk9wJbyrAeC3Mw==",
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
	expectedBody := `<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
	<script>
        globals.username = 'admin'
	</script>
</head>

<body>
    <div id="root">
        <div class="form-block">
            <h3>初次修改密码</h3>
            <div class="prompt-line prompt-default prompt-info">为确保您的账户安全，初次登陆后请修改密码</div>
            <form id="confirm-form" autocomplete="off" action="{{.Action}}" method="POST">
              <div class="error-placeholder">
                {{ if .Error }}
                <p class="pf-c-form__helper-text pf-m-error">
                  <svg style="vertical-align:-0.125em" fill="currentColor" height="1em" width="1em" viewBox="0 0` +
		` 512 512" aria-hidden="true" role="img" class="pf-m-error__icon">
                    <path d="M504 256c0 136.997-111.043 248-248 248S8 392.997 8 256C8 119.083 119.043 8 256 8s248` +
		` 111.083 248 248zm-248 50c-25.405 0-46 20.595-46 46s20.595 46 46 46 46-20.595 46-46-20.595-46-46-46zm-43` +
		`.673-165.346l7.418 136c.347 6.364 5.609 11.346 11.982 11.346h48.546c6.373 0 11.635-4.982 11.982-11.346l7.` +
		`418-136c.375-6.874-5.098-12.654-11.982-12.654h-63.383c-6.884 0-12.356 5.78-11.981 12.654z" transform=""></path>
                  </svg>
                  {{ .Error }}
                </p>
                {{ end }}
              </div>
                <label class="form-label required-label" for="new-password">新密码</label>
                <div class="form-input-line">
                    <span role="img" tabindex="-1" class="password-input-icon" onclick="togglePassword(this)">
                        <svg viewBox="64 64 896 896" focusable="false" width="1em" height="1em" fill="currentColor">
                            <path
                                d="M942.2 486.2Q889.47 375.11 816.7 305l-50.88 50.88C807.31 395.53 843.45 447.4 874.` +
		`7 512 791.5 684.2 673.4 766 512 766q-72.67 0-133.87-22.38L323 798.75Q408 838 512 838q288.3 0 430.2-300.3a60.` +
		`29 60.29 0 000-51.5zm-63.57-320.64L836 122.88a8 8 0 00-11.32 0L715.31 232.2Q624.86 186 512 186q-288.3 0-` +
		`430.2 300.3a60.3 60.3 0 000 51.5q56.69 119.4 136.5 191.41L112.48 835a8 8 0 000 11.31L155.17 889a8 8 0 0011.` +
		`31 0l712.15-712.12a8 8 0 000-11.32zM149.3 512C232.6 339.8 350.7 258 512 258c54.54 0 104.13 9.36 149.12 28.` +
		`39l-70.3 70.3a176 176 0 00-238.13 238.13l-83.42 83.42C223.1 637.49 183.3 582.28 149.3 512zm246.7 0a112.11` +
		` 112.11 0 01146.2-106.69L401.31 546.2A112 112 0 01396 512z">
                            </path>
                            <path
                                d="M508 624c-3.46 0-6.87-.16-10.25-.47l-52.82 52.82a176.09 176.09 0 00227.42-227.` +
		`42l-52.82 52.82c.31 3.38.47 6.79.47 10.25a111.94 111.94 0 01-112 112z">
                            </path>
                            <path style="display: none;"
                                d="M942.2 486.2C847.4 286.5 704.1 186 512 186c-192.2 0-335.4 100.5-430.2 300.3a60.` +
		`3 60.3 0 000 51.5C176.6 737.5 319.9 838 512 838c192.2 0 335.4-100.5 430.2-300.3 7.7-16.2 7.7-35 0-51.5zM512` +
		` 766c-161.3 0-279.4-81.8-362.7-254C232.6 339.8 350.7 258 512 258c161.3 0 279.4 81.8 362.7 254C791.5 684.2` +
		` 673.4 766 512 766zm-4-430c-97.2 0-176 78.8-176 176s78.8 176 176 176 176-78.8 176-176-78.8-176-176-176zm0` +
		` 288c-61.9 0-112-50.1-112-112s50.1-112 112-112 112 50.1 112 112-50.1 112-112 112z">
                            </path>
                        </svg>
                    </span>
                    <input class="password-input" id="new-password" name="new_password" type="password">
                </div>
                <div class="prompt-line prompt-default prompt-error">密码长度8~32位</div>
                <div class="prompt-line prompt-default prompt-error">包含英文字母、数字、特殊字符` + "`" +
		`~!@#$%^&*()-_=+\|[{}];:'",<.>/?</div>
                <div class="prompt-line prompt-default prompt-ok">不能和账号及账号逆序相同</div>
                <br>
                <label class="form-label required-label" for="username">确认密码</label>
                <div class="form-input-line">
                    <span role="img" tabindex="-1" class="password-input-icon" onclick="togglePassword(this)">
                        <svg viewBox="64 64 896 896" focusable="false" width="1em" height="1em" fill="currentColor">
                            <path
                                d="M942.2 486.2Q889.47 375.11 816.7 305l-50.88 50.88C807.31 395.53 843.45` +
		` 447.4 874.7 512 791.5 684.2 673.4 766 512 766q-72.67 0-133.87-22.38L323 798.75Q408 838 512 838q288.3` +
		` 0 430.2-300.3a60.29 60.29 0 000-51.5zm-63.57-320.64L836 122.88a8 8 0 00-11.32 0L715.31 232.2Q624.86` +
		` 186 512 186q-288.3 0-430.2 300.3a60.3 60.3 0 000 51.5q56.69 119.4 136.5 191.41L112.48 835a8 8 0 000 ` +
		` 11.31L155.17 889a8 8 0 0011.31 0l712.15-712.12a8 8 0 000-11.32zM149.3 512C232.6 339.8 350.7 258 512` +
		` 258c54.54 0 104.13 9.36 149.12 28.39l-70.3 70.3a176 176 0 00-238.13 238.13l-83.42 83.42C223.1 637.49` +
		` 183.3 582.28 149.3 512zm246.7 0a112.11 112.11 0 01146.2-106.69L401.31 546.2A112 112 0 01396 512z">
                            </path>
                            <path
                                d="M508 624c-3.46 0-6.87-.16-10.25-.47l-52.82 52.82a176.09 176.09 0` +
		` 00227.42-227.42l-52.82 52.82c.31 3.38.47 6.79.47 10.25a111.94 111.94 0 01-112 112z">
                            </path>
                            <path style="display: none;"
                                d="M942.2 486.2C847.4 286.5 704.1 186 512 186c-192.2 0-335.4 100.5-430.2` +
		` 300.3a60.3 60.3 0 000 51.5C176.6 737.5 319.9 838 512 838c192.2 0 335.4-100.5 430.2-300.3 7.7-16.2` +
		` 7.7-35 0-51.5zM512 766c-161.3 0-279.4-81.8-362.7-254C232.6 339.8 350.7 258 512 258c161.3 0 279.4 81.8` +
		` 362.7 254C791.5 684.2 673.4 766 512 766zm-4-430c-97.2 0-176 78.8-176 176s78.8 176 176 176 176-78.8` +
		` 176-176-78.8-176-176-176zm0 288c-61.9 0-112-50.1-112-112s50.1-112 112-112 112 50.1 112 112-50.1 112-112 112z">
                            </path>
                        </svg>
                    </span>
                    <input class="password-input" id="confirm-password" name="confirm-password" type="password"
                    >
                </div>
                <div><input id="next" name="next" type="text" value="/" hidden readonly></div>
                <div><input id="csrf_token" name="csrf_token" type="text" value="{{.CSRFToken}}" hidden></div>
                <div><input id="then" name="then" type="text" value="{{.Then}}" hidden></div>
                <div class="prompt-line prompt-default prompt-error">两次输入密码需要一致</div>
                <div class="btn-block">
                    <button id="confirm-btn" type="submit" class="btn-primary confirm-btn"
                        formnovalidate><span>确认</span></button>
                </div>
            </form>
        </div>
    </div>
    <script>
        const togglePassword = (element) => {
            element.querySelectorAll('path').forEach((path) => {
                if (path.style.display === 'none') {
                    path.style.display = '';
                } else {
                    path.style.display = 'none';
                }
            });
            const input = element.nextElementSibling;
            if (input.type === 'password') {
                input.type = 'text';
            } else {
                input.type = 'password';
            }
        }

        let passwordValid1 = false;
        let passwordValid2 = false;
        let passwordValid3 = true;
        let confirmValid = false;
        const prompt1 = document.getElementsByClassName("prompt-line")[1];
        const prompt2 = document.getElementsByClassName("prompt-line")[2];
        const prompt3 = document.getElementsByClassName("prompt-line")[3];
        const prompt4 = document.getElementsByClassName("prompt-line")[4];

        const updateConfirmBtn = () => {
            btnValid = passwordValid1 && passwordValid2 && passwordValid3 && confirmValid;
            const btn = document.getElementById('confirm-btn');
            if (btnValid) {
                btn.disabled = false;
            } else {
                btn.disabled = true;
            }
        }

        const comparePassword = () => {
            const newPassword = document.getElementById("new-password").value;
            const confirmPassword = document.getElementById("confirm-password").value;
            return newPassword === confirmPassword;
        }

        const switchPromptType = (prompt, testRes) => {
            if (testRes) {
                prompt.classList.remove("prompt-error");
                prompt.classList.add("prompt-ok");
            } else {
                prompt.classList.remove("prompt-ok");
                prompt.classList.add("prompt-error");
            }
        }

        document.getElementById("new-password").addEventListener("input", (event) => {
            const newPassword = event.target.value;

            passwordValid1 = newPassword.length >= 8 && newPassword.length <= 32
            switchPromptType(prompt1, passwordValid1)
            passwordValid2 = /^(?=.*[0-9])(?=.*[A-Za-z])(?=.*[` + "`" +
		`~!@#$%^&*()\-_=+\\|\[{}\];:'",<.>/?])[A-Za-z0-9` + "`" +
		`~!@#$%^&*()\-_=+\\|\[{}\];:'",<.>/?]+$/.test(newPassword)
            switchPromptType(prompt2, passwordValid2)
            const reverseStr = (s) => s.split('').reverse().join('');
            passwordValid3 = newPassword !== globals.username && newPassword !== reverseStr(globals.username)
            switchPromptType(prompt3, passwordValid3)

            confirmValid = comparePassword()
            switchPromptType(prompt4, confirmValid)

            updateConfirmBtn()
        })

        document.getElementById("confirm-password").addEventListener("input", () => {
            confirmValid = comparePassword()
            switchPromptType(prompt4, confirmValid)
            updateConfirmBtn()
        })

        document.getElementById("confirm-form").addEventListener("submit", (event) => {
            if (!passwordValid1 || !passwordValid2 || !passwordValid3 || !confirmValid) {
                event.preventDefault()
            }
        })
    </script>
    <style>
        body,html{margin:0;padding:0;font-size:14px;font-family:'Montserrat',sans-serif;box-sizing:border-box}
        input,button,.password-input-icon{outline:0;transition:all .2s cubic-bezier(0.645,0.045,0.355,1)}
        #root{background:linear-gradient(70deg,#256cba,#a9d2f0);width:100vw;height:100vh;display:flex;` +
		`align-items:center;justify-content:center}
        .form-block{margin-left:500px;padding:0 64px;width:500px;height:500px;display:flex;flex-direction:column;` +
		`justify-content:center;border-radius:4px;background:#fff;box-shadow:0 3px 10px rgba(51,51,51,0.1);` +
		`box-sizing:border-box}
        .form-block h3{margin:0;font-size:24px;margin:24px 0;color:#333;font-weight:normal}
        .prompt-line{color:#89939b;margin:.25em 0;position:relative;margin-left:1.5em}
        .prompt-default::before{content:"";display:inline-block;width:1em;height:1em;position:absolute;top:.25em;` +
		`left:-1.25em;margin-right:1em}
        .prompt-default.prompt-info::before{background-image:url("data:image/svg+xml,%3Csvg ` +
		`xmlns='http://www.w3.org/2000/svg' viewBox='64 64 896 896' fill='%234b8bea'%3E%3Cpath d='M512 64C264.6 64` +
		` 64 264.6 64 512s200.6 448 448 448 448-200.6 448-448S759.4 64 512 64zm32 664c0 4.4-3.6 8-8` +
		` 8h-48c-4.4 0-8-3.6-8-8V456c0-4.4 3.6-8 8-8h48c4.4 0 8 3.6 8 8v272zm-32-344a48.01 48.01 0 010-96 48.01` +
		` 48.01 0 010 96z'%3E%3C/path%3E%3C/svg%3E")}
        .prompt-default.prompt-inactive::before{background-image:url("data:image/svg+xml,%3Csvg ` +
		`xmlns='http://www.w3.org/2000/svg' viewBox='64 64 896 896' fill='%23cccccc'%3E%3Cpath ` +
		`d='M512 64C264.6 64 64 264.6 64 512s200.6 448 448 448 448-200.6 448-448S759.4 64 512 64zm193.5` +
		` 301.7l-210.6 292a31.8 31.8 0 01-51.7 0L318.5 484.9c-3.8-5.3 0-12.7 6.5-12.7h46.9c10.2 0 19.9 4.9 25.9` +
		` 13.3l71.2 98.8 157.2-218c6-8.3 15.6-13.3 25.9-13.3H699c6.5 0 10.3 7.4 6.5 12.7z'%3E%3C/path%3E%3C/svg%3E")}
        .prompt-default.prompt-ok::before{background-image:url("data:image/svg+xml,%3Csvg ` +
		`xmlns='http://www.w3.org/2000/svg' viewBox='64 64 896 896' fill='%2320c41a'%3E%3Cpath d='M512 64C264.6` +
		` 64 64 264.6 64 512s200.6 448 448 448 448-200.6 448-448S759.4 64 512 64zm193.5 301.7l-210.6 292a31.8 31.8` +
		` 0 01-51.7 0L318.5 484.9c-3.8-5.3 0-12.7 6.5-12.7h46.9c10.2 0 19.9 4.9 25.9 13.3l71.2 98.8 157.2-218c6-8.3` +
		` 15.6-13.3 25.9-13.3H699c6.5 0 10.3 7.4 6.5 12.7z'%3E%3C/path%3E%3C/svg%3E")}
        .prompt-default.prompt-error::before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.` +
		`org/2000/svg' viewBox='64 64 896 896' fill='%23e94547'%3E%3Cpath d='M512 64c247.4 0 448 200.6 448 448S759.4` +
		` 960 512 960 64 759.4 64 512 264.6 64 512 64zm127.98 274.82h-.04l-.08.06L512 466.75 384.14 338.88c-.04-.` +
		`05-.06-.06-.08-.06a.12.12 0 00-.07 0c-.03 0-.05.01-.09.05l-45.02 45.02a.2.2 0 00-.05.09.12.12 0 000 .07v.` +
		`02a.27.27 0 00.06.06L466.75 512 338.88 639.86c-.05.04-.06.06-.06.08a.12.12 0 000 .07c0 .03.01.05.05.09l45.` +
		`02 45.02a.2.2 0 00.09.05.12.12 0 00.07 0c.02 0 .04-.01.08-.05L512 557.25l127.86 127.87c.04.04.06.05.08.05a` +
		`.12.12 0 00.07 0c.03 0 .05-.01.09-.05l45.02-45.02a.2.2 0 00.05-.09.12.12 0 000-.07v-.02a.27.27 0 00-.05-.` +
		`06L557.25 512l127.87-127.86c.04-.04.05-.06.05-.08a.12.12 0 000-.07c0-.03-.01-.05-.05-.09l-45.02-45.02a.2.2` +
		` 0 00-.09-.05.12.12 0 00-.07 0z'%3E%3C/path%3E%3C/svg%3E")}
        .form-block form{display:flex;flex-direction:column}
        .form-label{color:#666;max-width:100%;margin:.25em 0}
        .alert-line{color:#ff4d4f;max-width:100%;margin:.25em 0;transition:all .2s cubic-bezier(0.645,0.045,0.355,1)}
        .alert-line.hidden-alert{opacity:0}
        .form-block .required-label::before{margin-inline-end:.25em;color:#ff4d4f;font-family:SimSun,sans-serif;` +
		`content:"*"}
        .form-block input{box-sizing:border-box;padding:0 .5em;line-height:22px;height:32px;width:100%;border-` +
		`radius:2px;background:#fff;border:1px solid #d9d9d9}
        .form-input-line{position:relative}
        .form-input-line .password-input{padding-right:7%}
        .password-input-icon{position:absolute;top:50%;right:2.5%;transform:translateY(-50%);display:flex;` +
		`align-items:center;cursor:pointer;outline:0;color:#939393}
        .password-input-icon:hover{color:#2c2c2c}
        .password-input-icon:hover+input,.form-block input:hover{border:1px solid #4096ff}
        .form-block input:focus{border:1px solid #1677ff;box-shadow:0 0 0 2px rgba(5,145,255,0.1)}
        .btn-block{margin-top:24px;display:flex;gap:1em;justify-content:right}
        .btn-block button{width:96px;height:32px;border:0;border-radius:2px;cursor:pointer}
        .btn-primary{color:white;background-color:#356ac4}
        .btn-primary:hover{background-color:#4b8bea}
        .btn-primary:active{background-color:#234c9e}
        .login-btn{height:40px!important;width:100%!important;box-shadow:0 2px 0 rgba(5,145,255,0.1)}
        .cancel-btn{background-color:#fff!important;color:black;border:1px solid #ccc!important}
        .cancel-btn:hover{background-color:#f8f8f8!important}
        .cancel-btn:active{background-color:#e8e8e8!important}

    </style>
</body>

</html>`
	if rr.Body.String() != expectedBody {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expectedBody)
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
		Value:   "MTcxNjYzMjc5Mnxsa2NwY055UUxRdVUwTjcyVUNRRzUtTE5FMW1VOC05TWtTdGZrYXhKRVYxLUtDcXplcjJBTm1ITXFrSlBOZnkzWVBiZ2FFM0t5Y1V3VTlFMkZuNWJFRTJvcmJwTjk5UXJpSTNqbGdLZllvTFRpRWFZSU4zNXh0TmNLZ2NEYUZWcm5id3RDVTZ3QmRDd3JWSm9lRUpTOWdxZk9FaVpsS3hmbWJBTU9NZlRKLXB6REZUVUdwM0FHZUkzeC1seEZ3RmZiX1gyZWFIYUxJRmlONDloRFVOZHJaRXVFazFGZzlhQnNnTHotRHJJUnlEZHVUVW13VW81bDJVdHJWWmlwSFc0VUFhWHZfeUVNRXl5T1JFbXB1WkUzYWRyZ0VoRWhjYXprRmt0NjVvYXJBcTRYeUFOZ1VxaEZ3bWZ0aW9lM2tMQy1teGdQUVNPbk40UkFVZU5OZm80NUdXS29YOXZYS0dUOFpWTmhKdElpRy1mZmRma1JVeXhpOUlxamJWVmVxeVJ6VllaYTdzNERad2NJOFNzeldHYm9xTnAxZW5hQjNjNlV3N01QVGxMeTM3YWM5MVc1aTZoRnJiZGxWUkFHOC05SmRjei1qVjhBanViSWc9PXzDmy8u3Jdey5SMnWC9vwYlO_biv4GPXk9wJbyrAeC3Mw==",
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
