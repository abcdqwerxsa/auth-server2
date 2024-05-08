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

// Package fuyaopassword implements fuyaoidp login interfaces
package fuyaopassword

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"text/template"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"

	"openfuyao/oauth-server/assets/templates"
	"openfuyao/oauth-server/cmd/oauth-server/app/config"
	"openfuyao/oauth-server/pkg/authenticators"
	"openfuyao/oauth-server/pkg/constants"
	"openfuyao/oauth-server/pkg/fuyaoerrors"
	"openfuyao/oauth-server/pkg/idp"
	"openfuyao/oauth-server/pkg/protector"
	"openfuyao/oauth-server/pkg/sessions"
	"openfuyao/oauth-server/pkg/store"
	"openfuyao/oauth-server/pkg/zlog"
)

// LoginForm contains the fields used by fuyao login
type LoginForm struct {
	Action    string
	Then      string
	CSRFToken string
}

// OutputHTML writes the contents back to web
func (l *LoginForm) OutputHTML(w http.ResponseWriter, tpl string, name string) {
	tplForm, err := template.New(name).Parse(tpl)
	if err != nil {
		http.Error(w, fuyaoerrors.ErrStrFailToDisplayLogin, http.StatusInternalServerError)
		return
	}
	if err = tplForm.Execute(w, l); err != nil {
		http.Error(w, fuyaoerrors.ErrStrFailToDisplayLogin, http.StatusInternalServerError)
		return
	}
}

// Login works for fuyao login, implement the login interfaces
type Login struct {
	Provider string
	// CSRF csrf.CSRF
	K8sClient        kubernetes.Interface
	TokenStore       *store.K8sSecretStore
	Authenticator    authenticators.PasswordAuthenticator
	idpLoginStore    *sessions.CookieStore
	loginIPProtector *protector.LoginIPProtector
}

// NewLogin returns the fuyao Login instance
func NewLogin(
	idpLoginStore *sessions.CookieStore,
	k8sClient kubernetes.Interface,
	tokenStore *store.K8sSecretStore,
	loginIPProtector *protector.LoginIPProtector,
	loginConfig *config.LoginConfig,
) *Login {
	return &Login{
		Provider:         loginConfig.Provider,
		K8sClient:        k8sClient,
		TokenStore:       tokenStore,
		Authenticator:    authenticators.NewFuyaoPasswordAuthenticator(k8sClient, loginConfig.UserNamespace),
		idpLoginStore:    idpLoginStore,
		loginIPProtector: loginIPProtector,
	}
}

// LoginHandler deals with both GET/POST requests
func (l *Login) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// deal with GET
		l.renderLoginForm(w, r)
	} else if r.Method == http.MethodPost {
		// deal with POST
		l.processLogin(w, r)
	} else {
		http.Error(w, fuyaoerrors.ErrStrRequestMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
}

// LogoutHandler in openFuyao fuyaoPasswordProvider delete the accessToken secret
func (l *Login) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// check logged in status
	accessToken, err := l.getAccessToken(r)
	if err != nil {
		http.Error(w, fuyaoerrors.ErrStrNotLogin, http.StatusBadRequest)
		return
	}
	loggedIn, err := l.authenticateByWebhook(accessToken)
	if !loggedIn || err != nil {
		http.Error(w, err.Error(), fuyaoerrors.ErrStatusCode[err])
	}

	// delete the accessToken secret
	if err = l.TokenStore.RemoveByAccess(context.TODO(), accessToken); err != nil {
		http.Error(w, err.Error(), fuyaoerrors.ErrStatusCode[err])
	}
	return
}

// PasswordConfirmHandler works when the user login for the first time
func (l *Login) PasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	// check http method
	if r.Method != http.MethodPost {
		http.Error(w, fuyaoerrors.ErrStrRequestMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	// read userinfo from session-store
	loginData := l.idpLoginStore.Get(r)
	username, ok := loginData.GetString(constants.UserName)
	if !ok {
		http.Error(w, fuyaoerrors.ErrStrNotLogin, http.StatusUnauthorized)
		return
	}

	// read params from r.url
	var requestBody PasswordConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, fuyaoerrors.ErrStrFailToUnmarshalData, http.StatusBadRequest)
		return
	}
	newPassword := requestBody.NewPassword
	then := requestBody.Then
	if len(newPassword) == 0 {
		http.Error(w, fuyaoerrors.ErrStrUsernameOrPasswordMissing, http.StatusBadRequest)
		return
	}
	if len(then) == 0 {
		then = "/"
	}

	// password confirmation logic
	if err := l.Authenticator.ConfirmPassword(context.Background(), username, newPassword); err != nil {
		http.Error(w, err.Error(), fuyaoerrors.ErrStatusCode[err])
		return
	}

	// no need to keep the info in idpLoginStore, erase them in the cookie/database
	if err := l.idpLoginStore.Put(w, make(sessions.Values)); err != nil {
		zlog.LogWarnf("cannot delete the loginstore used in authorization, err: %v", err)
	}
	zlog.LogInfof("Password Confirmation succeed for user: %s", username)

	// redirect normally
	http.Redirect(w, r, then, http.StatusFound)
}

// PasswordResetHandler resets the password
func (l *Login) PasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	// check http method
	if r.Method != http.MethodPost {
		http.Error(w, fuyaoerrors.ErrStrRequestMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	// add an access token validation, since all the services are required to expose in this version
	accessToken, err := l.getAccessToken(r)
	if err != nil {
		http.Error(w, fuyaoerrors.ErrStrNotLogin, http.StatusBadRequest)
		return
	}

	loggedIn, err := l.authenticateByWebhook(accessToken)
	if !loggedIn || err != nil {
		http.Error(w, err.Error(), fuyaoerrors.ErrStatusCode[err])
	}

	// read params from r.url
	var requestBody PasswordResetRequest
	if err = json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, fuyaoerrors.ErrStrFailToUnmarshalData, http.StatusBadRequest)
		return
	}

	username := requestBody.Username
	oldPassword := requestBody.OriginalPassword
	newPassword := requestBody.NewPassword
	if len(username) == 0 || len(oldPassword) == 0 || len(newPassword) == 0 {
		http.Error(w, fuyaoerrors.ErrStrUsernameOrPasswordMissing, http.StatusBadRequest)
		return
	}

	if err := l.Authenticator.ResetPassword(context.Background(), username, oldPassword, newPassword); err != nil {
		http.Error(w, err.Error(), fuyaoerrors.ErrStatusCode[err])
		return
	}
	zlog.LogInfof("Password Reset succeed for user: %s", username)

	http.Redirect(w, r, "/auth/login/fuyaoPasswordProvider", http.StatusFound)
}

func (l *Login) getAccessToken(r *http.Request) (string, error) {
	// blindly get access-token from header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Check if the Authorization header starts with "Bearer "
		if strings.HasPrefix(authHeader, "Bearer ") {
			// Extract the access token
			accessToken := strings.TrimPrefix(authHeader, "Bearer ")
			return accessToken, nil
		}
	}

	return "", fuyaoerrors.ErrNotLogin
}

func (l *Login) authenticateByWebhook(accessToken string) (bool, error) {
	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: accessToken},
	}

	tokenReviewResponse, err := l.K8sClient.AuthenticationV1().TokenReviews().Create(
		context.TODO(), tokenReview, metav1.CreateOptions{})
	if err != nil {
		zlog.LogErrorf("cannot post tokenReview to k8s, err: %v", err)
		return false, fuyaoerrors.ErrNotLogin
	}

	return tokenReviewResponse.Status.Authenticated, nil
}

func (l *Login) renderLoginForm(w http.ResponseWriter, r *http.Request) {
	// 生成 uri
	uri, err := idp.GetBaseURL(r)
	if err != nil {
		http.Error(w, "unable to fetch requestURL", http.StatusInternalServerError)
		return
	}

	// 生成csrf token，从r中抽取then
	then := r.URL.Query().Get(constants.ThenParam)
	if len(then) == 0 {
		then = "/"
	}

	// 生成loginForm
	loginForm := LoginForm{
		Action: uri.String(),
		Then:   then,
	}

	// render form
	loginForm.OutputHTML(w, templates.DefaultLoginTemplateString, "loginForm")
}

func (l *Login) processLogin(w http.ResponseWriter, r *http.Request) {
	// fetch form value
	username := r.FormValue(constants.UsernameParam)
	password := r.FormValue(constants.PasswordParam)
	csrfToken := r.FormValue(constants.CSRFParam)
	then := r.FormValue(constants.ThenParam)

	// check form value
	if len(username) == 0 || len(password) == 0 {
		http.Error(w, fuyaoerrors.ErrStrUsernameOrPasswordMissing, http.StatusBadRequest)
		return
	}
	if len(then) == 0 {
		then = "/"
	}
	zlog.LogInfof("Login request: Username: %s, Then: %s\n", username, then)
	zlog.LogWarnf("currently does not check csrfToken: %s", csrfToken)

	// login devastation check
	ipAddress := getIPAddress(r)
	if l.loginIPProtector.IsLocked(ipAddress) {
		http.Error(w, fuyaoerrors.ErrStrLoginBlocked, http.StatusUnauthorized)
		return
	}

	// verify the password
	response, ok, err := l.Authenticator.AuthenticatePassword(context.Background(), username, password)

	// service internal error
	if err != nil && !errors.Is(err, fuyaoerrors.ErrPasswordAuthenticationFailed) {
		http.Error(w, fuyaoerrors.ErrStrLoginServiceDown, http.StatusInternalServerError)
		return
	}

	// password authentication error
	if !ok {
		// current ip failed times +1
		l.loginIPProtector.AddFailedLogin(ipAddress, time.Now())
		http.Error(w, fuyaoerrors.ErrStrPasswordAuthenticationFailed, http.StatusUnauthorized)
		return
	}

	// successfully login, erase ip block flag
	l.loginIPProtector.Unlock(ipAddress)

	if err = l.saveLoginStateToSession(response.User, w); err != nil {
		http.Error(w, fuyaoerrors.ErrStrLoginServiceDown, http.StatusInternalServerError)
		return
	}

	zlog.LogInfof("Successfully logging in with %s", response.User.GetName())

	// 重定向回到 /oauth/authorize
	http.Redirect(w, r, then, http.StatusFound)
}

func (l *Login) saveLoginStateToSession(user user.Info, w http.ResponseWriter) error {
	values := sessions.Values{}
	values[constants.UserName] = user.GetName()
	values[constants.UserUID] = user.GetUID()
	values[constants.UserGroups] = user.GetGroups()

	// serialize extra (map[string][]string)
	jsonExtra, err := json.Marshal(user.GetExtra())
	if err != nil {
		zlog.LogErrorf("cannot marshal data, err: %v", err)
		return fuyaoerrors.ErrFailToMarshalData
	}
	values[constants.UserExtra] = jsonExtra
	return l.idpLoginStore.Put(w, values)
}

// ---- util functions ----
func getIPAddress(r *http.Request) string {
	ipWithPort := r.RemoteAddr

	// fetch the first part if port is contained in the ipWithPort
	ipParts := strings.Split(ipWithPort, ":")
	ip := ipParts[0]

	return ip
}
