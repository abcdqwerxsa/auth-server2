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
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
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
	"openfuyao/oauth-server/pkg/fuyaostore"
	"openfuyao/oauth-server/pkg/httpserver"
	"openfuyao/oauth-server/pkg/idp"
	"openfuyao/oauth-server/pkg/protector"
	"openfuyao/oauth-server/pkg/sessions"
	"openfuyao/oauth-server/pkg/zlog"
)

// LoginForm contains the fields used by fuyao login
type LoginForm struct {
	Action    string
	Then      string
	CSRFToken string
	UserName  string
	Error     string
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
	consoleServiceHost string
	K8sClient          kubernetes.Interface
	TokenStore         *fuyaostore.K8sSecretStore
	Authenticator      authenticators.PasswordAuthenticator
	idpLoginStore      *sessions.CookieStore
	loginIPProtector   *protector.LoginIPProtector
}

// NewLogin returns the fuyao Login instance
func NewLogin(
	idpLoginStore *sessions.CookieStore,
	k8sClient kubernetes.Interface,
	tokenStore *fuyaostore.K8sSecretStore,
	loginIPProtector *protector.LoginIPProtector,
	loginConfig *config.LoginConfig,
) *Login {
	return &Login{
		Provider:           loginConfig.Provider,
		consoleServiceHost: loginConfig.ConsoleServiceHost,
		K8sClient:          k8sClient,
		TokenStore:         tokenStore,
		Authenticator:      authenticators.NewFuyaoPasswordAuthenticator(k8sClient, loginConfig.UserNamespace),
		idpLoginStore:      idpLoginStore,
		loginIPProtector:   loginIPProtector,
	}
}

// LoginHandler deals with both GET/POST requests
func (l *Login) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// deal with GET
		l.handleLoginForm(w, r)
	} else if r.Method == http.MethodPost {
		// deal with POST
		l.processLogin(w, r)
	} else {
		http.Error(w, fuyaoerrors.ErrStrRequestMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
}

// PasswordConfirmHandler works when the user login for the first time
func (l *Login) PasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// deal with GET
		l.handlePasswordConfirmForm(w, r)
	} else if r.Method == http.MethodPost {
		// deal with POST
		l.processPasswordConfirm(w, r)
	} else {
		http.Error(w, fuyaoerrors.ErrStrRequestMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
}

func (l *Login) handlePasswordConfirmForm(w http.ResponseWriter, r *http.Request) {
	// 生成 uri
	uri, err := idp.GetBaseURL(r)
	if err != nil {
		http.Error(w, "unable to fetch requestURL", http.StatusInternalServerError)
		return
	}

	// fetch then from r
	then := r.URL.Query().Get(constants.ThenParam)
	if len(then) == 0 {
		then = "/"
	}

	// get error from r
	errString := r.URL.Query().Get(constants.ErrorParam)

	// read userinfo from session-store
	loginData := l.idpLoginStore.Get(r)
	username, ok := loginData.GetString(constants.UserName)
	if !ok {
		http.Error(w, fuyaoerrors.ErrStrNotLogin, http.StatusUnauthorized)
		return
	}

	// 生成loginForm
	loginForm := LoginForm{
		Action:   uri.String(),
		Then:     then,
		UserName: username,
		Error:    errString,
	}

	// render form
	loginForm.OutputHTML(w, templates.DefaultPasswordConfirmTemplateString, constants.PasswordConfirmFormTemplate)
}

func (l *Login) processPasswordConfirm(w http.ResponseWriter, r *http.Request) {
	// read userinfo from session-store
	loginData := l.idpLoginStore.Get(r)
	username, ok := loginData.GetString(constants.UserName)
	if !ok {
		http.Redirect(w, r, l.consoleServiceHost, http.StatusFound)
		return
	}

	newPassword := r.FormValue(constants.NewPasswordParam)
	then := r.FormValue(constants.ThenParam)
	if len(newPassword) == 0 {
		redirectGetMethodWithError(w, r, fuyaoerrors.ErrStrUsernameOrPasswordMissing, then)
		return
	}
	if len(then) == 0 {
		then = "/"
	}

	// password confirmation logic
	if err := l.Authenticator.ConfirmPassword(context.Background(), username, newPassword); err != nil {
		redirectGetMethodWithError(w, r, err.Error(), then)
		return
	}

	// set first-login to false in the oauth-session
	// if fail in the following 8 lines only idpLogin cookie first-login is tainted, we can still redirect safely
	ok = loginData.SetLoggedIn()
	if !ok {
		zlog.LogError("fail to set first-login state to false, probably due to web modification")
	} else if err := l.idpLoginStore.Put(w, loginData); err != nil {
		zlog.LogError("fail to store loginState to session")
	} else {
		zlog.LogInfo("Successfully set idpLogin state for password confirmation.")
	}
	zlog.LogInfof("Password Confirmation succeed for user: %s", username)

	// redirect normally
	http.Redirect(w, r, then, http.StatusFound)
}

// PasswordResetHandler resets the password
func (l *Login) PasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	// check http method
	if r.Method != http.MethodPost {
		httpserver.RespondWithStatusMsg(w, http.StatusMethodNotAllowed, 0, fuyaoerrors.ErrStrRequestMethodNotAllowed)
		return
	}

	// add an access token validation, since all the services are required to expose in this version
	accessToken, err := l.getAccessToken(r)
	if err != nil {
		httpserver.RespondWithStatusMsg(w, http.StatusUnauthorized, 0, fuyaoerrors.ErrStrNotLogin)
		return
	}

	loggedIn, err := l.authenticateByWebhook(accessToken)
	if !loggedIn || err != nil {
		httpserver.RespondWithStatusMsg(w, fuyaoerrors.ErrStatusCode[err], 0, err.Error())
	}

	// read params from r.url
	var requestBody PasswordResetRequest
	if err = json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		httpserver.RespondWithStatusMsg(w, http.StatusBadRequest, 0, fuyaoerrors.ErrStrFailToUnmarshalData)
		return
	}

	username := requestBody.Username
	oldPassword := requestBody.OriginalPassword
	newPassword := requestBody.NewPassword
	if len(username) == 0 || len(oldPassword) == 0 || len(newPassword) == 0 {
		httpserver.RespondWithStatusMsg(w, http.StatusBadRequest, 0, fuyaoerrors.ErrStrUsernameOrPasswordMissing)
		return
	}

	if err := l.Authenticator.ResetPassword(context.Background(), username, oldPassword, newPassword); err != nil {
		httpserver.RespondWithStatusMsg(w, fuyaoerrors.ErrStatusCode[err], 0, err.Error())
		return
	}
	zlog.LogInfof("Password Reset succeed for user: %s", username)

	httpserver.RespondWithStatusMsg(w, http.StatusOK, 0, "Password Reset OK")
	return
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

func (l *Login) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	// 生成 uri
	uri, err := idp.GetBaseURL(r)
	if err != nil {
		zlog.LogErrorf("unable to fetch requestURL, err: %v", err)
		http.Error(w, "unable to fetch requestURL", http.StatusInternalServerError)
		return
	}

	// 从r中抽取then
	then := r.URL.Query().Get(constants.ThenParam)
	if len(then) == 0 {
		then = "/"
	}

	// redirect if already logged in
	loginData := l.idpLoginStore.Get(r)
	_, ok := loginData.GetString(constants.UserName)
	if ok {
		http.Redirect(w, r, then, http.StatusFound)
		return
	}

	// get error from r
	errString := r.URL.Query().Get(constants.ErrorParam)

	// 生成loginForm
	loginForm := LoginForm{
		Action: uri.String(),
		Then:   then,
		Error:  errString,
	}

	// render form
	loginForm.OutputHTML(w, templates.DefaultLoginTemplateString, constants.LoginFormTemplate)
}

func (l *Login) processLogin(w http.ResponseWriter, r *http.Request) {
	// fetch form value
	username := r.FormValue(constants.UsernameParam)
	password := r.FormValue(constants.PasswordParam)
	csrfToken := r.FormValue(constants.CSRFParam)
	then := r.FormValue(constants.ThenParam)

	// check form value
	if len(username) == 0 || len(password) == 0 {
		redirectGetMethodWithError(w, r, fuyaoerrors.ErrStrUsernameOrPasswordMissing, then)
		return
	}
	if len(then) == 0 {
		then = "/"
	}
	zlog.LogInfof("Login request: Username: %s, Then: %s\n", username, then)
	zlog.LogWarnf("currently does not check csrfToken: %s", csrfToken)

	// login devastation check
	ipAddress := getIPAddress(r)
	if locked, remainingTime := l.loginIPProtector.CheckLocked(ipAddress); locked {
		errString := strings.Replace(fuyaoerrors.ErrStrLoginBlocked, "%s",
			strconv.FormatInt(remainingTime, constants.Decimal), 1)
		redirectGetMethodWithError(w, r, errString, then)
		return
	}

	// verify the password
	response, ok, err := l.Authenticator.AuthenticatePassword(context.Background(), username, password)

	// service internal error
	if err != nil && !errors.Is(err, fuyaoerrors.ErrPasswordAuthenticationFailed) {
		redirectGetMethodWithError(w, r, fuyaoerrors.ErrStrLoginServiceDown, then)
		return
	}

	// password authentication error
	if !ok {
		// current ip failed times +1
		remainingAttempt := l.loginIPProtector.AddFailedLogin(ipAddress, time.Now())

		// still got login attempts
		if remainingAttempt > 0 {
			errString := strings.Replace(fuyaoerrors.ErrStrPasswordAuthenticationFailedWithCount, "%s",
				strconv.FormatInt(int64(remainingAttempt), constants.Decimal), 1)
			redirectGetMethodWithError(w, r, errString, then)
			return
		}

		// trigger ip blocking
		lockDuration := int64(l.loginIPProtector.LockDuration.Minutes())
		errString := strings.Replace(fuyaoerrors.ErrStrPasswordAuthenticationFailedLocked, "%s",
			strconv.FormatInt(lockDuration, constants.Decimal), 1)
		redirectGetMethodWithError(w, r, errString, then)
		return
	}

	// successfully login, erase ip block flag
	l.loginIPProtector.Unlock(ipAddress)

	if err = l.saveLoginStateToSession(response.User, w); err != nil {
		redirectGetMethodWithError(w, r, fuyaoerrors.ErrStrLoginServiceDown, then)
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
	extra := user.GetExtra()

	// add the web-oauthserver session-id
	const sessionIDLength = 32
	sessionID, err := generateSessionID(sessionIDLength)
	extra[constants.OAuthServerSessionID] = []string{sessionID}

	// save the extra information
	jsonExtra, err := json.Marshal(extra)
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

func redirectGetMethodWithError(w http.ResponseWriter, r *http.Request, errString, then string) {
	// build redirect url
	encodedErrString := url.QueryEscape(errString)
	encodedThen := url.QueryEscape(then)
	redirect := fmt.Sprintf("%s?then=%s&error=%s", r.URL.String(), encodedThen, encodedErrString)

	// redirect to GET handleLogin
	http.Redirect(w, r, redirect, http.StatusFound)
}

func generateSessionID(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	sessionID := make([]byte, length)

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			zlog.LogErrorf("Cannot generate random char, err: %v", err)
			return "", err
		}
		sessionID[i] = charset[num.Int64()]
	}

	return string(sessionID), nil
}
