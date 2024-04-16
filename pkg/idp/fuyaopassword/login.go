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

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"

	"oauth-server/assets/templates"
	"oauth-server/pkg/authenticators"
	"oauth-server/pkg/constants"
	"oauth-server/pkg/fuyaoerrors"
	"oauth-server/pkg/idp"
	"oauth-server/pkg/protector"
	"oauth-server/pkg/sessions"
	"oauth-server/pkg/zlog"
)

// LoginForm contains the fields used by fuyao login
type LoginForm struct {
	Action    string
	Then      string
	CSRFToken string
}

// OutputHTML writes the contents back to web
func (l *LoginForm) OutputHTML(w http.ResponseWriter, tpl string, name string) {
	tplForm := template.Must(template.New(name).Parse(tpl))
	if err := tplForm.Execute(w, l); err != nil {
		http.Error(w, fuyaoerrors.ErrStrFailToDisplayLogin, http.StatusInternalServerError)
		return
	}
}

// Login works for fuyao login, implement the login interfaces
type Login struct {
	Provider string
	// CSRF csrf.CSRF
	Authenticator    authenticators.PasswordAuthenticator
	idpLoginStore    *sessions.CookieStore
	loginIPProtector *protector.LoginIPProtector
}

// NewLogin returns the fuyao Login instance
func NewLogin(
	idpLoginStore *sessions.CookieStore,
	k8sClient kubernetes.Interface,
	loginIPProtector *protector.LoginIPProtector,
	provider, ns string,
) *Login {
	return &Login{
		Provider:         provider,
		Authenticator:    authenticators.NewFuyaoPasswordAuthenticator(k8sClient, ns),
		idpLoginStore:    idpLoginStore,
		loginIPProtector: loginIPProtector,
	}
}

// LoginHandler deals with both GET/POST requests
func (l *Login) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 处理GET请求
		l.renderLoginForm(w, r)
	} else if r.Method == http.MethodPost {
		// 处理POST请求
		l.processLogin(w, r)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

// PasswordConfirmHandler works when the user login for the first time
func (l *Login) PasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: 要不这里也先get一次然后再post一次？还是直接让前台处理好get这部分 我先把post的逻辑写在这里
	// 即使是请求发到了这里，在更改之前还是要检测一下数据库是否已经是首次登陆，不是就要报错
	// read userinfo from session-store
	loginData := l.idpLoginStore.Get(r)
	username, ok := loginData.GetString(constants.UserName)
	if !ok {
		http.Error(w, fuyaoerrors.ErrStrNotLogin, http.StatusUnauthorized)
		return
	}

	// read params from r.url
	newPassword := r.FormValue(constants.NewPasswordParam)
	then := r.FormValue(constants.ThenParam)
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
		zlog.Warnf("cannot delete the loginstore used in authorization, err: %v", err)
	}
	zlog.Infof("Password Confirmation succeed for user: %s", username)

	// 正常重定向
	http.Redirect(w, r, then, http.StatusFound)
}

// PasswordResetHandler resets the password
func (l *Login) PasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	// read params from r.url
	username := r.FormValue(constants.UsernameParam)
	oldPassword := r.FormValue(constants.OriginalPasswordParam)
	newPassword := r.FormValue(constants.NewPasswordParam)
	if len(username) == 0 || len(oldPassword) == 0 || len(newPassword) == 0 {
		http.Error(w, fuyaoerrors.ErrStrUsernameOrPasswordMissing, http.StatusBadRequest)
		return
	}

	if err := l.Authenticator.ResetPassword(context.Background(), username, oldPassword, newPassword); err != nil {
		http.Error(w, err.Error(), fuyaoerrors.ErrStatusCode[err])
		return
	}
	zlog.Infof("Password Reset succeed for user: %s", username)

	// 正常重定向, TODO: 是否要将 url 单独写到一个文件中
	http.Redirect(w, r, "/auth/login", http.StatusFound)
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
	// 处理登录表单提交
	username := r.FormValue(constants.UsernameParam)
	password := r.FormValue(constants.PasswordParam)
	// csrfToken := r.FormValue("csrf_token")
	then := r.FormValue(constants.ThenParam)

	// TODO: then 要check是否是当前访问的relative url，不是要重定向到 "/" 这里是不是一定是绝对url
	// TODO: 验证 CSRF Token

	// 验证用户名 密码
	if len(username) == 0 || len(password) == 0 {
		http.Error(w, fuyaoerrors.ErrStrUsernameOrPasswordMissing, http.StatusBadRequest)
		return
	}
	if len(then) == 0 {
		then = "/"
	}
	zlog.Infof("Login request: Username: %s, Then: %s\n", username, then)

	// 防爆破check，是否当前ip会被封禁
	ipAddress := getIPAddress(r)
	if l.loginIPProtector.IsLocked(ipAddress) {
		http.Error(w, fuyaoerrors.ErrStrLoginBlocked, http.StatusUnauthorized)
		return
	}

	// 进行登陆check
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

	// TODO: 将session中写入用户信息，这里的sessionSave有bug
	if err = l.saveLoginStateToSession(response.User, w); err != nil {
		http.Error(w, fuyaoerrors.ErrStrLoginServiceDown, http.StatusInternalServerError)
		return
	}

	zlog.Infof("Successfully logging in with %s", response.User.GetName())

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
		zlog.Errorf("cannot marshal data, err: %v", err)
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
