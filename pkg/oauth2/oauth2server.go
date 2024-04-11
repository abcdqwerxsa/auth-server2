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
	"errors"
	"fmt"
	"github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v4"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"log"
	"net/http"
	"net/url"
	"oauth-server/pkg/configs"
	"oauth-server/pkg/constants"
	"oauth-server/pkg/fuyaoerrors"
	"oauth-server/pkg/generators"
	"oauth-server/pkg/sessions"
	fuyaostore "oauth-server/pkg/store"
	"oauth-server/pkg/zlog"
)

var (
	manager     *manage.Manager
	clientStore *store.ClientStore
)

type FuyaoAuthorizeRequest struct {
	server.AuthorizeRequest
	identityProvider string
}

type FuyaoAuthorizeServer struct {
	// 继承并重写部分接口
	*server.Server
	// session-store 实现，这个是存储用户是否已经通过账户密码登录的接口
	idpLoginStore *sessions.CookieStore
}

func NewFuyaoAuthorizeServer(cfg *server.Config, manager oauth2.Manager, idpLoginStore *sessions.CookieStore) *FuyaoAuthorizeServer {
	return &FuyaoAuthorizeServer{
		server.NewServer(cfg, manager),
		// TODO: set this through config
		idpLoginStore,
	}
}

func (s *FuyaoAuthorizeServer) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) error {
	// 这个就是本质的使用对象，我这里只需要重写这个函数应该就没问题了
	// fetch params
	// TODO: 所有的expiration都要后续检查一遍
	ctx := r.Context()

	req, err := s.ValidationAuthorizeRequest(r)
	if err != nil {
		// 错误处理 直接redirect
		return s.handleError(w, req, err)
	}

	// check whether containing sessionID, if so fetching the user
	// 这个我先从cookie中取吧，先看看oauth2自己的storage实现方式，不行就访问gorilla-session
	userResponse, ok, err := s.AuthorizeThroughSession(w, r)
	if err != nil {
		return s.handleError(w, req, err)
	}

	if !ok {
		// otherwise redirect to login (using the selected identityProvider)
		// 这里就要根据不同的 identityProvider 来进行认证请求 TODO: 验证provider要不要放在这里呢
		if err = s.RedirectToLogin(req, w, r); err != nil {
			return s.handleError(w, req, err)
		}
		return nil
	}

	//// specify the scope of authorization
	//if fn := s.AuthorizeScopeHandler; fn != nil {
	//	scope, err := fn(w, r)
	//	if err != nil {
	//		return err
	//	} else if scope != "" {
	//		req.Scope = scope
	//	}
	//}
	//
	//// specify the expiration time of access token
	//if fn := s.AccessTokenExpHandler; fn != nil {
	//	exp, err := fn(w, r)
	//	if err != nil {
	//		return err
	//	}
	//	req.AccessTokenExp = exp
	//}

	// generate the oauth code 在把code 存储到etcd的同时也要存入用户信息，这样在token接口使用code就可以从etcd中获取用户信息等
	req.UserID = userResponse.User.GetName()
	ti, err := s.GetAuthorizeToken(ctx, &req.AuthorizeRequest)
	if err != nil {
		return s.handleError(w, req, err)
	}

	// If the redirect URI is empty, the default domain provided by the client is used.
	if req.RedirectURI == "" {
		client, err := s.Manager.GetClient(ctx, req.ClientID)
		if err != nil {
			return err
		}
		req.RedirectURI = client.GetDomain()
	}

	// redirect to client callback endpoints
	return s.redirect(w, req, s.GetAuthorizeData(req.ResponseType, ti))
}

func (s *FuyaoAuthorizeServer) RedirectToLogin(req *FuyaoAuthorizeRequest, w http.ResponseWriter, r *http.Request) error {
	// TODO: maybe we have multiple internal idps in the future
	if req.identityProvider != constants.FuyaoIdpProvider {
		return fuyaoerrors.ErrIdentityProviderIncorrect
	}
	loginRedirectURL, err := buildLoginRedirectURL(r, req.identityProvider)
	if err != nil {
		return err
	}

	http.Redirect(w, r, loginRedirectURL.String(), http.StatusFound)
	return nil
}

func buildLoginRedirectURL(r *http.Request, idp string) (*url.URL, error) {
	// 原始 URL
	//originalURL := "https://oauth-openshift.apps.my-ocp-cluster.com/oauth/authorize?client_id=console&idp=my_htpasswd_provider&redirect_uri=https%3A%2F%2Fconsole-openshift-console.apps.my-ocp-cluster.com%2Fauth%2Fcallback&response_type=code&scope=user%3Afull&state=3c0476b9"
	originalURL := r.URL

	redirectURL := &url.URL{
		Scheme: originalURL.Scheme,
		Host:   originalURL.Host,
		Path:   fmt.Sprintf("/auth/login/%s", idp),
	}

	thenParamVal := originalURL.String()
	// 在重定向 URL 的查询参数中添加 then 参数
	query := redirectURL.Query()
	query.Set("then", thenParamVal)
	redirectURL.RawQuery = query.Encode()

	return redirectURL, nil
}

func (s *FuyaoAuthorizeServer) ValidationAuthorizeRequest(r *http.Request) (*FuyaoAuthorizeRequest, error) {
	// original call
	req, err := s.Server.ValidationAuthorizeRequest(r)
	if err != nil {
		return nil, err
	}

	// fetch the path parameter identityProvider
	idp := r.FormValue("identity_provider")
	if idp == "" {
		return nil, fuyaoerrors.ErrIdentityProviderIncorrect
	}

	return &FuyaoAuthorizeRequest{
		AuthorizeRequest: *req,
		identityProvider: idp,
	}, nil
}

func (s *FuyaoAuthorizeServer) AuthorizeThroughSession(w http.ResponseWriter, r *http.Request) (*authenticator.Response, bool, error) {
	// fetch the cached user info
	cookieData := s.idpLoginStore.Get(r)

	username, ok1 := cookieData.GetString(constants.UserName)
	uid, ok2 := cookieData.GetString(constants.UserUID)
	groups, ok3 := cookieData.GetArrayString(constants.UserGroups)
	extras, ok4 := cookieData.GetExtras(constants.UserExtra)

	// if it isn't the first login
	if ok4 && extras["first-login"][0] == "false" {
		// immediately delete the userinfo
		if err := s.idpLoginStore.Put(w, make(sessions.Values)); err != nil {
			zlog.Errorf("cannot delete the loginstore used in authorization, err: %v", err)
			return nil, false, err
		}
	}

	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, false, nil
	}

	return &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   username,
			UID:    uid,
			Groups: groups,
			Extra:  extras,
		},
	}, true, nil

}

func (s *FuyaoAuthorizeServer) GetErrorData(err error) (map[string]interface{}, int, http.Header) {
	// deal with incorrect identity_provider error
	if errors.Is(err, fuyaoerrors.ErrIdentityProviderIncorrect) {
		data := make(map[string]interface{})
		data["error"] = "incorrect_identity_provider"
		data["error_code"] = http.StatusBadRequest
		data["error_description"] = fuyaoerrors.ErrStrIdentityProviderIncorrect
		header := make(http.Header)
		return data, http.StatusBadRequest, header
	}

	return s.Server.GetErrorData(err)
}

func (s *FuyaoAuthorizeServer) handleError(w http.ResponseWriter, req *FuyaoAuthorizeRequest, err error) error {
	if fn := s.PreRedirectErrorHandler; fn != nil {
		return fn(w, &req.AuthorizeRequest, err)
	}

	return s.redirectError(w, req, err)
}

func (s *FuyaoAuthorizeServer) redirectError(w http.ResponseWriter, req *FuyaoAuthorizeRequest, err error) error {
	if req == nil {
		return err
	}

	data, _, _ := s.GetErrorData(err)
	return s.redirect(w, req, data)
}

func (s *FuyaoAuthorizeServer) redirect(w http.ResponseWriter, req *FuyaoAuthorizeRequest, data map[string]interface{}) error {
	uri, err := s.GetRedirectURI(&req.AuthorizeRequest, data)
	if err != nil {
		return err
	}

	w.Header().Set("Location", uri)
	w.WriteHeader(302)
	return nil
}

func NewOAuthServer(idpLoginStore *sessions.CookieStore, k8sClient kubernetes.Interface, ns string) *FuyaoAuthorizeServer {
	manager = manage.NewDefaultManager()
	// 这里可能需要后续把这些config单独拿出来
	// 设置access_token 和 authorization_code 的超时时间
	manager.SetAuthorizeCodeTokenCfg(configs.DefaultAuthorizeCodeTokenCfg)
	manager.SetAuthorizeCodeExp(configs.DefaultCodeExp)
	manager.MapAuthorizeGenerate(generators.NewFuyaoAuthorizeGenerate())

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	// TODO: 这个要以配置的方式拆解出去
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("access_token_sign_key", []byte("i_am_the_secrets"), jwt.SigningMethodHS512))
	//manager.MapAccessGenerate(generates.NewAccessGenerate())
	//
	// TODO: 这里的id和secret是不是要改成可以配置的，所有需要走oauth2的client都要在这里配置一下
	clientStore = store.NewClientStore()
	clientStore.Set("console", &models.Client{
		ID:     "console",
		Secret: "console-password",
	})

	// TODO: 这个manager是否要重新new一个新的
	manager.MapClientStorage(clientStore)

	tokenStore := fuyaostore.NewK8sSecretStore(k8sClient, ns)
	manager.MapTokenStorage(tokenStore)

	srv := NewFuyaoAuthorizeServer(server.NewConfig(), manager, idpLoginStore)

	srv.SetInternalErrorHandler(func(err error) (re *oauth2errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *oauth2errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	// token request function configurations
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetAllowGetAccessRequest(false)

	return srv
}

func (s *FuyaoAuthorizeServer) OAuth2AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.HandleAuthorizeRequest(w, r); err != nil {
		// TODO: 错误处理
	}
	// TODO: 考虑把redirect部分拿出来？
}

func (s *FuyaoAuthorizeServer) OAuth2TokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.HandleTokenRequest(w, r); err != nil {
		// TODO: 错误处理
	}
	// TODO: 考虑把redirect部分拿出来？
}

func (s *FuyaoAuthorizeServer) HandleTokenRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	gt, tgr, err := s.ValidationTokenRequest(r)
	if err != nil {
		return s.tokenError(w, err)
	}

	ti, err := s.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		return s.tokenError(w, err)
	}

	return s.token(w, s.GetTokenData(ti), nil)
}

func (s *FuyaoAuthorizeServer) tokenError(w http.ResponseWriter, err error) error {
	data, statusCode, header := s.GetErrorData(err)
	return s.token(w, data, header, statusCode)
}

func (s *FuyaoAuthorizeServer) token(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error {
	if fn := s.ResponseTokenHandler; fn != nil {
		return fn(w, data, header, statusCode...)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}
