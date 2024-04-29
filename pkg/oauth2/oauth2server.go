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

// Package oauth2
package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

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

	"openfuyao/oauth-server/cmd/oauth-server/app/config"
	"openfuyao/oauth-server/pkg/constants"
	"openfuyao/oauth-server/pkg/fuyaoerrors"
	"openfuyao/oauth-server/pkg/generators"
	"openfuyao/oauth-server/pkg/sessions"
	fuyaostore "openfuyao/oauth-server/pkg/store"
	"openfuyao/oauth-server/pkg/zlog"
)

// FuyaoAuthorizeRequest extends the original AuthorizeRequest in go-oauth2
type FuyaoAuthorizeRequest struct {
	server.AuthorizeRequest
	identityProvider string
}

// FuyaoAuthorizeServer extends the original authorize server in go-oauth2
type FuyaoAuthorizeServer struct {
	// inherits and overrides some interfaces
	*server.Server
	// session-store implementation, which stores whether the user has logged in via account password
	idpLoginStore *sessions.CookieStore
	// tokenStore stores the code/access-token in the k8s secret
	tokenStore oauth2.TokenStore
}

// NewFuyaoAuthorizeServer inits a FuyaoAuthorizeServer
func NewFuyaoAuthorizeServer(
	cfg *server.Config,
	manager oauth2.Manager,
	idpLoginStore *sessions.CookieStore,
	tokenStore oauth2.TokenStore,
) *FuyaoAuthorizeServer {
	return &FuyaoAuthorizeServer{
		Server:        server.NewServer(cfg, manager),
		idpLoginStore: idpLoginStore,
		tokenStore:    tokenStore,
	}
}

// NewOAuthServer inits the go-oauth2 oauth server
func NewOAuthServer(
	idpLoginStore *sessions.CookieStore,
	tokenStore *fuyaostore.K8sSecretStore,
	cfg *config.OAuthServerConfig,
) *FuyaoAuthorizeServer {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(
		&manage.Config{AccessTokenExp: cfg.AccessTokenExp, RefreshTokenExp: cfg.RefreshTokenExp,
			IsGenerateRefresh: cfg.IsGenerateRefresh})
	manager.SetAuthorizeCodeExp(cfg.AuthCodeExp)
	manager.MapAuthorizeGenerate(generators.NewFuyaoAuthorizeGenerate())

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	// generate jwt access token
	manager.MapAccessGenerate(
		generates.NewJWTAccessGenerate(cfg.JWTKeyID, []byte(cfg.JWTPrivateKey), jwt.SigningMethodHS512))

	clientStore := store.NewClientStore()
	for client, secret := range cfg.ClientMapper {
		clientStore.Set(client, &models.Client{
			ID:     client,
			Secret: secret,
		})
	}
	manager.MapClientStorage(clientStore)
	manager.MapTokenStorage(tokenStore)

	srv := NewFuyaoAuthorizeServer(server.NewConfig(), manager, idpLoginStore, tokenStore)
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

// OAuthAuthorizeHandler http handler for /oauth/authorize
func (s *FuyaoAuthorizeServer) OAuthAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	// fetch params
	ctx := r.Context()

	req, err := s.ValidateAuthorizeRequest(r)
	if err != nil {
		s.wrapReturnErrorHandler(w, s.redirectAuthorizationCodeError(w, req, err))
		return
	}

	// check whether containing sessionID, if so fetching the user
	// implement through secured-cookie
	userResponse, ok, err := s.AuthorizeThroughSession(w, r)
	if err != nil {
		s.wrapReturnErrorHandler(w, s.redirectAuthorizationCodeError(w, req, err))
		return
	}

	if !ok {
		// otherwise redirect to login (using the selected identityProvider)
		if err = s.RedirectToLogin(req, w, r); err != nil {
			s.wrapReturnErrorHandler(w, s.redirectAuthorizationCodeError(w, req, err))
			return
		}
		return
	}

	// generate the oauth code
	req.UserID = userResponse.User.GetName()
	ti, err := s.GetAuthorizeToken(ctx, &req.AuthorizeRequest)
	if err != nil {
		s.wrapReturnErrorHandler(w, s.redirectAuthorizationCodeError(w, req, err))
		return
	}

	// use the default client domain if the redirect URI is empty
	if req.RedirectURI == "" {
		client, err := s.Manager.GetClient(ctx, req.ClientID)
		if err != nil {
			s.wrapReturnErrorHandler(w, err)
		}
		req.RedirectURI = client.GetDomain()
	}

	// finally we redirect to the client callback interface
	s.wrapReturnErrorHandler(w, s.redirectAuthorizationCode(w, req, s.GetAuthorizeData(req.ResponseType, ti)))
	return
}

// OAuthTokenHandler http handler for /oauth/token
func (s *FuyaoAuthorizeServer) OAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	gt, tgr, err := s.ValidationTokenRequest(r)
	if err != nil {
		s.wrapReturnErrorHandler(w, s.generateTokenError(w, err))
		return
	}

	ti, err := s.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		// delete expired authorization code
		if delErr := s.deleteExpiredAuthCode(tgr); delErr != nil {
			zlog.LogErrorf("delete expired auth code goes wrong: err: %v", delErr)
		}
		s.wrapReturnErrorHandler(w, s.generateTokenError(w, err))
		return
	}

	s.wrapReturnErrorHandler(w, s.returnAccessToken(w, s.GetTokenData(ti), nil))

	return
}

// RedirectToLogin redirects to login page when sessionId is missing
func (s *FuyaoAuthorizeServer) RedirectToLogin(
	req *FuyaoAuthorizeRequest,
	w http.ResponseWriter,
	r *http.Request,
) error {
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

// ValidateAuthorizeRequest makes sure the request params do not miss necessary params
func (s *FuyaoAuthorizeServer) ValidateAuthorizeRequest(r *http.Request) (*FuyaoAuthorizeRequest, error) {
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

// AuthorizeThroughSession authorize the user with session stored data
func (s *FuyaoAuthorizeServer) AuthorizeThroughSession(
	w http.ResponseWriter,
	r *http.Request,
) (*authenticator.Response, bool, error) {
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
			zlog.LogErrorf("cannot delete the loginstore used in authorization, err: %v", err)
			return nil, false, err
		}
	}

	if !ok1 || !ok2 || !ok3 || !ok4 {
		// the session is broken, flush it
		if err := s.idpLoginStore.Put(w, make(sessions.Values)); err != nil {
			zlog.LogErrorf("cannot delete the loginstore used in authorization, err: %v", err)
			return nil, false, err
		}
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

// GetErrorData forms the error return data for oauth2.0
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

// deleteExpiredAuthCode flush the auth code secret if expiry
func (s *FuyaoAuthorizeServer) deleteExpiredAuthCode(tgr *oauth2.TokenGenerateRequest) error {
	code := tgr.Code
	ti, err := s.tokenStore.GetByCode(context.Background(), code)

	if err != nil {
		zlog.LogErrorf("cannot get auth code, err: %v", err)
		return err
	} else if ti != nil && ti.GetCodeCreateAt().Add(ti.GetCodeExpiresIn()).Before(time.Now()) {
		// delete the auth code
		if err = s.tokenStore.RemoveByCode(context.Background(), code); err != nil {
			return err
		}
		zlog.LogInfof("successfully delete auth code in secret")
	}

	return nil
}

func (s *FuyaoAuthorizeServer) handleError(w http.ResponseWriter, req *FuyaoAuthorizeRequest, err error) error {
	if fn := s.PreRedirectErrorHandler; fn != nil {
		return fn(w, &req.AuthorizeRequest, err)
	}

	return s.redirectAuthorizationCodeError(w, req, err)
}

func (s *FuyaoAuthorizeServer) wrapReturnErrorHandler(w http.ResponseWriter, err error) {
	if err != nil {
		zlog.LogErrorf("fail when writing error back to the http response header, err: %v", err)
		http.Error(w, fuyaoerrors.ErrStrWritingHttpHeader, http.StatusInternalServerError)
		return
	}
	return
}

func (s *FuyaoAuthorizeServer) redirectAuthorizationCode(
	w http.ResponseWriter,
	req *FuyaoAuthorizeRequest,
	data map[string]interface{},
) error {
	uri, err := s.GetRedirectURI(&req.AuthorizeRequest, data)
	if err != nil {
		return err
	}

	w.Header().Set("Location", uri)
	w.WriteHeader(http.StatusFound)
	return nil
}

func (s *FuyaoAuthorizeServer) redirectAuthorizationCodeError(
	w http.ResponseWriter,
	req *FuyaoAuthorizeRequest,
	err error,
) error {
	if req == nil {
		return err
	}

	data, _, _ := s.GetErrorData(err)
	return s.redirectAuthorizationCode(w, req, data)
}

func (s *FuyaoAuthorizeServer) generateTokenError(w http.ResponseWriter, err error) error {
	data, statusCode, header := s.GetErrorData(err)
	return s.returnAccessToken(w, data, header, statusCode)
}

func (s *FuyaoAuthorizeServer) returnAccessToken(
	w http.ResponseWriter,
	data map[string]interface{},
	header http.Header,
	statusCode ...int,
) error {
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
