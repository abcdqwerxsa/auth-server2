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

// Package apiserver inits all the necessary components
package apiserver

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	overallconfigs "openfuyao/oauth-server/cmd/oauth-server/app/config"
	"openfuyao/oauth-server/pkg/config"
	"openfuyao/oauth-server/pkg/httpserver"
	"openfuyao/oauth-server/pkg/idp/fuyaopassword"
	"openfuyao/oauth-server/pkg/oauth2"
	"openfuyao/oauth-server/pkg/protector"
	"openfuyao/oauth-server/pkg/sessions"
	"openfuyao/oauth-server/pkg/zlog"
)

// OAuthServerAPIServer is the true apiserver that handles requests
type OAuthServerAPIServer struct {
	Server      *http.Server
	Router      *mux.Router
	Login       *fuyaopassword.Login
	OAuthServer *oauth2.FuyaoAuthorizeServer
}

// NewOAuthServerAPIServer inits a new oauthserver apiserver
func NewOAuthServerAPIServer(
	cfg *overallconfigs.OAuthServerAPIServerConfig,
	stopCh <-chan struct{},
) (*OAuthServerAPIServer, error) {
	// init httpserver
	server, err := httpserver.NewHttpServer(cfg.HttpServerConfig)
	if err != nil {
		return nil, err
	}
	router := mux.NewRouter()
	server.Handler = router

	// init each component
	k8sClient := config.GetKubernetesClient(cfg.K8sConfig)
	idpLoginStore := sessions.NewSessionStore(
		cfg.IDPLoginStoreConfig.SessionName, cfg.IDPLoginStoreConfig.SessionMaxAge,
		[]byte(cfg.IDPLoginStoreConfig.SigningKey), []byte(cfg.IDPLoginStoreConfig.EncryptionKey))
	loginIPProtector := protector.NewLoginIPProtector(cfg.IPProtectorConfig)
	login := fuyaopassword.NewLogin(idpLoginStore, k8sClient, loginIPProtector,
		cfg.LoginConfig.Provider, cfg.LoginConfig.UserNamespace)
	oauthServer := oauth2.NewOAuthServer(idpLoginStore, k8sClient, cfg.OAuthServerConfig)

	return &OAuthServerAPIServer{
		Server:      server,
		Router:      router,
		Login:       login,
		OAuthServer: oauthServer,
	}, nil
}

// PrepareRun registers the router and the access logger
func (s *OAuthServerAPIServer) PrepareRun(stopCh <-chan struct{}) error {
	s.Router.Use(httpserver.AccessLoggingMiddleware)
	s.Router.HandleFunc("/auth/login/fuyaoPasswordProvider", s.Login.LoginHandler)
	s.Router.HandleFunc("/auth/password/confirm/fuyaoPasswordProvider", s.Login.PasswordConfirmHandler)
	s.Router.HandleFunc("/auth/password/modify/fuyaoPasswordProvider", s.Login.PasswordResetHandler)
	s.Router.HandleFunc("/oauth/authorize", s.OAuthServer.OAuthAuthorizeHandler)
	s.Router.HandleFunc("/oauth/token", s.OAuthServer.OAuthTokenHandler)
	return nil
}

// Run simply runs the server and gracefully shutdown the server if errors occur
func (s *OAuthServerAPIServer) Run(ctx context.Context) error {
	shutdownCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-ctx.Done()
		err := s.Server.Shutdown(shutdownCtx)
		zlog.LogErrorf("server shuts down, err: %v", err)
	}()

	zlog.LogInfof("Start listening on %s", s.Server.Addr)
	var err error
	if s.Server.TLSConfig != nil {
		err = s.Server.ListenAndServeTLS("", "")
	} else {
		err = s.Server.ListenAndServe()
	}

	return err
}
