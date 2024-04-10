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

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"oauth-server/pkg/configs"
	"oauth-server/pkg/idp/fuyaopassword"
	"oauth-server/pkg/oauth2"
	"oauth-server/pkg/sessions"
)

var (
	portvar int
)

func init() {
	flag.IntVar(&portvar, "p", 9096, "the base port for the server")
}

func main() {
	flag.Parse()

	// prepare all necessary components
	k8sClient := configs.GetKubernetesClient(nil)
	idpLoginStore := sessions.NewSessionStore("idpLogin", 300, []byte("auth"), []byte("encrypt123123123"))
	login := fuyaopassword.NewLogin(idpLoginStore, k8sClient, "oauth-user")
	oauthServer := oauth2.NewOAuthServer(idpLoginStore, k8sClient, "oauth-code-token")

	// all routers
	http.HandleFunc("/auth/login/fuyaoPasswordProvider", login.LoginHandler)

	http.HandleFunc("/auth/password/confirm/fuyaoPasswordProvider", login.FuyaoPasswordConfirmHandler)

	http.HandleFunc("/auth/password/modify/fuyaoPasswordProvider", login.FuyaoPasswordResetHandler)

	http.HandleFunc("/oauth/authorize", oauthServer.OAuth2AuthorizeHandler)

	http.HandleFunc("/oauth/token", oauthServer.OAuth2TokenHandler)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", portvar), nil))
}
