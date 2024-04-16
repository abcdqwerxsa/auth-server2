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

package fuyaoerrors

import (
	"errors"
	"net/http"
)

const (
	ErrStrFailToDisplayLogin           = "unable to display login page"
	ErrStrUsernameOrPasswordMissing    = "missing username or password in the post request"
	ErrStrFailToParseForm              = "cannot parse the form"
	ErrStrLoginServiceDown             = "the login server returns error, please check logs for details"
	ErrStrPasswordAuthenticationFailed = "incorrect username or password"
	ErrStrPasswordSame                 = "the new password is the same as the original password"
	ErrStrPasswordTooWeak              = "the input new password cannot pass the complexity check"
	ErrStrIdentityProviderIncorrect    = "the input identity_provider is not valid"
	ErrStrTokenTypeUnrecognized        = "the input token type is not valid"
	ErrStrFailToCreateSecret           = "fail to create k8s secret resource"
	ErrStrFailToDeleteSecret           = "fail to delete k8s secret resource"
	ErrStrFailToGetSecret              = "fail to get k8s secret resource"
	ErrStrFailToPatchSecret            = "fail to patch k8s secret resource"
	ErrStrNotImplemented               = "function is not implemented"
	ErrStrFailToMarshalData            = "cannot unmarshal data"
	ErrStrFailToUnmarshalData          = "cannot unmarshal data"
	ErrStrNotFirstLogin                = "this user is not the first time logging in, please go to the login page"
	ErrStrNotLogin                     = "user not logged in, unauthorized to do anything"
	ErrStrLoginBlocked                 = "request is blocked due to multiple failed login attempts"
	// httpserver errors
	ErrStrInvalidHttpAndHttpsPort = "http and https port cannot be invalid at the same time"
	ErrStrEmptyCertFile           = "the tls cert file is empty to serve https requests"
	ErrStrEmptyPrivateKeyFile     = "the tls private key file is empty to serve https requests"
	ErrStrEmptyMasterCAFile       = "the master CA file is empty to serve https requests"
	ErrStrFailToLoadCert          = "the cert and private key does not match"
	// oauthServerOption errors
	ErrStrOAuthServerConfigFileMissing = "the configfile is missing to start the httpserver"
	ErrStrJWTPrivateKeyMissing         = "the JWT private key is missing to start the httpserver"
	ErrStrHttpServerConfigMissing      = "the config is incomplete to start the server"
)

var (
	ErrFailToDisplayLogin           = errors.New(ErrStrFailToDisplayLogin)
	ErrUsernameOrPasswordMissing    = errors.New(ErrStrUsernameOrPasswordMissing)
	ErrFailToParseForm              = errors.New(ErrStrFailToParseForm)
	ErrLoginServiceDown             = errors.New(ErrStrLoginServiceDown)
	ErrPasswordAuthenticationFailed = errors.New(ErrStrPasswordAuthenticationFailed)
	ErrPasswordSame                 = errors.New(ErrStrPasswordSame)
	ErrPasswordTooWeak              = errors.New(ErrStrPasswordTooWeak)
	ErrIdentityProviderIncorrect    = errors.New(ErrStrIdentityProviderIncorrect)
	ErrTokenTypeUnrecognized        = errors.New(ErrStrTokenTypeUnrecognized)
	ErrFailToCreateSecret           = errors.New(ErrStrFailToCreateSecret)
	ErrFailToDeleteSecret           = errors.New(ErrStrFailToDeleteSecret)
	ErrFailToGetSecret              = errors.New(ErrStrFailToGetSecret)
	ErrFailToPatchSecret            = errors.New(ErrStrFailToPatchSecret)
	ErrNotImplemented               = errors.New(ErrStrNotImplemented)
	ErrFailToMarshalData            = errors.New(ErrStrFailToMarshalData)
	ErrFailToUnmarshalData          = errors.New(ErrStrFailToUnmarshalData)
	ErrNotFirstLogin                = errors.New(ErrStrNotFirstLogin)
	ErrNotLogin                     = errors.New(ErrStrNotLogin)
	ErrLoginBlocked                 = errors.New(ErrStrLoginBlocked)
	// httpserver errors
	ErrInvalidHttpAndHttpsPort = errors.New(ErrStrInvalidHttpAndHttpsPort)
	ErrEmptyCertFile           = errors.New(ErrStrEmptyCertFile)
	ErrEmptyPrivateKeyFile     = errors.New(ErrStrEmptyPrivateKeyFile)
	ErrEmptyMasterCAFile       = errors.New(ErrStrEmptyMasterCAFile)
	ErrFailToLoadCert          = errors.New(ErrStrFailToLoadCert)
	ErrIntExitSignal           = 255
	// oauthServerOption errors
	ErrOAuthServerConfigFileMissing = errors.New(ErrStrOAuthServerConfigFileMissing)
	ErrJWTPrivateKeyMissing         = errors.New(ErrStrJWTPrivateKeyMissing)
	ErrHttpServerConfigMissing      = errors.New(ErrStrHttpServerConfigMissing)
)

var ErrStatusCode = map[error]int{
	ErrFailToDisplayLogin:           http.StatusInternalServerError,
	ErrUsernameOrPasswordMissing:    http.StatusBadRequest,
	ErrFailToParseForm:              http.StatusInternalServerError,
	ErrLoginServiceDown:             http.StatusInternalServerError,
	ErrPasswordAuthenticationFailed: http.StatusUnauthorized,
	ErrPasswordSame:                 http.StatusUnauthorized,
	ErrPasswordTooWeak:              http.StatusBadRequest,
	ErrIdentityProviderIncorrect:    http.StatusBadRequest,
	ErrTokenTypeUnrecognized:        http.StatusBadRequest,
	ErrFailToCreateSecret:           http.StatusInternalServerError,
	ErrFailToDeleteSecret:           http.StatusInternalServerError,
	ErrFailToGetSecret:              http.StatusInternalServerError,
	ErrFailToPatchSecret:            http.StatusInternalServerError,
	ErrNotImplemented:               http.StatusNotImplemented,
	ErrFailToMarshalData:            http.StatusInternalServerError,
	ErrFailToUnmarshalData:          http.StatusInternalServerError,
	ErrNotFirstLogin:                http.StatusConflict,
	ErrNotLogin:                     http.StatusUnauthorized,
	ErrLoginBlocked:                 http.StatusUnauthorized,
}
