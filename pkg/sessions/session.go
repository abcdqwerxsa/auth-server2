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

package sessions

import (
	"encoding/json"
	"net/http"
	"oauth-server/pkg/constants"
	"oauth-server/pkg/zlog"

	gorilla "github.com/gorilla/sessions"
)

type CookieStore struct {
	// name of the cookie used for session data
	name string
	// do not use store's Get method, it mucks with global state for caching purposes
	// decoding a single small cookie multiple times is not the end of the world
	// currently we do not have any single request paths that decode the cookie multiple times
	store gorilla.Store
}

func NewSessionStore(name string, maxAge int, secrets ...[]byte) *CookieStore {
	cookie := gorilla.NewCookieStore(secrets...)
	// we encode expiration information into the cookie data to avoid browser bugs
	// since we do not set the Expires or Max-Age attributes, all cookies created by this store are session cookies
	cookie.Options.MaxAge = maxAge
	// TODO: change to false for debugging, in production changing these two to true
	cookie.Options.HttpOnly = false
	cookie.Options.Secure = false
	return &CookieStore{name: name, store: cookie}
}

func (s *CookieStore) Get(r *http.Request) Values {
	// always use New to avoid global state
	session, err := s.store.New(r, s.name)
	if err != nil {
		// ignore all errors, this could occur from poorly handling key rotation.
		// depending on how keys are incorrectly rotated,
		// verification or decryption can fail with various different errors.
		// even with a malicious actor trying to mess with the cookie,
		// there does not seem to be much that we gain from erroring
		// instead of just ignoring the junk data and returning empty Values.
		// empty Values means the user has to reauthenticate instead of getting stuck
		// on an error page until their cookie expires or is removed.
		// we leak less state information using this approach.

		// log the error in case we ever need to know that it is occurring
		// we do not log the request as that could leak sensitive information such as the cookie
		zlog.Infof("failed to decode secure session cookie %s: %v", s.name, err)

		return make(map[interface{}]interface{})
	}
	return session.Values
}

func (s *CookieStore) Put(w http.ResponseWriter, v Values) error {
	// build a session from an empty request to avoid any decoding overhead
	// always use New to avoid global state
	r := &http.Request{}
	session, err := s.store.New(r, s.name)
	if err != nil {
		return err
	}

	// override the values for the session
	session.Values = v

	// write the encoded cookie, the request parameter is ignored
	return s.store.Save(r, w, session)
}

// Values provide interfaces to read string/int data
type Values map[interface{}]interface{}

func (v Values) GetString(key string) (string, bool) {
	str, _ := v[key].(string)
	return str, len(str) != 0
}

func (v Values) GetInt64(key string) (int64, bool) {
	i, _ := v[key].(int64)
	return i, i != 0
}

func (v Values) GetArrayString(key string) ([]string, bool) {
	arrayStr, _ := v[key].([]string)
	return arrayStr, arrayStr != nil
}

func (v Values) GetExtras(key string) (map[string][]string, bool) {
	byteExtras, ok := v[key].([]byte)
	if !ok {
		return nil, false
	}
	extras := make(map[string][]string)
	err := json.Unmarshal(byteExtras, &extras)
	return extras, err == nil
}

func (v Values) GetExtraByKey(key string) ([]string, bool) {
	extras, ok := v.GetExtras(constants.UserExtra)
	if !ok {
		return nil, ok
	}

	ret, ok := extras[key]
	return ret, ok
}
