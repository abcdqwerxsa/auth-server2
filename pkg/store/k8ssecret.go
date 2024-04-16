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

// Package store defines how to store the auth code and access token
package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"oauth-server/pkg/constants"
	"oauth-server/pkg/fuyaoerrors"
	"oauth-server/pkg/zlog"
)

// K8sSecretStore is the k8sSecret store interface
type K8sSecretStore struct {
	// k8s client
	k8sClient kubernetes.Interface
	// store namespace
	ns string
}

// NewK8sSecretStore inits a new K8sSecretStore
func NewK8sSecretStore(k8sClient kubernetes.Interface, ns string) *K8sSecretStore {
	return &K8sSecretStore{
		k8sClient: k8sClient,
		ns:        ns,
	}
}

// Create creates a new code/access-token/refresh-token
func (s *K8sSecretStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	if code := info.GetCode(); code != "" {
		return s.createByCode(ctx, info)
	}
	if access := info.GetAccess(); access != "" {
		return s.createByAccess(ctx, info)
	}
	if refresh := info.GetRefresh(); refresh != "" {
		return s.createByRefresh(ctx, info)
	}
	return fuyaoerrors.ErrTokenTypeUnrecognized
}

func (s *K8sSecretStore) createByCode(ctx context.Context, info oauth2.TokenInfo) error {
	// prepare ttl
	currentTime := time.Now()
	info.SetCodeCreateAt(currentTime)
	if exp := info.GetCodeExpiresIn(); exp == 0 {
		zlog.Warn("the oauth code expiration time is not set")
	}

	// serialize the info
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	// save the info to secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.CodePrefix + info.GetCode(),
			Namespace: s.ns,
		},
		Data: map[string][]byte{
			"userinfo": data,
		},
	}

	// create the secret
	_, err = s.k8sClient.CoreV1().Secrets(s.ns).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		zlog.Errorf("cannot create code secret %s, err: %v", info.GetCode(), err)
		return fuyaoerrors.ErrFailToCreateSecret
	}

	return nil
}

func (s *K8sSecretStore) createByAccess(ctx context.Context, info oauth2.TokenInfo) error {
	// prepare ttl
	currentTime := time.Now()
	info.SetAccessCreateAt(currentTime)
	if exp := info.GetAccessExpiresIn(); exp == 0 {
		zlog.Warn("the oauth access-token expiration time is not set")
	}

	// serialize the info
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	// save the info to secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			// TODO: secret name only allows lowercase letters, check if there're conflicts if simply lowercasing them?
			Name:      refactorSecretName(constants.AccessPrefix + info.GetAccess()),
			Namespace: s.ns,
		},
		Data: map[string][]byte{
			"userinfo": data,
		},
	}

	// create the secret
	_, err = s.k8sClient.CoreV1().Secrets(s.ns).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		zlog.Errorf("cannot create access-token secret %s, err: %v", info.GetAccess(), err)
		return fuyaoerrors.ErrFailToCreateSecret
	}

	return nil
}

func (s *K8sSecretStore) createByRefresh(ctx context.Context, info oauth2.TokenInfo) error {
	return fuyaoerrors.ErrNotImplemented
}

// RemoveByCode removes the auth-code
func (s *K8sSecretStore) RemoveByCode(ctx context.Context, code string) error {
	name := constants.CodePrefix + code
	err := s.k8sClient.CoreV1().Secrets(s.ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		zlog.Errorf("cannot delete auth-code secret %s, err: %v", code, err)
		return fuyaoerrors.ErrFailToDeleteSecret
	}

	return nil
}

// RemoveByAccess removes the access-token
func (s *K8sSecretStore) RemoveByAccess(ctx context.Context, access string) error {
	name := refactorSecretName(constants.AccessPrefix + access)
	err := s.k8sClient.CoreV1().Secrets(s.ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		zlog.Errorf("cannot delete access-token secret %s, err: %v", access, err)
		return fuyaoerrors.ErrFailToDeleteSecret
	}

	return nil
}

// RemoveByRefresh removes the refresh-token
func (s *K8sSecretStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return fuyaoerrors.ErrNotImplemented
}

// GetByCode gets the auth-code data
func (s *K8sSecretStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	// get the secret
	name := constants.CodePrefix + code
	userdata, err := s.k8sClient.CoreV1().Secrets(s.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		zlog.Errorf("cannot get auth-code secret %s, err: %v", code, err)
		return nil, fuyaoerrors.ErrFailToGetSecret
	}

	// unmarshal to data
	return s.decodeUserInfo(userdata.Data["userinfo"])
}

// GetByAccess gets the access-token data
func (s *K8sSecretStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	// get the secret
	name := refactorSecretName(constants.AccessPrefix + access)
	userdata, err := s.k8sClient.CoreV1().Secrets(s.ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		zlog.Errorf("cannot get access-token secret %s, err: %v", access, err)
		return nil, fuyaoerrors.ErrFailToGetSecret
	}

	// unmarshal to data
	return s.decodeUserInfo(userdata.Data["userinfo"])
}

// GetByRefresh gets the refresh-token data
func (s *K8sSecretStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	return nil, fuyaoerrors.ErrNotImplemented
}

func (s *K8sSecretStore) decodeUserInfo(data []byte) (oauth2.TokenInfo, error) {
	var userinfo models.Token
	err := json.Unmarshal(data, &userinfo)
	if err != nil {
		zlog.Errorf("cannot unmarshal secret data, err: %v", err)
		return nil, fuyaoerrors.ErrFailToUnmarshalData
	}

	return &userinfo, nil
}

func refactorSecretName(data string) string {
	lowerData := strings.ToLower(data)
	lowerData = strings.ReplaceAll(lowerData, ".", "")
	lowerData = strings.ReplaceAll(lowerData, "_", "-")
	return lowerData
}
