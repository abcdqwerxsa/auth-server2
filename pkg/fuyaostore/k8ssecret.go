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

// Package fuyaostore defines how to fuyaostore the auth code and access token
package fuyaostore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"openfuyao/oauth-server/pkg/constants"
	"openfuyao/oauth-server/pkg/fuyaoerrors"
	"openfuyao/oauth-server/pkg/zlog"
)

// K8sSecretStore is the k8sSecret store interface
type K8sSecretStore struct {
	// k8s client
	k8sClient kubernetes.Interface
	// fuyaostore namespace
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
func (s *K8sSecretStore) Create(info oauth2.TokenInfo) error {
	if code := info.GetCode(); code != "" {
		return s.createByCode(info)
	}
	if access := info.GetAccess(); access != "" {
		return s.createByAccess(info)
	}
	if refresh := info.GetRefresh(); refresh != "" {
		return s.createByRefresh(info)
	}
	return fuyaoerrors.ErrTokenTypeUnrecognized
}

func (s *K8sSecretStore) createByCode(info oauth2.TokenInfo) error {
	// prepare ttl
	currentTime := time.Now()
	info.SetCodeCreateAt(currentTime)
	if exp := info.GetCodeExpiresIn(); exp == 0 {
		zlog.LogWarn("the oauth code expiration time is not set")
	}

	// serialize the info
	data, err := json.Marshal(info)
	if err != nil {
		return errors.New("cannot marshal data")
	}

	// generate auth code name
	authNameID, err := generateRandomName()
	if err != nil {
		return errors.New("generate auth-code name failed")
	}

	// save the info to secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.CodePrefix + authNameID,
			Namespace: s.ns,
		},
		Data: map[string][]byte{
			"userinfo": data,
		},
	}

	// create the secret
	_, err = s.k8sClient.CoreV1().Secrets(s.ns).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		zlog.LogErrorf("cannot create code secret")
		return fuyaoerrors.ErrFailToCreateSecret
	}

	return nil
}

func (s *K8sSecretStore) createByAccess(info oauth2.TokenInfo) error {
	// prepare ttl
	currentTime := time.Now()
	info.SetAccessCreateAt(currentTime)
	if exp := info.GetAccessExpiresIn(); exp == 0 {
		zlog.LogWarn("the oauth access-token expiration time is not set")
	}

	return nil
}

func (s *K8sSecretStore) createByRefresh(info oauth2.TokenInfo) error {
	return fuyaoerrors.ErrNotImplemented
}

// RemoveByCode removes the auth-code
func (s *K8sSecretStore) RemoveByCode(code string) error {
	codeList, err := s.k8sClient.CoreV1().Secrets(s.ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	var target *corev1.Secret
	for _, codeItem := range codeList.Items {
		info, err := s.decodeUserInfo(codeItem.Data["userinfo"])
		if err != nil {
			continue
		}
		if info.GetCode() == code {
			target = &codeItem
			break
		}
	}

	if target == nil {
		zlog.LogErrorf("cannot delete access-token secret")
		return fuyaoerrors.ErrFailToDeleteSecret
	}

	err = s.k8sClient.CoreV1().Secrets(s.ns).Delete(context.Background(), target.Name, metav1.DeleteOptions{})
	if err != nil {
		zlog.LogErrorf("cannot delete auth-code secret")
		return fuyaoerrors.ErrFailToDeleteSecret
	}

	return nil
}

// RemoveByAccess removes the access-token
func (s *K8sSecretStore) RemoveByAccess(access string) error {
	return fuyaoerrors.ErrNotImplemented
}

// RemoveByRefresh removes the refresh-token
func (s *K8sSecretStore) RemoveByRefresh(refresh string) error {
	return fuyaoerrors.ErrNotImplemented
}

// GetByCode gets the auth-code data
func (s *K8sSecretStore) GetByCode(code string) (oauth2.TokenInfo, error) {
	codeList, err := s.k8sClient.CoreV1().Secrets(s.ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, codeItem := range codeList.Items {
		info, err := s.decodeUserInfo(codeItem.Data["userinfo"])
		if err != nil {
			continue
		}
		if info.GetCode() == code {
			return info, nil
		}
	}

	zlog.LogErrorf("cannot get auth-code secret")
	return nil, fuyaoerrors.ErrFailToGetSecret
}

// GetByAccess gets the access-token data
func (s *K8sSecretStore) GetByAccess(access string) (oauth2.TokenInfo, error) {
	return nil, fuyaoerrors.ErrNotImplemented
}

// GetByRefresh gets the refresh-token data
func (s *K8sSecretStore) GetByRefresh(refresh string) (oauth2.TokenInfo, error) {
	return nil, fuyaoerrors.ErrNotImplemented
}

func (s *K8sSecretStore) decodeUserInfo(data []byte) (oauth2.TokenInfo, error) {
	var userinfo models.Token
	err := json.Unmarshal(data, &userinfo)
	if err != nil {
		zlog.LogErrorf("cannot unmarshal secret data")
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

func generateRandomName() (string, error) {
	const nameLength = 20
	var authCodeNameBytes [nameLength]byte
	_, err := io.ReadFull(rand.Reader, authCodeNameBytes[:])
	if err != nil {
		return "", err
	}
	authCodeName := hex.EncodeToString(authCodeNameBytes[:])
	return authCodeName, nil
}
