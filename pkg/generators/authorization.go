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

package generators

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"strings"
)

// NewFuyaoAuthorizeGenerate create to generate the authorize code instance
func NewFuyaoAuthorizeGenerate() *FuyaoAuthorizeGenerate {
	return &FuyaoAuthorizeGenerate{}
}

// FuyaoAuthorizeGenerate generate the authorize code
type FuyaoAuthorizeGenerate struct{}

// Token based on the UUID generated token
func (ag *FuyaoAuthorizeGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic) (string, error) {
	buf := bytes.NewBufferString(data.Client.GetID())
	buf.WriteString(data.UserID)
	token := uuid.NewMD5(uuid.Must(uuid.NewRandom()), buf.Bytes())
	code := base64.URLEncoding.EncodeToString([]byte(token.String()))
	code = strings.ToLower(strings.TrimRight(code, "="))

	return code, nil
}
