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

package authenticators

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// TestPBKDF2EncryptorEncryptPassword test EncryptPassword interface
func TestPBKDF2EncryptorEncryptPassword(t *testing.T) {
	type args struct {
		rawPassword []byte
	}

	encryptor := &PBKDF2Encryptor{
		saltLength:    16,
		iterations:    100000,
		keyLength:     64,
		encryptMethod: sha256.New,
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"encrypt succeed but since the salt is generated totally randomly, want cannot equal to got",
			args{rawPassword: []byte("Soup4@LL")},
			"1pVI1niQz47OcynRlWibwtM+lmDNdgYVr84I6ZWDb0E8WOSZu/PZ46mnP7H/FyIlV7S6pIu8irFEQU4P988bPB2QTHJlaTISol+Hnl7SVkE=",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptor.EncryptPassword(tt.args.rawPassword)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != 0 {
				t.Errorf("EncryptPassword() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPBKDF2EncryptorVerifyPassword test Verify Password interface
func TestPBKDF2EncryptorVerifyPassword(t *testing.T) {
	type args struct {
		rawPassword       []byte
		encryptedPassword []byte
	}

	encryptor := &PBKDF2Encryptor{
		saltLength:    16,
		iterations:    100000,
		keyLength:     64,
		encryptMethod: sha256.New,
	}

	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			"verify password succeed",
			args{
				rawPassword:       []byte("Soup4@LL"),
				encryptedPassword: []byte("1pVI1niQz47OcynRlWibwtM+lmDNdgYVr84I6ZWDb0E8WOSZu/PZ46mnP7H/FyIlV7S6pIu8irFEQU4P988bPB2QTHJlaTISol+Hnl7SVkE="),
			},
			true,
			false,
		},
		{
			"verify password fail: raw password does not match",
			args{
				rawPassword:       []byte("soup4@LL"),
				encryptedPassword: []byte("1pVI1niQz47OcynRlWibwtM+lmDNdgYVr84I6ZWDb0E8WOSZu/PZ46mnP7H/FyIlV7S6pIu8irFEQU4P988bPB2QTHJlaTISol+Hnl7SVkE="),
			},
			false,
			false,
		},
		{
			"verify password fail: cannot decode base64 encrypted password",
			args{
				rawPassword:       []byte("soup4@LL"),
				encryptedPassword: []byte("r1R43niQz47OcynRlWibwtM+lmDNdgYVr84I6ZWDb0E8WOSZu/PZ46mnP7H/FyIlV7S6pIu8irFEQU4P988bPB2QTHJlaTISol+Hnl7SVkE#"),
			},
			false,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptor.VerifyPassword(tt.args.rawPassword, tt.args.encryptedPassword)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyPassword() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPBKDF2Encryptor(t *testing.T) {
	tests := []struct {
		name string
		want *PBKDF2Encryptor
	}{
		{
			"successfully tested",
			&PBKDF2Encryptor{
				saltLength:    16,
				iterations:    100000,
				keyLength:     64,
				encryptMethod: sha256.New,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPBKDF2Encryptor(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPBKDF2Encryptor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewFuyaoPasswordAuthenticator(t *testing.T) {
	type args struct {
		k8sClient dynamic.Interface
		namespace string
	}
	scheme := runtime.NewScheme()
	var resource runtime.Object
	fakeClient := dynamicfake.NewSimpleDynamicClient(scheme, resource)
	tests := []struct {
		name string
		args args
		want *FuyaoPasswordAuthenticator
	}{
		{
			"successfully init",
			args{
				k8sClient: fakeClient,
				namespace: "oauth-user",
			},
			&FuyaoPasswordAuthenticator{
				k8sClient: fakeClient,
				encryptor: NewPBKDF2Encryptor(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewFuyaoPasswordAuthenticator(tt.args.k8sClient, tt.args.namespace); !reflect.DeepEqual(got.k8sClient, tt.want.k8sClient) {
				t.Errorf("NewFuyaoPasswordAuthenticator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFuyaoPasswordAuthenticator_checkPasswordComplexity(t *testing.T) {
	type fields struct {
		k8sClient dynamic.Interface
		ns        string
		encryptor Encryptor
	}
	type args struct {
		username string
		passwd   []byte
	}

	scheme := runtime.NewScheme()
	var resource runtime.Object
	fakeClient := dynamicfake.NewSimpleDynamicClient(scheme, resource)
	encryptor := &PBKDF2Encryptor{
		saltLength:    16,
		iterations:    100000,
		keyLength:     64,
		encryptMethod: sha256.New,
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			"succeed",
			fields{
				k8sClient: fakeClient,
				ns:        "oauth-user",
				encryptor: encryptor,
			},
			args{
				username: "admin",
				passwd:   []byte("test@123"),
			},
			true,
		},
		{
			"len fewer than 8",
			fields{
				k8sClient: fakeClient,
				ns:        "oauth-user",
				encryptor: encryptor,
			},
			args{
				username: "admin",
				passwd:   []byte("test@12"),
			},
			false,
		},
		{
			"no special chars",
			fields{
				k8sClient: fakeClient,
				ns:        "oauth-user",
				encryptor: encryptor,
			},
			args{
				username: "admin",
				passwd:   []byte("test1234"),
			},
			false,
		},
		{
			"same as username",
			fields{
				k8sClient: fakeClient,
				ns:        "oauth-user",
				encryptor: encryptor,
			},
			args{
				username: "admin",
				passwd:   []byte("admin"),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &FuyaoPasswordAuthenticator{
				k8sClient: tt.fields.k8sClient,
				encryptor: tt.fields.encryptor,
			}
			if got := a.checkPasswordComplexity(tt.args.username, tt.args.passwd); got != tt.want {
				t.Errorf("checkPasswordComplexity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reverseString(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"reverse string",
			args{s: "test@123"},
			"321@tset",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverseString(tt.args.s); got != tt.want {
				t.Errorf("reverseString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFuyaoPasswordAuthenticator_fetchUserInfoAndStoredPassword(t *testing.T) {
	type fields struct {
		k8sClient dynamic.Interface
		ns        string
		encryptor Encryptor
	}
	type args struct {
		username string
	}

	scheme := runtime.NewScheme()
	var resource runtime.Object
	fakeClient := dynamicfake.NewSimpleDynamicClient(scheme, resource)
	encryptor := &PBKDF2Encryptor{
		saltLength:    16,
		iterations:    100000,
		keyLength:     64,
		encryptMethod: sha256.New,
	}
	userinfo := &user.DefaultInfo{
		Name:   "admin",
		Groups: []string{"system:admin"},
		Extra: map[string][]string{
			"first-login": {"true"},
		},
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    user.Info
		want1   []byte
		wantErr bool
	}{
		{
			"successfully fetch",
			fields{
				k8sClient: fakeClient,
				ns:        "oauth-user",
				encryptor: encryptor,
			},
			args{username: "admin"},
			userinfo,
			[]byte("lXc1sa8Y/6AWFg5LXUBo+iccNxwvcwot3rXlOaY40nvSW9+3pp+EXY7pypWnVdLh3wOrds1UOUjr8BhlyycPqNUbqSvGOQi6nqcEJc7T9zQ="),
			false,
		},
		{
			"no secret",
			fields{
				k8sClient: fakeClient,
				ns:        "oauth-user",
				encryptor: encryptor,
			},
			args{username: "admin"},
			nil,
			[]byte(""),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &FuyaoPasswordAuthenticator{
				k8sClient: tt.fields.k8sClient,
				encryptor: tt.fields.encryptor,
			}
			got, got1, err := a.fetchUserInfoAndStoredPassword(tt.args.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("fetchUserInfoAndStoredPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fetchUserInfoAndStoredPassword() got = %v, want %v", got, tt.want)
			}
			if !bytes.Equal(got1, tt.want1) {
				t.Errorf("fetchUserInfoAndStoredPassword() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
