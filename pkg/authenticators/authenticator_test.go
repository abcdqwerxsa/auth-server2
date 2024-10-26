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
	"crypto/sha256"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// TestPBKDF2EncryptorEncryptPassword test EncryptPassword interface
func TestPBKDF2EncryptorEncryptPassword(t *testing.T) {
	type args struct {
		rawPassword string
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
			args{rawPassword: "Soup4@LL"},
			"1pVI1niQz47OcynRlWibwtM+lmDNdgYVr84I6ZWDb0E8WOSZu/PZ46mnP7H/FyIlV7S6pIu8irFEQU4P988bPB2QTHJlaTISol+Hnl7SVkE=",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptor.EncryptPassword([]byte(tt.args.rawPassword))
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) == 0 {
				t.Errorf("EncryptPassword() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPBKDF2EncryptorVerifyPassword test Verify Password interface
func TestPBKDF2EncryptorVerifyPassword(t *testing.T) {
	type args struct {
		rawPassword       string
		encryptedPassword string
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
				rawPassword:       "Soup4@LL",
				encryptedPassword: "tEasO4NNBhygFPFP0rNZ0ivAQazrLzasW2w3DURXYOfy+A7yV57sZm0d13rGdMBQEGnNK9V4bEkAeibXIBO5hfjASfWK8VEdp2bECSEwWEw=",
			},
			true,
			false,
		},
		{
			"verify password fail: raw password does not match",
			args{
				rawPassword:       "soup4@LL",
				encryptedPassword: "tEasO4NNBhygFPFP0rNZ0ivAQazrLzasW2w3DURXYOfy+A7yV57sZm0d13rGdMBQEGnNK9V4bEkAeibXIBO5hfjASfWK8VEdp2bECSEwWEw=",
			},
			false,
			false,
		},
		{
			"verify password fail: cannot decode base64 encrypted password",
			args{
				rawPassword:       "soup4@LL",
				encryptedPassword: "r1R43niQz47OcynRlWibwtM+lmDNdgYVr84I6ZWDb0E8WOSZu/PZ46mnP7H/FyIlV7S6pIu8irFEQU4P988bPB2QTHJlaTISol+Hnl7SVkE#",
			},
			false,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encryptor.VerifyPassword([]byte(tt.args.rawPassword), []byte(tt.args.encryptedPassword))
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
			_ = NewPBKDF2Encryptor()
		})
	}
}

func TestNewFuyaoPasswordAuthenticator(t *testing.T) {
	type args struct {
		k8sClient kubernetes.Interface
		namespace string
	}
	fakeClient := fake.NewSimpleClientset()
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
				ns:        "oauth-user",
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
		k8sClient kubernetes.Interface
		ns        string
		encryptor Encryptor
	}
	type args struct {
		username string
		passwd   string
	}

	fakeClient := fake.NewSimpleClientset()
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
				passwd:   "test@123",
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
				passwd:   "test@12",
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
				passwd:   "test1234",
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
				passwd:   "admin",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &FuyaoPasswordAuthenticator{
				k8sClient: tt.fields.k8sClient,
				ns:        tt.fields.ns,
				encryptor: tt.fields.encryptor,
			}
			if got := a.checkPasswordComplexity(tt.args.username, []byte(tt.args.passwd)); got != tt.want {
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
		k8sClient kubernetes.Interface
		ns        string
		encryptor Encryptor
	}
	type args struct {
		username string
	}

	testUserSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin",
			Namespace: "oauth-user",
		},
		Data: map[string][]byte{
			"username":           []byte("admin"),
			"groups":             []byte("system:admin"),
			"extra":              []byte(`{"first-login":["true"]}`),
			"encrypted-password": []byte("lXc1sa8Y/6AWFg5LXUBo+iccNxwvcwot3rXlOaY40nvSW9+3pp+EXY7pypWnVdLh3wOrds1UOUjr8BhlyycPqNUbqSvGOQi6nqcEJc7T9zQ="),
		},
	}
	fakeClient := fake.NewSimpleClientset(testUserSecret)
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
		want1   string
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
			"lXc1sa8Y/6AWFg5LXUBo+iccNxwvcwot3rXlOaY40nvSW9+3pp+EXY7pypWnVdLh3wOrds1UOUjr8BhlyycPqNUbqSvGOQi6nqcEJc7T9zQ=",
			false,
		},
		{
			"no secret",
			fields{
				k8sClient: fake.NewSimpleClientset(),
				ns:        "oauth-user",
				encryptor: encryptor,
			},
			args{username: "admin"},
			nil,
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &FuyaoPasswordAuthenticator{
				k8sClient: tt.fields.k8sClient,
				ns:        tt.fields.ns,
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
			if string(got1) != tt.want1 {
				t.Errorf("fetchUserInfoAndStoredPassword() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
