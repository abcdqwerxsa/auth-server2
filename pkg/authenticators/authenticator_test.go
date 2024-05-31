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
)

// TestPBKDF2EncryptorEncryptPassword test EncryptPassword interface
func TestPBKDF2EncryptorEncryptPassword(t *testing.T) {
	type args struct {
		rawPassword string
	}

	encryptor := &PBKDF2Encryptor{
		saltLength:    16,
		iterations:    10000,
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
			got, err := encryptor.EncryptPassword(tt.args.rawPassword)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
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
		iterations:    10000,
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
				encryptedPassword: "1pVI1niQz47OcynRlWibwtM+lmDNdgYVr84I6ZWDb0E8WOSZu/PZ46mnP7H/FyIlV7S6pIu8irFEQU4P988bPB2QTHJlaTISol+Hnl7SVkE=",
			},
			true,
			false,
		},
		{
			"verify password fail: raw password does not match",
			args{
				rawPassword:       "soup4@LL",
				encryptedPassword: "1pVI1niQz47OcynRlWibwtM+lmDNdgYVr84I6ZWDb0E8WOSZu/PZ46mnP7H/FyIlV7S6pIu8irFEQU4P988bPB2QTHJlaTISol+Hnl7SVkE=",
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
				iterations:    10000,
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
