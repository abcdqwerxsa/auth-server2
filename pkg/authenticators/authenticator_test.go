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
	"hash"
	"testing"
)

func TestPBKDF2Encryptor_EncryptPassword(t *testing.T) {
	type fields struct {
		saltLength    int
		iterations    int
		keyLength     int
		encryptMethod func() hash.Hash
	}
	type args struct {
		rawPassword string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			"admin",
			fields{
				saltLength:    16,
				iterations:    10000,
				keyLength:     64,
				encryptMethod: sha256.New,
			},
			args{rawPassword: "soup4@LL"},
			"mR7xeqbBN3G632b19xRrM2CcOEJUWDTp2+uYFt6yu0af0kB34HcUZur1dKEdrRf/E7hA8+k7F51zQ9cFVBzBezYdw6esAgxOse3oZv6LLoc=",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &PBKDF2Encryptor{
				saltLength:    tt.fields.saltLength,
				iterations:    tt.fields.iterations,
				keyLength:     tt.fields.keyLength,
				encryptMethod: tt.fields.encryptMethod,
			}
			got, err := e.EncryptPassword(tt.args.rawPassword)
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

func TestPBKDF2Encryptor_VerifyPassword(t *testing.T) {
	type fields struct {
		saltLength    int
		iterations    int
		keyLength     int
		encryptMethod func() hash.Hash
	}
	type args struct {
		rawPassword       string
		encryptedPassword string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			"admin",
			fields{
				saltLength:    16,
				iterations:    10000,
				keyLength:     64,
				encryptMethod: sha256.New,
			},
			args{
				"soup4@LL",
				"mR7xeqbBN3G632b19xRrM2CcOEJUWDTp2+uYFt6yu0af0kB34HcUZur1dKEdrRf/E7h" +
					"A8+k7F51zQ9cFVBzBezYdw6esAgxOse3oZv6LLoc=",
			},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &PBKDF2Encryptor{
				saltLength:    tt.fields.saltLength,
				iterations:    tt.fields.iterations,
				keyLength:     tt.fields.keyLength,
				encryptMethod: tt.fields.encryptMethod,
			}
			got, err := e.VerifyPassword(tt.args.rawPassword, tt.args.encryptedPassword)
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
