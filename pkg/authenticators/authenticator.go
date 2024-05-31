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

// Package authenticators check deals with password authentication
package authenticators

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"hash"
	"regexp"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"

	"openfuyao/oauth-server/pkg/constants"
	"openfuyao/oauth-server/pkg/fuyaoerrors"
	"openfuyao/oauth-server/pkg/zlog"
)

// PasswordAuthenticator in an authenticator that uses username/password to verify identities
type PasswordAuthenticator interface {
	AuthenticatePassword(ctx context.Context, username, password string) (*authenticator.Response, bool, error)
	ResetPassword(ctx context.Context, username, oldPassword, newPassword string) error
	ConfirmPassword(ctx context.Context, username, newPassword string) error
}

// FuyaoPasswordAuthenticator is the default password authenticator for fuyao-oauth-server
type FuyaoPasswordAuthenticator struct {
	k8sClient kubernetes.Interface
	ns        string
	encryptor Encryptor
}

// NewFuyaoPasswordAuthenticator inits FuyaoPasswordAuthenticator
func NewFuyaoPasswordAuthenticator(k8sClient kubernetes.Interface, namespace string) *FuyaoPasswordAuthenticator {
	return &FuyaoPasswordAuthenticator{
		k8sClient: k8sClient,
		ns:        namespace,
		encryptor: NewPBKDF2Encryptor(),
	}
}

// AuthenticatePassword authenticates the password
func (a *FuyaoPasswordAuthenticator) AuthenticatePassword(
	ctx context.Context,
	username, passwd string,
) (*authenticator.Response, bool, error) {
	// fetch old password
	userinfo, base64EncryptedPassword, err := a.fetchUserInfoAndStoredPassword(username)
	if err != nil {
		return nil, false, err
	}

	// verify the input password
	if ok, err := a.encryptor.VerifyPassword(passwd, base64EncryptedPassword); !ok || err != nil {
		return nil, false, err
	}

	return &authenticator.Response{User: userinfo}, true, nil
}

func (a *FuyaoPasswordAuthenticator) checkPasswordComplexity(username, passwd string) bool {
	// check password length
	if len(passwd) < constants.PasswordMinLen || len(passwd) > constants.PasswordMaxLen {
		zlog.LogError("the password length should lie between 8 and 32")
		return false
	}

	// check that the password at least contains one lowercase/uppercase letter, one number and one special character
	reUpperCase := regexp.MustCompile(`[A-Z]`)
	reLowerCase := regexp.MustCompile(`[a-z]`)
	reDigit := regexp.MustCompile(`[0-9]`)
	reSpecialChar := regexp.MustCompile(`[!\"#$%&'()*+,-./:;<=>?@[\]^_{|}~ ]`)

	if (!reUpperCase.MatchString(passwd) && !reLowerCase.MatchString(passwd)) || !reDigit.MatchString(passwd) ||
		!reSpecialChar.MatchString(passwd) {
		zlog.LogError("password must contain at least one lowercase letter or one uppercase letter, " +
			"one number, and one special character")
		return false
	}

	// check that the password cannot contain more than two consecutive identical characters
	if checkOverTwoConsecutiveChars(passwd) {
		zlog.LogError("password cannot contain more than two consecutive identical characters")
		return false
	}

	// check whether the password is contained in username / reversed username
	if passwd == username || passwd == reverseString(username) {
		zlog.LogError("password cannot be the same as the account number or the reverse account number")
		return false
	}

	return true
}

func reverseString(s string) string {
	var reversed string
	for _, char := range s {
		reversed = string(char) + reversed
	}
	return reversed
}

func checkOverTwoConsecutiveChars(s string) bool {
	const maxConsecutiveChars = 2
	count := 1 // counter to keep track of the current character's consecutive occurrences

	// Iterate through the password starting from the second character
	for i := 1; i < len(s); i++ {
		// If the current character is the same as the previous character
		if s[i] == s[i-1] {
			count++ // Increment the counter
			// If the count exceeds 2, return true as the password has more than two consecutive identical characters
			if count > maxConsecutiveChars {
				return true
			}
		} else {
			count = 1 // Reset the counter if the current character is different from the previous one
		}
	}

	// If no consecutive characters are found, return false
	return false
}

func (a *FuyaoPasswordAuthenticator) fetchUserInfoAndStoredPassword(username string) (user.Info, string, error) {
	// get the secret
	secret, err := a.k8sClient.CoreV1().Secrets(a.ns).Get(context.TODO(), username, v1.GetOptions{})
	if err != nil {
		zlog.LogErrorf("cannot get the password secret for %s, err: %v", username, err)
		return nil, "", fuyaoerrors.ErrPasswordAuthenticationFailed
	}

	// fetch encrypted password
	base64EncryptedPassword, err := readStringFromSecretData(secret.Data, "encrypted-password")
	if err != nil {
		return nil, "", err
	}

	// prepare userinfo
	var userinfo user.DefaultInfo
	userinfo.Name = username
	userinfo.UID = string(secret.UID)
	groups, err := readStringFromSecretData(secret.Data, "groups")
	if err != nil {
		return nil, "", err
	}
	if groups != "" {
		userinfo.Groups = strings.Split(groups, ",")
	}
	extra, err := readExtraFromSecretData(secret.Data, "extra")
	if err != nil {
		return nil, "", err
	}
	firstLoginField, ok := extra[constants.UserFirstLogin]
	if !ok {
		return nil, "", fuyaoerrors.ErrLoginServiceDown
	}
	firstLogin := firstLoginField[0]
	if firstLogin != "true" && firstLogin != "false" {
		return nil, "", fuyaoerrors.ErrLoginServiceDown
	}
	userinfo.Extra = make(map[string][]string)
	userinfo.Extra[constants.UserFirstLogin] = []string{firstLogin}

	return &userinfo, base64EncryptedPassword, nil
}

func readStringFromSecretData(secretData map[string][]byte, key string) (string, error) {
	base64Data, ok := secretData[key]
	if !ok {
		zlog.LogErrorf("the base64 secretData %s is missing in the secret", key)
		return "", fuyaoerrors.ErrLoginServiceDown
	}

	return string(base64Data), nil
}

func readExtraFromSecretData(secretData map[string][]byte, key string) (map[string][]string, error) {
	base64Data, ok := secretData[key]
	if !ok {
		zlog.LogErrorf("the base64 secretData %s is missing in the secret", key)
		return nil, fuyaoerrors.ErrLoginServiceDown
	}

	var extra map[string][]string
	err := json.Unmarshal(base64Data, &extra)
	if err != nil {
		zlog.LogErrorf("unmarshaling secretData goes wrong for key %s, err: %v", key, err)
		return nil, fuyaoerrors.ErrLoginServiceDown
	}

	return extra, err
}

func (a *FuyaoPasswordAuthenticator) savePassword(username, passwd string, firstLogin bool) error {
	// get the secret
	secret, err := a.k8sClient.CoreV1().Secrets(a.ns).Get(context.TODO(), username, v1.GetOptions{})
	if err != nil {
		zlog.LogErrorf("cannot get the password secret for %s, err: %v", username, err)
		return fuyaoerrors.ErrPasswordAuthenticationFailed
	}

	// check whether firstLogin
	extra, err := readExtraFromSecretData(secret.Data, "extra")
	if err != nil {
		return err
	}
	firstLoginField, ok := extra[constants.UserFirstLogin]
	if !ok {
		return fuyaoerrors.ErrLoginServiceDown
	}
	storedFirstLogin := firstLoginField[0]
	if firstLogin && storedFirstLogin == "false" {
		zlog.LogErrorf("the user has already logged in and changed the password, cannot reconfirm it")
		return fuyaoerrors.ErrNotFirstLogin
	}

	// encrypt the password
	encryptedPassword, err := a.encryptor.EncryptPassword(passwd)
	if err != nil {
		return fuyaoerrors.ErrLoginServiceDown
	}

	// set new password
	secret.Data["encrypted-password"] = []byte(encryptedPassword)
	extra[constants.UserFirstLogin][0] = "false"
	byteExtra, err := json.Marshal(extra)
	if err != nil {
		zlog.LogErrorf("fail to marshal extra bytes, err: %v", err)
		return fuyaoerrors.ErrFailToMarshalData
	}
	secret.Data["extra"] = byteExtra

	// save the secret back to the k8s
	_, err = a.k8sClient.CoreV1().Secrets(a.ns).Update(context.TODO(), secret, v1.UpdateOptions{})
	if err != nil {
		zlog.LogErrorf("cannot save password to k8s secret, err: %v", err)
		return fuyaoerrors.ErrFailToPatchSecret
	}

	return nil
}

// ConfirmPassword is used when the user first logins in
func (a *FuyaoPasswordAuthenticator) ConfirmPassword(ctx context.Context, username, newPassword string) error {
	// 提取旧的加密密码
	_, base64EncryptedOldPassword, err := a.fetchUserInfoAndStoredPassword(username)
	if err != nil {
		return err
	}

	// check 旧密码是否没有改
	if ok, err := a.encryptor.VerifyPassword(newPassword, base64EncryptedOldPassword); ok || err != nil {
		if err == nil {
			zlog.LogError("password verification failed")
			return fuyaoerrors.ErrPasswordSame
		}
		return err
	}

	// 校验 password 复杂度
	if ok := a.checkPasswordComplexity(username, newPassword); !ok {
		return fuyaoerrors.ErrPasswordTooWeak
	}

	// 存储新密码
	if err := a.savePassword(username, newPassword, true); err != nil {
		return err
	}

	return nil
}

// ResetPassword modifies the user password
func (a *FuyaoPasswordAuthenticator) ResetPassword(
	ctx context.Context,
	username, oldPassword, newPassword string,
) error {
	// 新旧密码不能相同
	if oldPassword == newPassword {
		return fuyaoerrors.ErrPasswordSame
	}

	// 获取加密后密码
	_, base64EncryptedOldPassword, err := a.fetchUserInfoAndStoredPassword(username)
	if err != nil {
		return err
	}

	// check 旧密码是否正确
	if ok, err := a.encryptor.VerifyPassword(oldPassword, base64EncryptedOldPassword); !ok || err != nil {
		if err == nil {
			zlog.LogError("password verification failed")
			return fuyaoerrors.ErrPasswordAuthenticationFailed
		}
		return err
	}

	// 校验 password 复杂度
	if ok := a.checkPasswordComplexity(username, newPassword); !ok {
		return fuyaoerrors.ErrPasswordTooWeak
	}

	// 存储新密码
	if err := a.savePassword(username, newPassword, false); err != nil {
		return err
	}

	return nil
}

// Encryptor manages the encrypt and decrypt funcs & config
type Encryptor interface {
	VerifyPassword(newPassword, encryptedOldPassword string) (bool, error)
	EncryptPassword(rawPassword string) (string, error)
}

// PBKDF2Encryptor is the encryptor + decryptor using PBKDF2 algorithm
type PBKDF2Encryptor struct {
	saltLength    int
	iterations    int
	keyLength     int
	encryptMethod func() hash.Hash
}

// NewPBKDF2Encryptor inits PBKDF2Encryptor
func NewPBKDF2Encryptor() *PBKDF2Encryptor {
	return &PBKDF2Encryptor{
		saltLength:    16,
		iterations:    10000,
		keyLength:     64,
		encryptMethod: sha256.New,
	}
}

// EncryptPassword encrypts the password
func (e *PBKDF2Encryptor) EncryptPassword(rawPassword string) (string, error) {
	// 生成随机的盐值
	salt := make([]byte, e.saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fuyaoerrors.ErrLoginServiceDown
	}

	// 使用 PBKDF2 算法生成密文
	encryptedPassword := pbkdf2.Key([]byte(rawPassword), salt, e.iterations, e.keyLength, e.encryptMethod)

	// 将盐值和密文合并并编码为 Base64 字符串
	encryptedData := append(salt, encryptedPassword...)
	encryptedPasswordBase64 := base64.StdEncoding.EncodeToString(encryptedData)

	// 返回加密后的密码
	return encryptedPasswordBase64, nil
}

// VerifyPassword checks whether the rawPassword can be encrypted to the stored encryptedPassword
func (e *PBKDF2Encryptor) VerifyPassword(rawPassword, encryptedPassword string) (bool, error) {
	// decode加密后的密码
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return false, fuyaoerrors.ErrPasswordAuthenticationFailed
	}

	// 提取盐值和密文
	salt := encryptedData[:e.saltLength]
	encryptedPasswordBytes := encryptedData[e.saltLength:]

	// 使用相同的盐值和加密算法对原始密码进行加密
	newEncryptedPassword := pbkdf2.Key([]byte(rawPassword), salt, e.iterations, e.keyLength, e.encryptMethod)

	// 比较加密后的密码是否相同
	return string(encryptedPasswordBytes) == string(newEncryptedPassword), nil
}
