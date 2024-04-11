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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"oauth-server/pkg/constants"
	"oauth-server/pkg/fuyaoerrors"
	"oauth-server/pkg/zlog"
	"strings"
	"unicode"
)

// PasswordAuthenticator in an authenticator that uses username/password to verify identities
type PasswordAuthenticator interface {
	AuthenticatePassword(ctx context.Context, username, password string) (*authenticator.Response, bool, error)
	ResetPassword(ctx context.Context, username, oldPassword, newPassword string) error
	ConfirmPassword(ctx context.Context, username, newPassword string) error
}

// FuyaoPasswordAuthenticator is the default password authenticator for fuyao-oauth-server
type FuyaoPasswordAuthenticator struct {
	// 这里需要加上一些 client-go 方便与 secret 交互
	// session 的交互先不要放在这里
	// session-store 实现，这个是存储用户是否已经通过账户密码登录的接口
	k8sClient kubernetes.Interface
	ns        string
	// TODO: should we let users configure the encryptor
	encryptor Encryptor
}

func NewFuyaoPasswordAuthenticator(k8sClient kubernetes.Interface, namespace string) *FuyaoPasswordAuthenticator {
	return &FuyaoPasswordAuthenticator{
		k8sClient: k8sClient,
		ns:        namespace,
		encryptor: NewPBKDF2Encryptor(),
	}
}

func (a *FuyaoPasswordAuthenticator) AuthenticatePassword(
	ctx context.Context,
	username, password string,
) (*authenticator.Response, bool, error) {
	// 取出旧 password 将 password 加密并比较
	userinfo, base64EncryptedPassword, err := a.fetchUserInfoAndStoredPassword(username)
	if err != nil {
		return nil, false, err
	}

	// verify the input password
	if ok, err := a.encryptor.VerifyPassword(password, base64EncryptedPassword); !ok || err != nil {
		return nil, false, err
	}

	//// 为了打通流程进行简易校验
	//if username != password {
	//	return nil, false, nil
	//}
	//adminUser := &user.DefaultInfo{
	//	Name: "admin",
	//	UID:  "test123456",
	//}
	//
	//return &authenticator.Response{User: adminUser}, true, nil
	return &authenticator.Response{User: userinfo}, true, nil
}

func (a *FuyaoPasswordAuthenticator) checkPasswordComplexity(username, password string) bool {
	// check password length
	if len(password) < constants.PasswordMinLen || len(password) > constants.PasswordMaxLen {
		zlog.Error("the password length should lie between 8 and 32")
		return false
	}

	// check that the password at least contains one lowercase/uppercase letter, one number and one special character
	var (
		hasLowercase bool
		hasUppercase bool
		hasDigit     bool
		hasSpecial   bool
	)
	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLowercase = true
		case unicode.IsUpper(char):
			hasUppercase = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasLowercase || !hasUppercase || !hasDigit || !hasSpecial {
		zlog.Error("密码必须包含至少一个小写字母、一个大写字母、一个数字和一个特殊字符")
		return false
	}

	// check whether the password is contained in username / reversed username
	if strings.Contains(password, username) || strings.Contains(password, reverseString(username)) {
		zlog.Error("密码不能和账号及账号逆序一样")
		return false
	}

	return true
}

// 反转字符串
func reverseString(s string) string {
	var reversed string
	for _, char := range s {
		reversed = string(char) + reversed
	}
	return reversed
}

func (a *FuyaoPasswordAuthenticator) fetchUserInfoAndStoredPassword(username string) (user.Info, string, error) {
	// get the secret
	secret, err := a.k8sClient.CoreV1().Secrets(a.ns).Get(context.TODO(), username, metav1.GetOptions{})
	if err != nil {
		zlog.Errorf("cannot get the password secret for %s, err: %v", username, err)
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
	groups, _ := readStringFromSecretData(secret.Data, "groups")
	if groups != "" {
		userinfo.Groups = strings.Split(groups, ",")
	}
	extra, _ := readExtraFromSecretData(secret.Data, "extra")
	firstLoginField, ok := extra["first-login"]
	if !ok {
		return nil, "", fuyaoerrors.ErrLoginServiceDown
	}
	firstLogin := firstLoginField[0]
	if firstLogin != "true" && firstLogin != "false" {
		return nil, "", fuyaoerrors.ErrLoginServiceDown
	}
	userinfo.Extra = make(map[string][]string)
	userinfo.Extra["first-login"] = []string{firstLogin}

	return &userinfo, base64EncryptedPassword, nil
}

func readStringFromSecretData(secretData map[string][]byte, key string) (string, error) {
	base64Data, ok := secretData[key]
	if !ok {
		zlog.Errorf("the base64 secretData %s is missing in the secret", key)
		return "", fuyaoerrors.ErrLoginServiceDown
	}

	//decodedData, err := base64.StdEncoding.DecodeString(string(base64Data))
	//if err != nil {
	//	zlog.Errorf("decoding secretData goes wrong for key %s, err: %v", key, err)
	//	return "", fuyaoerrors.ErrLoginServiceDown
	//}

	return string(base64Data), nil
}

func readExtraFromSecretData(secretData map[string][]byte, key string) (map[string][]string, error) {
	base64Data, ok := secretData[key]
	if !ok {
		zlog.Errorf("the base64 secretData %s is missing in the secret", key)
		return nil, fuyaoerrors.ErrLoginServiceDown
	}

	//decodedData, err := base64.StdEncoding.DecodeString(string(base64Data))
	//if err != nil {
	//	zlog.Errorf("decoding secretData goes wrong for key %s, err: %v", key, err)
	//	return nil, fuyaoerrors.ErrLoginServiceDown
	//}

	var extra map[string][]string
	err := json.Unmarshal(base64Data, &extra)
	if err != nil {
		zlog.Errorf("unmarshaling secretData goes wrong for key %s, err: %v", key, err)
		return nil, fuyaoerrors.ErrLoginServiceDown
	}

	return extra, err
}

func (a *FuyaoPasswordAuthenticator) savePassword(username, password string, firstLogin bool) error {
	// get the secret
	secret, err := a.k8sClient.CoreV1().Secrets(a.ns).Get(context.TODO(), username, metav1.GetOptions{})
	if err != nil {
		zlog.Errorf("cannot get the password secret for %s, err: %v", username, err)
		return fuyaoerrors.ErrPasswordAuthenticationFailed
	}

	// check whether firstLogin
	extra, _ := readExtraFromSecretData(secret.Data, "extra")
	firstLoginField, ok := extra["first-login"]
	if !ok {
		return fuyaoerrors.ErrLoginServiceDown
	}
	storedFirstLogin := firstLoginField[0]
	if firstLogin && storedFirstLogin == "false" {
		zlog.Errorf("the user has already logged in and changed the password, cannot reconfirm it")
		return fuyaoerrors.ErrNotFirstLogin
	}

	// encrypt the password
	encryptedPassword, err := a.encryptor.EncryptPassword(password)
	if err != nil {
		return fuyaoerrors.ErrLoginServiceDown
	}

	// set new password
	secret.Data["encrypted-password"] = []byte(encryptedPassword)
	extra["first-login"][0] = "false"
	byteExtra, err := json.Marshal(extra)
	if err != nil {
		zlog.Errorf("fail to marshal extra bytes, err: %v", err)
		return fuyaoerrors.ErrFailToMarshalData
	}
	secret.Data["extra"] = byteExtra

	// save the secret back to the k8s
	_, err = a.k8sClient.CoreV1().Secrets(a.ns).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		zlog.Errorf("cannot save password to k8s secret, err: %v", err)
		return fuyaoerrors.ErrFailToPatchSecret
	}

	return nil
}

func (a *FuyaoPasswordAuthenticator) ConfirmPassword(ctx context.Context, username, newPassword string) error {
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

func (a *FuyaoPasswordAuthenticator) ResetPassword(ctx context.Context, username, oldPassword, newPassword string) error {
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
		return err
	}

	// 校验 password 复杂度
	if ok := a.checkPasswordComplexity(username, newPassword); !ok {
		return errors.New(fuyaoerrors.ErrStrPasswordTooWeak)
	}

	// 存储新密码
	if err := a.savePassword(username, newPassword, false); err != nil {
		return err
	}

	return nil
}

// Encryptor manages the encrypt and decrypt funcs & configs
type Encryptor interface {
	VerifyPassword(newPassword, encryptedOldPassword string) (bool, error)
	EncryptPassword(rawPassword string) (string, error)
}

type PBKDF2Encryptor struct {
	saltLength    int
	iterations    int
	keyLength     int
	encryptMethod func() hash.Hash
}

func NewPBKDF2Encryptor() *PBKDF2Encryptor {
	return &PBKDF2Encryptor{
		saltLength:    16,
		iterations:    10000,
		keyLength:     64,
		encryptMethod: sha256.New,
	}
}

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
