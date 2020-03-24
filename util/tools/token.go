package tools

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

//GetTokenSign 生成token
func GetTokenSign(key string) (string, error) {
	if key == "" {
		return "", errors.New("key is nil")
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["iat"] = time.Now().Unix()
	token.Claims = claims

	tokenStr, err := token.SignedString([]byte(key))
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

//GetTokenSignWithUserName 生成token
func GetTokenSignWithUserName(userName string, exp time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(exp).Unix()
	claims["iat"] = time.Now().Unix()
	claims["userName"] = userName
	token.Claims = claims

	key := conf.C.JwtKey
	if key == "" {
		return "", errors.New("key is nil")
	}

	tokenStr, err := token.SignedString([]byte(key))
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}