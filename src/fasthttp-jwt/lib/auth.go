package lib

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/savsgio/go-logger"
	"time"
)

var JWTSignKey = []byte("TestForFasthttpWithJWT")

type UserCredential struct {
	Username []byte `json:"username"`
	Password []byte `json:"password"`
	jwt.StandardClaims
}

func CreateToken(username []byte, password []byte) (string, time.Time) {
	logger.Debugf("Create new token for user %s", username)

	expireAt := time.Now().Add(1 * time.Minute)

	// Embed User information to `token`
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS512, &UserCredential{
		Username: username,
		Password: password,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireAt.Unix(),
		},
	})

	// token -> string. Only server knows this secret (foobar).
	tokenString, err := newToken.SignedString(JWTSignKey)
	if err != nil {
		logger.Error(err)
	}

	return tokenString, expireAt
}

func JWTValidate(requestToken string) (*jwt.Token, *UserCredential, error) {
	logger.Debug("Validating token...")

	/*
		// Let's parse this by the secrete, which only server knows.
		rToken, err := jwt.Parse(requestToken, func(token *jwt.Token) (interface{}, error) {
			return JWTSignKey, nil
		})
	*/

	// In another way, you can decode token to your struct, which needs to satisfy `jwt.StandardClaims`
	user := &UserCredential{}
	token, err := jwt.ParseWithClaims(requestToken, user, func(token *jwt.Token) (interface{}, error) {
		return JWTSignKey, nil
	})

	return token, user, err
}
