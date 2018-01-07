package main

import (
	"fmt"
	"github.com/buaazp/fasthttprouter"
	"github.com/dgrijalva/jwt-go"
	"github.com/savsgio/go-logger"
	"github.com/valyala/fasthttp"
	"time"
)

func init() {
	logger.Setup("debug")
}

var JWTSignKey = []byte("TestForFasthttpWithJWT")

type UserCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	jwt.StandardClaims
}

func createTokenString(username string, password string) string {
	logger.Debugf("Create new token for user %s", username)

	// Embed User information to `token`
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &UserCredential{
		Username: username,
		Password: password,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
		},
	})
	// token -> string. Only server knows this secret (foobar).
	tokenstring, err := newToken.SignedString(JWTSignKey)
	if err != nil {
		logger.Error(err)
	}
	return tokenstring
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
	rToken, err := jwt.ParseWithClaims(requestToken, user, func(token *jwt.Token) (interface{}, error) {
		return JWTSignKey, nil
	})

	return rToken, user, err
}

func Login(ctx *fasthttp.RequestCtx) {
	user := ctx.QueryArgs().Peek("user")
	passwd := ctx.QueryArgs().Peek("passwd")
	userToken := string(ctx.QueryArgs().Peek("token"))

	// for example, server receive token string in request header.
	if len(userToken) == 0 {
		userToken = createTokenString(string(user), string(passwd))
	}

	rToken, userData, err := JWTValidate(userToken)

	fmt.Println("ExpireAt: ", time.Unix(userData.ExpiresAt, 0).String())

	if err != nil {
		fmt.Fprintf(ctx, "Token %s | Valid: %t | Error: %v", userToken, rToken.Valid, err)
	} else {
		fmt.Fprintf(ctx, "Token %s | Valid: %t", userToken, rToken.Valid)
	}
}

func main() {
	router := fasthttprouter.New()
	router.GET("/", Login)

	server := &fasthttp.Server{
		Name:    "JWTTestServer",
		Handler: router.Handler,
	}

	logger.Debug("Listening in http://localhost:8000...")
	logger.Fatal(server.ListenAndServe(":8000"))
}
