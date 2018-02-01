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
	Username []byte `json:"username"`
	Password []byte `json:"password"`
	jwt.StandardClaims
}

func createToken(username []byte, password []byte) (string, time.Time) {
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

func Login(ctx *fasthttp.RequestCtx) {
	qUser := ctx.QueryArgs().Peek("user")
	qPasswd := ctx.QueryArgs().Peek("passwd")
	fasthttpJwtCookie := ctx.Request.Header.Cookie("fasthttp_jwt")

	// for example, server receive token string in request header.
	if len(fasthttpJwtCookie) == 0 {
		tokenString, expireAt := createToken(qUser, qPasswd)

		// Set cookie for domain
		cookie := fasthttp.AcquireCookie()
		cookie.SetDomain("localhost")
		cookie.SetKey("fasthttp_jwt")
		cookie.SetValue(tokenString)
		cookie.SetExpire(expireAt)
		ctx.Response.Header.SetCookie(cookie)
	}
}

func CheckToken(ctx *fasthttp.RequestCtx) {
	fasthttpJwtCookie := ctx.Request.Header.Cookie("fasthttp_jwt")

	if len(fasthttpJwtCookie) == 0 {
		fmt.Fprint(ctx, "Login required...")
		return
	}

	token, _, err := JWTValidate(string(fasthttpJwtCookie))

	if !token.Valid {
		fmt.Fprint(ctx, "Your session is expired, login again please...")
		return
	}

	fmt.Fprintf(ctx, "Token: %s | Valid: %t | Error: %v", token.Raw, token.Valid, err)
}

func main() {
	router := fasthttprouter.New()
	router.GET("/", Login)
	router.GET("/check", CheckToken)

	server := &fasthttp.Server{
		Name:    "JWTTestServer",
		Handler: router.Handler,
	}

	logger.Debug("Listening in http://localhost:8000...")
	logger.Fatal(server.ListenAndServe(":8000"))
}
