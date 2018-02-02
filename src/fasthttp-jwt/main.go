package main

import (
	"fmt"
	"github.com/buaazp/fasthttprouter"
	"github.com/savsgio/go-logger"
	"github.com/valyala/fasthttp"
	"fasthttp-jwt/lib"
)

func init() {
	logger.Setup("debug")
}

func Index(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("text/html")
	fmt.Fprint(ctx, "<h1>Hola, estas en el Index...<h1>")
}

func Login(ctx *fasthttp.RequestCtx) {
	qUser := []byte("savsgio")
	qPasswd := []byte("mypasswd")
	fasthttpJwtCookie := ctx.Request.Header.Cookie("fasthttp_jwt")

	// for example, server receive token string in request header.
	if len(fasthttpJwtCookie) == 0 {
		tokenString, expireAt := lib.CreateToken(qUser, qPasswd)

		// Set cookie for domain
		cookie := fasthttp.AcquireCookie()
		cookie.SetKey("fasthttp_jwt")
		cookie.SetValue(tokenString)
		cookie.SetExpire(expireAt)
		ctx.Response.Header.SetCookie(cookie)
	}

	ctx.Redirect("/", ctx.Response.StatusCode())
}

func main() {
	router := fasthttprouter.New()
	router.GET("/login", Login)
	router.GET("/", lib.Middleware(Index))

	server := &fasthttp.Server{
		Name:    "JWTTestServer",
		Handler: router.Handler,
	}

	logger.Debug("Listening in http://localhost:8000...")
	logger.Fatal(server.ListenAndServe(":8000"))
}
