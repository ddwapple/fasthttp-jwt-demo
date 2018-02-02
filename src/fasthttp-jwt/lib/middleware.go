package lib

import (
	"errors"
	"fmt"
	"github.com/valyala/fasthttp"
)

func CheckTokenMiddleware(ctx *fasthttp.RequestCtx) error {
	fasthttpJwtCookie := ctx.Request.Header.Cookie("fasthttp_jwt")

	if len(fasthttpJwtCookie) == 0 {
		return errors.New("login required")
	}

	token, _, err := JWTValidate(string(fasthttpJwtCookie))

	if !token.Valid {
		return errors.New("your session is expired, login again please")
	}

	return err
}

type middleware func(ctx *fasthttp.RequestCtx) error

var MiddlewareList = []middleware{
	CheckTokenMiddleware,
}

// BasicAuth is the basic auth handler
func Middleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return fasthttp.RequestHandler(func(ctx *fasthttp.RequestCtx) {

		for _, middleware := range MiddlewareList {
			if err := middleware(ctx); err != nil {
				fmt.Fprint(ctx, err)
				return
			}
		}

		next(ctx)
	})
}
