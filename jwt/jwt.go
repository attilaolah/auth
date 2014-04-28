// Package jwt implements authentication based on JSON web tokens.
package jwt

import (
	"net/http"

	"github.com/go-martini/martini"
	"github.com/dgrijalva/jwt-go"
)

// KeyFunc is a function type used to retrieve token signing keys.
type KeyFunc func(*http.Request, *jwt.Token) ([]byte, error)

// Options allows setting a custom key function.
type Options struct {
	KeyFunc KeyFunc
}

// JWT injects a handler that authenticates based on JSON web tokens.
func JWT(options ...Options) martini.Handler {
	return prepare(options).handler
}

// Handler is the middleware that ends up being injected in the Martini pipeline.
func (o *Options) handler(res http.ResponseWriter, req *http.Request, c martini.Context) {
	t, err := jwt.ParseFromRequest(req, o.jwtKeyFunc(req))
	if err != nil {
		res.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(res, "Not Authorized", http.StatusUnauthorized)
		return
	}
	c.Map(t)
}

// Wrap the key function in a closure to allow passing in the request.
func (o *Options) jwtKeyFunc(req *http.Request) jwt.Keyfunc {
	return func(t *jwt.Token) ([]byte, error) {
		return o.KeyFunc(req, t)
	}
}

// Set up the default options.
func prepare(options []Options) (o *Options) {
	if len(options) > 0 {
		o = &options[0]
	} else {
		o = &Options{}
	}
	if o.KeyFunc == nil {
		o.KeyFunc = func(*http.Request, *jwt.Token) ([]byte, error) {
			return nil, nil
		}
	}
	return
}
