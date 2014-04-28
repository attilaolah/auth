package google

import (
	"github.com/attilaolah/auth/jwt/provider/google"
	"github.com/dgrijalva/jwt-go"

	"appengine"
	"appengine/urlfetch"
)

// KeyFunc can be used with a JWT middleware.
func KeyFunc(req *http.Request, t *jwt.Token) ([]byte, error) {
	return GetCertificate(urlfetch.Client(appengine.NewContext(req)), t.Header["kid"].(string))
}
