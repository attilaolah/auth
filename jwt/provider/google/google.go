package google

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// URL for downloading certificates
const url = "https://www.googleapis.com/oauth2/v1/certs"

var (
	client = http.Client{}
	// Minimum interval between successful downloads (excluding the first update)
	DownloadInterval = 2 * time.Minute
	// ErrNotFound is returned when the requested certificate was not found
	ErrNotFound = errors.New("Google APIs certificate not found")
)

type certs struct {
	sync.Mutex

	certs   map[string]string
	checked time.Time
}

var cache certs

// Get all certificates
func (cache *certs) get(c http.Client, key string) (raw string, err error) {
	cache.Lock()
	defer cache.Unlock()

	// Try to look up the cert first
	// (maybe it was cached while we were waiting on the mutex)
	raw, ok := cache.certs[key]
	if ok {
		return
	}

	// Protect against flooding the certificate server
	if cache.checked.IsZero() {
		// This is the first download, don't block
		if err = cache.download(c); err == nil {
			// Note that we don't block for the full download interval.
			// This is because the certificates might change right after server startup.
			cache.checked.Add(time.Second)
		}
	} else {
		now := time.Now().UTC()
		if now.Sub(cache.checked) > DownloadInterval {
			// For subsequent downloads, block for DownloadInterval
			if err = cache.download(c); err == nil {
				cache.checked = now
			}
		}
	}

	if err == nil {
		if raw, ok = cache.certs[key]; !ok {
			err = ErrNotFound
		}
	}
	return
}

func (cache *certs) download(c http.Client) (err error) {
	resp, err := c.Get(url)
	if err == nil && resp.StatusCode == 200 {
		err = json.NewDecoder(resp.Body).Decode(&cache.certs)
	}
	return
}

// KeyFunc can be used with a JWT middleware.
func KeyFunc(req *http.Request, t *jwt.Token) ([]byte, error) {
	return GetCertificate(client, t.Header["kid"].(string))
}

// GetCertificate returns a certificate for a given key
func GetCertificate(c http.Client, key string) (cert []byte, err error) {
	raw, err := cache.get(c, key)
	cert = []byte(raw)
	return
}
