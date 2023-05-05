package controller

import (
	"github.com/saurabhbgp9693/EncryptionSite/services"
	"net/http"
)

func Handlers(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {

	case "/generate-key":
		services.KeyGen(w, r)
	case "/genKey":
		services.GenKeyHandler(r)
	case "/encrypt":
		services.EncryptHandler(w, r)
	case "/enc-message":
		services.EncryptMessage(w, r)
	case "/decrypt":
		services.DecryptPage(w, r)
	default:
		services.HomePage(w)
	}
}
