package controller


import (
	"encryptedWorld/services"
	"net/http"
)


func Handlers(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/login":
		services.Index(w, r)
	case "/login-submit":
		services.OnClick(w, r)
	case "/generate-key":
		services.KeyGen(w,r)
	case "/genKey":
		services.GenKeyHandler(w,r)
	case "/encrypt":
		services.EncryptHandler(w,r)
	case "/enc-message":
		services.EncryptMessage(w,r)
	case "/decrypt":
		services.DecryptPage(w, r)
	case "/dec-message":
		services.DecryptMessage(w,r)
	default:
		services.HomePage(w,r)
	}
}
