package router

import (
	"github.com/saurabhbgp9693/EncryptionSite/controller"
	"net/http"
)

func RouterHandler() {
	// Register the route handlers
	http.HandleFunc("/", controller.Handlers)
}
