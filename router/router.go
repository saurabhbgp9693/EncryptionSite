package router

import (
	"encryptedWorld/controller"
	"net/http"
)



func RouterHandler(){
	// Register the route handlers
	http.HandleFunc("/", controller.Handlers)
}