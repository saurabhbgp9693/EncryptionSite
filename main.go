package main

import (
	"github.com/saurabhbgp9693/EncryptionSite/router"
	"log"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// router.RouterHandler()
	// Start the server
	// http.HandleFunc("/", controller.Handlers)
	router.RouterHandler()

	log.Fatal(http.ListenAndServe(":8082", nil))

}
