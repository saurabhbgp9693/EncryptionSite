package main

import (
	"encryptedWorld/router"
	"log"
	"net/http"
)

func main() {
	// router.RouterHandler()
	// Start the server
	// http.HandleFunc("/", controller.Handlers)
	router.RouterHandler()
	
	log.Fatal(http.ListenAndServe(":8080", nil))

	
}
// func hello(w http.ResponseWriter, r *http.Request){

// 	fmt.Fprint(w,"hello World",nil)

// }