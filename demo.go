package main

import (
	"log"
	"net/http"
)

func main() {
	// Serve static files from the "static" directory
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/", http.StripPrefix("/static/", fs))

	// Start the server
	log.Fatal(http.ListenAndServe(":8081", nil))
}
