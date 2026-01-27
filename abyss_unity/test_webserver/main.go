package main

import (
	"log"
	"mime"
	"net/http"
	"strings"
)

func main() {
	const addr = "127.0.0.1:8899"

	// Register custom MIME type
	_ = mime.AddExtensionType(".aml", "text/aml")
	_ = mime.AddExtensionType(".obj", "model/obj")

	// Wrap the file server with custom Content-Type logic
	fs := http.FileServer(http.Dir("."))
	//fs := limitFileServer(100000)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check if file ends with .aml
		if strings.HasSuffix(r.URL.Path, ".aml") {
			w.Header().Set("Content-Type", "text/aml")
		}
		// Prevent directory traversal by cleaning the path
		//r.URL.Path = path.Clean(r.URL.Path)
		fs.ServeHTTP(w, r)
	})

	log.Printf("Serving on http://localhost%s/\n", addr)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal(err)
	}
}
