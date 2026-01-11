package main

import (
	"log"
	"mime"
	"net/http"
)

func main() {
	mime.AddExtensionType(".js", "text/javascript")
	mime.AddExtensionType(".aml", "text/aml")
	mime.AddExtensionType(".obj", "model/obj")

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Println("Server starting on :8080...")
	// 서버 시작 (포트 8080)
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatal(err)
	}
}
