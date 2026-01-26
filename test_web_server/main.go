package main

import (
	"log"
	"mime"
	"net/http"
)

func cacheHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=120, stale-while-revalidate=30")
	w.Header().Set("ETag", "a1b2c3d4")
	w.Header().Set("Expires", "Thu, 01 Dec 2027 16:00:00 GMT")

	w.Write([]byte("This content should be cached"))
}

func main() {
	mime.AddExtensionType(".js", "text/javascript")
	mime.AddExtensionType(".aml", "text/aml")
	mime.AddExtensionType(".obj", "model/obj")

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.Handle("/c/", http.StripPrefix("/c/", http.HandlerFunc(cacheHandler)))

	log.Println("Server starting on :8080...")
	// 서버 시작 (포트 8080)
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatal(err)
	}
}
