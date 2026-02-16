// Package chirpy is a project showcasing a Go HTTP server for Boot.dev
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	serveMux := http.NewServeMux()

	server := http.Server{
		Addr: ":8080",
		Handler: serveMux,
	}

	err := server.ListenAndServe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
