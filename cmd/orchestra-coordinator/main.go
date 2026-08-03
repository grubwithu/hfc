package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/grubwithu/orchestra/internal/coordinator"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8081", "HTTP listen address")
	modelID := flag.String("model-id", "", "immutable Program Model identifier")
	flag.Parse()
	if *modelID == "" {
		log.Fatal("-model-id is required")
	}

	server := &http.Server{
		Addr:              *listen,
		Handler:           coordinator.NewHandler(coordinator.New(*modelID)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Orchestra V2 coordinator listening on %s model=%s", *listen, *modelID)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
