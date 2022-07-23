package main

import (
	isuports "github.com/isucon/isucon12-qualify/webapp/go"
	"log"
	"net/http"
)

import _ "net/http/pprof"

func main() {
	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	isuports.Run()
}
