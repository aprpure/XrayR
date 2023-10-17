package main

import (
	"log"

	"github.com/wyx2685/XrayR/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
