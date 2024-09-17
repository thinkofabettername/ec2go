package main

import (
	"log"
	"os"
)

func stringIn(needle string, haystack []string) bool {
	for _, h := range haystack {
		if needle == h {
			return true
		}
	}
	return false
}

func getHome() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("could not obtain home directory", err)
	}
	return homeDir
}
