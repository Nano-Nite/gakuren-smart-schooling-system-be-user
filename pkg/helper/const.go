package helper

import "os"

var API_VERSION = os.Getenv("API_VERSION")

func init() {
	if API_VERSION == "" {
		API_VERSION = "v1"
	}
}
