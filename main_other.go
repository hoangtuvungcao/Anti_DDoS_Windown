//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("WAF-Shield packet engine requires Windows and WinDivert; run go test ./... for portable validation.")
}
