package main

import (
	"os"
	"os/exec"
)

// Forward to cmd/kyidentity
func main() {
	cmd := exec.Command("go", append([]string{"run", "./cmd/kyidentity"}, os.Args[1:]...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
}
