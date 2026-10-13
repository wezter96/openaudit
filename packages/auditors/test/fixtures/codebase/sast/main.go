package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
)

var awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

func main() {
	h := md5.New()
	fmt.Println(h)
	cmd := exec.Command("sh", "-c", os.Args[1])
	_ = cmd.Run()
}
