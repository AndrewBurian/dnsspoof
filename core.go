package main

import (
	"fmt"
	"os"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("dnsspoof requires root!")
		return
	}

	fmt.Println("Running spoofer")

	spoof("wlp3s0")
}
