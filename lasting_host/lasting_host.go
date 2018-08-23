package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"../chord"
)

func main() {
	//hostName := chord.GetOutboundIP() + ":" + "5678"

	//hostName := "farm01"
	//portNumber := 5678

	kpubs := chord.GetKpubString(os.Args[2])
	portNumber, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal("invalid portNumber")
	}
	fmt.Printf("pub key str is %v\n", kpubs)
	chord.CreateLastingRing(portNumber, kpubs)

}
