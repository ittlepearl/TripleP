package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"

	"../chord"
)

var (
	client *chord.Client
)

// this is a fake buddy list
func initBuddylist() {
	key03 := "MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhALWqVDtXP5WDkNUm2UWsTkB7miuWGlMmEItdHIlyWSIHAgMBAAE="
	key02 := "MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAKlKhSi0kM1f1r+0iQDhsyweQDDyYGYyfw0svmaC6S3jAgMBAAE="

	vm03 := chord.Buddy{
		PublicKey: (key03),
		ChatKey:   []byte("the-key-has-to-be-32-bytes-long!"),
	}
	vm02 := chord.Buddy{
		PublicKey: (key02),
		ChatKey:   []byte("the-key-has-to-be-32-bytes-long!"),
	}
	nodeId03 := client.Ring.HashVnodeId(key03, 0)
	fmt.Println("init: nodeid03: ", nodeId03)
	client.Ring.BuddyList[string(nodeId03)] = vm03
	nodeId02 := client.Ring.HashVnodeId(key02, 0)
	fmt.Println("init: nodeid02: ", nodeId02)
	client.Ring.BuddyList[string(nodeId02)] = vm02
}

func chatWith(nodeId string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		log.Println("{TripleP} [INFO] Enter [TripleP -e] to leave chat. Enter any other message to send to the other.")
		message := scanner.Text()
		// fmt.Println(message)
		if message == "TripleP -e" {
			log.Println("{TripleP} [INFO] Saving history...")
			err := client.Ring.SaveChatHistory(nodeId)
			if err != nil {
				log.Println("{TripleP} [ERROR] Fail to save history, got ", err)
			} else {
				log.Println("{TripleP} [INFO] Saving history done.")
			}
			return
		} else {
			_, err := client.Ring.SendChatMessage(nodeId, message)
			if err != nil {
				log.Println("{TripleP} [ERROR]  Fail to send message, got", err)
			}
		}
	}

}

func handleReadBuddy() {
	var command string
	fmt.Printf("Index \t nodeId\n")
	buddylist := client.Ring.BuddyList
	count := 0
	tempList := make([]string, 0)
	for _, buddy := range buddylist {
		fmt.Printf("%d \t %s\n", count, buddy.PublicKey)
		count++
		tempList = append(tempList, buddy.PublicKey)
	}

	for true {
		log.Println("{TripleP} [INFO] Enter [history] to read history with a friend. Enter number of a friend to start chat! Enter [end] to return main menu.")
		fmt.Scanln(&command)
		if command == "end" {
			return
		}

		if command == "history" {
			log.Println("{TripleP} [INFO] please enter the number of friend:")
			var numstr string
			var number int
			fmt.Scanln(&numstr)
			number, err := strconv.Atoi(numstr)
			if err != nil || number < 0 || number >= len(tempList) {
				log.Println("{TripleP} [Error] input or idx out of range")
			}
			history, err := client.Ring.FetchHistory(tempList[number])
			if err != nil {
				log.Println("{TripleP} [INFO] There is no chat history before.")
			} else {
				fmt.Println(history)
			}
		} else {
			idx, err := strconv.Atoi(command)
			if err != nil || idx < 0 || idx >= len(tempList) {
				// fmt.Println(err)
				// fmt.Println(idx)
				log.Println("{TripleP} [Error] invalid input or idx out of range")
			} else {
				chatWith(tempList[idx])
			}
		}
	}
}

func handleAddFriend(key string) {
	chatKeyBytes, err := client.Ring.HandShakeProcess(key)
	if err != nil {
		log.Print("{TripleP} [Error] fail to handshake to initialize a chat key, got", err)
	}
	newFriend := chord.Buddy{
		PublicKey: (key),
		ChatKey:   chatKeyBytes,
	}
	nodeId := client.Ring.HashVnodeId(key, 0)
	client.Ring.BuddyList[string(nodeId)] = newFriend
}

/*
 format to run user_interface:
 go run user_interface.go [listen_port] [regOrJoin] [Join?privFilename:null] [Join?pubFilename:null]
 go run user_interface.go 5678 join ../key/private.key ../key/public.key
*/
func main() {
	// handle argument
	portNumber, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal("{TripleP} [Error] invalid portNumber")
		return
	}

	fmt.Println("/////////////////////////////////////////////")
	fmt.Println("//          Welcome to TripleP!            //")
	fmt.Println("//         Pure P2P chat system            //")
	fmt.Println("/////////////////////////////////////////////")

	regOrJoin := os.Args[2]
	if regOrJoin == "join" {
		privFilename := os.Args[3]
		pubFilename := os.Args[4]
		client = chord.JoinWithKey(portNumber, "172.22.154.210:5678", privFilename, pubFilename)
		log.Printf("{TripleP} [INFO] Welcome Back! user %s.\n", client.Config.Hostname)
	} else if regOrJoin == "register" {
		log.Println("{TripleP} [INFO] Welcome! new user.")
		client = chord.Register(portNumber, "172.22.154.210:5678")
	} else {
		log.Fatal("{TripleP} [Error] incorrect regOrJoin input! enter \"join\" or \"register\"!")
		return
	}

	// initialize buddy list
	// initBuddylist()

	// wait for user input
	// select a friend to enter chat
	// send & show message
EXIT:
	for true {
		log.Println("{TripleP} [INFO] Enter 'exit' to exit. Enter 'read' to read buddylist. Enter 'add' to add a friend to buddylist.")
		var command string
		fmt.Scanln(&command)
		switch command {
		case "exit":
			log.Println("{TripleP} [INFO] See you!")
			break EXIT
		case "read":
			handleReadBuddy()
		case "add":
			log.Println("{TripleP} [INFO] Enter [UserID]:")
			var newKpub string
			fmt.Scanln(&newKpub)
			handleAddFriend(newKpub)
			handleReadBuddy()
		}
	}

}
