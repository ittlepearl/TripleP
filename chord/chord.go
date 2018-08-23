/*
This package is used to provide an implementation of the
Chord network protocol.
*/
package chord

import (
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"strconv"
	"time"
)

// Implements the methods needed for a Chord ring
type Transport interface {
	// Gets a list of the vnodes on the box
	ListVnodes(string) ([]*Vnode, error)

	// Ping a Vnode, check for liveness
	Ping(*Vnode) (bool, error)

	// Request a nodes predecessor
	GetPredecessor(*Vnode) (*Vnode, error)

	// Notify our successor of ourselves
	Notify(target, self *Vnode) ([]*Vnode, error)

	// Find a successor
	FindSuccessors(*Vnode, int, []byte) ([]*Vnode, error)

	// Clears a predecessor if it matches a given vnode. Used to leave.
	ClearPredecessor(target, self *Vnode) error

	// Instructs a node to skip a given successor. Used to leave.
	SkipSuccessor(target, self *Vnode) error

	// Register for an RPC callbacks
	Register(*Vnode, VnodeRPC)

	// Send message to a vnode
	SendMessage(*Vnode, *Vnode, string, int) (bool, error)

	// Send handshake message to a vnode
	SendHandShakeMessage(*Vnode, *Vnode, string, int) ([]byte, error)

	// Transfer data to be saved in chord
	TransferData(*Vnode, string, []byte, int) ([]byte, string, error)
}

// These are the methods to invoke on the registered vnodes
type VnodeRPC interface {
	GetPredecessor() (*Vnode, error)
	Notify(*Vnode) ([]*Vnode, error)
	FindSuccessors(int, []byte) ([]*Vnode, error)
	ClearPredecessor(*Vnode) error
	SkipSuccessor(*Vnode) error
	GetLocalRing() *Ring
}

// Delegate to notify on ring events
type Delegate interface {
	NewPredecessor(local, remoteNew, remotePrev *Vnode)
	Leaving(local, pred, succ *Vnode)
	PredecessorLeaving(local, remote *Vnode)
	SuccessorLeaving(local, remote *Vnode)
	Shutdown()
}

// Configuration for Chord nodes
type Config struct {
	Hostname      string // Local host name
	HostAddr      string
	NumVnodes     int              // Number of vnodes per physical node
	HashFunc      func() hash.Hash // Hash function to use
	StabilizeMin  time.Duration    // Minimum stabilization time
	StabilizeMax  time.Duration    // Maximum stabilization time
	NumSuccessors int              // Number of successors to maintain
	Delegate      Delegate         // Invoked to handle ring events
	hashBits      int              // Bit size of the hash function
}

// Represents an Vnode, local or remote
type Vnode struct {
	Id      []byte // Virtual ID
	Host    string // Host addr
	HostIdf string // Host identifier
	Kpub    string
}

// Represents a local Vnode
type localVnode struct {
	Vnode
	ring        *Ring
	successors  []*Vnode
	finger      []*Vnode
	last_finger int
	predecessor *Vnode
	stabilized  time.Time
	timer       *time.Timer
}
type Buddy struct {
	PublicKey string
	ChatKey   []byte
}

// Stores the state required for a Chord ring
type Ring struct {
	config        *Config
	transport     Transport
	vnodes        []*localVnode
	delegateCh    chan func()
	shutdown      chan bool
	handShakeCh   chan tcpBodyVnodesInt
	kFile         []byte
	kPrivate      *rsa.PrivateKey
	BuddyList     map[string]Buddy // key is string(Vnoce.Id), value is shared symmetric key with this node
	ChatHistory   map[string]string
	peerFiles     map[string]string
	peerBuddyList map[string]string
}

// Returns the default Ring configuration
func DefaultConfig(hostname string, hostAddr string) *Config {
	return &Config{
		hostname,
		hostAddr,
		8,        // 8 vnodes
		sha1.New, // SHA1
		time.Duration(15 * time.Second),
		time.Duration(45 * time.Second),
		8,   // 8 successors
		nil, // No delegate
		160, // 160bit hash function
	}
}

// Creates a new Chord ring given the config and transport
func Create(conf *Config, trans Transport) (*Ring, error) {
	// Initialize the hash bits
	conf.hashBits = conf.HashFunc().Size() * 8

	// Create and initialize a ring
	ring := &Ring{}
	ring.init(conf, trans)
	ring.setLocalSuccessors()
	ring.schedule()
	return ring, nil
}

// Joins an existing Chord ring
func Join(conf *Config, trans Transport, existing string) (*Ring, error) {
	// Initialize the hash bits
	conf.hashBits = conf.HashFunc().Size() * 8

	// Request a list of Vnodes from the remote host
	hosts, err := trans.ListVnodes(existing)
	if err != nil {
		fmt.Errorf("listing vonde failed")
		return nil, err
	}
	if hosts == nil || len(hosts) == 0 {
		return nil, fmt.Errorf("Remote host has no vnodes!")
	}

	// Create a ring
	ring := &Ring{}
	ring.init(conf, trans)

	// Acquire a live successor for each Vnode
	for _, vn := range ring.vnodes {
		// Get the nearest remote vnode
		nearest := nearestVnodeToKey(hosts, vn.Id)

		// Query for a list of successors to this Vnode
		succs, err := trans.FindSuccessors(nearest, conf.NumSuccessors, vn.Id)
		if err != nil {
			return nil, fmt.Errorf("Failed to find successor for vnodes! Got %s", err)
		}
		if succs == nil || len(succs) == 0 {
			return nil, fmt.Errorf("Failed to find successor for vnodes! Got no vnodes!")
		}

		// Assign the successors
		for idx, s := range succs {
			vn.successors[idx] = s
		}
	}

	// Start delegate handler
	if ring.config.Delegate != nil {
		go ring.delegateHandler()
	}

	// Do a fast stabilization, will schedule regular execution
	for _, vn := range ring.vnodes {
		vn.stabilize()
	}
	return ring, nil
}

// Leaves a given Chord ring and shuts down the local vnodes
func (r *Ring) Leave() error {
	// Shutdown the vnodes first to avoid further stabilization runs
	r.stopVnodes()

	// Instruct each vnode to leave
	var err error
	for _, vn := range r.vnodes {
		err = mergeErrors(err, vn.leave())
	}

	// Wait for the delegate callbacks to complete
	r.stopDelegate()
	return err
}

// Shutdown shuts down the local processes in a given Chord ring
// Blocks until all the vnodes terminate.
func (r *Ring) Shutdown() {
	r.stopVnodes()
	r.stopDelegate()
}

// Does a key lookup for up to N successors of a key
func (r *Ring) Lookup(n int, key []byte) ([]*Vnode, error) {
	// Ensure that n is sane
	if n > r.config.NumSuccessors {
		return nil, fmt.Errorf("Cannot ask for more successors than NumSuccessors!")
	}

	// Hash the key
	h := r.config.HashFunc()
	h.Write(key)
	key_hash := h.Sum(nil)

	// Find the nearest local vnode
	nearest := r.nearestVnode(key_hash)

	// Use the nearest node for the lookup
	successors, err := nearest.FindSuccessors(n, key_hash)
	if err != nil {
		return nil, err
	}

	// Trim the nil successors
	for successors[len(successors)-1] == nil {
		successors = successors[:len(successors)-1]
	}
	return successors, nil
}

func (r *Ring) HashVnodeId(hostname string, idx int) []byte {
	// Hash the key
	h := r.config.HashFunc()
	h.Write([]byte(hostname))
	binary.Write(h, binary.BigEndian, uint16(idx))
	key_hash := h.Sum(nil)
	return key_hash
}

func (r *Ring) VnodeLookup(n int, hostname string, idx int) ([]*Vnode, error) {
	// Ensure that n is sane
	if n > r.config.NumSuccessors {
		return nil, fmt.Errorf("Cannot ask for more successors than NumSuccessors!")
	}
	key_hash := r.HashVnodeId(hostname, idx)
	// Find the nearest local vnode
	nearest := r.nearestVnode(key_hash)

	// Use the nearest node for the lookup
	successors, err := nearest.FindSuccessors(n, key_hash)
	if err != nil {
		return nil, err
	}

	// Trim the nil successors
	for successors[len(successors)-1] == nil {
		successors = successors[:len(successors)-1]
	}
	return successors, nil
}

const (
	Send = iota
	Receive
)

func (r *Ring) AppendHistory(id string, message string, option int) {
	// fmt.Println("appending history")
	t := time.Now()
	if option == Send {
		r.ChatHistory[id] += t.Format("2006-01-02 15:04:05") + " [ You  ] : " + message + "\n"
	} else {
		r.ChatHistory[id] += t.Format("2006-01-02 15:04:05") + " [He/She] : " + message + "\n"
	}
}

func (r *Ring) SendChatMessage(key string, message string) (bool, error) {
	// 1. find if the node is in the chattable
	vnodeId := r.HashVnodeId(key, 0)
	contact, ok := r.BuddyList[string(vnodeId)]
	if !ok {
		fmt.Println("Not in buddylist")
		keyBytes, err := r.HandShakeProcess(key)
		if err != nil {
			fmt.Print("fail to handshake to initialize a chat key, got", err)
		}
		r.BuddyList[string(vnodeId)] = Buddy{PublicKey: (key), ChatKey: keyBytes}
		err = r.SaveBuddyList()
		if err != nil {
			fmt.Println("Save new buddylist fail")
		}
		contact = r.BuddyList[string(vnodeId)]
	}
	// encrypt message with shared key
	cipherMsg, err := Encrypt([]byte(message), contact.ChatKey)
	if err != nil {
		return false, err
	}
	nodes, err := r.VnodeLookup(1, key, 0)
	if err != nil {
		return false, err
	}

	//TODO CHANGE THIS
	srcVnode := &r.vnodes[0].Vnode
	success, err := r.transport.SendMessage(nodes[0], srcVnode, string(cipherMsg), chatMessage)
	if !success {
		fmt.Println("[error] fail to send message")
		return false, err
	}
	r.AppendHistory(key, message, Send)

	return true, nil
}

func (r *Ring) getPrimaryVnode() *Vnode {
	return &r.vnodes[0].Vnode
}

func (r *Ring) HandShakeProcess(key string) ([]byte, error) {
	targetNode, err := r.VnodeLookup(1, key, 0)
	if err != nil {
		return nil, err
	}

	sourceNode := &r.vnodes[0].Vnode
	keyBytes, err := r.transport.SendHandShakeMessage(targetNode[0], sourceNode, sourceNode.HostIdf, 0)
	if err == nil {
		log.Printf("{TripleP} [INFO] Handshake finished!\n")
		return keyBytes, nil
	}
	return nil, err
}

// save BuddyList
func (r *Ring) SaveBuddyList() error {

	// serialzie buddylist
	jsonBtye, err := json.Marshal(r.BuddyList)
	if err != nil {
		log.Println("fail to marshal buddylist into json")
		return err
	}

	// TODO:encrypt
	//cipherMsg, err := Encrypt([]byte(history), secretKey)
	cipherMsg, err := Encrypt(jsonBtye, r.kFile)

	// get target vnode
	failnum := 0
	var lasterr error
	for i := 1; i < 4; i++ {
		dataID := "BuddyListOf_" + r.vnodes[0].HostIdf + strconv.Itoa(i) // name of buddylist file
		targetVns, err := r.Lookup(1, []byte(dataID))
		if err != nil {
			log.Println("save buddylist: vnode lookup fail")
			failnum++
			lasterr = err
			continue
		}

		_, resdataId, err := r.transport.TransferData(targetVns[0], dataID, cipherMsg, SaveBuddyList)
		if err != nil || resdataId != dataID {
			failnum++
			lasterr = err
			continue
		}
	}

	if failnum < 3 {
		return nil
	} else {
		return lasterr
	}

}

// fetch BuddyList
func (r *Ring) FetchBuddyList() (map[string]Buddy, error) {
	rootkey := "BuddyListOf_" + r.vnodes[0].HostIdf
	var lasterr error
	for i := 0; i < 4; i++ {
		key := rootkey + strconv.Itoa(i)
		targetVns, err := r.Lookup(1, []byte(key))
		if err != nil {
			fmt.Println("no target vns")
			lasterr = err
			continue
		}
		resdata, resdataId, err := r.transport.TransferData(targetVns[0], key, nil, FetchBuddyList)
		if err != nil {
			lasterr = err
			continue
		}
		if resdataId == key {
			// decrypt
			plaintxt, err := Decrypt(resdata, r.kFile)
			var buddylist map[string]Buddy
			err = json.Unmarshal(plaintxt, &buddylist)
			if err != nil {
				fmt.Println("unmarshal fial")
				lasterr = err
				continue
			}
			return buddylist, nil
		}
	}
	return nil, lasterr
}

func (r *Ring) SaveChatHistory(userIdf string) error {
	history, ok := r.ChatHistory[userIdf]
	if ok != true {
		return fmt.Errorf("Error in fetching history from memory")
	}
	key := r.getPrimaryVnode().HostIdf + "with" + userIdf
	destVnodes, err := r.Lookup(1, []byte(key))
	if err != nil {
		log.Println("save history vnode lookup fail")
		return fmt.Errorf("save history vnode lookup fail")
	}
	// fmt.Println("dest:", destVnodes[0].HostIdf)
	cipherMsg, err := Encrypt([]byte(history), r.kFile)
	_, resdataId, err := r.transport.TransferData(destVnodes[0], key, cipherMsg, SaveData)
	if err != nil || resdataId != key {
		log.Print("fail to save chatfile with", userIdf)
		return err
	}
	return nil
}

func (r *Ring) FetchHistory(targetIdf string) (string, error) {
	key := r.getPrimaryVnode().HostIdf + "with" + targetIdf

	destVnodes, err := r.Lookup(1, []byte(key))
	if err != nil {
		log.Println("fetch history vnode lookup fail")
		return "none", fmt.Errorf("fetch history vnode lookup fail")
	}

	ciphertxt, resdataId, err := r.transport.TransferData(destVnodes[0], key, nil, FetchData)
	if err != nil || resdataId != key {
		log.Println("fetch history fail")
		return "none", fmt.Errorf("fetch history fail, got %s", err)
	}

	history, err := Decrypt(ciphertxt, r.kFile)
	if err != nil {
		log.Println("decryption fails")
		return "none", fmt.Errorf("decryption fails")
	}
	return string(history), nil
}
