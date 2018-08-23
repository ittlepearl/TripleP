package chord

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log"
	"sort"
)

func (r *Ring) init(conf *Config, trans Transport) {
	// Set our variables
	r.config = conf
	r.vnodes = make([]*localVnode, conf.NumVnodes)
	r.transport = InitLocalTransport(trans)
	r.delegateCh = make(chan func(), 32)
	r.handShakeCh = make(chan tcpBodyVnodesInt)
	r.kPrivate = nil
	r.kFile = []byte("32-bytes-key-for-file-encryption")
	r.BuddyList = make(map[string]Buddy)
	r.ChatHistory = make(map[string]string)
	r.peerFiles = make(map[string]string)
	r.peerBuddyList = make(map[string]string)

	// Initializes the vnodes
	for i := 0; i < conf.NumVnodes; i++ {
		vn := &localVnode{}
		r.vnodes[i] = vn
		vn.ring = r
		vn.init(i)
	}

	// Sort the vnodes
	sort.Sort(r)
}

// Len is the number of vnodes
func (r *Ring) Len() int {
	return len(r.vnodes)
}

// Less returns whether the vnode with index i should sort
// before the vnode with index j.
func (r *Ring) Less(i, j int) bool {
	return bytes.Compare(r.vnodes[i].Id, r.vnodes[j].Id) == -1
}

// Swap swaps the vnodes with indexes i and j.
func (r *Ring) Swap(i, j int) {
	r.vnodes[i], r.vnodes[j] = r.vnodes[j], r.vnodes[i]
}

// Returns the nearest local vnode to the key
func (r *Ring) nearestVnode(key []byte) *localVnode {
	for i := len(r.vnodes) - 1; i >= 0; i-- {
		if bytes.Compare(r.vnodes[i].Id, key) == -1 {
			return r.vnodes[i]
		}
	}
	// Return the last vnode
	return r.vnodes[len(r.vnodes)-1]
}

// Schedules each vnode in the ring
func (r *Ring) schedule() {
	if r.config.Delegate != nil {
		go r.delegateHandler()
	}
	for i := 0; i < len(r.vnodes); i++ {
		r.vnodes[i].schedule()
	}
}

// Wait for all the vnodes to shutdown
func (r *Ring) stopVnodes() {
	r.shutdown = make(chan bool, r.config.NumVnodes)
	for i := 0; i < r.config.NumVnodes; i++ {
		<-r.shutdown
	}
}

// Stops the delegate handler
func (r *Ring) stopDelegate() {
	if r.config.Delegate != nil {
		// Wait for all delegate messages to be processed
		<-r.invokeDelegate(r.config.Delegate.Shutdown)
		close(r.delegateCh)
	}
}

// Initializes the vnodes with their local successors
func (r *Ring) setLocalSuccessors() {
	numV := len(r.vnodes)
	numSuc := min(r.config.NumSuccessors, numV-1)
	for idx, vnode := range r.vnodes {
		for i := 0; i < numSuc; i++ {
			vnode.successors[i] = &r.vnodes[(idx+i+1)%numV].Vnode
		}
	}
}

// Invokes a function on the delegate and returns completion channel
func (r *Ring) invokeDelegate(f func()) chan struct{} {
	if r.config.Delegate == nil {
		return nil
	}

	ch := make(chan struct{}, 1)
	wrapper := func() {
		defer func() {
			ch <- struct{}{}
		}()
		f()
	}

	r.delegateCh <- wrapper
	return ch
}

// This handler runs in a go routine to invoke methods on the delegate
func (r *Ring) delegateHandler() {
	for {
		f, ok := <-r.delegateCh
		if !ok {
			break
		}
		r.safeInvoke(f)
	}
}

// Called to safely call a function on the delegate
func (r *Ring) safeInvoke(f func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Caught a panic invoking a delegate function! Got: %s", r)
		}
	}()
	f()
}

func (r *Ring) setKey(key *rsa.PrivateKey) {
	r.kPrivate = key
}

func (r *Ring) getKey() *rsa.PrivateKey {
	return r.kPrivate
}

func encryptWithPubK(plaintext []byte, key []byte) ([]byte, error) {
	return nil, nil
}

func decryptWithPriK(plaintext []byte) ([]byte, error) {
	return nil, nil
}

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
