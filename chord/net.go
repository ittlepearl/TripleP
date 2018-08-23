package chord

import (
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

/*
TCPTransport provides a TCP based Chord transport layer. This allows Chord
to be implemented over a network, instead of only using the LocalTransport. It is
meant to be a simple implementation, optimizing for simplicity instead of performance.
Messages are sent with a header frame, followed by a body frame. All data is encoded
using the GOB format for simplicity.

Internally, there is 1 Goroutine listening for inbound connections, 1 Goroutine PER
inbound connection.
*/
type TCPTransport struct {
	sock     *net.TCPListener
	timeout  time.Duration
	maxIdle  time.Duration
	lock     sync.RWMutex
	local    map[string]*localRPC
	inbound  map[*net.TCPConn]struct{}
	poolLock sync.Mutex
	pool     map[string][]*tcpOutConn
	shutdown int32
}

type tcpOutConn struct {
	host   string
	sock   *net.TCPConn
	header tcpHeader
	enc    *gob.Encoder
	dec    *gob.Decoder
	used   time.Time
}

const (
	tcpPing = iota
	tcpListReq
	tcpGetPredReq
	tcpNotifyReq
	tcpFindSucReq
	tcpClearPredReq
	tcpSkipSucReq
	tcpMessage
	tcpHandShake
	tcpSaveData
	tcpFetchData
	tcpSaveBuddyList
	tcpFetchBuddyList
)

type tcpHeader struct {
	ReqType int
}

// Potential body types
type tcpBodyError struct {
	Err error
}
type tcpBodyString struct {
	S string
}
type tcpBodyVnode struct {
	Vn *Vnode
}
type tcpBodyTwoVnode struct {
	Target *Vnode
	Vn     *Vnode
}
type tcpBodyFindSuc struct {
	Target *Vnode
	Num    int
	Key    []byte
}
type tcpBodyVnodeError struct {
	Vnode *Vnode
	Err   error
}
type tcpBodyVnodeListError struct {
	Vnodes []*Vnode
	Err    error
}
type tcpBodyBoolError struct {
	B   bool
	Err error
}

type tcpBodyKeyError struct {
	Key []byte
	Err error
}

type tcpBodyDataTransferError struct {
	Target *Vnode
	DataID string
	Data   []byte
	Err    error
}

type tcpBodyVnodesString struct {
	VnTarget *Vnode
	VnSource *Vnode
	S        string
	option   int
}
type tcpBodyVnodesInt struct {
	VnTarget *Vnode
	VnSource *Vnode
	handStep int
	key      string
}

// Creates a new TCP transport on the given listen address with the
// configured timeout duration.
func InitTCPTransport(listen string, timeout time.Duration) (*TCPTransport, error) {
	// Try to start the listener
	sock, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}

	// allocate maps
	local := make(map[string]*localRPC)
	inbound := make(map[*net.TCPConn]struct{})
	pool := make(map[string][]*tcpOutConn)

	// Maximum age of a connection
	maxIdle := time.Duration(300 * time.Second)

	// Setup the transport
	tcp := &TCPTransport{sock: sock.(*net.TCPListener),
		timeout: timeout,
		maxIdle: maxIdle,
		local:   local,
		inbound: inbound,
		pool:    pool}

	// Listen for connections
	go tcp.listen()

	// Reap old connections
	go tcp.reapOld()

	// Done
	return tcp, nil
}

// Checks for a local vnode
func (t *TCPTransport) get(vn *Vnode) (VnodeRPC, bool) {
	key := vn.String()
	t.lock.RLock()
	defer t.lock.RUnlock()
	w, ok := t.local[key]
	if ok {
		return w.obj, ok
	} else {
		return nil, ok
	}
}

// Checks for a local vnode
func (lt *TCPTransport) getVnode(vn *Vnode) (*Vnode, bool) {
	key := vn.String()
	lt.lock.RLock()
	defer lt.lock.RUnlock()
	w, ok := lt.local[key]
	if ok {
		return w.vnode, ok
	} else {
		return nil, ok
	}
}

// Gets an outbound connection to a host
func (t *TCPTransport) getConn(host string) (*tcpOutConn, error) {
	// Check if we have a conn cached
	var out *tcpOutConn
	t.poolLock.Lock()
	if atomic.LoadInt32(&t.shutdown) == 1 {
		t.poolLock.Unlock()
		return nil, fmt.Errorf("TCP transport is shutdown")
	}
	list, ok := t.pool[host]
	if ok && len(list) > 0 {
		out = list[len(list)-1]
		list = list[:len(list)-1]
		t.pool[host] = list
	}
	t.poolLock.Unlock()
	if out != nil {
		// Verify that the socket is valid. Might be closed.
		if _, err := out.sock.Read(nil); err == nil {
			return out, nil
		}
		out.sock.Close()
	}

	// Try to establish a connection
	conn, err := net.DialTimeout("tcp", host, t.timeout)
	if err != nil {
		return nil, err
	}

	// Setup the socket
	sock := conn.(*net.TCPConn)
	t.setupConn(sock)
	enc := gob.NewEncoder(sock)
	dec := gob.NewDecoder(sock)
	now := time.Now()

	// Wrap the sock
	out = &tcpOutConn{host: host, sock: sock, enc: enc, dec: dec, used: now}
	return out, nil
}

// Returns an outbound TCP connection to the pool
func (t *TCPTransport) returnConn(o *tcpOutConn) {
	// Update the last used time
	o.used = time.Now()

	// Push back into the pool
	t.poolLock.Lock()
	defer t.poolLock.Unlock()
	if atomic.LoadInt32(&t.shutdown) == 1 {
		o.sock.Close()
		return
	}
	list, _ := t.pool[o.host]
	t.pool[o.host] = append(list, o)
}

// Setup a connection
func (t *TCPTransport) setupConn(c *net.TCPConn) {
	c.SetNoDelay(true)
	c.SetKeepAlive(true)
}

// Gets a list of the vnodes on the box
func (t *TCPTransport) ListVnodes(host string) ([]*Vnode, error) {
	// Get a conn
	out, err := t.getConn(host)
	if err != nil {
		return nil, err
	}

	// Response channels
	respChan := make(chan []*Vnode, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		out.header.ReqType = tcpListReq
		body := tcpBodyString{S: host}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyVnodeListError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- resp.Vnodes
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return nil, fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return nil, err
	case res := <-respChan:
		return res, nil
	}
}

// Ping a Vnode, check for liveness
func (t *TCPTransport) Ping(vn *Vnode) (bool, error) {
	// Get a conn
	out, err := t.getConn(vn.Host)
	if err != nil {
		return false, err
	}

	// Response channels
	respChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		out.header.ReqType = tcpPing
		body := tcpBodyVnode{Vn: vn}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyBoolError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- resp.B
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return false, fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return false, err
	case res := <-respChan:
		return res, nil
	}
}

//option for sendMessage
const (
	chatMessage = iota
)

// Ping a Vnode, check for liveness
func (t *TCPTransport) SendMessage(targetVn *Vnode, srcVnode *Vnode, message string, option int) (bool, error) {
	// Get a conn
	out, err := t.getConn(targetVn.Host)
	if err != nil {
		return false, err
	}

	// Response channels
	respChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	// TODO: use of option??

	go func() {
		// Send a list command
		out.header.ReqType = tcpMessage

		body := tcpBodyVnodesString{VnTarget: targetVn, S: message, VnSource: srcVnode}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyBoolError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- resp.B
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return false, fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return false, err
	case res := <-respChan:
		return res, nil
	}
}

//option for TransferData
const (
	SaveData = iota
	FetchData
	SaveBuddyList
	FetchBuddyList
)

func (t *TCPTransport) TransferData(targetVn *Vnode, dataID string, data []byte, option int) ([]byte, string, error) {
	// Get a conn
	out, err := t.getConn(targetVn.Host)
	if err != nil {
		return nil, "", err
	}

	// Response channels
	respChan := make(chan tcpBodyDataTransferError, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		if option == SaveData {
			out.header.ReqType = tcpSaveData
		} else if option == FetchData {
			out.header.ReqType = tcpFetchData
		} else if option == SaveBuddyList {
			out.header.ReqType = tcpSaveBuddyList
		} else if option == FetchBuddyList {
			out.header.ReqType = tcpFetchBuddyList
		}

		body := tcpBodyDataTransferError{Target: targetVn, DataID: dataID, Data: data, Err: nil}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyDataTransferError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- resp
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return nil, "", fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return nil, "", err
	case res := <-respChan:
		return res.Data, res.DataID, nil
	}

}

func (t *TCPTransport) SendHandShakeMessage(targetVn *Vnode, sourceVn *Vnode, key string, step int) ([]byte, error) {
	out, err := t.getConn(targetVn.Host)
	if err != nil {
		return nil, err
	}

	// Response channels
	respChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		out.header.ReqType = tcpHandShake
		mykey := sourceVn.HostIdf
		body := tcpBodyVnodesInt{VnTarget: targetVn, VnSource: sourceVn, handStep: 0, key: mykey}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyKeyError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- resp.Key
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return nil, fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return nil, err
	case res := <-respChan:
		return res, nil
	}
}

// Request a nodes predecessor
func (t *TCPTransport) GetPredecessor(vn *Vnode) (*Vnode, error) {
	// Get a conn
	out, err := t.getConn(vn.Host)
	if err != nil {
		return nil, err
	}

	respChan := make(chan *Vnode, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		out.header.ReqType = tcpGetPredReq
		body := tcpBodyVnode{Vn: vn}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyVnodeError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- resp.Vnode
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return nil, fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return nil, err
	case res := <-respChan:
		return res, nil
	}
}

// Notify our successor of ourselves
func (t *TCPTransport) Notify(target, self *Vnode) ([]*Vnode, error) {
	// Get a conn
	out, err := t.getConn(target.Host)
	if err != nil {
		return nil, err
	}

	respChan := make(chan []*Vnode, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		out.header.ReqType = tcpNotifyReq
		body := tcpBodyTwoVnode{Target: target, Vn: self}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyVnodeListError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- resp.Vnodes
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return nil, fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return nil, err
	case res := <-respChan:
		return res, nil
	}
}

// Find a successor
func (t *TCPTransport) FindSuccessors(vn *Vnode, n int, k []byte) ([]*Vnode, error) {
	// Get a conn
	out, err := t.getConn(vn.Host)
	if err != nil {
		return nil, err
	}

	respChan := make(chan []*Vnode, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		out.header.ReqType = tcpFindSucReq
		body := tcpBodyFindSuc{Target: vn, Num: n, Key: k}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyVnodeListError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- resp.Vnodes
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return nil, fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return nil, err
	case res := <-respChan:
		return res, nil
	}
}

// Clears a predecessor if it matches a given vnode. Used to leave.
func (t *TCPTransport) ClearPredecessor(target, self *Vnode) error {
	// Get a conn
	out, err := t.getConn(target.Host)
	if err != nil {
		return err
	}

	respChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		out.header.ReqType = tcpClearPredReq
		body := tcpBodyTwoVnode{Target: target, Vn: self}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- true
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return err
	case <-respChan:
		return nil
	}
}

// Instructs a node to skip a given successor. Used to leave.
func (t *TCPTransport) SkipSuccessor(target, self *Vnode) error {
	// Get a conn
	out, err := t.getConn(target.Host)
	if err != nil {
		return err
	}

	respChan := make(chan bool, 1)
	errChan := make(chan error, 1)

	go func() {
		// Send a list command
		out.header.ReqType = tcpSkipSucReq
		body := tcpBodyTwoVnode{Target: target, Vn: self}
		if err := out.enc.Encode(&out.header); err != nil {
			errChan <- err
			return
		}
		if err := out.enc.Encode(&body); err != nil {
			errChan <- err
			return
		}

		// Read in the response
		resp := tcpBodyError{}
		if err := out.dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}

		// Return the connection
		t.returnConn(out)
		if resp.Err == nil {
			respChan <- true
		} else {
			errChan <- resp.Err
		}
	}()

	select {
	case <-time.After(t.timeout):
		return fmt.Errorf("Command timed out!")
	case err := <-errChan:
		return err
	case <-respChan:
		return nil
	}
}

// Register for an RPC callbacks
func (t *TCPTransport) Register(v *Vnode, o VnodeRPC) {
	key := v.String()
	t.lock.Lock()
	t.local[key] = &localRPC{v, o}
	t.lock.Unlock()
}

// Shutdown the TCP transport
func (t *TCPTransport) Shutdown() {
	atomic.StoreInt32(&t.shutdown, 1)
	t.sock.Close()

	// Close all the inbound connections
	t.lock.RLock()
	for conn := range t.inbound {
		conn.Close()
	}
	t.lock.RUnlock()

	// Close all the outbound
	t.poolLock.Lock()
	for _, conns := range t.pool {
		for _, out := range conns {
			out.sock.Close()
		}
	}
	t.pool = nil
	t.poolLock.Unlock()
}

// Closes old outbound connections
func (t *TCPTransport) reapOld() {
	for {
		if atomic.LoadInt32(&t.shutdown) == 1 {
			return
		}
		time.Sleep(30 * time.Second)
		t.reapOnce()
	}
}

func (t *TCPTransport) reapOnce() {
	t.poolLock.Lock()
	defer t.poolLock.Unlock()
	for host, conns := range t.pool {
		max := len(conns)
		for i := 0; i < max; i++ {
			if time.Since(conns[i].used) > t.maxIdle {
				conns[i].sock.Close()
				conns[i], conns[max-1] = conns[max-1], nil
				max--
				i--
			}
		}
		// Trim any idle conns
		t.pool[host] = conns[:max]
	}
}

// Listens for inbound connections
func (t *TCPTransport) listen() {
	for {
		conn, err := t.sock.AcceptTCP()
		if err != nil {
			if atomic.LoadInt32(&t.shutdown) == 0 {
				fmt.Printf("[ERR] Error accepting TCP connection! %s", err)
				continue
			} else {
				return
			}
		}

		// Setup the conn
		t.setupConn(conn)

		// Register the inbound conn
		t.lock.Lock()
		t.inbound[conn] = struct{}{}
		t.lock.Unlock()

		// Start handler
		go t.handleConn(conn)
	}
}

// Handles inbound TCP connections
func (t *TCPTransport) handleConn(conn *net.TCPConn) {
	// Defer the cleanup
	defer func() {
		t.lock.Lock()
		delete(t.inbound, conn)
		t.lock.Unlock()
		conn.Close()
	}()

	dec := gob.NewDecoder(conn)
	enc := gob.NewEncoder(conn)
	header := tcpHeader{}
	var sendResp interface{}
	for {
		// Get the header
		if err := dec.Decode(&header); err != nil {
			if atomic.LoadInt32(&t.shutdown) == 0 && err.Error() != "EOF" {
				// log.Printf("[ERR] Failed to decode TCP header! Got %s", err)
			}
			return
		}

		// Read in the body and process request
		switch header.ReqType {
		case tcpPing:
			body := tcpBodyVnode{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body! Got %s", err)
				return
			}

			// Generate a response
			_, ok := t.get(body.Vn)
			if ok {
				sendResp = tcpBodyBoolError{B: ok, Err: nil}
			} else {
				sendResp = tcpBodyBoolError{B: ok, Err: fmt.Errorf("Target VN not found! Target %s:%s",
					body.Vn.Host, body.Vn.String())}
			}

		case tcpMessage:
			body := tcpBodyVnodesString{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body with sendMessage header! Got %s", err)
				return
			}
			//log.Printf("new tcpMessage")
			// Generate a response
			obj, ok := t.get(body.VnTarget)
			if ok {
				//log.Printf("ok to get vnTarget")
				fmt.Printf("{TripleP} [INFO] Received an encrypted message: %v\n", body.S)

				srcVnodeId := body.VnSource.Id
				ring := obj.GetLocalRing()
				contact, ok := ring.BuddyList[string(srcVnodeId[:])]
				if ok {

					decryptkey := contact.ChatKey
					encryptedText := []byte(body.S)
					decrypteBbytes, _ := Decrypt(encryptedText, decryptkey)
					decryptedString := string(decrypteBbytes)
					fmt.Printf("Message decrypted is: %v\n", decryptedString)

					ring.AppendHistory(body.VnSource.HostIdf, decryptedString, Receive)
					// fmt.Println("after appending: ", ring.ChatHistory)

					sendResp = tcpBodyBoolError{B: true, Err: nil}
				} else {
					fmt.Println("key unfound")
				}

			} else {
				sendResp = tcpBodyBoolError{B: ok, Err: fmt.Errorf("Target VN not found! Target %s:%s",
					body.VnTarget.Host, body.VnTarget.String())}
			}

		case tcpHandShake:
			body := tcpBodyVnodesInt{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body with tcpHandShake header! Got %s", err)
				return
			}
			// TODO: THIS IS A VERY AD HOC IMPLEMENTATION CHANGE IT LATER
			obj, ok := t.get(body.VnTarget)
			if ok {
				key := []byte("the-key-has-to-be-32-bytes-long!")
				srcPublicKey := body.VnSource.HostIdf
				obj.GetLocalRing().BuddyList[string(body.VnSource.Id)] = Buddy{PublicKey: srcPublicKey, ChatKey: key}
				// save new BuddyList to chord
				obj.GetLocalRing().SaveBuddyList()

				sendResp = tcpBodyKeyError{Key: key, Err: nil}
				// fmt.Printf("Received init: %v\n", body.handStep)
				log.Printf("{TripleP} [INFP] You got a new friend! %s\n", body.VnSource.HostIdf)
			} else {
				sendResp = tcpBodyKeyError{Key: nil, Err: fmt.Errorf("Target VN not found! Target %s:%s",
					body.VnTarget.Host, body.VnTarget.String())}
			}

		case tcpListReq:
			body := tcpBodyString{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body! Got %s", err)
				return
			}

			// Generate all the local clients
			res := make([]*Vnode, 0, len(t.local))

			// Build list
			t.lock.RLock()
			for _, v := range t.local {
				res = append(res, v.vnode)
			}
			t.lock.RUnlock()

			// Make response
			sendResp = tcpBodyVnodeListError{Vnodes: trimSlice(res)}

		case tcpGetPredReq:
			body := tcpBodyVnode{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body! Got %s", err)
				return
			}

			// Generate a response
			obj, ok := t.get(body.Vn)
			resp := tcpBodyVnodeError{}
			sendResp = &resp
			if ok {
				node, err := obj.GetPredecessor()
				resp.Vnode = node
				resp.Err = err
			} else {
				resp.Err = fmt.Errorf("Target VN not found! Target %s:%s",
					body.Vn.Host, body.Vn.String())
			}

		case tcpNotifyReq:
			body := tcpBodyTwoVnode{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body! Got %s", err)
				return
			}
			if body.Target == nil {
				return
			}

			// Generate a response
			obj, ok := t.get(body.Target)
			resp := tcpBodyVnodeListError{}
			sendResp = &resp
			if ok {
				nodes, err := obj.Notify(body.Vn)
				resp.Vnodes = trimSlice(nodes)
				resp.Err = err
			} else {
				resp.Err = fmt.Errorf("Target VN not found! Target %s:%s",
					body.Target.Host, body.Target.String())
			}

		case tcpFindSucReq:
			body := tcpBodyFindSuc{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body! Got %s", err)
				return
			}

			// Generate a response
			obj, ok := t.get(body.Target)
			resp := tcpBodyVnodeListError{}
			sendResp = &resp
			if ok {
				nodes, err := obj.FindSuccessors(body.Num, body.Key)
				resp.Vnodes = trimSlice(nodes)
				resp.Err = err
			} else {
				resp.Err = fmt.Errorf("Target VN not found! Target %s:%s",
					body.Target.Host, body.Target.String())
			}

		case tcpClearPredReq:
			body := tcpBodyTwoVnode{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body! Got %s", err)
				return
			}

			// Generate a response
			obj, ok := t.get(body.Target)
			resp := tcpBodyError{}
			sendResp = &resp
			if ok {
				resp.Err = obj.ClearPredecessor(body.Vn)
			} else {
				resp.Err = fmt.Errorf("Target VN not found! Target %s:%s",
					body.Target.Host, body.Target.String())
			}

		case tcpSkipSucReq:
			body := tcpBodyTwoVnode{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body! Got %s", err)
				return
			}

			// Generate a response
			obj, ok := t.get(body.Target)
			resp := tcpBodyError{}
			sendResp = &resp
			if ok {
				resp.Err = obj.SkipSuccessor(body.Vn)
			} else {
				resp.Err = fmt.Errorf("Target VN not found! Target %s:%s",
					body.Target.Host, body.Target.String())
			}

		case tcpSaveData:
			body := tcpBodyDataTransferError{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body with tcpSaveData header! Got %s", err)
				return
			}
			log.Println("saving history")
			obj, ok := t.get(body.Target)
			if ok {
				dataID := body.DataID
				fileName := "temp_" + dataID
				obj.GetLocalRing().peerFiles[dataID] = fileName
				f, err := os.Create(fileName)
				if err != nil {
					sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("cant create temp file")}
					goto SendResponse
				}
				f.Write(body.Data)
				f.Sync()
				log.Println("saved to local file", fileName)
				sendResp = tcpBodyDataTransferError{Data: nil, DataID: dataID, Err: nil}

			} else {
				log.Println("fail to get target vnode")
				sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("Target VN not found! Target %s:%s",
					body.Target.Host, body.Target.String())}
			}

		case tcpSaveBuddyList:
			body := tcpBodyDataTransferError{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body with tcpSaveData header! Got %s", err)
				return
			}
			obj, ok := t.get(body.Target)
			if ok {
				dataID := body.DataID
				fileName := "temp_" + dataID
				obj.GetLocalRing().peerBuddyList[dataID] = fileName
				f, err := os.Create(fileName)
				if err != nil {
					sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("cant create temp file")}
					goto SendResponse
				}
				f.Write(body.Data)
				f.Sync()
				sendResp = tcpBodyDataTransferError{Data: nil, DataID: dataID, Err: nil}

			} else {
				sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("Target VN not found! Target %s:%s",
					body.Target.Host, body.Target.String())}
			}

		case tcpFetchData:
			fmt.Println("fetching history")
			body := tcpBodyDataTransferError{}
			if err := dec.Decode(&body); err != nil {
				fmt.Printf("[ERR] Failed to decode TCP body with tcpSaveData header! Got %s", err)
				return
			}
			obj, ok := t.get(body.Target)
			if ok {
				dataID := body.DataID
				ring := obj.GetLocalRing()
				fileName, ok := ring.peerFiles[dataID]
				if !ok {
					sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("file not exist")}
					goto SendResponse
				}

				b, err := ioutil.ReadFile(fileName)
				if err != nil {
					sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("read file error")}
					goto SendResponse
				}

				sendResp = tcpBodyDataTransferError{Data: b, DataID: dataID, Err: nil}
			} else {
				sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("Target VN not found! Target %s:%s",
					body.Target.Host, body.Target.String())}
			}

		case tcpFetchBuddyList:
			body := tcpBodyDataTransferError{}
			if err := dec.Decode(&body); err != nil {
				// log.Printf("[ERR] Failed to decode TCP body with tcpSaveData header! Got %s", err)
				return
			}
			obj, ok := t.get(body.Target)
			if ok {
				dataID := body.DataID
				ring := obj.GetLocalRing()
				fileName, ok := ring.peerBuddyList[dataID]
				if !ok {
					//fmt.Println("file not exist")
					sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("file not exist")}
					goto SendResponse
				}

				b, err := ioutil.ReadFile(fileName)
				if err != nil {
					fmt.Println("read file error")
					sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("read file error")}
					goto SendResponse
				}
				sendResp = tcpBodyDataTransferError{Data: b, DataID: dataID, Err: nil}
			} else {
				sendResp = tcpBodyDataTransferError{Err: fmt.Errorf("Target VN not found! Target %s:%s",
					body.Target.Host, body.Target.String())}
			}

		default:
			log.Printf("[ERR] Unknown request type! Got %d", header.ReqType)
			return
		}

	SendResponse:
		// Send the response
		if err := enc.Encode(sendResp); err != nil {
			// log.Printf("[ERR] Failed to send TCP body! Got %s", err)
			return
		}
	}
}

// Trims the slice to remove nil elements
func trimSlice(vn []*Vnode) []*Vnode {
	if vn == nil {
		return vn
	}

	// Find a non-nil index
	idx := len(vn) - 1
	for vn[idx] == nil {
		idx--
	}
	return vn[:idx+1]
}
