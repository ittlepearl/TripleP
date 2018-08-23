package chord

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type clientDelegate struct {
	shutdown bool
}

type Client struct {
	Config *Config         // config of chord
	Ring   *Ring           // ring of chord
	Kpriv  *rsa.PrivateKey // private key of client
}

func (m *clientDelegate) NewPredecessor(local, remoteNew, remotePrev *Vnode) {
	fmt.Printf("System stable!\n")
}
func (m *clientDelegate) Leaving(local, pred, succ *Vnode) {
	fmt.Printf("leaving\n")
}
func (m *clientDelegate) PredecessorLeaving(local, remote *Vnode) {
	fmt.Printf("predecessor leaving\n")
}
func (m *clientDelegate) SuccessorLeaving(local, remote *Vnode) {
}
func (m *clientDelegate) Shutdown() {
	m.shutdown = true
	fmt.Printf("shutdown\n")
}

//get the outBoundIP
func GetOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func CreateLastingRing(port int, hostName string) {
	conf := clientConfig(hostName, port)
	// need at least 2 vnode for the initial ring, otherwise it would segafault
	conf.NumVnodes = 2
	listenAddr := GetOutboundIP() + ":"
	listenAddr += strconv.Itoa(port)
	timeout := time.Duration(20 * time.Millisecond)
	trans, err := InitTCPTransport(listenAddr, timeout)
	if err != nil {
		log.Fatal("failed to init tcp transport")
	}

	r, err := Create(conf, trans)
	if err != nil {
		log.Fatalf("unexpected err. %s", err)
	}
	defer r.Shutdown()
	sum := 1
	for sum < 1000 {
		time.Sleep(20 * time.Second)
	}
}

/* join chord with private key and public key
** -- port: own listensing port
** -- serviceHost: ip address of introducer
** -- keyFilename: pem file of private key
 */
func JoinWithKey(port int, serviceHost string, kprivFilename string, kpubFilename string) *Client {
	privatekey := GetKpriv(kprivFilename)
	publickey := GetKpubString(kpubFilename)

	conf := clientConfig(publickey, port)
	listenAddr := GetOutboundIP() + ":"
	listenAddr += strconv.Itoa(port)
	// fmt.Printf("local addr is %v\n", listenAddr)
	timeout := time.Duration(20 * time.Millisecond)
	trans, err := InitTCPTransport(listenAddr, timeout)
	if err != nil {
		log.Fatal("failed to init tcp transport")
	}

	r, err := Join(conf, trans, serviceHost)
	if err != nil {
		log.Fatalf("failed to join service with hostname %v with error %v\n", serviceHost, err)
	}

	r.kPrivate = privatekey

	buddylist, err := r.FetchBuddyList()
	if err != nil {
		log.Println("{TripleP} [INFO] You have no buddylist saved before.")
	} else {
		log.Println("{TripleP} [INFO] Succesfully fetch your buddylist! You can read your buddylist now. ")
		r.BuddyList = buddylist
	}

	return &Client{
		conf,
		r,
		privatekey,
	}
}

func Register(port int, serviceHost string) *Client {
	filenames, _ := GenerateKeyPairs()
	log.Println("{TripleP} [INFO} Filename of Kpriv:", filenames[0])
	log.Println("{TripleP} [INFO} Filename of Kpub:", filenames[1])
	client := JoinWithKey(port, serviceHost, filenames[0], filenames[1])

	return client
}

/* local helper function*/

// return a client config
func clientConfig(hostname string, clientPort int) *Config {
	d := &clientDelegate{}
	return &Config{
		hostname,
		GetOutboundIP() + ":" + strconv.Itoa(clientPort),
		1,        // 1 vnode
		sha1.New, // SHA1
		time.Duration(15 * time.Second),
		time.Duration(45 * time.Second),
		8,   // 8 successors
		d,   // delegate obj
		160, // 160bit hash function

	}
}

// return private key
func GetKpriv(keyFilename string) *rsa.PrivateKey {
	var privatekey *rsa.PrivateKey

	fileinfo, err := os.Stat(keyFilename)
	file, err := os.Open(keyFilename)
	if err != nil {
		fmt.Println("can not open private key file")
	}
	defer file.Close()

	readinPrivbytes := make([]byte, fileinfo.Size())
	_, err = file.Read(readinPrivbytes)
	if err != nil {
		fmt.Println("can not read in private key")
	}

	block, _ := pem.Decode(readinPrivbytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		fmt.Println("failed to decode PEM block containing private key")
	}

	privatekey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	return privatekey
}

// return public key as string using private key
func GetKpubString(keyFilename string) string {
	fileinfo, err := os.Stat(keyFilename)
	file, err := os.Open(keyFilename)
	if err != nil {
		fmt.Println("can not open private key file")
	}
	defer file.Close()

	readinPubbytes := make([]byte, fileinfo.Size())
	_, err = file.Read(readinPubbytes)
	if err != nil {
		fmt.Println("can not read in private key")
	}

	s := string(readinPubbytes)
	substring := strings.Split(s, "\n")
	pubStr := ""

	for i := 1; i < len(substring)-2; i++ {
		pubStr += substring[i]
	}
	return pubStr
}

func GenerateKeyPairs() ([]string, *rsa.PrivateKey) {
	privFilename := "../key/private.key"
	pubFilename := "../key/public.key"
	privatekey, _ := rsa.GenerateKey(rand.Reader, 256)
	// fmt.Println("generate private:", privatekey)

	// save private key in pem form
	privbytes := x509.MarshalPKCS1PrivateKey(privatekey)
	privfile, _ := os.Create(privFilename)
	var pempriv = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privbytes}
	pem.Encode(privfile, pempriv)
	privfile.Close()

	// save public key in pem form
	pubfile, _ := os.Create(pubFilename)
	pubbytes, _ := x509.MarshalPKIXPublicKey(privatekey.Public())
	var pempub = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubbytes}
	pem.Encode(pubfile, pempub)
	pubfile.Close()

	return []string{privFilename, pubFilename}, privatekey
}
