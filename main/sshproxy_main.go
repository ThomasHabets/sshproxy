package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"

	"code.google.com/p/go.crypto/ssh"
)

var (
	target        = flag.String("target", "", "SSH server to connect to.")
	listen        = flag.String("listen", "", "Address to listen to.")
	keyfile       = flag.String("keyfile", "", "SSH server key file.")
	clientKeyfile = flag.String("client_keyfile", "", "SSH client key file.")

	privateKey       ssh.Signer
	clientPrivateKey ssh.Signer
)

func makeConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{}
	config.AuthLogCallback = func(conn ssh.ConnMetadata, method string, err error) {
		log.Printf("(%s) Attempt method %s: %v", conn.RemoteAddr(), method, err)
		log.Printf("... user: %s", conn.User())
		log.Printf("... session: %v", conn.SessionID())
		log.Printf("... clientVersion: %s", conn.ClientVersion())
		log.Printf("... serverVersion: %s", conn.ServerVersion())
		log.Printf("... localAddr: %v", conn.LocalAddr())
	}
	config.AddHostKey(privateKey)
	return config
}

func main() {
	flag.Parse()

	// Load SSH server key.
	privateBytes, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		log.Fatalf("Can't read private key file %q (-keyfile).", *keyfile)
	}
	privateKey, err = ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatalf("Parse error reading private key %q: %v", *keyfile, err)
	}

	// Load SSH client key.
	clientPrivateBytes, err := ioutil.ReadFile(*clientKeyfile)
	if err != nil {
		log.Fatalf("Can't read client private key file %q (-client_keyfile).", *clientKeyfile)
	}
	clientPrivateKey, err = ssh.ParsePrivateKey(clientPrivateBytes)
	if err != nil {
		log.Fatalf("Parse error client reading private key %q: %v", *clientKeyfile, err)
	}

	if *listen == "" {
		log.Fatalf("-listen is required.")
	}

	if *target == "" {
		log.Fatalf("-target is required.")
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("Failed to listen to %q: %v", *listen, err)
	}

	log.Printf("Ready to accept connections.")
	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("accept(): %v", err)
			continue
		}
		// TODO: handle connections in separate processes, so that log.Fatalf() works.
		// e.g. nConn, err := net.FileListener(os.NewFile(*fileNo, "connection"))
		go handleConnection(nConn)
	}
}

type keyboardInteractive struct {
	user, instruction string
	questions         []string
	echos             []bool
	reply             chan []string
}

func handshakeKBI() (<-chan *ssh.Client, *ssh.ServerConfig) {
	authKBI := make(chan keyboardInteractive, 10)
	userChan := make(chan string, 10)
	upstreamConnected := make(chan error, 10)
	ua := ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		log.Printf("upstream auth: %q %q %v", user, instruction, questions)
		q := keyboardInteractive{
			user:        user,
			instruction: instruction,
			questions:   questions,
			echos:       echos,
			reply:       make(chan []string, 10),
		}
		authKBI <- q
		ans := <-q.reply
		log.Printf("answering upstream")
		return ans, nil
	})

	upstreamConf := &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{
			ua,
		},
	}

	downstreamConf := makeConfig()
	downstreamConf.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, chal ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		userChan <- c.User()
		for try := range authKBI {
			log.Printf("downstream auth: %+v", try)
			defer close(try.reply)
			reply, err := chal(try.user, try.instruction, try.questions, try.echos)
			if err != nil {
				log.Printf("server chal: %v", err)
			}
			log.Printf("got reply from downstream: %v", reply)
			try.reply <- reply
		}
		if err := <-upstreamConnected; err != nil {
			log.Fatalf("upstream not connected: %v", err)
		}
		return nil, nil
	}
	upstreamChannel := make(chan *ssh.Client)
	go func() {
		upstreamConf.User = <-userChan
		defer close(upstreamChannel)
		defer close(authKBI)
		upstream, err := ssh.Dial("tcp", *target, upstreamConf)
		if err != nil {
			upstreamConnected <- err
			log.Fatalf("upstream dial: %v", err)
		}
		log.Printf("upstream is connected")
		upstreamChannel <- upstream
	}()

	return upstreamChannel, downstreamConf
}

func handshakeKey() (<-chan *ssh.Client, *ssh.ServerConfig) {
	upstreamConnected := make(chan error, 10)
	userChan := make(chan string, 10)
	downstreamConf := makeConfig()
	downstreamConf.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		thisKey := strings.SplitN(strings.Trim(string(ssh.MarshalAuthorizedKey(key)), "\n"), " ", 3)
		log.Printf("Public key callback: %q", thisKey)
		// TODO: certs.
		d, err := ioutil.ReadFile("authorized_keys")
		if err != nil {
			log.Fatal(err)
		}
		authOk := false
		for _, line := range strings.Split(string(d), "\n") {
			parts := strings.SplitN(line, " ", 3)
			if parts[0] == thisKey[0] && parts[1] == thisKey[1] {
				authOk = true
				break
			}
		}
		if authOk {
			userChan <- c.User()
			return nil, nil
		}
		return nil, fmt.Errorf("no I don't think so")
	}

	upstreamConf := &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(clientPrivateKey),
		},
	}
	upstreamChannel := make(chan *ssh.Client)
	go func() {
		upstreamConf.User = <-userChan
		defer close(upstreamChannel)
		upstream, err := ssh.Dial("tcp", *target, upstreamConf)
		if err != nil {
			upstreamConnected <- err
			log.Fatalf("upstream dial: %v", err)
		}
		log.Printf("upstream is connected")
		upstreamChannel <- upstream
	}()
	return upstreamChannel, downstreamConf
}

func handshake(wg *sync.WaitGroup, conn net.Conn) (<-chan ssh.NewChannel, *ssh.Client, error) {
	//upstreamChannel, downstreamConf, _ := handshakeKBI()
	upstreamChannel, downstreamConf := handshakeKey()

	var err error

	_, channels, reqs, err := ssh.NewServerConn(conn, downstreamConf)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}
	upstream := <-upstreamChannel

	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range reqs {
			log.Printf("downstream->upstream req: %+v", req)
			ok, payload, err := upstream.Conn.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Fatalf("request: %v", err)
			}
			req.Reply(ok, payload)
		}
	}()
	return channels, upstream, nil
}

func handleConnection(conn net.Conn) {
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		log.Printf("Connection closed.")
		conn.Close()
	}()

	channels, upstream, err := handshake(&wg, conn)
	if err != nil {
		log.Fatal(err)
	}
	for newChannel := range channels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := handleChannel(upstream, newChannel); err != nil {
				log.Printf("handleChannel: %v", err)
			}
		}()
	}
}

type source string

const (
	UPSTREAM   source = "upstream"
	DOWNSTREAM source = "downstream"
)

func dataForward(from source, wg *sync.WaitGroup, src, dst ssh.Channel) {
	defer wg.Done()
	defer dst.Close()
	for {
		data := make([]byte, 16)
		n, err := src.Read(data)
		if err == io.EOF {
			break
		}
		if n == 0 {
			continue
		}
		if err != nil {
			log.Fatalf("read from %s: %v", from, err)
		}
		if nw, err := dst.Write(data[:n]); err != nil {
			log.Fatalf("write(%d) of data from %s: %v", n, from, err)
		} else if nw != n {
			log.Fatalf("short write %d < %d from %s", nw, n, from)
		}
	}
	log.Printf("closing the one that's NOT %s", from)
}

func requestForward(from source, wg *sync.WaitGroup, in <-chan *ssh.Request, fwd ssh.Channel) {
	defer wg.Done()
	for req := range in {
		log.Printf("req from %s of type %s", from, req.Type)
		ok, err := fwd.SendRequest(req.Type, req.WantReply, req.Payload)
		if err == io.EOF {
			continue
		} else if err != nil {
			log.Fatalf("%s fwd.SendRequest(): %v", from, err)
		}
		log.Printf("... req ok: %v", ok)
		req.Reply(ok, nil)
	}
}

// handleChannel forwards data and requests between upstream and downstream.
// It blocks until until channel is closed.
func handleChannel(upstreamClient *ssh.Client, newChannel ssh.NewChannel) error {
	log.Printf("Downstream requested new channel of type %s", newChannel.ChannelType())

	var wg sync.WaitGroup
	okReturn := make(chan bool)
	okWait := make(chan bool)
	go func() {
		<-okWait
		wg.Wait()
		okReturn <- true
	}()

	// Open channel with server.
	upstream, upstreamRequests, err := upstreamClient.Conn.OpenChannel(newChannel.ChannelType(), nil)
	if err != nil {
		newChannel.Reject(ssh.UnknownChannelType, "failed")
		return fmt.Errorf("upstream chan create failed: %v", err)
	}
	defer upstream.Close()

	downstream, downstreamRequests, err := newChannel.Accept()
	if err != nil {
		return fmt.Errorf("downstream: could not accept channel: %v", err)
	}
	defer downstream.Close()

	// Discard all requests from server.
	wg.Add(2)
	go requestForward(UPSTREAM, &wg, upstreamRequests, downstream)
	go requestForward(DOWNSTREAM, &wg, downstreamRequests, upstream)

	// downstream -> upstream.
	wg.Add(2)
	go dataForward(DOWNSTREAM, &wg, downstream, upstream)
	go dataForward(UPSTREAM, &wg, upstream, downstream)
	okWait <- true
	<-okReturn
	return nil
}
