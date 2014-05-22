package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"

	"code.google.com/p/go.crypto/ssh"
)

var (
	target  = flag.String("target", "", "SSH server to connect to.")
	listen  = flag.String("listen", "", "Address to listen to.")
	keyfile = flag.String("keyfile", "", "SSH server key file.")

	privateKey ssh.Signer
)

func makeConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{}
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
		go handleConnection(nConn)
	}
}

func handleConnection(conn net.Conn) {
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		log.Printf("Connection closed.")
		conn.Close()
	}()

	type keyboardInteractive struct {
		user, instruction string
		questions         []string
		echos             []bool
		reply             chan []string
	}
	var upstream *ssh.Client
	authKBI := make(chan keyboardInteractive, 10)
	config := makeConfig()

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
	var err error
	upstreamConnected := make(chan error, 10)
	userChan := make(chan string, 10)
	go func() {
		upstreamConf.User = <-userChan
		defer close(upstreamConnected)
		defer close(authKBI)
		upstream, err = ssh.Dial("tcp", *target, upstreamConf)
		if err != nil {
			upstreamConnected <- err
			log.Fatalf("upstream dial: %v", err)
		}
		log.Printf("upstream is connected")
		upstreamConnected <- nil
	}()
	config.AuthLogCallback = func(conn ssh.ConnMetadata, method string, err error) {
		log.Printf("Attempt: %+v %q %v", conn, method, err)
		log.Printf("... server: %s", conn.ServerVersion())
		log.Printf("... upstream: %s", conn.ClientVersion())
	}
	config.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, chal ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
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
		err = <-upstreamConnected
		if err != nil {
			log.Fatalf("upstream not connected: %v", err)
		}
		return nil, err
	}

	_, channels, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}

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
	for newChannel := range channels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleChannel(upstream, newChannel)
		}()
	}
}

func handleChannel(client *ssh.Client, newChannel ssh.NewChannel) {
	log.Printf("Downstream requested new channel of type %s", newChannel.ChannelType())

	var wg sync.WaitGroup
	defer wg.Wait()

	// Open channel with server.
	upstream, upstreamRequests, err := client.Conn.OpenChannel(newChannel.ChannelType(), nil)
	if err != nil {
		log.Printf("upstream chan create failed: %v", err)
		newChannel.Reject(ssh.UnknownChannelType, "failed")
		return
	}

	downstream, downstreamRequests, err := newChannel.Accept()
	if err != nil {
		log.Fatalf("downstream: could not accept channel: %v", err)
	}

	// Discard all requests from server.
	wg.Add(1)
	go func(in <-chan *ssh.Request) {
		defer wg.Done()
		for req := range in {
			log.Printf("req from upstream of type %s", req.Type)
			ok, err := downstream.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Fatalf("downstream.SendRequest(): %v", err)
			}
			req.Reply(ok, nil)
		}
	}(upstreamRequests)

	// Handle requests from client.
	wg.Add(1)
	go func(in <-chan *ssh.Request) {
		defer wg.Done()
		for req := range in {
			log.Printf("request from downstream of type %s", req.Type)
			ok, err := upstream.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Fatalf("upstream.SendRequest(): %v", err)
			}
			req.Reply(ok, nil)
		}
	}(downstreamRequests)

	// Client -> server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			data := make([]byte, 16)
			n, err := downstream.Read(data)
			if err == io.EOF {
				break
			}
			if n == 0 {
				continue
			}
			if err != nil {
				log.Fatalf("read from downstream : %v", err)
			}
			//log.Printf("data from downstream: %q", data[:n])
			if _, err := upstream.Write(data[:n]); err != nil {
				log.Fatalf("write %d upstream: %v", n, err)
			}
		}
		log.Printf("closing downstream")
	}()

	// server -> client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer upstream.Close()
		defer downstream.Close()
		for {
			data := make([]byte, 16)
			n, err := upstream.Read(data)
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatalf("reading from upstream: %v", err)
			}
			if n == 0 {
				continue
			}
			if _, err := downstream.Write(data[:n]); err != nil {
				log.Fatalf("write %d downstream: %v", n, err)
			}
			//log.Printf(": Data on channel: %q", data[:n])
		}
		log.Printf("closing upstream")
	}()
}
