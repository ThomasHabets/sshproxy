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

	var client *ssh.Client
	config := makeConfig()
	config.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		// Should use constant-time compare (or better, salt+hash) in
		// a production setting.
		clientConf := &ssh.ClientConfig{
			User: c.User(),
			Auth: []ssh.AuthMethod{
				ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
					log.Printf("Interactive: %s, %s, %v, %v", user, instruction, questions, echos)
					var ans []string
					for _ = range questions {
						ans = append(ans, string(pass))
					}
					return ans, nil
				}),
				ssh.Password(string(pass)),
			},
		}
		var err error
		client, err = ssh.Dial("tcp", *target, clientConf)
		if err != nil {
			log.Fatalf("client dial: %v", err)
		}
		return nil, nil
	}

	_, channels, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range reqs {
			log.Printf("Client->server req: %+v", req)
			ok, payload, err := client.Conn.SendRequest(req.Type, req.WantReply, req.Payload)
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
			handleChannel(client, newChannel)
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
