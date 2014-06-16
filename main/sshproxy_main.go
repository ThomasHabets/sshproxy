package main

/*
 *  Copyright (C) 2014 Thomas Habets <thomas@habets.se>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
   ssh-keygen -N "" -f id_rsa
   ./listener -listen 127.0.0.1:2022 \
       ./sshproxy \
       -conn_fd '{}' \
       -keyfile id_rsa \
       -target 127.0.0.1:22 \
       -logdir sshlogdir \
       -log_upstream \
       -log_downstream \
       -auth=kbi
 *
 **/
import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"code.google.com/p/go.crypto/ssh"
	"github.com/ThomasHabets/sshproxy/handshakekbi"
	"github.com/ThomasHabets/sshproxy/handshakekey"
)

var (
	target        = flag.String("target", "", "SSH server to connect to.")
	connFD        = flag.String("conn_fd", "", "File descriptor to work with.")
	keyfile       = flag.String("keyfile", "", "SSH server key file.")
	logdir        = flag.String("logdir", "", "Directory in which to create logs.")
	logUpstream   = flag.Bool("log_upstream", false, "Log data from upstream (server).")
	logDownstream = flag.Bool("log_downstream", false, "Log data from downstream (client).")

	auth = flag.String("auth", "", "Auth mode (key, kbi).")

	// For -auth=key
	clientKeyfile  = flag.String("client_keyfile", "", "auth=key: SSH client key file.")
	authorizedKeys = flag.String("authorized_keys", "", "auth=key: Authorized keys for clients.")

	auther     Handshake
	privateKey ssh.Signer

	user string
)

// Handshake is the auth type proxied.
type Handshake interface {
	Handshake(*ssh.ServerConfig, string) <-chan *ssh.Client
}

func makeConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{}
	config.AuthLogCallback = func(conn ssh.ConnMetadata, method string, err error) {
		log.Printf("(%s) Attempt method %s: %v", conn.RemoteAddr(), method, err)
		log.Printf("... user: %s", conn.User())
		log.Printf("... session: %v", conn.SessionID())
		log.Printf("... clientVersion: %s", conn.ClientVersion())
		log.Printf("... serverVersion: %s", conn.ServerVersion())
		log.Printf("... localAddr: %v", conn.LocalAddr())
		user = conn.User()
	}
	config.AddHostKey(privateKey)
	return config
}

func mandatoryFlag(name string) {
	f := flag.Lookup(name)
	if f.Value.String() == f.DefValue {
		log.Fatalf("-%s is mandatory", name)
	}
}

func main() {
	flag.Parse()
	mandatoryFlag("conn_fd")
	mandatoryFlag("target")
	mandatoryFlag("keyfile")
	mandatoryFlag("logdir")

	if *auth == "key" {
		mandatoryFlag("authorized_keys")
		mandatoryFlag("client_keyfile")
		// Load SSH client key.
		privBytes, err := ioutil.ReadFile(*clientKeyfile)
		if err != nil {
			log.Fatalf("Can't read client private key file %q (-client_keyfile).", *clientKeyfile)
		}
		priv, err := ssh.ParsePrivateKey(privBytes)
		if err != nil {
			log.Fatalf("Parse error client reading private key %q: %v", *clientKeyfile, err)
		}

		auther = &handshakekey.HandshakeKey{
			AuthorizedKeys:   *authorizedKeys,
			ClientPrivateKey: priv,
		}
	} else if *auth == "kbi" {
		auther = &handshakekbi.HandshakeKBI{}
	} else {
		fmt.Fprintf(os.Stderr, "Unknown auth mode %q.", *auth)
		os.Exit(1)
	}

	// Load SSH server key.
	privateBytes, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		log.Fatalf("Can't read private key file %q (-keyfile).", *keyfile)
	}
	privateKey, err = ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatalf("Parse error reading private key %q: %v", *keyfile, err)
	}

	connFDInt, err := strconv.Atoi(*connFD)
	if err != nil {
		log.Fatalf("-conn_fd %q is not int: %v", *connFD, err)
	}
	f := os.NewFile(uintptr(connFDInt), "connection")
	conn, err := net.FileConn(f)
	if err != nil {
		log.Fatalf("Broken FD passed in: %v", err)
	}
	f.Close()
	handleConnection(conn)
}

func handshake(wg *sync.WaitGroup, conn net.Conn) (<-chan ssh.NewChannel, *ssh.Client, error) {
	downstreamConf := makeConfig()
	upstreamChannel := auther.Handshake(downstreamConf, *target)

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
		go func(newChannel ssh.NewChannel) {
			defer wg.Done()
			if err := handleChannel(conn, upstream, newChannel); err != nil {
				log.Printf("handleChannel: %v", err)
			}
		}(newChannel)
	}
}

type source string

const (
	sourceUpstream   source = "upstream"
	sourceDownstream source = "downstream"
)

func reverseDirection(s source) source {
	if s == sourceUpstream {
		return sourceDownstream
	}
	return sourceUpstream
}

func reader(from source, src ssh.Channel) <-chan []byte {
	ch := make(chan []byte)
	go func() {
		defer close(ch)
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
			ch <- data[:n]
		}
	}()
	return ch
}

func writer(from source, dst ssh.Channel, ch <-chan []byte) {
	for data := range ch {
		n := len(data)
		if nw, err := dst.Write(data[:n]); err != nil {
			log.Fatalf("write(%d) of data from %s: %v", n, from, err)
		} else if nw != n {
			log.Fatalf("short write %d < %d from %s", nw, n, from)
		}
	}
}

func dataForward(channelID string, from source, wg *sync.WaitGroup, src, dst ssh.Channel) {
	defer wg.Done()
	defer dst.Close()
	ch := reader(from, src)
	if (from == sourceUpstream && *logUpstream) || (from == sourceDownstream && *logDownstream) {
		ch = dataLogger(fmt.Sprintf("%s.%s", channelID, from), ch)
	}
	writer(from, dst, ch)
	log.Printf("closing %s", reverseDirection(from))
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

func dataLogger(fn string, ch <-chan []byte) <-chan []byte {
	newCh := make(chan []byte)
	f, err := os.Create(path.Join(*logdir, fn))
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		defer close(newCh)
		defer f.Close()
		for data := range ch {
			newCh <- data
			f.Write(data)
		}
	}()
	return newCh
}

// handleChannel forwards data and requests between upstream and downstream.
// It blocks until until channel is closed.
func handleChannel(conn net.Conn, upstreamClient *ssh.Client, newChannel ssh.NewChannel) error {
	channelID := uuid.New()
	f, err := os.Create(path.Join(*logdir, fmt.Sprintf("%s.meta", channelID)))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	startTime := time.Now()
	if _, err := f.WriteString(fmt.Sprintf("User: %s\nStartTime: %s\nRemote addr: %s\n", user, startTime, conn.RemoteAddr())); err != nil {
		log.Fatal(err)
	}

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
	go requestForward(sourceUpstream, &wg, upstreamRequests, downstream)
	go requestForward(sourceDownstream, &wg, downstreamRequests, upstream)

	// downstream -> upstream.
	wg.Add(2)
	go dataForward(channelID, sourceDownstream, &wg, downstream, upstream)
	go dataForward(channelID, sourceUpstream, &wg, upstream, downstream)
	okWait <- true
	<-okReturn

	n := time.Now()
	if _, err := f.WriteString(fmt.Sprintf("EndTime: %s\nDuration: %s\n", n, n.Sub(startTime))); err != nil {
		log.Fatal(err)
	}
	return nil
}
