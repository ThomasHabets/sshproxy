package main

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
	"strings"
	"sync"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"code.google.com/p/go.crypto/ssh"
)

var (
	target        = flag.String("target", "", "SSH server to connect to.")
	connFD        = flag.String("conn_fd", "", "File descriptor to work with.")
	keyfile       = flag.String("keyfile", "", "SSH server key file.")
	clientKeyfile = flag.String("client_keyfile", "", "SSH client key file.")
	logdir        = flag.String("logdir", ".", "Directory in which to create logs.")
	logUpstream   = flag.Bool("log_upstream", false, "Log data from upstream (server).")
	logDownstream = flag.Bool("log_downstream", false, "Log data from downstream (client).")

	privateKey       ssh.Signer
	clientPrivateKey ssh.Signer

	user string
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

	if *connFD == "" {
		log.Fatalf("-connFD is required.")
	}

	if *target == "" {
		log.Fatalf("-target is required.")
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
		user = upstreamConf.User
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
	UPSTREAM   source = "upstream"
	DOWNSTREAM source = "downstream"
)

func reverseDirection(s source) source {
	if s == UPSTREAM {
		return DOWNSTREAM
	}
	return UPSTREAM
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

func dataForward(channelId string, from source, wg *sync.WaitGroup, src, dst ssh.Channel) {
	defer wg.Done()
	defer dst.Close()
	ch := reader(from, src)
	if (from == UPSTREAM && *logUpstream) || (from == DOWNSTREAM && *logDownstream) {
		ch = dataLogger(fmt.Sprintf("%s.%s", channelId, from), ch)
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
	channelId := uuid.New()
	f, err := os.Create(path.Join(*logdir, fmt.Sprintf("%s.meta", channelId)))
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
	go requestForward(UPSTREAM, &wg, upstreamRequests, downstream)
	go requestForward(DOWNSTREAM, &wg, downstreamRequests, upstream)

	// downstream -> upstream.
	wg.Add(2)
	go dataForward(channelId, DOWNSTREAM, &wg, downstream, upstream)
	go dataForward(channelId, UPSTREAM, &wg, upstream, downstream)
	okWait <- true
	<-okReturn

	n := time.Now()
	if _, err := f.WriteString(fmt.Sprintf("EndTime: %s\nDuration: %s\n", n, n.Sub(startTime))); err != nil {
		log.Fatal(err)
	}
	return nil
}
