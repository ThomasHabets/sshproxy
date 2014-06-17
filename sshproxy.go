package sshproxy

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
 */
import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"code.google.com/p/go.crypto/ssh"
)

// SSHProxy proxies a connection to a target.
type SSHProxy struct {
	// Conn is the connection to downstream client.
	Conn net.Conn

	// Target is the name of the upstream server.
	Target string

	// Auther is the handshake implementation.
	Auther Handshake

	// PrivateKey is the private key of the SSHProxy server.
	PrivateKey ssh.Signer

	// Logging settings.
	LogUpstream, LogDownstream bool
	LogDir                     string

	user string
}

// Handshake is the auth type proxied.
type Handshake interface {
	// Handshake handshakes downstream client, and returns a channel where the client object is then sent.
	// Because this function has to be run *concurrently* with ssh.NewServerConn(), it's never right to
	// call this synchronously, and the API makes that clear.
	Handshake(conf *ssh.ServerConfig, target string) <-chan *ssh.Client
}

func (p *SSHProxy) makeConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{}
	config.AuthLogCallback = func(conn ssh.ConnMetadata, method string, err error) {
		log.Printf("(%s) Attempt method %s: %v", conn.RemoteAddr(), method, err)
		log.Printf("... user: %s", conn.User())
		log.Printf("... session: %v", conn.SessionID())
		log.Printf("... clientVersion: %s", conn.ClientVersion())
		log.Printf("... serverVersion: %s", conn.ServerVersion())
		log.Printf("... localAddr: %v", conn.LocalAddr())
		p.user = conn.User()
	}
	config.AddHostKey(p.PrivateKey)
	return config
}

func (p *SSHProxy) handshake(wg *sync.WaitGroup) (<-chan ssh.NewChannel, *ssh.Client, error) {
	downstreamConf := p.makeConfig()
	upstreamChannel := p.Auther.Handshake(downstreamConf, p.Target)

	var err error

	_, channels, reqs, err := ssh.NewServerConn(p.Conn, downstreamConf)
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

// Run handshakes and handles the connection.
func (p *SSHProxy) Run() {
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		log.Printf("Connection closed.")
		p.Conn.Close()
	}()

	channels, upstream, err := p.handshake(&wg)
	if err != nil {
		log.Fatal(err)
	}
	for newChannel := range channels {
		wg.Add(1)
		go func(newChannel ssh.NewChannel) {
			defer wg.Done()
			if err := p.handleChannel(p.Conn, upstream, newChannel); err != nil {
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

func (p *SSHProxy) dataForward(channelID string, from source, wg *sync.WaitGroup, src, dst ssh.Channel) {
	defer wg.Done()
	defer dst.Close()
	ch := reader(from, src)
	if (from == sourceUpstream && p.LogUpstream) || (from == sourceDownstream && p.LogDownstream) {
		ch = p.dataLogger(fmt.Sprintf("%s.%s", channelID, from), ch)
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

func (p *SSHProxy) dataLogger(fn string, ch <-chan []byte) <-chan []byte {
	newCh := make(chan []byte)
	f, err := os.Create(path.Join(p.LogDir, fn))
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
func (p *SSHProxy) handleChannel(conn net.Conn, upstreamClient *ssh.Client, newChannel ssh.NewChannel) error {
	channelID := uuid.New()
	startTime := time.Now()
	f, err := os.Create(path.Join(p.LogDir, fmt.Sprintf("%s.meta", channelID)))
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		n := time.Now()
		if _, err := f.WriteString(fmt.Sprintf("EndTime: %s\nDuration: %s\n", n, n.Sub(startTime))); err != nil {
			log.Fatal(err)
		}
		f.Close()
	}()
	if _, err := f.WriteString(fmt.Sprintf(`User: %s
Target: %s
StartTime: %s
Client: %s
`, p.user, p.Target, startTime, conn.RemoteAddr())); err != nil {
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
	go p.dataForward(channelID, sourceDownstream, &wg, downstream, upstream)
	go p.dataForward(channelID, sourceUpstream, &wg, upstream, downstream)
	okWait <- true
	<-okReturn
	return nil
}
