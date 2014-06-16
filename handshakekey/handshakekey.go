package handshakekey

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"code.google.com/p/go.crypto/ssh"
)

type HandshakeKey struct {
	ClientPrivateKey ssh.Signer
}

func (h *HandshakeKey) Handshake(downstreamConf *ssh.ServerConfig, target string) <-chan *ssh.Client {
	var user string
	upstreamConnected := make(chan error, 10)
	userChan := make(chan string, 10)
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
			ssh.PublicKeys(h.ClientPrivateKey),
		},
	}
	upstreamChannel := make(chan *ssh.Client)
	go func() {
		upstreamConf.User = <-userChan
		user = upstreamConf.User
		defer close(upstreamChannel)
		upstream, err := ssh.Dial("tcp", target, upstreamConf)
		if err != nil {
			upstreamConnected <- err
			log.Fatalf("upstream dial: %v", err)
		}
		log.Printf("upstream is connected")
		upstreamChannel <- upstream
	}()
	return upstreamChannel
}
