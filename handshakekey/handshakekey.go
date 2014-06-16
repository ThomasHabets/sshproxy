package handshakekey

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
 */
import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"code.google.com/p/go.crypto/ssh"
)

// HandshakeKey implements SSH key auth to proxy, and then uses a differnt local key against the target.
type HandshakeKey struct {
	AuthorizedKeys   string
	ClientPrivateKey ssh.Signer
}

// Handshake performs the handshake.
func (h *HandshakeKey) Handshake(downstreamConf *ssh.ServerConfig, target string) <-chan *ssh.Client {
	var user string
	upstreamConnected := make(chan error, 10)
	userChan := make(chan string, 10)
	downstreamConf.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		thisKey := strings.SplitN(strings.Trim(string(ssh.MarshalAuthorizedKey(key)), "\n"), " ", 3)
		log.Printf("Public key callback: %q", thisKey)
		// TODO: certs.
		d, err := ioutil.ReadFile(h.AuthorizedKeys)
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
