package handshakekbi

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
	"log"

	"code.google.com/p/go.crypto/ssh"
)

type keyboardInteractive struct {
	user, instruction string
	questions         []string
	echos             []bool
	reply             chan []string
}

// HandshakeKBI implements straight forwarding of KeyboardInteractive auth.
type HandshakeKBI struct{}

// Handshake performs KeyboardInteractive proxy handshake.
func (k *HandshakeKBI) Handshake(downstreamConf *ssh.ServerConfig, target string) <-chan *ssh.Client {
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
