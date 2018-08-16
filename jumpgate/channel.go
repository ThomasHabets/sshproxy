package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/semaphore"
)

const (
	semAll int64 = 100
)

type channel struct {
	channel       ssh.Channel
	clientChannel ssh.Channel
	req           <-chan *ssh.Request
	clientReq     <-chan *ssh.Request
}

// TODO: time out with ctx.
func (c *channel) run(ctx context.Context) error {
	defer c.channel.Close()
	sem := semaphore.NewWeighted(semAll)

	var mu sync.Mutex
	var errs []error

	sem.Acquire(ctx, 1)
	go func() {
		defer sem.Release(1)
		if _, err := io.Copy(c.channel, c.clientChannel); err != nil {
			mu.Lock()
			defer mu.Unlock()
			errs = append(errs, fmt.Errorf("client->server streaming: %v", err))
			return
		}
		log.Debugf("... Channel client->server done")
		if err := c.channel.Close(); err != nil {
			mu.Lock()
			defer mu.Unlock()
			errs = append(errs, fmt.Errorf("closing server channel: %v", err))
			return
		}
	}()

	sem.Acquire(ctx, 1)
	go func() {
		defer sem.Release(1)
		if _, err := io.Copy(c.clientChannel, c.channel); err != nil {
			mu.Lock()
			defer mu.Unlock()
			errs = append(errs, fmt.Errorf("server->client streaming: %v", err))
			return
		}
		log.Debugf("... Channel server->client done")
	}()

	var cDone, sDone bool
	for !cDone && !sDone {
		select {
		case r := <-c.req:
			if r == nil {
				sDone = true
				c.req = nil
				continue
			}
			log.Debugf("Server request: %v", r)
			b, err := c.clientChannel.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("client SendRequest failed: %v", err))
				mu.Unlock()
			} else {
				if r.WantReply {
					if err := r.Reply(b, r.Payload); err != nil {
						mu.Lock()
						errs = append(errs, fmt.Errorf("server Reply failed: %v", err))
						mu.Unlock()
					}
				}
			}
		case r := <-c.clientReq:
			if r == nil {
				cDone = true
				c.clientReq = nil
				continue
			}
			log.Debugf("Client request: %v", r)
			b, err := c.channel.SendRequest(r.Type, r.WantReply, r.Payload)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("server SendRequest failed: %v", err))
				mu.Unlock()
			} else {
				if r.WantReply {
					if err := r.Reply(b, r.Payload); err != nil {
						mu.Lock()
						errs = append(errs, fmt.Errorf("client Reply failed: %v", err))
						mu.Unlock()
					}
				}
			}
		}
	}
	log.Debugf("... Channel closing")
	sem.Acquire(ctx, semAll)
	var ss []string
	for _, e := range errs {
		ss = append(ss, e.Error())
	}
	if len(ss) > 0 {
		return errors.New(strings.Join(ss, ";"))
	}
	return nil
}
