package main

import (
	"context"
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type sconn struct {
	conn net.Conn
	cfg  ssh.ServerConfig

	// Filled in after handshake.
	password string
	target   string
	meta     ssh.ConnMetadata
	key      ssh.PublicKey
	user     string
	client   ssh.Conn
}

func user2Target(in string) (string, string, error) {
	t := strings.SplitN(in, "%", 2)
	if len(t) < 2 {
		return "", "", fmt.Errorf("username has wrong format: %q", in)
	}
	return t[0], t[1], nil
}

func (sc *sconn) pubkeyCallback(inmeta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	meta := inmeta.(*decodedConnMetadata)
	fprint := ssh.FingerprintSHA256(key)
	log.Infof("Pubkey attempt by %s to %s from %s: %v", meta.User(), meta.target, meta.RemoteAddr().String(), fprint)

	var n int
	if err := db.QueryRowContext(
		context.TODO(),
		`SELECT 1 FROM acl WHERE pubkey=$1 AND target=$2`,
		fprint,
		meta.target).Scan(&n); err != nil {
		return nil, fmt.Errorf("acl rejects key %q from connecting to %q", fprint, meta.target)
	}

	sc.meta = meta
	sc.key = key
	sc.user = meta.User()
	sc.target = meta.target
	if err := db.QueryRowContext(
		context.TODO(),
		`SELECT password FROM passwords WHERE target=$1`,
		meta.target).Scan(&sc.password); err != nil {
		return nil, fmt.Errorf("getting password for %q: %v", meta.target, err)
	}
	log.Infof("... Accepted pubkey %q for user %q target %q", fprint, meta.User(), meta.target)
	return nil, nil
}

func (sc *sconn) keyboardInteractive(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	log.Debugf("... keyboardinteractive: %q %q %q %v", user, instruction, questions, echos)
	var ans []string
	for _ = range questions {
		ans = append(ans, sc.password)
	}
	return ans, nil
}

func (sc *sconn) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	// TODO: check host cert, if present.
	log.Debugf("... Host key %q: %v", hostname, ssh.FingerprintSHA256(key))
	var k string
	if err := db.QueryRowContext(
		context.TODO(),
		`SELECT pubkey FROM host_keys WHERE target=$1`,
		sc.target).Scan(&k); err != nil {
		return fmt.Errorf("getting host key %q: %v", sc.target, err)
	}
	if got, want := ssh.FingerprintSHA256(key), k; got != want {
		return fmt.Errorf("wrong host key. got %q, want %q", got, want)
	}
	return nil
}

type decodedConnMetadata struct {
	user   string
	target string
	meta   ssh.ConnMetadata
}

func (m *decodedConnMetadata) User() string {
	return m.user
}

// SessionID returns the session hash, also denoted by H.
func (m *decodedConnMetadata) SessionID() []byte {
	return m.meta.SessionID()
}

func (m *decodedConnMetadata) ClientVersion() []byte {
	return m.meta.ClientVersion()
}

func (m *decodedConnMetadata) ServerVersion() []byte {
	return m.meta.ServerVersion()
}

// RemoteAddr returns the remote address for this connection.
func (m *decodedConnMetadata) RemoteAddr() net.Addr {
	return m.meta.RemoteAddr()
}

// LocalAddr returns the local address for this connection.
func (m *decodedConnMetadata) LocalAddr() net.Addr {
	return m.meta.LocalAddr()
}

func (sc *sconn) certCallback(meta ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) {
	user, target, err := user2Target(meta.User())
	if err != nil {
		// TODO: show error message to user
		log.Errorf("bad username %q", meta.User())
		return nil, err
	}

	checker := ssh.CertChecker{
		UserKeyFallback: sc.pubkeyCallback,
		// IsRevoked: TODO,
		IsUserAuthority: func(ca ssh.PublicKey) bool {
			cafpr := ssh.FingerprintSHA256(ca)
			var n int
			if err := db.QueryRowContext(
				context.TODO(),
				`SELECT 1 FROM cas WHERE pubkey=$1 AND target=$2`,
				cafpr,
				target).Scan(&n); err != nil {
				log.Errorf("Unknown CA %q for %q provided", cafpr, target)
				return false
			}
			sc.meta = meta
			sc.key = pub
			sc.user = user
			sc.target = target
			if err := db.QueryRowContext(
				context.TODO(),
				`SELECT password FROM passwords WHERE target=$1`,
				target).Scan(&sc.password); err != nil {
				log.Errorf("getting password for %q: %v", target, err)
				// TODO: show error to user.
				return false
			}
			log.Infof("... Accepted certificate %q using CA %q", ssh.FingerprintSHA256(pub), cafpr)
			return true
		},
	}
	t := decodedConnMetadata{
		user:   user,
		target: target,
		meta:   meta,
	}
	return checker.Authenticate(&t, pub)
}

// TODO: time out with ctx.
func (sc *sconn) handleConnection(ctx context.Context) error {
	sc.cfg.PublicKeyCallback = sc.certCallback
	conn, chch, requestch, err := ssh.NewServerConn(sc.conn, &sc.cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Debugf("... Server connected!")

	log.Debugf("... dialing %q as user %q password", sc.target, sc.user)
	sc.client, err = ssh.Dial("tcp", sc.target, &ssh.ClientConfig{
		User: sc.user,
		// Timeout: TODO,
		BannerCallback:  ssh.BannerDisplayStderr(),
		HostKeyCallback: sc.hostKeyCallback,
		Auth: []ssh.AuthMethod{
			ssh.Password(sc.password),
			ssh.KeyboardInteractive(sc.keyboardInteractive),
		},
	})
	if err != nil {
		return err
	}

	var chchDone, rchDone bool
	for !chchDone && !rchDone {
		select {
		case nch := <-chch:
			if nch == nil {
				log.Debugf("... No more channels")
				chch = nil
				chchDone = true
				continue
			}
			log.Debugf("... New channel type %q extradata %v", nch.ChannelType(), nch.ExtraData())
			ch, req, err := nch.Accept()
			if err != nil {
				log.Errorf("Failed to accept channel: %v", err)
			}
			clientChannel, clientReq, err := sc.client.OpenChannel(nch.ChannelType(), nch.ExtraData())
			c := &channel{
				channel:       ch,
				clientChannel: clientChannel,
				clientReq:     clientReq,
				req:           req,
			}
			go func() {
				if err := c.run(ctx); err != nil {
					log.Errorf("Channel failed: %v", err)
				}
			}()
		case req := <-requestch:
			if req == nil {
				log.Debugf("... No more requests")
				requestch = nil
				rchDone = true
				continue
			}
			log.Debugf("... New connection req: %v", req)
		}
	}
	log.Infof("... Server connection closing")
	return nil
}
