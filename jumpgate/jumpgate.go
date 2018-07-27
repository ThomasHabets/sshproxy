package main

import (
	"context"
	"flag"
	"io/ioutil"
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	password = "XXXXXXX"
)

var (
	addr      = flag.String("addr", ":2022", "Address to listen to.")
	serverKey = flag.String("server_key", "jumpgate-key", "Server key.")
)

func main() {
	flag.Parse()

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Listening to %q: %v", *addr, err)
	}

	log.Infof("Ready on %q", *addr)
	cfg := ssh.ServerConfig{}
	{
		b, err := ioutil.ReadFile(*serverKey)
		if err != nil {
			log.Fatalf("Can't read private key file %q (-server_key): %v", *serverKey, err)
		}
		sk, err := ssh.ParsePrivateKey(b)
		if err != nil {
			log.Fatalf("Can't parse private key file %q (-server_key): %v", *serverKey, err)
		}
		cfg.AddHostKey(sk)
	}
	ctx := context.Background()
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Errorf("accept(): %v", err)
		}
		t := sconn{
			conn: conn,
			cfg:  cfg,
		}
		if err := t.handleConnection(ctx); err != nil {
			log.Errorf("Handling connection: %v", err)
		}
	}

}
