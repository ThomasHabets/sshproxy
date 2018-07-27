package main

import (
	"context"
	"database/sql"
	"flag"
	"io/ioutil"
	"net"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var (
	addr      = flag.String("addr", ":2022", "Address to listen to.")
	serverKey = flag.String("server_key", "jumpgate-key", "Server key.")
	dbType    = flag.String("db_type", "sqlite3", "Database type.")
	dbConn    = flag.String("db", "", "Database connect string.")

	db *sql.DB
)

func main() {
	flag.Parse()

	if flag.NArg() > 0 {
		log.Fatalf("Trailing cmdline args: %q", flag.Args())
	}

	var err error
	db, err = sql.Open(*dbType, *dbConn)
	if err != nil {
		log.Fatalf("Failed to connect to DB %q %q: %v", *dbType, *dbConn)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping DB %q %q: %v", *dbType, *dbConn)
	}
	defer db.Close()

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
		go func() {
			if err := t.handleConnection(ctx); err != nil {
				log.Errorf("Handling connection: %v", err)
			}
		}()
	}

}
