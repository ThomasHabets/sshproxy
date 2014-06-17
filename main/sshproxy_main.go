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
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"

	"code.google.com/p/go.crypto/ssh"
	"github.com/ThomasHabets/sshproxy"
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

	privateKey ssh.Signer

	user string
)

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

	var auther sshproxy.Handshake
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
	p := sshproxy.SSHProxy{
		Target:        *target,
		Conn:          conn,
		Auther:        auther,
		PrivateKey:    privateKey,
		LogDir:        *logdir,
		LogUpstream:   *logUpstream,
		LogDownstream: *logDownstream,
	}
	log.Printf("sshproxy: running...")
	p.Run()
}
