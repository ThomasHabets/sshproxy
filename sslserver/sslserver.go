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
 *
 **/
import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
)

var (
	keyfile  = flag.String("key", "", "SSL server key file.")
	certfile = flag.String("cert", "", "SSL server CRT file.")
	listen   = flag.String("listen", "", "Listen address.")
)

func mandatoryFlag(name string) {
	f := flag.Lookup(name)
	if f.Value.String() == f.DefValue {
		log.Fatalf("-%s is mandatory", name)
	}
}

func readLine(r io.Reader) (string, error) {
	var b bytes.Buffer
	for {
		ch := make([]byte, 1)
		if n, err := r.Read(ch); n != 1 || err != nil {
			return "", nil
		}
		if ch[0] == '\n' {
			break
		}
		if n, err := b.Write(ch); n != 1 || err != nil {
			return "", nil
		}
		if b.Len() > 256 {
			return "", fmt.Errorf("Target line too long.")
		}
	}
	return b.String(), nil
}

func handle(c net.Conn) {
	defer c.Close()
	l, err := readLine(c)
	if err != nil {
		log.Print(err)
		return
	}
	log.Printf("Connecting to %s...", l)
	args := flag.Args()
	args = append(args, "-conn_fd=3")
	args = append(args, "-target="+l)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
	}
	mine := os.NewFile(uintptr(fds[0]), "connection")
	theirs := os.NewFile(uintptr(fds[1]), "connection")
	cmd.ExtraFiles = []*os.File{theirs}
	if err := cmd.Start(); err != nil {
		log.Printf("cmd.Start(): %v", err)
		return
	}
	theirs.Close()
	go io.Copy(c, mine)
	_, err = io.Copy(mine, c)
	if err != nil {
		log.Printf("Copying from network to socketpair(): %v", err)
	}
	mine.Close()
	if err := cmd.Wait(); err != nil {
		log.Printf("cmd.Wait(): %v", err)
	}
	log.Printf("Done.")
}

func main() {
	flag.Parse()
	mandatoryFlag("key")
	mandatoryFlag("cert")
	mandatoryFlag("listen")

	cert, err := tls.LoadX509KeyPair(*certfile, *keyfile)
	if err != nil {
		log.Fatalf("server: loadkeys(%s,  %s): %s", *certfile, *keyfile, err)
	}
	conf := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	l, err := tls.Listen("tcp", *listen, &conf)
	if err != nil {
		log.Fatalf("tls Listen: %v", err)
	}
	log.Printf("Ready...")
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept(): %v", err)
			continue
		}
		go handle(c)
	}
}
