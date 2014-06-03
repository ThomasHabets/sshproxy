// ./listener -listen 0.0.0.0:2022 ./next-program -conn_fd '{}'
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
)

var (
	listen = flag.String("listen", "", "Listen address.")
)

func handleConnection(conn *net.TCPConn) {
	defer conn.Close()
	args := flag.Args()[1:]
	for n := range args {
		if args[n] == "{}" {
			args[n] = "3"
		}
	}
	cmd := exec.Command(flag.Args()[0], args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	func() {
		if f, err := conn.File(); err != nil {
			log.Printf("Command start failed: %v", err)
		} else {
			defer conn.Close()
			defer f.Close()
			cmd.ExtraFiles = []*os.File{f}
		}
		if err := cmd.Start(); err != nil {
			log.Printf("Command start failed: %v", err)
		}
	}()
	if err := cmd.Wait(); err != nil {
		log.Printf("Command wait failed: %v", err)
	}
}

func main() {
	flag.Parse()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("Failed to listen to %q: %v", *listen, err)
	}
	log.Printf("Ready")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept(): %v", err)
			continue
		}
		go handleConnection(conn.(*net.TCPConn))
	}
}
