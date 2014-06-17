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
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

var (
	proxy  = flag.String("proxy", "", "SSHProxy host:port.")
	target = flag.String("target", "", "Target to connect to.")
)

func mandatoryFlag(name string) {
	f := flag.Lookup(name)
	if f.Value.String() == f.DefValue {
		log.Fatalf("-%s is mandatory", name)
	}
}

func main() {
	flag.Parse()
	mandatoryFlag("proxy")
	mandatoryFlag("target")

	conf := tls.Config{
		// TODO: Secure settings.
		InsecureSkipVerify: true,
	}

	c, err := tls.Dial("tcp", *proxy, &conf)
	if err != nil {
		log.Fatalf("tls Dial: %v", err)
	}
	if _, err := c.Write([]byte(fmt.Sprintf("%s\n", *target))); err != nil {
		log.Fatalf("Write: %v", err)
	}
	go io.Copy(os.Stdout, c)
	io.Copy(c, os.Stdin)
}
