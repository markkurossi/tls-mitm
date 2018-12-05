//
// main.go
//
// Copyright (c) 2018 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"time"
)

const (
	keyBits = 4096
)

var config *tls.Config

func main() {
	keygen := flag.String("keygen", "", "Generate a keypair to the named file.")
	san := flag.String("san", "", "Subject alternative name for key.")
	keyFile := flag.String("key", "mitm", "TLS key and certificate.")
	listen := flag.String("listen", "", "The address to listen to.")
	proxy := flag.String("proxy", "", "The address to proxy connections.")
	flag.Parse()

	if len(*keygen) > 0 {
		err := makeKey(*keygen, *san)
		if err != nil {
			log.Fatalf("Failed to create keypair: %s\n", err)
		}
		return
	}
	if len(*listen) == 0 {
		fmt.Printf("No listen address specified\n")
		return
	}
	if len(*proxy) == 0 {
		fmt.Printf("No proxy address specified\n")
		return
	}

	key, cert, certBytes, err := loadKey(*keyFile)
	if err != nil {
		log.Fatalf("Failed to load key '%s': %s\n", *keyFile, err)
	}

	config = &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{
					certBytes,
				},
				PrivateKey: key,
				Leaf:       cert,
			},
		},
	}

	listener, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		log.Fatalf("TLS listen failed: %s\n", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept failed: %s\n", err)
			continue
		}
		fmt.Printf("New connection from %s\n", conn.RemoteAddr())
		go handleConnection(conn, *proxy)
	}
}

func handleConnection(conn net.Conn, proxy string) {
	defer conn.Close()

	server, err := tls.Dial("tcp", proxy, config)
	if err != nil {
		fmt.Printf("Dial %s failed: %s\n", proxy, err)
		return
	}
	defer server.Close()

	go copyStream(server, conn, fmt.Sprintf("%s->%s", proxy, conn.RemoteAddr()))
	copyStream(conn, server, fmt.Sprintf("%s->%s", conn.RemoteAddr(), proxy))
}

func copyStream(from, to net.Conn, name string) {
	var buf [4096]byte
	for {
		n, err := from.Read(buf[:])
		if err != nil {
			return
		}
		fmt.Printf("%s:\n%s", name, hex.Dump(buf[:n]))
		n, err = to.Write(buf[:n])
		if err != nil {
			return
		}
	}
}

func loadKey(path string) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	keyBytes, err := ioutil.ReadFile(fmt.Sprintf("%s.prv", path))
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	certBytes, err := ioutil.ReadFile(fmt.Sprintf("%s.crt", path))
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, cert, certBytes, nil
}

func makeKey(path, san string) error {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	err = ioutil.WriteFile(fmt.Sprintf("%s.prv", path), keyBytes, 0600)
	if err != nil {
		return err
	}

	subject := pkix.Name{
		Organization:       []string{"R&D"},
		OrganizationalUnit: []string{"CTO Office"},
		CommonName:         "markkurossi.com",
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	now := time.Now()

	var DNSNames []string
	var IPAddresses []net.IP

	if len(san) > 0 {
		ip := net.ParseIP(san)
		if ip != nil {
			IPAddresses = append(IPAddresses, ip)
		} else {
			DNSNames = append(DNSNames, san)
		}
	}

	cert := &x509.Certificate{
		SerialNumber: serial,
		Issuer:       subject,
		Subject:      subject,
		NotBefore:    now.Add(time.Hour * 24 * -10),
		NotAfter:     now.Add(time.Hour * 24 * 365 * 5),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:    DNSNames,
		IPAddresses: IPAddresses,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert,
		&key.PublicKey, key)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fmt.Sprintf("%s.crt", path), certBytes, 0644)
}
