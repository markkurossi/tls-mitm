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
	keygen := flag.Bool("keygen", false, "Generate CA and TLS keys.")
	certgen := flag.String("certgen", "",
		"Generate TLS certificates with argument subject alternative name.")
	listen := flag.String("listen", "", "The address to listen to.")
	proxy := flag.String("proxy", "", "The address to proxy connections.")
	flag.Parse()

	if *keygen {
		err := makeKeys()
		if err != nil {
			log.Fatalf("Failed to create keypair: %s\n", err)
		}
		return
	}
	if len(*certgen) > 0 {
		err := makeCert(*certgen)
		if err != nil {
			log.Fatalf("Failed to create certificate: %s\n", err)
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

	key, err := loadKey("mitm")
	if err != nil {
		log.Fatalf("Failed to load key: %s\n", err)
	}
	cert, certBytes, err := loadCert("mitm")
	if err != nil {
		log.Fatalf("Failed to load certificate: %s\n", err)
	}
	caCert, _, err := loadCert("mitm-ca")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %s\n", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

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
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			fmt.Printf("chains: %v\n", verifiedChains)
			return nil
		},
		InsecureSkipVerify: true,
		RootCAs:            caCertPool,
		Renegotiation:      tls.RenegotiateFreelyAsClient,
	}
	config.BuildNameToCertificate()

	listener, err := tls.Listen("tcp", *listen, config)
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

	go copyStream(conn, server, fmt.Sprintf("Client(%s)->Server(%s)",
		conn.RemoteAddr(), proxy))
	copyStream(server, conn, fmt.Sprintf("Server(%s)->Client(%s)",
		proxy, conn.RemoteAddr()))
}

func copyStream(from, to net.Conn, name string) {
	var buf [4096]byte
	for {
		n, err := from.Read(buf[:])
		if err != nil {
			fmt.Printf("%s: read failed: %s\n", name, err)
			return
		}
		fmt.Printf("%s:\n%s", name, hex.Dump(buf[:n]))
		n, err = to.Write(buf[:n])
		if err != nil {
			fmt.Printf("%s: write failed: %s\n", name, err)
			return
		}
	}
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(fmt.Sprintf("%s.prv", path))
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(keyBytes)
}

func loadCert(path string) (*x509.Certificate, []byte, error) {
	certBytes, err := ioutil.ReadFile(fmt.Sprintf("%s.crt", path))
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, certBytes, nil
}

func makeKeys() error {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	err = ioutil.WriteFile("mitm-ca.prv", keyBytes, 0600)
	if err != nil {
		return err
	}

	subject := pkix.Name{
		Organization:       []string{"Man-in-the-Middle"},
		OrganizationalUnit: []string{"CA"},
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	now := time.Now()

	cert := &x509.Certificate{
		SerialNumber: serial,
		Issuer:       subject,
		Subject:      subject,
		NotBefore:    now.Add(time.Hour * 24 * -10),
		NotAfter:     now.Add(time.Hour * 24 * 365 * 5),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert,
		&key.PublicKey, key)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile("mitm-ca.crt", certBytes, 0644)
	if err != nil {
		return err
	}

	key, err = rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}
	keyBytes = x509.MarshalPKCS1PrivateKey(key)
	return ioutil.WriteFile("mitm.prv", keyBytes, 0600)
}

func makeCert(san string) error {
	caKey, err := loadKey("mitm-ca")
	if err != nil {
		return err
	}
	caCert, _, err := loadCert("mitm-ca")
	if err != nil {
		return err
	}
	key, err := loadKey("mitm")
	if err != nil {
		return err
	}

	var DNSNames []string
	var IPAddresses []net.IP

	subject := pkix.Name{
		Organization:       []string{"Man-in-the-Middle"},
		OrganizationalUnit: []string{"Proxy"},
	}

	if len(san) > 0 {
		subject.CommonName = san

		ip := net.ParseIP(san)
		if ip != nil {
			IPAddresses = append(IPAddresses, ip)
		} else {
			DNSNames = append(DNSNames, san)
		}
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	now := time.Now()

	cert := &x509.Certificate{
		SerialNumber: serial,
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
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert,
		&key.PublicKey, caKey)
	return ioutil.WriteFile("mitm.crt", certBytes, 0644)
}
