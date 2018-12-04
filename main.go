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
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"time"
)

func main() {
	keygen := flag.String("keygen", "", "Generate a keypair to the named file.")
	san := flag.String("san", "", "Subject alternative name for key.")
	flag.Parse()

	if len(*keygen) > 0 {
		err := makeKey(*keygen, *san)
		if err != nil {
			fmt.Printf("Failed to create keypair: %s\n", err)
		}
		return
	}
}

func makeKey(path, san string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
