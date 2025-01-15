package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type Options struct {
	CaCertificates string
	ClientCert     string
	OutputFile     string
}

func parseArgs() Options {
	// Define flags
	caCertificates := flag.String("caCertificates", "", "the certificate authority file location (mandatory)")
	clientCert := flag.String("clientCert", "", "the file location of a client certificate (optional)")
	outputFile := flag.String("outputFile", "", "Output the valid CA certificates to a pem file (optional)")

	// Parse the command-line flags
	flag.Parse()

	// Check if the mandatory caCertificates argument is provided
	if *caCertificates == "" {
		help()
		os.Exit(1)
	}

	return Options{
		CaCertificates: *caCertificates,
		ClientCert:     *clientCert,
		OutputFile:     *outputFile,
	}
}

func help() {
	fmt.Println("Usage: xdcrTLSValidator [options]")
	fmt.Println("Options:")
	fmt.Println("  -caCertificates string")
	fmt.Println("        the certificate authority file location (mandatory)")
	fmt.Println("  -clientCert string")
	fmt.Println("        the file location of a client certificate (optional)")
	fmt.Println("  -outputFile string")
	fmt.Println("        Output the valid CA certificates to a pem file (optional)")
	fmt.Println("  -h, --help")
	fmt.Println("        display this help message")
}

// This function mirrors that of XDCR's ValidateCertificates() function
func validateAndFilterCaCerts(certificate []byte, unableToParse [][]byte, signatureFailed [][]byte) ([]*x509.Certificate, error) {
	// Implement certificate validation logic here
	// check validity of server root certificates
	var validCaCerts []*x509.Certificate
	var counter int
	var unableToParseCounter int
	var signatureFailedCounter int
	for {
		var block *pem.Block
		block, certificate = pem.Decode(certificate)
		if block == nil {
			break
		}
		counter++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			printCertificateDetails(counter, cert, fmt.Sprintf("UnableToParse: %v", err.Error()))
			unableToParse = append(unableToParse, block.Bytes)
			unableToParseCounter++
			continue
		}

		// check the signature of cert
		err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		if err != nil {
			printCertificateDetails(counter, cert, fmt.Sprintf("Signature failed: %v", err.Error()))
			signatureFailed = append(signatureFailed, block.Bytes)
			signatureFailedCounter++
			if strings.Contains(err.Error(), "ECDSA verification failure") {
				runECDSAVerificationDebug(cert)
			} else if strings.Contains(err.Error(), "crypto/rsa: verification error") {
				runRSAVerificationDebug(cert)
			}
			continue
		}

		printCertificateDetails(counter, cert, "")

		// add the cert to the list of root certificates
		validCaCerts = append(validCaCerts, cert)
	}
	// We should have at least one root certificate
	if len(validCaCerts) == 0 {
		return nil, fmt.Errorf("No valid root certificate found\n")
	}
	fmt.Printf("Read a total of %d certificates. UnableToParse: %d. Signature failed: %d\n", counter, unableToParseCounter, signatureFailedCounter)
	return validCaCerts, nil
}

func runRSAVerificationDebug(cert *x509.Certificate) {
	// Extract the RSA public key from the certificate
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Println("Certificate does not contain an RSA public key")
		return
	}

	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		// Verify the signature using the RSA public key
		hash := crypto.SHA256.New()
		hash.Write(cert.RawTBSCertificate)
		digest := hash.Sum(nil)

		// This is just what we can extract from VerifyPCSK1v15 below for debugging purposes
		if pubKey.Size() != len(cert.Signature) {
			fmt.Printf("RSA verification failed: public key size %d does not match signature size %d\n", pubKey.Size(), len(cert.Signature))
		}

		// THe rest of them can't be extracted
		err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, cert.Signature)
		if err != nil {
			fmt.Printf("SHA256 RSA verification failed: %v\n", err)
		}
	}
}

func runECDSAVerificationDebug(cert *x509.Certificate) {
	// Extract the ECDSA public key from the certificate
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("Certificate does not contain an ECDSA public key")
		return
	}

	// Extract the signature from the certificate
	var signature struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(cert.Signature, &signature)
	if err != nil {
		fmt.Printf("Failed to unmarshal signature: %v\n", err)
		return
	}

	// Verify the signature using the ECDSA public key
	valid := ecdsa.VerifyASN1(pubKey, cert.RawTBSCertificate, cert.Signature)
	if valid {
		fmt.Println("ECDSA verification succeeded")
	} else {
		fmt.Println("ECDSA verification failed - with curve params: %v", pubKey.Curve.Params())
	}
}

func printCertificateDetails(counter int, certificate *x509.Certificate, failedReason string) {
	if failedReason != "" {
		fmt.Printf("Certificate Details (%d) - %s:\n", counter, failedReason)
	} else {
		fmt.Printf("Certificate Details (%d):\n", counter)
	}
	fmt.Printf("  Subject: %s\n", certificate.Subject)
	fmt.Printf("  Issuer: %s\n", certificate.Issuer)
	fmt.Printf("  Serial Number: %s\n", certificate.SerialNumber)
	fmt.Printf("  Not Before: %s\n", certificate.NotBefore)
	fmt.Printf("  Not After: %s\n", certificate.NotAfter)
	fmt.Printf("  Signature Algorithm: %s\n", certificate.SignatureAlgorithm)
	fmt.Printf("  Public Key Algorithm: %s\n", certificate.PublicKeyAlgorithm)
	fmt.Printf("  DNS Names: %v\n", certificate.DNSNames)
	fmt.Printf("  Email Addresses: %v\n", certificate.EmailAddresses)
	fmt.Printf("  IP Addresses: %v\n", certificate.IPAddresses)
}

func validateClientCert(caCerts []*x509.Certificate, clientCert []byte) error {
	// Create a certificate pool and add the CA certificates
	certPool := x509.NewCertPool()
	for _, caCert := range caCerts {
		certPool.AddCert(caCert)
	}

	// Decode the client certificate PEM block
	clientBlock, _ := pem.Decode(clientCert)
	if clientBlock == nil {
		return fmt.Errorf("failed to decode client certificate PEM block")
	}

	// Parse the client certificate
	clientCertParsed, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing client certificate: %v", err)
	}

	// Verify the client certificate against the CA certificates
	opts := x509.VerifyOptions{
		Roots: certPool,
	}

	if _, err := clientCertParsed.Verify(opts); err != nil {
		if strings.Contains(err.Error(), "certificate signed by unknown authority") {
			fmt.Printf("Note: This failure (%v) generally means that the CA is not trusted by the system\n", err)
		}
		return fmt.Errorf("client certificate verification failed: %v", err)
	}

	return nil
}

// writeCertsToPEM writes the given certificates to a PEM file at the specified location
func writeCertsToPEM(outputFile string, certs []*x509.Certificate) error {
	// Create or open the output file
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer file.Close()

	// Write each certificate to the file in PEM format
	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(file, pemBlock); err != nil {
			return fmt.Errorf("error encoding certificate to PEM: %v", err)
		}
	}

	return nil
}

func main() {
	// Check if no arguments are passed or if help is requested
	if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		help()
		os.Exit(0)
	}

	// Parse arguments
	options := parseArgs()
	// Validate the file extension of caCertificates
	if !strings.HasSuffix(options.CaCertificates, ".pem") {
		fmt.Println("Error: caCertificates file must have a .pem extension")
		os.Exit(1)
	}
	fmt.Println("CA Certificates location:", options.CaCertificates)

	var caCert []byte
	var clientCert []byte
	var err error

	if len(options.ClientCert) > 0 {
		fmt.Println("Client Certificate location:", options.ClientCert)
		if !strings.HasSuffix(options.ClientCert, ".pem") {
			fmt.Println("Error: client certificaate file must have a .pem extension")
			os.Exit(1)
		}

		clientCert, err = os.ReadFile(options.ClientCert)
		if err != nil {
			fmt.Println("Error reading client certificate:", err)
			os.Exit(1)
		}
	}

	// Read the CA certificate
	caCert, err = os.ReadFile(options.CaCertificates)
	if err != nil {
		fmt.Println("Error reading CA certificate:", err)
		os.Exit(1)
	}

	var unableToParseCerts [][]byte
	var signatureFailedCerts [][]byte
	// Validate the CA certificates
	fmt.Printf("Validating CA certificates...\n")
	validCaCerts, err := validateAndFilterCaCerts(caCert, unableToParseCerts, signatureFailedCerts)
	if err != nil {
		fmt.Println("Error validating CA certificates:", err)
		os.Exit(1)
	}

	if len(options.ClientCert) > 0 {
		// Validate the client certificate
		err = validateClientCert(validCaCerts, clientCert)
		if err != nil {
			fmt.Println("Error validating client certificate using filtered CA certs:", err)
			// It's ok to continue with invalid client certs and into the next output section
		}
	}

	// Print the output file location
	if len(options.OutputFile) > 0 {
		fmt.Println("Output valid certs to file:", options.OutputFile)
		err = writeCertsToPEM(options.OutputFile, validCaCerts)
		if err != nil {
			os.Exit(1)
		}
	}

	// Exit gracefully
	os.Exit(0)
}
