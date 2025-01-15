# xdcrTLSValidator

## Description
`xdcrTLSValidator` is a tool for running through the verification of a CA file that XDCR performs. 
It will output the certificates details and whether or not they are valid. 
It is also able to filter out the invalid certificates and output the valid CA certs to an output file if desired.

## Usage
```sh
xdcrTLSValidator -caCertificates <caCertificatesFile> [-clientCert <clientCertFile>] [-outputFile <outputFile>]
```

## How to Build

To build the `xdcrTLSValidator` tool, you need to have Go installed on your system. Follow the steps below to build the project:

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. Build the project using `go build`:
    ```sh
    go build -o xdcrTLSValidator
    ```

This will create an executable file named `xdcrTLSValidator` in the current directory.

## How to use

Using one of the source nodes of the Couchbase Cluster, run the tool against the CA file that is to be supplied for
XDCR remote cluster reference creation. The CA file should represent the list of certificate authorities that
the target cluster currently trusts.

## Example output:

```sh
./xdcrTLSValidator -caCertificates ~/ca-pem-file.pem
CA Certificates location: .../ca-pem-file.pem
Validating CA certificates...
Certificate Details (1) - Signature failed: crypto/rsa: verification error:
...
SHA256 RSA verification failed: crypto/rsa: verification error
Certificate Details (2) - Signature failed: x509: ECDSA verification failure:
...
ECDSA verification failed - with curve params: %v &{... 384 P-384}
Certificate Details (3) - Signature failed: crypto/rsa: verification error:
...
SHA256 RSA verification failed: crypto/rsa: verification error
Certificate Details (4):
  Subject: CN=<>
  Issuer: CN=<>
  Serial Number: ---
  Not Before: 2011-01-10 21:01:41 +0000 UTC
  Not After: 2026-01-10 21:11:41 +0000 UTC
  Signature Algorithm: SHA1-RSA
  Public Key Algorithm: RSA
  DNS Names: []
  Email Addresses: []
  IP Addresses: []
Certificate Details (5):
...

Read a total of 16 certificates. UnableToParse: 0. Signature failed: 10
```

In the above example, the tool reads the CA certificates from the file `ca-pem-file.pem` and validates them. It then prints the details of each certificate and indicates whether the certificate is valid or not. In this case, the tool found that 10 certificates failed the signature verification.

If an output file has been specified, the tool will write the valid CA certificates to the output file. Running the output certificate file through the tool should result in all certificates being valid.
