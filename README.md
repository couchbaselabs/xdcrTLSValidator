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
