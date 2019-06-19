venafi-tpp
==========

venafi-tpp is a Go library for making API calls to a Venafi Trust Protection Platform server.

Venafi offers their own [vcert](https://github.com/Venafi/vcert) library, but it only implements half a dozen 
primitives. The goal is to eventually make venafi-tpp feature complete.

## Installation

Standard `go get`:

```
$ go get github.com/tradel/venafi-tpp
```

## Usage & Example

	v, err := venafi.NewClient("https://tpp.mycompany.com", "TPPAdmin", "Passw0rd", nil)
	if err != nil {
	    return err 
    }
    
    certDN := "\\VED\\Policy\\Certificates\\my-test-cert"
    cert, privateKey, err := v.Certs.Retrieve(certDN)
    if err != nil {
    	return err
    }
    
    println("Certificate CN:", cert.Subject.CommonName)
