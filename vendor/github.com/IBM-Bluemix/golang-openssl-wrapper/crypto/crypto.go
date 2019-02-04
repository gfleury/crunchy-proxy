package crypto

// #cgo CFLAGS: -I/usr/local/opt/openssl/include -I/usr/local/ssl/include
// #cgo LDFLAGS: -L/usr/local/opt/openssl/lib -lcrypto
import "C"
