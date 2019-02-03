package bio

// #cgo CFLAGS: -I/usr/local/opt/openssl/include -I/usr/local/ssl/include
// #cgo LDFLAGS: -L/usr/local/opt/openssl/lib -L/usr/local/ssl/lib -lssl -lcrypto
import "C"
