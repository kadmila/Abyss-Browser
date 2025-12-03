/*
Package aerr defines custom errors for abyss-core
*/
package aerr

import (
	"errors"
	"net"
	"strings"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"
	"github.com/quic-go/quic-go"
)

type AbyssError struct {
	RemoteAddr *net.UDPAddr
	RemoteHash string
	RemoteAURL *aurl.AURL
	_inner_err error
}

func NewConnErrM(connection quic.Connection, aurl *aurl.AURL, msg string) *AbyssError {
	return &AbyssError{
		RemoteAddr: connection.RemoteAddr().(*net.UDPAddr),
		RemoteHash: "",
		RemoteAURL: aurl,
		_inner_err: errors.New(msg),
	}
}
func NewConnErr(connection quic.Connection, aurl *aurl.AURL, err error) *AbyssError {
	return &AbyssError{
		RemoteAddr: connection.RemoteAddr().(*net.UDPAddr),
		RemoteHash: "",
		RemoteAURL: aurl,
		_inner_err: err,
	}
}

func (e *AbyssError) Error() string {
	var b strings.Builder
	if e.RemoteAddr != nil {
		b.WriteString("Remote address:")
		b.WriteString(e.RemoteAddr.String())
		b.WriteString("\n")
	}
	if e.RemoteHash != "" {
		b.WriteString("Remote hash:")
		b.WriteString(e.RemoteHash)
		b.WriteString("\n")
	}
	if e.RemoteAURL != nil {
		b.WriteString("Remote AURL:")
		b.WriteString(e.RemoteAURL.ToString())
		b.WriteString("\n")
	}
	b.WriteString(e._inner_err.Error())
	return b.String()
}
