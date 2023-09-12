package widevine

import (
	"154.pages.dev/encoding/protobuf"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
)

type Poster interface {
	Request_URL() string
	Request_Header() http.Header
	Request_Body([]byte) ([]byte, error)
	Response_Body([]byte) ([]byte, error)
}

func (m Module) Key(post Poster) ([]byte, error) {
	body, err := func() ([]byte, error) {
		b, err := m.signed_request()
		if err != nil {
			return nil, err
		}
		return post.Request_Body(b)
	}()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(
		"POST", post.Request_URL(), bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	if head := post.Request_Header(); head != nil {
		req.Header = head
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New(res.Status)
	}
	body, err = func() ([]byte, error) {
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		return post.Response_Body(b)
	}()
	if err != nil {
		return nil, err
	}
	return m.signed_response(body)
}

type Module struct {
	key_ID          []byte
	license_request []byte
	private_key     *rsa.PrivateKey
}

// key_id or content_id could be used, so entire PSSH is needed
func New_Module(private_key, client_ID, pssh []byte) (*Module, error) {
	pssh = pssh[32:]
	var mod Module
	// key_ID
	{
		m, err := protobuf.Consume(pssh) // WidevinePsshData
		if err != nil {
			return nil, err
		}
		mod.key_ID, _ = m.Bytes(2) // key_ids
	}
	// license_request
	{
		var m protobuf.Message               // LicenseRequest
		m.Add_Bytes(1, client_ID)            // client_id
		m.Add(2, func(m *protobuf.Message) { // content_id
			m.Add(1, func(m *protobuf.Message) { // widevine_pssh_data
				m.Add_Bytes(1, pssh) // pssh_data
			})
		})
		mod.license_request = m.Append(nil)
	}
	// private_key
	block, _ := pem.Decode(private_key)
	var err error
	mod.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &mod, nil
}

func (m Module) signed_request() ([]byte, error) {
	hash := sha1.Sum(m.license_request)
	signature, err := rsa.SignPSS(
		no_operation{},
		m.private_key,
		crypto.SHA1,
		hash[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash},
	)
	if err != nil {
		return nil, err
	}
	var signed_request protobuf.Message
	signed_request.Add_Bytes(2, m.license_request)
	signed_request.Add_Bytes(3, signature)
	return signed_request.Append(nil), nil
}

func unpad(buf []byte) []byte {
	if len(buf) >= 1 {
		pad := buf[len(buf)-1]
		if len(buf) >= int(pad) {
			buf = buf[:len(buf)-int(pad)]
		}
	}
	return buf
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
	return len(buf), nil
}
