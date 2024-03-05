package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "encoding/base64"
   "encoding/binary"
   "encoding/hex"
   "errors"
   "github.com/chmike/cmac-go"
   "io"
   "log/slog"
   "net/http"
)

type Poster interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, error)
   RequestBody([]byte) ([]byte, error)
   ResponseBody([]byte) ([]byte, error)
}

func (c *CDM) License(p Poster) (*LicenseMessage, error) {
   address, ok := p.RequestUrl()
   if !ok {
      return nil, errors.New("Poster.RequestUrl")
   }
   signed, err := func() ([]byte, error) {
      b, err := c.request_signed()
      if err != nil {
         return nil, err
      }
      return p.RequestBody(b)
   }()
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest("POST", address, bytes.NewReader(signed))
   if err != nil {
      return nil, err
   }
   req.Header, err = p.RequestHeader()
   if err != nil {
      return nil, err
   }
   res, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer res.Body.Close()
   if res.StatusCode != http.StatusOK {
      var b bytes.Buffer
      res.Write(&b)
      return nil, errors.New(b.String())
   }
   signed, err = func() ([]byte, error) {
      b, err := io.ReadAll(res.Body)
      if err != nil {
         return nil, err
      }
      return p.ResponseBody(b)
   }()
   if err != nil {
      return nil, err
   }
   slog.Debug("license", "response", base64.StdEncoding.EncodeToString(signed))
   return c.response(signed)
}

// wikipedia.org/wiki/Encrypted_Media_Extensions#Content_Decryption_Modules
type CDM struct {
   block cipher.Block
   key_id []byte
   license_request []byte
   private_key *rsa.PrivateKey
}

func (c *CDM) response(signed []byte) (*LicenseMessage, error) {
   var message protobuf.Message // SignedMessage
   err := message.Consume(signed)
   if err != nil {
      return nil, err
   }
   session_key, err := func() ([]byte, error) {
      v, ok := message.GetBytes(4) // bytes session_key
      if !ok {
         return nil, errors.New("session_key")
      }
      return rsa.DecryptOAEP(sha1.New(), nil, c.private_key, v, nil)
   }()
   if err != nil {
      return nil, err
   }
   c.block, err = func() (cipher.Block, error) {
      var b []byte
      b = append(b, 1)
      b = append(b, "ENCRYPTION"...)
      b = append(b, 0)
      b = append(b, c.license_request...)
      b = append(b, 0, 0, 0, 0x80)
      h, err := cmac.New(aes.NewCipher, session_key)
      if err != nil {
         return nil, err
      }
      h.Write(b)
      return aes.NewCipher(h.Sum(nil))
   }()
   if err != nil {
      return nil, err
   }
   // this is listed as: optional bytes msg = 2;
   // but assuming the type is: LICENSE = 2;
   // the result is actually: optional License msg = 2;
   license, ok := message.Get(2)
   if !ok {
      return nil, errors.New("License")
   }
   return &LicenseMessage{license}, nil
}

func (c CDM) Key(m *LicenseMessage) ([]byte, bool) {
   for _, field := range m.m {
      if container, ok := field.Get(3); ok { // KeyContainer key
         // this field is: optional bytes id = 1;
         // but CONTENT keys should always have it
         id, ok := container.GetBytes(1)
         if !ok {
            continue
         }
         if !bytes.Equal(id, c.key_id) {
            continue
         }
         iv, ok := container.GetBytes(2)
         if !ok {
            continue
         }
         key, ok := container.GetBytes(3)
         if !ok {
            continue
         }
         cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(key, key)
         return unpad(key), true
      }
   }
   return nil, false
}

// ISO/IEC 14496-12
//  aligned(8) class Box (
//     unsigned int(32) boxtype, optional unsigned int(8)[16] extended_type
//  ) {
//     BoxHeader(boxtype, extended_type);
//     // the remaining bytes are the BoxPayload
//  }
//
//  aligned(8) class BoxHeader (
//     unsigned int(32) boxtype, optional unsigned int(8)[16] extended_type
//  ) {
//     unsigned int(32) size;
//     unsigned int(32) type = boxtype;
//     if (size==1) {
//        unsigned int(64) largesize;
//     } else if (size==0) {
//        // box extends to end of file
//     }
//     if (boxtype=='uuid') {
//        unsigned int(8)[16] usertype = extended_type;
//     }
//  }
//
//  aligned(8) class FullBox(
//     unsigned int(32) boxtype,
//     unsigned int(8) v,
//     bit(24) f,
//     optional unsigned int(8)[16] extended_type
//  ) extends Box(boxtype, extended_type) {
//     FullBoxHeader(v, f);
//     // the remaining bytes are the FullBoxPayload
//  }
//
//  aligned(8) class FullBoxHeader(unsigned int(8) v, bit(24) f) {
//     unsigned int(8) version = v;
//     bit(24) flags = f;
//  }
//
// ISO/IEC 23001-7
//  aligned(8) class ProtectionSystemSpecificHeaderBox extends FullBox(
//     'pssh', version, flags=0,
//  ) {
//     unsigned int(8)[16] SystemID;
//     if (version > 0) {
//        unsigned int(32) KID_count;
//        {
//           unsigned int(8)[16] KID;
//        } [KID_count];
//     }
//     unsigned int(32) DataSize;
//     unsigned int(8)[DataSize] Data;
//  }
type PSSH struct {
   SpecificHeader struct {
      Size uint32
      Type Type
      Version uint8
      Flags [3]byte
      SystemId SystemId
      DataSize uint32
   }
   // all of the Widevine PSSH I have seen so far are single `key_id`, so we
   // are going to implement that for now, because its not clear what the logic
   // would be with multiple key_ids.
   Key_ID []byte
   content_id []byte
}

// some sites use content_id, in which case you need PSSH
func (p *PSSH) New(data []byte) error {
   buf := bytes.NewBuffer(data)
   err := binary.Read(buf, binary.BigEndian, &p.SpecificHeader)
   if err != nil {
      return err
   }
   var protect protobuf.Message
   if err := protect.Consume(buf.Bytes()); err != nil {
      return err
   }
   // Cannot be used in conjunction with content_id
   p.Key_ID, _ = protect.GetBytes(2)
   // Cannot be present in conjunction with key_id
   p.content_id, _ = protect.GetBytes(4)
   return nil
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

type SystemId [16]uint8

func (s SystemId) String() string {
   return hex.EncodeToString(s[:])
}

type Type [4]byte

func (t Type) String() string {
   return string(t[:])
}

type no_operation struct{}

func (no_operation) Read(buf []byte) (int, error) {
   return len(buf), nil
}

type LicenseMessage struct {
   m protobuf.Message
}
