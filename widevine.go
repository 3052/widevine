package widevine

import (
   "154.pages.dev/protobuf"
   "bytes"
   "crypto/x509"
   "encoding/binary"
   "encoding/hex"
   "encoding/pem"
   "net/http"
)

type Poster interface {
   RequestUrl() (string, bool)
   RequestHeader() (http.Header, error)
   RequestBody([]byte) ([]byte, error)
   ResponseBody([]byte) ([]byte, error)
}

func (p PSSH) CDM(private_key, client_id []byte) (*CDM, error) {
   var module CDM
   // key_id
   module.key_id = p.Key_ID
   // license_request
   var request protobuf.Message // LicenseRequest
   request.AddBytes(1, client_id) // client_id
   request.AddFunc(2, func(m *protobuf.Message) { // content_id
      m.AddFunc(1, func(m *protobuf.Message) { // widevine_pssh_data
         m.AddFunc(1, func(m *protobuf.Message) { // pssh_data
            m.AddBytes(2, p.Key_ID)
            m.AddBytes(4, p.content_id)
         })
      })
   })
   module.license_request = request.Encode()
   // private_key
   block, _ := pem.Decode(private_key)
   var err error
   module.private_key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      return nil, err
   }
   return &module, nil
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
   var pssh protobuf.Message
   if err := pssh.Consume(buf.Bytes()); err != nil {
      return err
   }
   // Cannot be used in conjunction with content_id
   p.Key_ID, _ = pssh.GetBytes(2)
   // Cannot be present in conjunction with key_id
   p.content_id, _ = pssh.GetBytes(4)
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
