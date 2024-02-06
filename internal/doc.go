package widevine

type poster interface {
   Request_URL() (string, bool)
   Request_Header() (http.Header, bool)
   Request_Body([]byte) ([]byte, error)
   Response_Body([]byte) ([]byte, error)
}

func (p *psshData) New(data []byte) error {
   // unsigned int(32) size;
   // unsigned int(32) type = boxtype;
   // unsigned int(8) version = v;
   // bit(24) flags = f;
   // unsigned int(8)[16] SystemID;
   // unsigned int(32) DataSize;
   if len(data) <= 31 {
      return errors.New("psshData.New")
   }
   var pssh protobuf.Message // WidevinePsshData
   err := pssh.Consume(data[32:])
   if err != nil {
      return err
   }
   var ok bool
   p.key_id, ok = pssh.GetBytes(2)
   if !ok {
      return errors.New("key_ids")
   }
   p.content_id, _ = pssh.GetBytes(4) // optional
   return nil
}

type cdm struct{}

type psshData struct {
   key_id []byte
   content_id []byte
}

type keyContainer struct {
   id []byte
   key []byte
}

func (psshData) cdm(private_key, client_id []byte) (*cdm, error)

func (cdm) keyContainer(poster) ([]keyContainer, error)

func (psshData) key([]keyContainer) ([]byte, bool)
