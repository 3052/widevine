package widevine

import (
   "bytes"
   "errors"
   "io"
   "net/http"
)

type Poster interface {
   Request_URL() (string, bool)
   Request_Header() (http.Header, bool)
   Request_Body([]byte) ([]byte, error)
   Response_Body([]byte) ([]byte, error)
}

func (m Module) Key(post Poster) ([]byte, error) {
   address, ok := post.Request_URL()
   if !ok {
      return nil, errors.New("Poster.Request_URL")
   }
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
   req, err := http.NewRequest("POST", address, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   if head, ok := post.Request_Header(); ok {
      req.Header = head
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
