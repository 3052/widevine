package curl

import (
   "fmt"
   "net/http"
   "net/http/httputil"
)

func location() {
   http.DefaultClient.CheckRedirect = nil
}

func no_location() {
   http.DefaultClient.CheckRedirect = func(*http.Request, []*http.Request) error {
      return http.ErrUseLastResponse
   }
}

func no_trace() {
   http.DefaultClient.Transport = nil
}

func no_verbose() {
   http.DefaultClient.Transport = nil
}

func trace() {
   http.DefaultClient.Transport = transport{
      f: func(r *http.Request) (int, error) {
         b, err := httputil.DumpRequest(r, true)
         if err != nil {
            return 0, err
         }
         return fmt.Println(string(b))
      },
   }
}

func verbose() {
   http.DefaultClient.Transport = transport{
      f: func(r *http.Request) (int, error) {
         return fmt.Println(r.Method, r.URL)
      },
   }
}

type transport struct {
   f func(*http.Request) (int, error)
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
   _, err := t.f(req)
   if err != nil {
      return nil, err
   }
   return http.DefaultTransport.RoundTrip(req)
}
