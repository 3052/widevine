package curl

import (
   "fmt"
   "io"
   "net/http"
   "strconv.pages.dev"
   "time"
)

type Progress struct {
   // godocs.io/builtin#cap
   // godocs.io/net/http#Response.Body
   chunk_cap int64
   // godocs.io/builtin#len
   // godocs.io/net/http#Response.Body
   chunk_len int64
   // godocs.io/builtin#cap
   // godocs.io/net/http#Response.ContentLength
   content_cap int64
   // godocs.io/net/http#Response.ContentLength
   content_len int64
   // godocs.io/io#WriterAt
   // godocs.io/net/http#Response.ContentLength
   content_off int
   // godocs.io/builtin#cap
   // godocs.io/time
   time_cap time.Time
   // godocs.io/builtin#len
   // godocs.io/time
   time_len time.Time
}

func New_Progress(chunks int) *Progress {
   var p Progress
   p.chunk_cap = int64(chunks)
   p.time_cap = time.Now()
   p.time_len = time.Now()
   return &p
}

// chunk length     content length
// --------------   ----------------
// chunk capacity   content capacity
func (p *Progress) Reader(res *http.Response) io.Reader {
   p.chunk_len += 1
   p.content_len += res.ContentLength
   p.content_cap = p.content_len * p.chunk_cap / p.chunk_len
   return io.TeeReader(res.Body, p)
}

func (p *Progress) Write(b []byte) (int, error) {
   p.content_off += len(b)
   if time.Since(p.time_len) >= time.Second {
      fmt.Println(p.percent(), " ", p.size(), " ", p.rate())
      p.time_len = time.Now()
   }
   return len(b), nil
}

func (p Progress) percent() strconv.Percent {
   return strconv.Percent(p.content_off) / strconv.Percent(p.content_cap)
}

func (p Progress) rate() strconv.Rate {
   since := time.Since(p.time_cap).Seconds()
   return strconv.Rate(p.content_off) / strconv.Rate(since)
}

func (p Progress) size() strconv.Size {
   return strconv.Size(p.content_off)
}
