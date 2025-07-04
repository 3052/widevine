package main

import (
   "bytes"
   "encoding/base64"
   "fmt"
   "log"
   "text/template" // Make sure this is imported
   "strings"
)

const masterTemplateString = `{{define "request"}}{"payload":"{{base64 .}}"}{{end}}{"signer":"widevine_test","request":"{{include "request" .|base64}}"}`

func main() {
   input := "hello"
   tmpl := template.New("masterTemplate")
   funcMap := template.FuncMap{
      "base64": func(data string) string {
         return base64.StdEncoding.EncodeToString([]byte(data))
      },
      "include": includeFun(tmpl),
   }
   tmpl, err := tmpl.Funcs(funcMap).Parse(masterTemplateString)
   if err != nil {
      log.Fatalf("Error parsing template: %v", err)
   }
   var buf bytes.Buffer
   err = tmpl.Execute(&buf, input) // Pass the data to the root template
   if err != nil {
      log.Fatalf("Error executing template: %v", err)
   }
   fmt.Println(buf.String())
}

func includeFun(t *template.Template) func(string, interface{}) (string, error) {
   return func(name string, data interface{}) (string, error) {
      var buf strings.Builder
      err := t.ExecuteTemplate(&buf, name, data)
      return buf.String(), err
   }
}
