package main

import (
   "log"
   "os"
   "text/template" // Make sure this is imported
)

const masterTemplateString = `
{{ if eq .Key "URL" }}
   http://example.com/upload
{{ else if eq .Key "Body" }}
   {{ .Value }}
{{ end }}
`

func main() {
   tmpl := template.New("masterTemplate")
   tmpl, err := tmpl.Parse(masterTemplateString)
   if err != nil {
      log.Fatalf("Error parsing template: %v", err)
   }
   value := struct{
      Key string
      Value string
   }{
      //Key: "URL",
      Key: "Body",
      Value: "hello world",
   }
   err = tmpl.Execute(os.Stdout, value) // Pass the data to the root template
   if err != nil {
      log.Fatalf("Error executing template: %v", err)
   }
}
