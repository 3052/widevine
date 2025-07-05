package main

import (
   "bytes"
   "fmt"
   "os"
   "text/template"
)

const definedTmplsString = `
{{- define "URL" -}}
http://example.com/upload
{{- end -}}

{{- define "Body" -}}
   {{.Value}}
{{- end -}}

{{- execTemplate .TemplateName . -}}
`

func main() {
   tmpl := template.New("main")
   funcs := template.FuncMap{
      "execTemplate": func(templateName string, data interface{}) (string, error) {
         var buf bytes.Buffer
         err := tmpl.ExecuteTemplate(&buf, templateName, data)
         if err != nil {
            return "", fmt.Errorf("error executing sub-template %q: %w", templateName, err)
         }
         return buf.String(), nil
      },
   }
   tmpl = tmpl.Funcs(funcs)
   var err error
   tmpl, err = tmpl.Parse(definedTmplsString)
   if err != nil {
      fmt.Println("Error parsing defined templates:", err)
      os.Exit(1)
   }
   data1 := struct {
      TemplateName string
      Name         string
   }{
      TemplateName: "greetingTemplate",
      Name:         "Alice",
   }
   err = tmpl.ExecuteTemplate(os.Stdout, "main", data1)
   if err != nil {
      fmt.Println("Error executing root template:", err)
   }
}
