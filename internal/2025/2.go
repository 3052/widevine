package main

import (
   "bytes"
   "fmt"
   "os"
   "text/template"
)

func main() {
   // Define individual reusable templates using "define"
   const definedTmplsString = `
   {{- define "greetingTemplate" -}}
      Hello, {{.Name}}!
   {{- end -}}

   {{- define "farewellTemplate" -}}
      Goodbye, {{.Name}}.
   {{- end -}}

   {{- define "infoTemplate" -}}
      User: {{.Name}}, Age: {{.Age}}
   {{- end -}}

   {{- define "listTemplate" -}}
      Items:
      {{- range .Items }}
      - {{.}}
      {{- end }}
   {{- end -}}

   {{- define "defaultTemplate" -}}
      Unknown input type or template name.
   {{- end -}}
   `

   // This is the template that will use our custom function.
   // It avoids the if/else if chain by calling the 'execTemplate' function.
   const mainTmplString = `
   {{- if .TemplateName -}}
      {{- execTemplate .TemplateName . -}}
   {{- else -}}
      {{- execTemplate "defaultTemplate" . -}}
   {{- end -}}
   `

   // 1. Create a new template set.
   tmpl := template.New("main")

   // 2. Define the custom function in a FuncMap.
   // This function will execute a named template and return its output as a string.
   funcs := template.FuncMap{
      "execTemplate": func(templateName string, data interface{}) (string, error) {
         var buf bytes.Buffer
         // Execute the named template into a buffer.
         // tmpl.ExecuteTemplate ensures it uses the *entire* template set.
         err := tmpl.ExecuteTemplate(&buf, templateName, data)
         if err != nil {
            return "", fmt.Errorf("error executing sub-template %q: %w", templateName, err)
         }
         return buf.String(), nil
      },
   }

   // 3. Associate the FuncMap with the template set *before* parsing.
   tmpl = tmpl.Funcs(funcs)

   // 4. Parse all the templates into the same set.
   // Order matters: definedTmplsString first, then mainTmplString so that
   // "main" can call the defined templates.
   var err error
   tmpl, err = tmpl.Parse(definedTmplsString)
   if err != nil {
      fmt.Println("Error parsing defined templates:", err)
      os.Exit(1)
   }
   tmpl, err = tmpl.Parse(mainTmplString) // Parse the main template after defined ones
   if err != nil {
      fmt.Println("Error parsing main template:", err)
      os.Exit(1)
   }

   // --- Example 1: Greeting ---
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
