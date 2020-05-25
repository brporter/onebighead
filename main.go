package main

import (
	"fmt"
	"html/template"
	_ "io/ioutil"
	_ "log"
	"net/http"

	"github.com/brporter/onebighead.com/controllers"
	"github.com/brporter/onebighead.com/middleware"
)

type Item struct {
	Name  string
	Price float32
}

type Page struct {
	Title string
	Body  []byte
	Items []Item
}

var templates = template.Must(template.ParseFiles("template.html"))

func main() {
	http.Handle("/auth", middleware.AuthMiddleware(http.HandlerFunc(controllers.AuthController)))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var p *Page

		claimsValue := r.Context().Value(middleware.KeyClaims)
		var claims map[string]interface{}

		if claimsValue != nil {
			claims = claimsValue.(map[string]interface{})
		}

		if len(claims) > 0 {
			p = &Page{
				Title: fmt.Sprintf("Hello, %v.", claims["given_name"].(string)),
				Body:  []byte("This is the body!"),
				Items: []Item{{Name: "Orange", Price: 1.25}, {Name: "Banana", Price: 3.00}}}
		} else {
			p = &Page{
				Title: "Hello, World. Not Authenticated!",
				Body:  []byte("This is the body!"),
				Items: []Item{{Name: "Orange", Price: 1.25}, {Name: "Banana", Price: 3.00}}}
		}

		templates.ExecuteTemplate(w, "template.html", p)
	})

	http.ListenAndServe(":8080", nil)
}
