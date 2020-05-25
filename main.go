package main

import (
	"html/template"
	_ "io/ioutil"
	_ "log"
	"net/http"
	"time"

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
	http.Handle("/auth", middleware.MethodFilteringMiddleware(
		map[string]http.Handler{"POST": http.HandlerFunc(controllers.AuthController)},
		middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("You are authenticated!"))
		}))))

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		var p *Page
		_, err := r.Cookie("token")

		if err == nil {
			p = &Page{
				Title: "Hello, World. Authenticated!",
				Body:  []byte("This is the body!"),
				Items: []Item{{Name: "Orange", Price: 1.25}, {Name: "Banana", Price: 3.00}}}
		} else {
			p = &Page{
				Title: "Hello, World. Not Authenticated!",
				Body:  []byte("This is the body!"),
				Items: []Item{{Name: "Orange", Price: 1.25}, {Name: "Banana", Price: 3.00}}}
		}

		expire := time.Now().AddDate(0, 0, 1)
		cookie := http.Cookie{
			Name:    "acookie",
			Value:   "avalueforthecookie",
			Expires: expire,
		}

		http.SetCookie(w, &cookie)

		templates.ExecuteTemplate(w, "template.html", p)
	})

	http.ListenAndServe(":8080", nil)
}
