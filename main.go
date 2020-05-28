package main

import (
	"fmt"
	"html/template"
	_ "io/ioutil"
	"log"
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

	http.Handle("/admin", middleware.AuthRequiredMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Admin portal. You are authenticated!"))
	})))

	http.Handle("/auth", middleware.MethodFilteringMiddleware(
		map[string]http.Handler{"POST": http.HandlerFunc(controllers.AuthController)},                                   // POST
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { middleware.PromptForAuthentication(w, r, "") }), // Everything Else
	))

	http.Handle("/name", middleware.AuthContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)

		claims := r.Context().Value(middleware.KeyClaims)
		if claims != nil {
			givenName, ok := claims.(map[string]interface{})["given_name"]

			if !ok {
				log.Println("Claims were present, but given_name wasn't found.")
				w.Write([]byte("Well! Hello there, mysterious stranger!"))
			} else {
				w.Write([]byte(fmt.Sprintf("Well! Hello there, %v!", givenName)))
			}
		} else {
			w.Write([]byte("Well! Hello there! Go on, keep your secrets! ;)"))
		}
	})))

	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Sup."))
	}))

	// http.Handle("/auth", middleware.MethodFilteringMiddleware(map[string]http.Handler{
	// 	"POST": http.HandlerFunc(controllers.AuthController),
	// }, middleware.AuthMiddleware(http.HandlerFunc(controllers.AuthController))))

	// http.Handle("/protected", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	w.WriteHeader(http.StatusAccepted)
	// 	w.Write([]byte("You are authenticated!"))
	// })))

	// http.Handle("/", middleware.AuthContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 	var p *Page

	// 	claimsValue := r.Context().Value(middleware.KeyClaims)
	// 	var claims map[string]interface{}

	// 	if claimsValue != nil {
	// 		claims = claimsValue.(map[string]interface{})
	// 	}

	// 	if len(claims) > 0 {
	// 		p = &Page{
	// 			Title: fmt.Sprintf("Hello, %v.", claims["given_name"].(string)),
	// 			Body:  []byte("This is the body!"),
	// 			Items: []Item{{Name: "Orange", Price: 1.25}, {Name: "Banana", Price: 3.00}}}
	// 	} else {
	// 		p = &Page{
	// 			Title: "Hello, World. Not Authenticated!",
	// 			Body:  []byte("This is the body!"),
	// 			Items: []Item{{Name: "Orange", Price: 1.25}, {Name: "Banana", Price: 3.00}}}
	// 	}

	// 	templates.ExecuteTemplate(w, "template.html", p)
	// })))

	http.ListenAndServe(":8080", nil)
}
