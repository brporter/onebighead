package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	_ "io/ioutil"
	"log"
	_ "log"
	"net/http"
	"time"

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
	configData, err := ioutil.ReadFile("auth.json")

	if err != nil {
		panic(err)
	}

	am, err := middleware.NewAuthenticationMiddleware(configData)

	if err != nil {
		panic(err)
	}

	go func() {
		timer := time.NewTimer(time.Hour)

		for {
			<-timer.C

			am.RefreshConfig(configData)

			timer.Reset(time.Hour)
		}
	}()

	http.Handle("/admin", am.RequiredMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("Admin portal. You are authenticated!"))
	})))

	http.Handle("/signin", http.HandlerFunc(am.SignInController))
	http.Handle("/signout", http.HandlerFunc(am.SignOutController))

	http.Handle("/name", am.ContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	http.ListenAndServe(":8080", nil)
}
