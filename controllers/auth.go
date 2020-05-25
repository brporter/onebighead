package controllers

import (
	"log"
	"net/http"
	"time"
)

// var templates = template.Must(template.ParseFiles("views/auth.html"))

func AuthController(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		log.Print("An unexpected GET request was made to the auth endpoint.")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad Request"))
	}

	if r.Method == "POST" {
		// A token may be present in a POST form field called 'id_token'.
		// Retrieve this token, and place it in a cookie
		r.ParseForm()

		if r.Form["id_token"] != nil && len(r.Form["id_token"][0]) != 0 {
			expire := time.Now().AddDate(0, 0, 1) // auth tokens are good for one day
			cookie := http.Cookie{Name: "authToken", Value: r.Form["id_token"][0], Expires: expire}
			http.SetCookie(w, &cookie)

			http.Redirect(w, r, "/hello", 302)
		}
	}
}
