package controllers

import (
	"net/http"
	"time"
)

// AuthController is an HTTP request handler for converting OpenID Connect tokens into authentication cookies
func AuthController(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)

		return
	}

	if r.Method == "POST" {
		// A token may be present in a POST form field called 'id_token'.
		// Retrieve this token, and place it in a cookie
		r.ParseForm()
		redirectURLValues := r.URL.Query()["state"]
		var redirectURL string

		if redirectURLValues != nil {
			redirectURL = redirectURLValues[0]
		} else {
			redirectURL = "/"
		}

		if r.Form["id_token"] != nil && len(r.Form["id_token"][0]) != 0 {
			expire := time.Now().AddDate(0, 0, 1) // auth tokens are good for one day
			cookie := http.Cookie{Name: "authToken", Value: r.Form["id_token"][0], Expires: expire}
			http.SetCookie(w, &cookie)

			http.Redirect(w, r, redirectURL, 302)
		}
	}
}
