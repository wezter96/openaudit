package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", r.URL.Query().Get("id")))
	defer rows.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	_ = client
}
