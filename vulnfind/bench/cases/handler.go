// Labelled benchmark case.
package main

import ("database/sql"; "fmt"; "net/http"; "os"; "os/exec"; "strconv"; "crypto/tls")

func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	db.Query(fmt.Sprintf("SELECT * FROM u WHERE name = '%s'", name)) // expect: GO-TAINT-SQLI
	db.Query("SELECT * FROM u WHERE name = $1", name) // safe
	id, _ := strconv.Atoi(r.FormValue("id"))
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %d", id)) // safe
	exec.Command("sh", "-c", "ping "+r.FormValue("host")).Run() // expect: GO-TAINT-CMDI
	os.ReadFile("/srv/" + r.FormValue("f")) // expect: GO-TAINT-PATH
	http.Redirect(w, r, r.URL.Query().Get("next"), 302) // expect: GO-TAINT-REDIRECT
	_ = &tls.Config{InsecureSkipVerify: true} // expect: GO-TLS-INSECURE
}
