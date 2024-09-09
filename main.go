package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type User struct {
	Uid       int    `db:"uid"`
	Email     string `db:"email"`
	Ref_token string `db:"ref_token"`
	// acc_token string
}
type Credentials struct {
	Access_token  string
	Refresh_token string
}

var secret []byte = []byte("some secret key hidden in .env or cloud-based")

func main() {
	mux := http.NewServeMux()
	db, err := sqlx.Open("postgres", "user=postgres password=123 sslmode=disable dbname=testovoe")
	if err != nil {
		fmt.Println(err)
	}
	db.MustExec(`create table if not exists users (
		uid serial primary key,
		email varchar(100) not null,	
		ref_token varchar(500) not null
	)`)
	mux.HandleFunc("/auth/{id}/obtaintokens", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		user := User{}
		err := db.Get(&user, "select * from users where uid=$1", id)
		if err != nil {
			log.Print(err)
			return
		}
		acc_token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
			"ipaddr": r.RemoteAddr,
			"uid":    user.Uid,
			"email":  user.Email,
			"exp":    time.Now().Add(time.Minute * 1).Unix(),
		}).SignedString(secret)
		if err != nil {
			log.Fatal(err)
			return
		}

		ref_token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
			"ipaddr": r.RemoteAddr,
			"uid":    user.Uid,
		}).SignedString(secret)
		if err != nil {
			log.Fatal(err)
		}
		updateRefreshToken(db, ref_token, &user)
		setTokensCookies(w, acc_token, ref_token)
	})
	mux.HandleFunc("/restricted", func(w http.ResponseWriter, r *http.Request) {
		tokenstring, err := r.Cookie("Access-Token")
		if tokenstring == nil {
			log.Print("token is empty. authorization needed")
			return
		}
		if err != nil {
			log.Fatal(err, "at cookie parsing")
			return
		}
		acc_token, err := validateToken(tokenstring.Value)
		if !acc_token.Valid {
			log.Print("token invalid")
		}
		if err != nil {
			log.Print(err, " at restricted validation")
			http.Redirect(w, r, "/auth/refreshtokens", http.StatusPermanentRedirect)
			//validation also detects token expiration
			return
		}
		log.Print("restricted data reached")

	})
	mux.HandleFunc("/auth/refreshtokens", func(w http.ResponseWriter, r *http.Request) {
		log.Print("refreshing tokens...")
		old_ref_token, err := r.Cookie("Refresh-Token")
		if err != nil {
			log.Print(err, " at refreshing")
			return
		}
		if old_ref_token.Value == "" {
			log.Print("empty token")
			return
		}
		token, err := validateToken(old_ref_token.Value)
		if err != nil {
			log.Fatal(err, "at ref-validation")
		}
		claims := token.Claims.(jwt.MapClaims)
		uid := claims["uid"]
		ipaddr := claims["ipaddr"]
		user := User{}
		err = db.Get(&user, "select * from users where uid=$1", uid)
		if err != nil {
			log.Fatal(err, "at db inserting")
			return
		}
		if user.Ref_token == base64.StdEncoding.EncodeToString([]byte(old_ref_token.Value)) {
			if ipaddr != r.RemoteAddr {
				//send to mail
				// auth := smtp.PlainAuth("", "username", "password", "host")
				// smtp.SendMail("address", auth, "sender@mailbox", []string{user.Email}, []byte("warning (new ip accessed)"))
				log.Print("sent corporate message: ", "<email warning>", "; on mail: ", user.Email)

			}
			new_ref_token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
				"ipaddr": r.RemoteAddr,
				"uid":    user.Uid,
			}).SignedString(secret)
			if err != nil {
				log.Fatal(err)
				return
			}
			updateRefreshToken(db, new_ref_token, &user)

			new_acc_token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
				"ipaddr": r.RemoteAddr,
				"uid":    user.Uid,
				"email":  user.Email,
				"exp":    time.Now().Add(time.Minute * 1).Unix(),
			}).SignedString(secret)
			if err != nil {
				log.Fatal(err)
				return
			}
			setTokensCookies(w, new_acc_token, new_ref_token)
		}
	})
	log.Fatal(http.ListenAndServe(":3000", mux))
}
func validateToken(token_to_verify string) (*jwt.Token, error) {
	return jwt.Parse(token_to_verify, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
}
func updateRefreshToken(db *sqlx.DB, token string, user *User) {
	encodedtoken := base64.StdEncoding.EncodeToString([]byte(token))
	db.MustExec("update users set ref_token=$1 where uid=$2", encodedtoken, user.Uid)

}
func setTokensCookies(w http.ResponseWriter, access string, refresh string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "Access-Token",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "Refresh-Token",
		Value:    refresh,
		Path:     "/",
		HttpOnly: true,
	})

}
