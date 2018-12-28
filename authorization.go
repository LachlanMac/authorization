package authorization


import (
	"golang.org/x/crypto/bcrypt"
	"database/sql"
	"fmt"
)

type User struct {
	
	Username string
	Password string
	Email string
}



func GenerateHashSalt(password string) string{


	passwordSlice := []byte(password)


	hash, err := bcrypt.GenerateFromPassword(passwordSlice, bcrypt.MinCost)
	if err != nil {
		fmt.Println(err)
	}


	return string(hash)

}

func VerifyHashedPassword(hashedPassword string, plainTextPassword []byte) bool{


	byteHash := []byte(hashedPassword)

	err := bcrypt.CompareHashAndPassword(byteHash, plainTextPassword)

	if err == nil{
		return true
	}else{
		return false
	}

}


func Authorize(account_id int, plainTextPassword []byte, db *sql.DB) bool {


	var password string
	sqlStatement := `SELECT password FROM users WHERE account_id=$1`
	row := db.QueryRow(sqlStatement, user.Username)

	err := row.Scan(&password)

	if err == sql.ErrNoRows {
		fmt.Println("Not found")
		return false
	}else if err != nil {
		fmt.Println("UNACUGHT ERROR")
		return false
	}else{


		fmt.Println("Found it, now compare passwords")


		return VerifyHashedPassword(password, plainTextPassword)

	}



}


func UserExists(user User, db *sql.DB) (bool, int){

	var account_id int
	sqlStatement := `SELECT account_id FROM users WHERE user_name=$1`
	row := db.QueryRow(sqlStatement, user.Username)

	err := row.Scan(&account_id)

	if err == sql.ErrNoRows {
		fmt.Println("USER NOT FOUND")
		return false, 0
	}else if err != nil {
		fmt.Println("UNCAUGHT ERROR : ", err)
		return true, 0
	}else{
		fmt.Println("USER ALREADY IN DB")
		return true, account_id
	}
}

func EmailExists(user User, db *sql.DB) bool{

	var account_id int
	sqlStatement := `SELECT account_id FROM users WHERE email=$1`
	row := db.QueryRow(sqlStatement, user.Email)

	err := row.Scan(&account_id)

	if err == sql.ErrNoRows {
		fmt.Println("USER NOT FOUND")
		return false
	}else if err != nil {
		fmt.Println("UNCAUGHT ERROR : ", err)
		return true
	}else{
		fmt.Println("USER ALREADY IN DB")
		return true
	}

}

