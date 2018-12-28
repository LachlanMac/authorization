package authorization


import (
	"golang.org/x/crypto/bcrypt"
	"database/sql"
	"fmt"
	"strconv"
)

type User struct {
	
	Username string
	Password string
	Email string
}


func GetUniqueIdentifier(username string) string {

	code := 71923

	for index, char := range username {
		code += (int(char) + index)
	}

	uniqueID := code / 2 + ((code + 2) * 2)

	uniqueString := strconv.Itoa(uniqueID)

	return uniqueString

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
	row := db.QueryRow(sqlStatement, account_id)

	err := row.Scan(&password)

	if err == sql.ErrNoRows {
		return false
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to Authorize a User", err)
		return false
	}else{
		return VerifyHashedPassword(password, plainTextPassword)
	}

}

func AwaitingAuthorization(account_id int, plainTextPassword []byte, db *sql.DB) (bool, string) {

	var password string
	var email string
	sqlStatement := `SELECT password, email FROM unverified_users WHERE account_id=$1`
	rows := db.QueryRow(sqlStatement, account_id)

	err := rows.Scan(&password, &email)

	if err == sql.ErrNoRows {
		return false, "nil"
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to Authorize a User", err)
		return false, "nil"
	}else{
		return VerifyHashedPassword(password, plainTextPassword), email
	}
}


func UserExists(user User, db *sql.DB) (bool, int){

	var account_id int
	sqlStatement := `SELECT account_id FROM users WHERE user_name=$1`
	row := db.QueryRow(sqlStatement, user.Username)

	err := row.Scan(&account_id)

	if err == sql.ErrNoRows {
		return false, 0
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to check if a User exists", err)
		return true, 0
	}else{

		return true, account_id
	}
}

func EmailExists(user User, db *sql.DB) bool{

	var account_id int
	sqlStatement := `SELECT account_id FROM users WHERE email=$1`
	row := db.QueryRow(sqlStatement, user.Email)

	err := row.Scan(&account_id)

	if err == sql.ErrNoRows {
		return false
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to check if an Email Address exists", err)
		return true
	}else{
		return true
	}

}

