package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	DB  *sql.DB
	RDB *redis.Client
}

type User struct {
	UserID   string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func validateUser(user User) error {
	if user.Name == "" {
		return errors.New("name is required")
	}

	return nil
}

func createUser(db *sql.DB, user User) error {
	var exists bool
	var err error
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)", user.Email).Scan(&exists)
	if err != nil || exists {
		fmt.Printf("User exists: %s\n", err)
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	if err != nil {
		fmt.Printf("Could not hash password: %s\n", err)
		return err
	}

	_, err = db.Exec("INSERT INTO users (name, email, password) VALUES($1, $2, $3)",
		user.Name, user.Email, string(hashedPassword))
	if err != nil {
		fmt.Printf("Could not create user: %s\n", err)
		return err
	}

	return nil
}

func initDB(db *sql.DB) {
	// Create users table
	_, err := db.Exec(`
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
	CREATE TABLE IF NOT EXISTS users (
		user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
		name VARCHAR,
		email VARCHAR,
		password VARCHAR,
		role VARCHAR DEFAULT 'user'
	);
	`)
	if err != nil {
		panic(err)
	}
}

func InvalidRequestError(c echo.Context) error {
	return c.JSON(400, echo.Map{"error": "Invalid request"})
}

func UnauthorizedError(c echo.Context) error {
	return c.JSON(401, echo.Map{"error": "Unauthorized"})
}

func SetCookie(c echo.Context, key, value string, expiration time.Time) {
	cookie := &http.Cookie{
		Name:     key,
		Value:    value,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiration,
	}
	c.SetCookie(cookie)
}

func (s *Server) VerifySessionAndUserID(ctx context.Context, sessionID string, userID string) bool {
	storedUserID, err := s.RDB.Get(ctx, sessionID).Result()
	if err != nil {
		fmt.Printf("Session not found or expired: %s\n", err)
		return false
	}

	if storedUserID != userID {
		fmt.Printf("Invalid session: %s\n", err)
		return false
	}

	return true
}

func (s *Server) SessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID, err := c.Cookie("userid")
		if err != nil {
			fmt.Printf("User cookie not found: %s\n", err)
			return UnauthorizedError(c)
		}

		sessionID, err := c.Cookie("session")
		if err != nil {
			fmt.Printf("Session cookie not found: %s\n", err)
			return UnauthorizedError(c)
		}

		if !s.VerifySessionAndUserID(context.Background(), sessionID.Value, userID.Value) {
			fmt.Printf("Invalid session: %s\n", err)
			return UnauthorizedError(c)
		}

		c.Set("userID", userID.Value)
		c.Set("sessionID", sessionID.Value)
		return next(c)
	}
}

func (s *Server) AdminAuthMiddleware(username, password string, c echo.Context) (bool, error) {
	// Be careful to use constant time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(username), []byte(os.Getenv("ADMIN_USERNAME"))) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(os.Getenv("ADMIN_PASSWORD"))) == 1 {
		return true, nil
	}
	return false, nil
}

func (s *Server) UserSignUpHandler(c echo.Context) error {
	var user User

	err := c.Bind(&user)
	if err != nil || len(user.Email) == 0 || len(user.Password) == 0 {
		return InvalidRequestError(c)
	}

	err = createUser(s.DB, user)
	if err != nil {
		fmt.Printf("Error creating user: %s\n", err)
		return InvalidRequestError(c)
	}

	return c.JSON(200, echo.Map{"status": "User created"})
}

func (s *Server) UserSignInHandler(c echo.Context) error {
	var user User

	// Read JSON body
	err := c.Bind(&user)
	if err != nil || len(user.Email) == 0 || len(user.Password) == 0 {
		return InvalidRequestError(c)
	}

	var userID string
	var hashedPassword string
	// Check if user exists
	err = s.DB.QueryRow("SELECT user_id, password FROM users WHERE email=$1", user.Email).Scan(&userID, &hashedPassword)
	if err != nil {
		fmt.Printf("Could find user information: %s\n", err)
		return UnauthorizedError(c)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		fmt.Printf("Failed to compare password hashes: %s\n", err)
		return UnauthorizedError(c)
	}

	sessionID := uuid.New().String()
	err = s.RDB.Set(c.Request().Context(), sessionID, userID, time.Hour*24).Err()
	if err != nil {
		fmt.Printf("Failed to create user session: %s\n", err)
		return UnauthorizedError(c)
	}

	SetCookie(c, "userid", userID, time.Now().Add(time.Hour*24))
	SetCookie(c, "session", sessionID, time.Now().Add(time.Hour*24))

	return c.JSON(200, echo.Map{
		"status": "success",
	})
}

func (s *Server) UserInfoHandler(c echo.Context) error {
	userID := c.Get("userID").(string)
	var userEmail string
	var userName string
	err := s.DB.QueryRow("SELECT email, name FROM users WHERE user_id=$1", userID).Scan(&userEmail, &userName)
	if err != nil {
		fmt.Printf("Could find user information: %s\n", err)
		return UnauthorizedError(c)
	}
	return c.JSON(200, echo.Map{
		"user_id": userID,
		"email":   userEmail,
		"name":    userName,
	})
}

func (s *Server) UserSignOutHandler(c echo.Context) error {
	sessionID := c.Get("sessionID").(string)
	s.RDB.Del(c.Request().Context(), sessionID)

	SetCookie(c, "userid", "", time.Unix(0, 0))
	SetCookie(c, "session", "", time.Unix(0, 0))

	return c.JSON(201, echo.Map{"status": "success"})
}

func (s *Server) UserSessionVerify(c echo.Context) error {
	userID := c.QueryParam("userid")
	sessionID := c.QueryParam("sessionid")

	if len(userID) == 0 || len(sessionID) == 0 {
		return InvalidRequestError(c)
	}

	if !s.VerifySessionAndUserID(c.Request().Context(), sessionID, userID) {
		fmt.Printf("Invalid session (%s, %s)\n", sessionID, userID)
		return UnauthorizedError(c)
	}

	var userEmail string
	var userName string
	err := s.DB.QueryRow("SELECT email, name FROM users WHERE user_id=$1", userID).Scan(&userEmail, &userName)
	if err != nil {
		fmt.Printf("Could find user information: %s\n", err)
		return UnauthorizedError(c)
	}

	return c.JSON(200, echo.Map{
		"user_id": userID,
		"email":   userEmail,
		"name":    userName,
	})
}

func (s *Server) AdminListUsersHandler(c echo.Context) error {
	// Query all users from the database
	rows, err := s.DB.Query("SELECT user_id, name, email FROM users")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to query users"})
	}
	defer rows.Close()

	// Iterate over the rows and build a list of users
	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.UserID, &user.Name, &user.Email); err != nil {
			return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to scan user row"})
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to iterate over user rows"})
	}

	// Return the list of users
	return c.JSON(http.StatusOK, users)
}

func (s *Server) AdminCreateUserHandler(c echo.Context) error {
	// Parse the request body to get the user data
	var user User
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request body"})
	}

	// Validate the user data
	if err := validateUser(user); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": err.Error()})
	}

	// Create a new user in the database
	err := createUser(s.DB, user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to create user"})
	}

	// Return a success response
	return c.JSON(http.StatusOK, echo.Map{"message": "User created successfully"})
}

func (s *Server) AdminUpdateUserHandler(c echo.Context) error {
	// Parse the request parameters to get the user ID
	userID := c.Param("id")

	// Parse the request body to get the updated user data
	var user User
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid request body"})
	}

	// Update the user with the given ID in the database
	// Prepare the SQL statement
	stmt, err := s.DB.Prepare("UPDATE users SET name=$1, email=$2, password=$3 WHERE id=$4")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to prepare SQL statement"})
	}
	defer stmt.Close()

	// Execute the SQL statement to update the user
	_, err = stmt.Exec(user.Name, user.Email, user.Password, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to update user"})
	}

	// Return a success response
	return c.JSON(http.StatusOK, echo.Map{"message": "User updated successfully"})
}

func (s *Server) AdminDeleteUserHandler(c echo.Context) error {
	// Parse the request parameters to get the user ID
	userID := c.Param("id")

	// Delete the user with the given ID from the database
	// Prepare the SQL statement
	stmt, err := s.DB.Prepare("DELETE FROM users WHERE id=$1")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to prepare SQL statement"})
	}
	defer stmt.Close()

	// Execute the SQL statement to delete the user
	result, err := stmt.Exec(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to delete user"})
	}

	// Check the affected rows to determine if the user was deleted successfully
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "Failed to get affected rows"})
	}

	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, echo.Map{"error": "User not found"})
	}

	// Return a success response
	return c.JSON(http.StatusOK, echo.Map{"message": "User deleted successfully"})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		panic(err)
	}
	defer db.Close()
	initDB(db)

	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_URL"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
	defer rdb.Close()

	e := echo.New()
	s := Server{
		DB:  db,
		RDB: rdb,
	}

	e.Use(middleware.LoggerWithConfig(middleware.DefaultLoggerConfig))

	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: allowedOrigins,
	}))

	e.Use(middleware.Recover())

	dashboard := e.Group("/dashboard")
	dashboard.Use(middleware.BasicAuth(s.AdminAuthMiddleware))
	dashboard.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Root:   "www",
		Browse: false,
	}))

	api := e.Group("/api")
	api.POST("/register", s.UserSignUpHandler)
	api.POST("/login", s.UserSignInHandler)
	api.POST("/logout", s.UserSignOutHandler, s.SessionMiddleware)
	api.GET("/profile", s.UserInfoHandler, s.SessionMiddleware)
	api.GET("/verify-session", s.UserSessionVerify)

	adminApi := api.Group("/admin")
	adminApi.Use(middleware.BasicAuth(s.AdminAuthMiddleware))
	adminApi.GET("/admin/users", s.AdminListUsersHandler)
	adminApi.POST("/admin/users/create", s.AdminCreateUserHandler)
	adminApi.PUT("/admin/users/:id", s.AdminUpdateUserHandler)
	adminApi.DELETE("/admin/users/:id", s.AdminDeleteUserHandler)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3030"
	}
	e.Start(":" + port)
}
