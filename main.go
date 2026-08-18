package main

import (
	"archive/zip"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed web/*
var webFiles embed.FS

var (
	db       *sql.DB
	userLoc  *time.Location
	timeZone = "Asia/Kolkata"
)

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./chronicle.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		log.Fatal("DB Open Error:", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS auth (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		username TEXT NOT NULL,
		password_hash TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS daily_logs (
		date TEXT PRIMARY KEY,
		content TEXT DEFAULT '',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err = db.Exec(schema); err != nil {
		log.Fatal("DB Schema Error:", err)
	}

	userLoc, err = time.LoadLocation(timeZone)
	if err != nil {
		userLoc = time.Local
	}
}

func getTodayDate() string {
	return time.Now().In(userLoc).Format("2006-01-02")
}

func generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var exists int
		err = db.QueryRow("SELECT 1 FROM sessions WHERE token = ?", cookie.Value).Scan(&exists)
		if err != nil || exists != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func main() {
	initDB()
	defer db.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	// Auth Endpoints
	http.HandleFunc("/api/auth/status", handleAuthStatus)
	http.HandleFunc("/api/auth/setup", handleSetup)
	http.HandleFunc("/api/auth/login", handleLogin)
	http.HandleFunc("/api/auth/logout", handleLogout)

	// App Endpoints (Pure text & calendar)
	http.HandleFunc("/api/day", authMiddleware(handleDay))
	http.HandleFunc("/api/log", authMiddleware(handleLog))
	http.HandleFunc("/api/export/day", authMiddleware(handleExportDay))
	http.HandleFunc("/api/export/month", authMiddleware(handleExportMonth))
	http.HandleFunc("/api/export/year", authMiddleware(handleExportYear))

	// Embedded Static UI
	contentStatic, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal("Embedded web load failed:", err)
	}
	http.Handle("/", http.FileServer(http.FS(contentStatic)))

	fmt.Printf("✓ Chronicle Server active at http://0.0.0.0:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ---------------- AUTH HANDLERS ----------------

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM auth").Scan(&count)
	isConfigured := count > 0

	isLoggedIn := false
	cookie, err := r.Cookie("session_token")
	if err == nil {
		var exists int
		_ = db.QueryRow("SELECT 1 FROM sessions WHERE token = ?", cookie.Value).Scan(&exists)
		isLoggedIn = (exists == 1)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"configured": isConfigured,
		"logged_in":  isLoggedIn,
	})
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM auth").Scan(&count)
	if count > 0 {
		http.Error(w, "Already configured", 400)
		return
	}

	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, "Invalid input", 400)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	db.Exec("INSERT INTO auth (id, username, password_hash) VALUES (1, ?, ?)", req.Username, string(hash))
	w.WriteHeader(http.StatusOK)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct{ Username, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input", 400)
		return
	}

	var dbUser, dbHash string
	err := db.QueryRow("SELECT username, password_hash FROM auth WHERE id = 1").Scan(&dbUser, &dbHash)
	if err != nil || dbUser != req.Username {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := generateToken()
	db.Exec("INSERT INTO sessions (token) VALUES (?)", token)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusOK)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
}

// ---------------- LOG HANDLERS ----------------

func handleDay(w http.ResponseWriter, r *http.Request) {
	date := r.URL.Query().Get("date")
	if date == "" {
		date = getTodayDate()
	}

	var content string
	_ = db.QueryRow("SELECT content FROM daily_logs WHERE date = ?", date).Scan(&content)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"date":    date,
		"content": content,
	})
}

func handleLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Date    string `json:"date"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input", 400)
		return
	}
	if req.Date == "" {
		req.Date = getTodayDate()
	}

	_, err := db.Exec(`
		INSERT INTO daily_logs (date, content, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(date) DO UPDATE SET content = excluded.content, updated_at = CURRENT_TIMESTAMP
	`, req.Date, req.Content)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleExportDay(w http.ResponseWriter, r *http.Request) {
	date := r.URL.Query().Get("date")
	if date == "" {
		date = getTodayDate()
	}

	var content string
	_ = db.QueryRow("SELECT content FROM daily_logs WHERE date = ?", date).Scan(&content)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.txt", date))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(content))
}

func handleExportMonth(w http.ResponseWriter, r *http.Request) {
	month := r.URL.Query().Get("month")
	if month == "" && len(getTodayDate()) >= 7 {
		month = getTodayDate()[:7]
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=Chronicle_%s.zip", month))
	w.Header().Set("Content-Type", "application/zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	rows, err := db.Query("SELECT date, content FROM daily_logs WHERE strftime('%Y-%m', date) = ?", month)
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d, content string
			if err := rows.Scan(&d, &content); err == nil && d != "" {
				f, _ := zw.Create(fmt.Sprintf("%s/%s.txt", month, d))
				f.Write([]byte(content))
			}
		}
	}
}

func handleExportYear(w http.ResponseWriter, r *http.Request) {
	year := r.URL.Query().Get("year")
	if year == "" && len(getTodayDate()) >= 4 {
		year = getTodayDate()[:4]
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=Chronicle_%s.zip", year))
	w.Header().Set("Content-Type", "application/zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	rows, err := db.Query("SELECT date, content FROM daily_logs WHERE strftime('%Y', date) = ?", year)
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d, content string
			if err := rows.Scan(&d, &content); err == nil && len(d) >= 7 {
				month := d[:7]
				f, _ := zw.Create(fmt.Sprintf("%s/%s/%s.txt", year, month, d))
				f.Write([]byte(content))
			}
		}
	}
}
