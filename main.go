package main

import (
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

// Embed everything inside the web folder
//
//go:embed web/*
var webFiles embed.FS

var (
	db       *sql.DB
	userLoc  *time.Location
	timeZone = "Asia/Kolkata"
)

type Task struct {
	ID            int64  `json:"id"`
	Title         string `json:"title"`
	TaskType      string `json:"task_type"` // 'rollover', 'daily', 'monthly'
	TargetDate    string `json:"target_date"`
	CreatedDate   string `json:"created_date"`
	CompletedDate string `json:"completed_date"`
	IsCompleted   bool   `json:"is_completed"`
	DaysTaken     int    `json:"days_taken"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./chronicle.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
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
		content TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		task_type TEXT NOT NULL,
		target_date TEXT,
		created_date TEXT NOT NULL,
		completed_date TEXT,
		is_completed INTEGER DEFAULT 0,
		days_taken INTEGER DEFAULT 0
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
		port = "8081" // Default set to 8081
	}

	// API Routes
	http.HandleFunc("/api/auth/status", handleAuthStatus)
	http.HandleFunc("/api/auth/setup", handleSetup)
	http.HandleFunc("/api/auth/login", handleLogin)
	http.HandleFunc("/api/auth/logout", handleLogout)

	http.HandleFunc("/api/today", authMiddleware(handleToday))
	http.HandleFunc("/api/log", authMiddleware(handleLog))
	http.HandleFunc("/api/tasks", authMiddleware(handleTasks))
	http.HandleFunc("/api/tasks/toggle", authMiddleware(handleTaskToggle))
	http.HandleFunc("/api/export/day", authMiddleware(handleExportDay))

	// Direct embedded filesystem root sub-tree
	contentStatic, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal("Failed to load embedded filesystem:", err)
	}
	fileServer := http.FileServer(http.FS(contentStatic))
	http.Handle("/", fileServer)

	fmt.Printf("✓ Chronicle Server running at http://0.0.0.0:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ---------------- HANDLERS ----------------

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM auth").Scan(&count)
	isConfigured := count > 0

	isLoggedIn := false
	cookie, err := r.Cookie("session_token")
	if err == nil {
		var exists int
		db.QueryRow("SELECT 1 FROM sessions WHERE token = ?", cookie.Value).Scan(&exists)
		isLoggedIn = (exists == 1)
	}

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
	db.QueryRow("SELECT COUNT(*) FROM auth").Scan(&count)
	if count > 0 {
		http.Error(w, "Already configured", 400)
		return
	}

	var req struct{ Username, Password string }
	json.NewDecoder(r.Body).Decode(&req)

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
	json.NewDecoder(r.Body).Decode(&req)

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

func handleToday(w http.ResponseWriter, r *http.Request) {
	today := getTodayDate()
	currentMonth := time.Now().In(userLoc).Format("2006-01")

	var content string
	db.QueryRow("SELECT content FROM daily_logs WHERE date = ?", today).Scan(&content)

	rows, _ := db.Query(`
		SELECT id, title, task_type, target_date, created_date, completed_date, is_completed, days_taken
		FROM tasks
		WHERE (task_type = 'rollover' AND (is_completed = 0 OR completed_date = ?))
		   OR (task_type = 'daily' AND target_date = ?)
		   OR (task_type = 'monthly' AND target_date = ?)
	`, today, today, currentMonth)
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		var completedDate, targetDate sql.NullString
		var isComp int
		rows.Scan(&t.ID, &t.Title, &t.TaskType, &targetDate, &t.CreatedDate, &completedDate, &isComp, &t.DaysTaken)
		t.IsCompleted = (isComp == 1)
		t.CompletedDate = completedDate.String
		t.TargetDate = targetDate.String
		tasks = append(tasks, t)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"date":    today,
		"content": content,
		"tasks":   tasks,
	})
}

func handleLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Date    string `json:"date"`
		Content string `json:"content"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Date == "" {
		req.Date = getTodayDate()
	}

	db.Exec(`
		INSERT INTO daily_logs (date, content, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(date) DO UPDATE SET content = excluded.content, updated_at = CURRENT_TIMESTAMP
	`, req.Date, req.Content)
	w.WriteHeader(http.StatusOK)
}

func handleTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var t Task
		json.NewDecoder(r.Body).Decode(&t)
		today := getTodayDate()
		t.CreatedDate = today

		if t.TaskType == "daily" {
			t.TargetDate = today
		} else if t.TaskType == "monthly" {
			t.TargetDate = time.Now().In(userLoc).Format("2006-01")
		}

		db.Exec(`
			INSERT INTO tasks (title, task_type, target_date, created_date, is_completed)
			VALUES (?, ?, ?, ?, 0)
		`, t.Title, t.TaskType, t.TargetDate, t.CreatedDate)
		w.WriteHeader(http.StatusCreated)
	}
}

func handleTaskToggle(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	today := getTodayDate()

	var createdDateStr string
	var isCompleted int
	err := db.QueryRow("SELECT created_date, is_completed FROM tasks WHERE id = ?", id).Scan(&createdDateStr, &isCompleted)
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}

	if isCompleted == 0 {
		createdDate, _ := time.Parse("2006-01-02", createdDateStr)
		todayDate, _ := time.Parse("2006-01-02", today)
		daysTaken := int(todayDate.Sub(createdDate).Hours() / 24)
		if daysTaken < 0 {
			daysTaken = 0
		}
		db.Exec(`UPDATE tasks SET is_completed = 1, completed_date = ?, days_taken = ? WHERE id = ?`, today, daysTaken, id)
	} else {
		db.Exec(`UPDATE tasks SET is_completed = 0, completed_date = NULL, days_taken = 0 WHERE id = ?`, id)
	}
	w.WriteHeader(http.StatusOK)
}

func handleExportDay(w http.ResponseWriter, r *http.Request) {
	date := r.URL.Query().Get("date")
	if date == "" {
		date = getTodayDate()
	}
	var content string
	db.QueryRow("SELECT content FROM daily_logs WHERE date = ?", date).Scan(&content)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.txt", date))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(content))
}
