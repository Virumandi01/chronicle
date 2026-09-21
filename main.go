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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed web/*
var webFiles embed.FS

var (
	db             *sql.DB
	userLoc        *time.Location
	timeZone       = "Asia/Kolkata"
	currentPairPIN string
	pinMutex       sync.Mutex
)

type Project struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	CreatedAt string `json:"created_at"`
}

type Task struct {
	ID            int64  `json:"id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	TaskType      string `json:"task_type"`
	TargetDate    string `json:"target_date"`
	CreatedDate   string `json:"created_date"`
	CompletedDate string `json:"completed_date"`
	IsCompleted   bool   `json:"is_completed"`
	DaysTaken     int    `json:"days_taken"`
}

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
	);
	CREATE TABLE IF NOT EXISTS tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT DEFAULT '',
		task_type TEXT NOT NULL,
		target_date TEXT,
		created_date TEXT NOT NULL,
		completed_date TEXT,
		is_completed INTEGER DEFAULT 0,
		days_taken INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS projects (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		path TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

	// Log & Task Endpoints
	http.HandleFunc("/api/day", authMiddleware(handleDay))
	http.HandleFunc("/api/log", authMiddleware(handleLog))
	http.HandleFunc("/api/tasks", authMiddleware(handleTasks))
	http.HandleFunc("/api/tasks/finish", authMiddleware(handleTaskFinish))
	http.HandleFunc("/api/export/day", authMiddleware(handleExportDay))
	http.HandleFunc("/api/export/month", authMiddleware(handleExportMonth))
	http.HandleFunc("/api/export/year", authMiddleware(handleExportYear))

	// Project & Git Analyser Endpoints
	http.HandleFunc("/api/projects", authMiddleware(handleProjects))
	http.HandleFunc("/api/git/analyze", authMiddleware(handleGitAnalyze))

	// Embedded UI
	contentStatic, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal("Embedded web load failed:", err)
	}
	http.Handle("/", http.FileServer(http.FS(contentStatic)))

	fmt.Printf("✓ Chronicle Server active at http://0.0.0.0:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ---------------- PROJECT & GIT ANALYSER HANDLERS ----------------

func handleProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rows, err := db.Query("SELECT id, name, path, created_at FROM projects ORDER BY id DESC")
		if err != nil {
			http.Error(w, "Database error", 500)
			return
		}
		defer rows.Close()

		projects := []Project{}
		for rows.Next() {
			var p Project
			rows.Scan(&p.ID, &p.Name, &p.Path, &p.CreatedAt)
			projects = append(projects, p)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(projects)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			Name string `json:"name"`
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Path == "" {
			http.Error(w, "Name and valid folder path are required", 400)
			return
		}

		// Normalize OS path
		cleanPath := filepath.Clean(req.Path)
		gitFolder := filepath.Join(cleanPath, ".git")
		if _, err := os.Stat(gitFolder); os.IsNotExist(err) {
			http.Error(w, "No valid .git repository found in this folder", 400)
			return
		}

		_, err := db.Exec("INSERT INTO projects (name, path) VALUES (?, ?)", req.Name, cleanPath)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func handleGitAnalyze(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("project_id")
	targetDate := r.URL.Query().Get("date")
	if targetDate == "" {
		targetDate = getTodayDate()
	}

	var name, repoPath string
	err := db.QueryRow("SELECT name, path FROM projects WHERE id = ?", projectID).Scan(&name, &repoPath)
	if err != nil {
		http.Error(w, "Project not found", 404)
		return
	}

	// Calculate 24-hour boundary for the day
	since := targetDate + " 00:00:00"
	until := targetDate + " 23:59:59"

	// Read-only Git command execution
	cmd := exec.Command("git", "-C", repoPath, "log",
		"--since="+since,
		"--until="+until,
		"--pretty=format:* [%h] %s (%an, %ar)",
	)

	out, err := cmd.Output()
	if err != nil {
		http.Error(w, "Git analysis failed: "+err.Error(), 500)
		return
	}

	commitSummary := strings.TrimSpace(string(out))
	if commitSummary == "" {
		commitSummary = "No git commits found on this date."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"project_name": name,
		"date":         targetDate,
		"commits":      commitSummary,
	})
}

// ---------------- EXISTING AUTH & DATA HANDLERS ----------------

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
		SameSite: http.SameSiteLaxMode, // Safari compatible
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

func handleDay(w http.ResponseWriter, r *http.Request) {
	date := r.URL.Query().Get("date")
	if date == "" {
		date = getTodayDate()
	}
	yearMonth := date
	if len(date) >= 7 {
		yearMonth = date[:7]
	}

	var content string
	_ = db.QueryRow("SELECT content FROM daily_logs WHERE date = ?", date).Scan(&content)

	activeTasks := []Task{}
	rows, err := db.Query(`
		SELECT id, title, description, task_type, target_date, created_date, completed_date, is_completed, days_taken
		FROM tasks
		WHERE (is_completed = 0 AND (
		   (task_type = 'until_finished' AND created_date <= ?)
		   OR (task_type = 'daily' AND (target_date = ? OR created_date = ?))
		   OR (task_type = 'monthly' AND strftime('%Y-%m', created_date) = ? AND created_date <= ?)
		)) OR (is_completed = 1 AND completed_date = ?)
	`, date, date, date, yearMonth, date, date)

	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t Task
			var completedDate, targetDate sql.NullString
			var isComp int
			if err := rows.Scan(&t.ID, &t.Title, &t.Description, &t.TaskType, &targetDate, &t.CreatedDate, &completedDate, &isComp, &t.DaysTaken); err == nil {
				t.IsCompleted = (isComp == 1)
				t.CompletedDate = completedDate.String
				t.TargetDate = targetDate.String
				activeTasks = append(activeTasks, t)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"date":    date,
		"content": content,
		"tasks":   activeTasks,
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

func handleTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var t Task
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			http.Error(w, "Invalid input", 400)
			return
		}
		if t.CreatedDate == "" {
			t.CreatedDate = getTodayDate()
		}

		if t.TaskType == "daily" && t.TargetDate == "" {
			t.TargetDate = t.CreatedDate
		} else if t.TaskType == "monthly" && t.TargetDate == "" && len(t.CreatedDate) >= 7 {
			t.TargetDate = t.CreatedDate[:7]
		}

		db.Exec(`
			INSERT INTO tasks (title, description, task_type, target_date, created_date, is_completed)
			VALUES (?, ?, ?, ?, ?, 0)
		`, t.Title, t.Description, t.TaskType, t.TargetDate, t.CreatedDate)
		w.WriteHeader(http.StatusCreated)
	}
}

func handleTaskFinish(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	finishDate := r.URL.Query().Get("date")
	if finishDate == "" {
		finishDate = getTodayDate()
	}

	var createdDateStr string
	var title string
	err := db.QueryRow("SELECT title, created_date FROM tasks WHERE id = ?", id).Scan(&title, &createdDateStr)
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}

	createdDate, _ := time.Parse("2006-01-02", createdDateStr)
	actionDate, _ := time.Parse("2006-01-02", finishDate)
	daysTaken := int(actionDate.Sub(createdDate).Hours() / 24)
	if daysTaken < 0 {
		daysTaken = 0
	}

	db.Exec(`UPDATE tasks SET is_completed = 1, completed_date = ?, days_taken = ? WHERE id = ?`, finishDate, daysTaken, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"title":        title,
		"created_date": createdDateStr,
		"days_taken":   daysTaken,
		"finish_date":  finishDate,
	})
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
