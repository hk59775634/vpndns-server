package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/vpndns/cdn/internal/config"
)

const (
	sessionCookieName = "vpndns_admin_session"
	sessionMaxAge     = 7 * 24 * 3600

	// defaultBcryptAdmin is bcrypt cost 10 for password "admin" (change via UI or PUT password_bcrypt).
	defaultBcryptAdmin = "$2a$10$IN3jbfshTCObzq4cWihrV.WOSX5O/1OejEpc/d3S5PmHJ3PCkrupO"
)

func newSessionSecret(c *config.Config) string {
	if c != nil {
		if s := strings.TrimSpace(c.Admin.SessionSecret); s != "" {
			return s
		}
	}
	if s := os.Getenv("VPNDNS_SESSION_SECRET"); strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "vpndns-insecure-fallback-change-session-secret"
	}
	return hex.EncodeToString(b)
}

func (s *Server) effectiveAdminUsername() string {
	u := strings.TrimSpace(s.cfgStore.Get().Admin.Username)
	if u == "" {
		return "admin"
	}
	return u
}

func (s *Server) effectivePasswordHash() []byte {
	h := strings.TrimSpace(s.cfgStore.Get().Admin.PasswordBcrypt)
	if h != "" {
		return []byte(h)
	}
	return []byte(defaultBcryptAdmin)
}

func (s *Server) signSessionToken(username string, expUnix int64) string {
	payload := username + "|" + strconv.FormatInt(expUnix, 10)
	mac := hmac.New(sha256.New, []byte(s.sessionSecret))
	_, _ = mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

func (s *Server) parseSessionToken(raw string) (username string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	dot := strings.LastIndex(raw, ".")
	if dot <= 0 || dot >= len(raw)-1 {
		return "", false
	}
	b64, sigHex := raw[:dot], raw[dot+1:]
	payloadBytes, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(payloadBytes) == 0 {
		return "", false
	}
	payload := string(payloadBytes)
	pipe := strings.LastIndex(payload, "|")
	if pipe <= 0 || pipe >= len(payload)-1 {
		return "", false
	}
	user := payload[:pipe]
	expStr := payload[pipe+1:]
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || expUnix < time.Now().Unix() {
		return "", false
	}
	mac := hmac.New(sha256.New, []byte(s.sessionSecret))
	_, _ = mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	sig, err := hex.DecodeString(sigHex)
	if err != nil || !hmac.Equal(expected, sig) {
		return "", false
	}
	return user, true
}

func (s *Server) sessionUser(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	u, ok := s.parseSessionToken(c.Value)
	if !ok {
		return ""
	}
	if u != s.effectiveAdminUsername() {
		return ""
	}
	return u
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   sessionMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

type loginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var b loginBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	wantUser := s.effectiveAdminUsername()
	if strings.TrimSpace(b.Username) != wantUser || bcrypt.CompareHashAndPassword(s.effectivePasswordHash(), []byte(b.Password)) != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	exp := time.Now().Add(sessionMaxAge * time.Second).Unix()
	token := s.signSessionToken(wantUser, exp)
	s.setSessionCookie(w, token)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	u := s.sessionUser(r)
	if u == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "username": u})
}

type passwordBody struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleAuthPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sessionUser(r) == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var b passwordBody
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	np := strings.TrimSpace(b.NewPassword)
	if len(np) < 6 {
		http.Error(w, "new_password: at least 6 characters", http.StatusBadRequest)
		return
	}
	if len(np) > 72 {
		http.Error(w, "new_password: at most 72 bytes", http.StatusBadRequest)
		return
	}
	if bcrypt.CompareHashAndPassword(s.effectivePasswordHash(), []byte(b.CurrentPassword)) != nil {
		http.Error(w, "current password incorrect", http.StatusUnauthorized)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(np), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cur := s.cfgStore.Get()
	if cur == nil {
		http.Error(w, "no config", http.StatusInternalServerError)
		return
	}
	c := *cur
	c.Admin.PasswordBcrypt = string(hash)
	c.Defaults()
	if err := config.Validate(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := config.Save(s.cfgPath, &c); err != nil {
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.cfgStore.Set(&c)
	if s.applyRuntime != nil {
		s.applyRuntime(&c)
	}
	_ = s.wl.LoadFromRedis(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "password_updated"})
}
