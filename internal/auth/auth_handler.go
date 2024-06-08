package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
)

type Handler struct {
	Service
}

func NewHandler(s Service) *Handler {
	return &Handler{Service: s}
}

func (h *Handler) GetTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		log.Println("Wrong method")
		http.Error(w, "Wrong method", http.StatusMethodNotAllowed)
	}
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user.Ip, err = getIP(r)
	if err != nil {
		log.Println("Error during getting IP: ", err)
		http.Error(w, "Error during getting IP", http.StatusInternalServerError)
		return
	}
	tokens, err := h.Service.getTokens(r.Context(), &user)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println("User doesn't exist", &user.Id)
			http.Error(w, "User doesn't exist", http.StatusUnauthorized)
			return
		}
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	setCookiesAndRespond(w, tokens)
}

func setCookiesAndRespond(w http.ResponseWriter, tokens *NewTokensRes) {
	cookie := http.Cookie{
		Name:  "accessToken",
		Value: tokens.AccessToken,
	}
	http.SetCookie(w, &cookie)

	cookie = http.Cookie{
		Name:  "refreshToken",
		Value: tokens.RefreshToken,
	}
	http.SetCookie(w, &cookie)

	w.WriteHeader(http.StatusOK)
}

func getIP(r *http.Request) (string, error) {
	ips := r.Header.Get("X-Forwarded-For")
	splitIps := strings.Split(ips, ",")

	if len(splitIps) > 0 {
		netIP := net.ParseIP(splitIps[len(splitIps)-1])
		if netIP != nil {
			return netIP.String(), nil
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}

	netIP := net.ParseIP(ip)
	if netIP != nil {
		ip := netIP.String()
		if ip == "::1" {
			return "127.0.0.1", nil
		}
		return ip, nil
	}

	return "", errors.New("IP not found")
}
