package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
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
		return
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
	tokens, err := h.Service.getNewTokens(r.Context(), &user.Id)
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

func (h *Handler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Println("Wrong method")
		http.Error(w, "Wrong method", http.StatusMethodNotAllowed)
		return
	}
	userIp, err := getIP(r)
	if err != nil {
		log.Println("Error during getting IP: ", err)
		http.Error(w, "Error during getting IP", http.StatusInternalServerError)
		return
	}

	accessToken, err := r.Cookie("Access-Token")
	if err != nil {
		log.Println("Access-Token cookie is missing")
		http.Error(w, "Access-Token cookie is missing", http.StatusUnauthorized)
		return
	}
	refrToken, err := r.Cookie("Refresh-Token")
	if err != nil {
		log.Println("Refresh-Token cookie is missing")
		http.Error(w, "Refresh-Token cookie is missing", http.StatusUnauthorized)
		return
	}
	request := RefreshTokenReq{Ip: userIp, AccessToken: *accessToken, RefreshToken: *refrToken}

	userId, err := h.Service.checkTokens(r.Context(), &request)
	if err != nil {
		log.Println("Error while compairing tokens: ", err)
		http.Error(w, fmt.Sprintf("Error Error while compairing tokens: %s", err.Error()), http.StatusUnauthorized)
		return
	}

	time.Sleep(10 * time.Second)
	newTokens, err := h.Service.getNewTokens(r.Context(), userId)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	setCookiesAndRespond(w, newTokens)
}

func setCookiesAndRespond(w http.ResponseWriter, tokens *NewTokensRes) {
	cookie := http.Cookie{
		Name:  "Access-Token",
		Value: tokens.AccessToken,
	}
	http.SetCookie(w, &cookie)

	cookie = http.Cookie{
		Name:  "Refresh-Token",
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
