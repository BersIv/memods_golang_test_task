package auth

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"memods_golang_test_task/util"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
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
	decodedRefreshToken, err := base64.StdEncoding.DecodeString(refrToken.Value)
	if err != nil {
		log.Println("Error while decoding refresh token: ", err)
		http.Error(w, "Error while decoding refresh token", http.StatusUnauthorized)
		return
	}

	secret := os.Getenv("SECRET_KEY")
	token, err := jwt.ParseWithClaims(accessToken.Value, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		log.Println("Error while parsing token: ", err)
		http.Error(w, "Error while parsing token", http.StatusInternalServerError)
		return
	}

	claims, ok := token.Claims.(*MyCustomClaims)
	if !ok || !token.Valid {
		log.Println("Invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if claims.ClientIp != userIp {
		log.Println("Ip changed!")
	}

	refreshToken, err := h.Service.getRefreshToken(r.Context(), &claims.ID)
	if err != nil {
		log.Println("Invalid refresh token: ", err)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	err = util.CompareTokens(*refreshToken, string(decodedRefreshToken))
	if err != nil {
		log.Println("Refresh token not same in database: ", err)
		http.Error(w, "Refresh token not same in database", http.StatusUnauthorized)
		return
	}

	//var newTokens NewTokensRes
	newTokens, err := h.Service.getNewTokens(r.Context(), &claims.UserId)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println(claims, userIp, newTokens)

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
