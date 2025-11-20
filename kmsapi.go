package main

/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"ep11go/ep11"
)

// ===================== GLOBALS =====================
var target ep11.Target_t

var (
	dataKey     []byte
	dataKeyFile string
	dbFile      string
	listenAddr  string
	serverCert  string
	serverKey   string
	caCert      string
)

// ===================== LOGGER =====================
var logger = log.New(os.Stdout, "", 0)

func logInfo(msg string) {
	logger.Printf("%s INFO %s", time.Now().Format(time.RFC3339), msg)
}

func logError(msg string) {
	logger.Printf("%s ERROR %s", time.Now().Format(time.RFC3339), msg)
}

// ===================== CONFIG =====================
func initConfig() {
	flag.StringVar(&dbFile, "db", "./keys.db", "Path to SQLite database file")
	flag.StringVar(&listenAddr, "port", ":4433", "Listen address in the form :port or host:port")
	flag.StringVar(&serverCert, "cert", "server.crt", "Server TLS certificate file")
	flag.StringVar(&serverKey, "key", "server.key", "Server TLS key file")
	flag.StringVar(&caCert, "ca", "ca.crt", "CA certificate for client verification")
	flag.Parse()

	if env := os.Getenv("DB_PATH"); env != "" {
		dbFile = env
	}
	if env := os.Getenv("PORT"); env != "" {
		listenAddr = "0.0.0.0:" + env
	}
}


func loadTLSConfig() (*tls.Config, error) {
	// Get base64 env vars
	caCrtB64 := os.Getenv("CA_CRT")
	serverCrtB64 := os.Getenv("SERVER_CRT")
	serverKeyB64 := os.Getenv("SERVER_KEY")

	if caCrtB64 == "" || serverCrtB64 == "" || serverKeyB64 == "" {
		return nil, fmt.Errorf("TLS environment variables missing")
	}

	// Decode base64
	caCrt, err := base64.StdEncoding.DecodeString(caCrtB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CA_CRT: %w", err)
	}

	serverCrt, err := base64.StdEncoding.DecodeString(serverCrtB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SERVER_CRT: %w", err)
	}

	serverKey, err := base64.StdEncoding.DecodeString(serverKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SERVER_KEY: %w", err)
	}

	// Load server cert and key
	cert, err := tls.X509KeyPair(serverCrt, serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server cert/key: %w", err)
	}

	// Create CA pool
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCrt) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	// Build TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // enforce client auth
		MinVersion:   tls.VersionTLS13,
	}

	return tlsConfig, nil
}


// ===================== DATABASE =====================
func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, err
	}
	sqlStmt := `
	CREATE TABLE IF NOT EXISTS keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pub TEXT NOT NULL,
		prv TEXT NOT NULL,
		aeskey TEXT NOT NULL,
		mac TEXT NOT NULL,
		coin TEXT NOT NULL,
		source TEXT NOT NULL,
		type TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(pub, source)
	);`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// ===================== AES KEY =====================
func initAESKey() ep11.KeyBlob {
	keyTemplate := ep11.Attributes{
		C.CKA_VALUE_LEN: 32,
		C.CKA_UNWRAP:    false,
		C.CKA_ENCRYPT:   true,
	}

	var aeskey ep11.KeyBlob
	aeskey, _ = ep11.GenerateKey(target,
		ep11.Mech(C.CKM_AES_KEY_GEN, nil),
		keyTemplate)

	return aeskey
}

// ===================== HANDLERS =====================
func generateDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	resp := "{ AESKEY}"
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func decryptDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	resp := "{ AESKEY}"
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func postKeyHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Pub    string `json:"pub"`
			Prv    string `json:"prv"`
			Coin   string `json:"coin"`
			Source string `json:"source"`
			Type   string `json:"type"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		if payload.Pub == "" || payload.Prv == "" || payload.Coin == "" ||
			(payload.Source != "user" && payload.Source != "backup") ||
			(payload.Type != "independent" && payload.Type != "tss") {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		perKeyAES := initAESKey()
		iv, _ := ep11.GenerateRandom(target, 16)
		encryptedPrv, err := ep11.EncryptSingle(target,
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			perKeyAES,
			[]byte(payload.Prv),
		)
		if err != nil {
			http.Error(w, "failed to encrypt private key: "+err.Error(), http.StatusInternalServerError)
			return
		}

		ivCipher := append(iv, encryptedPrv...)
		dataToMac := append(ivCipher, []byte(payload.Pub)...)
		dataToMac = append(dataToMac, []byte(payload.Source)...)
		dataToMac = append(dataToMac, []byte(payload.Coin)...)
		dataToMac = append(dataToMac, []byte(payload.Type)...)

		mac, err := ep11.SignSingle(target, ep11.Mech(C.CKM_AES_CMAC, nil), perKeyAES, dataToMac)
		if err != nil {
			http.Error(w, "failed to compute CMAC: "+err.Error(), http.StatusInternalServerError)
			return
		}

		encryptedPrvB64 := base64.StdEncoding.EncodeToString(append(iv, encryptedPrv...))
		aesKeyB64 := base64.StdEncoding.EncodeToString(perKeyAES)
		macB64 := base64.StdEncoding.EncodeToString(mac)

		_, err = db.Exec(
			"INSERT INTO keys(pub, prv, aeskey, mac, coin, source, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
			payload.Pub, encryptedPrvB64, aesKeyB64, macB64, payload.Coin, payload.Source, payload.Type,
		)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				http.Error(w, "pub + source already exists", http.StatusConflict)
				return
			}
			http.Error(w, "database error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"pub":    payload.Pub,
			"coin":   payload.Coin,
			"source": payload.Source,
			"type":   payload.Type,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func getKeyHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pub := r.URL.Query().Get("pub")
		source := r.URL.Query().Get("source")

		if pub == "" || (source != "user" && source != "backup") {
			http.Error(w, "pub and valid source (user|backup) are required", http.StatusBadRequest)
			return
		}

		var encryptedPrvB64, aesKeyB64, macB64, coin, keyType string
		err := db.QueryRow(
			"SELECT prv, aeskey, mac, coin, type FROM keys WHERE pub = ? AND source = ?", pub, source,
		).Scan(&encryptedPrvB64, &aesKeyB64, &macB64, &coin, &keyType)
		if err == sql.ErrNoRows {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "database error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		ivCipher, _ := base64.StdEncoding.DecodeString(encryptedPrvB64)
		aesKeyBytes, _ := base64.StdEncoding.DecodeString(aesKeyB64)
		storedMac, _ := base64.StdEncoding.DecodeString(macB64)

		if len(ivCipher) < 16 {
			http.Error(w, "invalid ciphertext", http.StatusInternalServerError)
			return
		}

		iv := ivCipher[:16]
		ciphertext := ivCipher[16:]
		dataToMac := append(ivCipher, []byte(pub)...)
		dataToMac = append(dataToMac, []byte(source)...)
		dataToMac = append(dataToMac, []byte(coin)...)
		dataToMac = append(dataToMac, []byte(keyType)...)

		computedMac, err := ep11.SignSingle(target, ep11.Mech(C.CKM_AES_CMAC, nil), aesKeyBytes, dataToMac)
		if err != nil {
			http.Error(w, "failed to compute CMAC", http.StatusInternalServerError)
			return
		}

		if !bytes.Equal(storedMac, computedMac) {
			http.Error(w, "integrity check failed", http.StatusInternalServerError)
			return
		}

		decryptedPrv, err := ep11.DecryptSingle(target, ep11.Mech(C.CKM_AES_CBC_PAD, iv), aesKeyBytes, ciphertext)
		if err != nil {
			http.Error(w, "failed to decrypt private key", http.StatusInternalServerError)
			return
		}

		resp := map[string]string{
			"pub":    pub,
			"prv":    string(decryptedPrv),
			"source": source,
			"type":   keyType,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// ===================== TLS =====================
func loadClientCAs(caFile string) *x509.CertPool {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("failed to read CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		log.Fatalf("failed to append CA cert")
	}
	return pool
}

// ===================== LOGGING MIDDLEWARE =====================
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()

		// Safe POST fields logging
		safeFields := ""
		if r.Method == http.MethodPost {
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
				bodyBytes, _ := json.Marshal(payload)
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				fields := []string{"pub", "coin", "source", "type"}
				safe := make([]string, 0)
				for _, f := range fields {
					if v, ok := payload[f]; ok {
						safe = append(safe, f+"="+fmt.Sprintf("%v", v))
					}
				}
				if len(safe) > 0 {
					safeFields = " fields: " + strings.Join(safe, ", ")
				}
			}
		}

		next.ServeHTTP(lrw, r)
		duration := time.Since(start)

		// Single-line log for rsyslog
		logInfo(fmt.Sprintf(
			"%s %s from %s -> %d (%s)%s",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			lrw.statusCode,
			duration.String(),
			safeFields,
		))
	})
}

// ===================== MAIN =====================
func main() {
	initConfig()
	logInfo("Configuration loaded")

	target = ep11.HsmInit("3.19")
	logInfo("HSM initialized")

	db, err := initDB()
	if err != nil {
		logError("Database init failed: " + err.Error())
		os.Exit(1)
	}
	defer db.Close()
	logInfo("Database initialized at " + dbFile)

	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.HandleFunc("/generateDataKey", generateDataKeyHandler).Methods("POST")
	r.HandleFunc("/decryptDataKey", decryptDataKeyHandler).Methods("POST")
	r.HandleFunc("/key", postKeyHandler(db)).Methods("POST")
	r.HandleFunc("/key", getKeyHandler(db)).Methods("GET")

        tlsConfig, err := loadTLSConfig()
	if err != nil {
		log.Fatalf("TLS setup failed: %v", err)
	}

	server := &http.Server{
		Addr:      listenAddr,
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	logInfo("Server listening on https://" + listenAddr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

