package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/smtp"
)

var path = "static/"

func HomePage(w http.ResponseWriter, r *http.Request) {
	filename := "home.html"

	t, err := template.ParseFiles(path + filename)
	if err != nil {
		fmt.Println("Error when parsing file", err)
		return
	}
	err = t.ExecuteTemplate(w, filename, nil)
	if err != nil {
		fmt.Println("Error when executing template", err)
		return
	}

}

func DecryptPage(w http.ResponseWriter, r *http.Request) {
	filename := "decrypt.html"
	t, err := template.ParseFiles(path + filename)
	if err != nil {
		fmt.Println("Error when parsing file", err)
		return
	}
	err = t.ExecuteTemplate(w, filename, nil)
	if err != nil {
		fmt.Println("Error when executing template", err)
		return
	}
}

func DecryptMessage(w http.ResponseWriter, r *http.Request) {
	cipher := r.FormValue("cipher")
	key := r.FormValue("key")
	plaintext, err := Decrypt([]byte(key), cipher)
	if err != nil {
		fmt.Println("failed to decrypt the message", err)
	}
	fmt.Fprintln(w, plaintext)
}

func KeyGen(w http.ResponseWriter, r *http.Request) {
	filename := "keygen.html"
	t, err := template.ParseFiles(path + filename)
	if err != nil {
		fmt.Println("Error when parsing file", err)
		return
	}
	err = t.ExecuteTemplate(w, filename, nil)
	if err != nil {
		fmt.Println("Error when executing template", err)
		return
	}

}

func GenKeyHandler(w http.ResponseWriter, r *http.Request) {
	key, err := GenerateAESKey(128)
	if err != nil {
		fmt.Println("failed to generate key", err)
	}
	email := r.FormValue("email")
	var mail []string
	mail = append(mail, email)

	data := fmt.Sprintf("%x", key)
	SendKey(mail, data)
}

func EncryptHandler(w http.ResponseWriter, r *http.Request) {
	filename := "encrypt.html"
	t, err := template.ParseFiles(path + filename)
	if err != nil {
		fmt.Println("Error when parsing file", err)
		return
	}
	err = t.ExecuteTemplate(w, filename, nil)
	if err != nil {
		fmt.Println("Error when executing template", err)
		return
	}

}

func EncryptMessage(w http.ResponseWriter, r *http.Request) {
	message := r.FormValue("message")
	key := r.FormValue("key")
	encryptedMessage, err := Encrypt([]byte(key), message)
	if err != nil {
		fmt.Println("failed to encrypt the message", err)
	}
	fmt.Fprintln(w, encryptedMessage)
}

func Index(w http.ResponseWriter, r *http.Request) {
	filename := "index.html"
	t, err := template.ParseFiles(path + filename)
	if err != nil {
		fmt.Println("Error when parsing file", err)
		return
	}
	err = t.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		fmt.Println("Error when executing template", err)
		return
	}
}

func OnClick(w http.ResponseWriter, r *http.Request) {
	message := r.FormValue("message")
	key := r.FormValue("key")
	fmt.Fprintln(w, message)
	fmt.Fprintln(w, key)

}

func Encrypt(key []byte, message string) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("key cannot be empty")
	}
	if len(message) == 0 {
		return "", fmt.Errorf("message cannot be empty")
	}

	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func Decrypt(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size: %d", len(cipherText))
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func GenerateAESKey(keySize int) ([]byte, error) {
	// Check if the key size is valid
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, fmt.Errorf("invalid key size. Key size must be 128, 192, or 256 bits")
	}

	// Generate a random key of the specified size
	key := make([]byte, keySize/8)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func SendKey(receiverEmail []string, key string) {
	var to = receiverEmail
	from := "saurabhbgp9693@gmail.com"
	password := "ycdwztmuofrelctr"
	msg := "Subject: Hello!\n\nYour AES Key is:\n\n"

	msg = msg + key
	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, password, "smtp.gmail.com"),
		from, []string{to[0]}, []byte(msg))

	if err != nil {
		panic(err)
	}
}
