package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/smtp"
)

var path = "static/"

func HomePage(w http.ResponseWriter) {
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
	if r.Method == "POST" {
		cipherM := r.FormValue("cipher")
		key := r.FormValue("key")
		plaintext, err := Decrypt([]byte(key), cipherM)
		if err != nil {
			fmt.Println("failed to decrypt the message", err)
		}

		_, err = fmt.Fprintf(w, `
			<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta http-equiv="X-UA-Compatible" content="IE=edge">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<link rel="preconnect" href="https://fonts.googleapis.com">
				<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
				<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@500&family=Pacifico&display=swap" rel="stylesheet">
 				<link rel="stylesheet" href="/static/css/enc.css">
 				<link rel="stylesheet" href="/static/css/nav.css">
				<title>Decrypt Cipher</title>
			</head>
		
			<body>
				<div class="container">
					
				<div class="encryptionHeader">
				<div class="nav-logo">
				<a href="/" ><img src='/static/img/logo.jpg'  alt="image"></a>
				</div>

				<div class="nav-title">
					<h1>Encryption World</h1>
				</div>
	
				<ul class="nav-list">
					<li class="nav-item">
						<a href="/" >Home</a>
					</li>

					<li class="nav-item">
						<a href="/about" >About</a>
					</li>
					<li class="nav-item">
						<a href="#contactus" >Contact Us</a>
					</li>
					<li class="nav-item">
						<a href="#" >Account</a>
					</li>
				</ul>
			</div>

					<div class="formbox">
						<h1 style="text-align: center">Decrypt Message</h1>
						<hr style="color: #5d0000; width: 4in">
						<form id="enc-form" method="POST">
							<label for="message">Cipher Text :</label><br>
							<input style="height: 0.7in; " name="cipher" id="cipher" required>
							<br>
							<label for="key">Key :</label>
							<br>
							<input type="text" name="key" id="key" minlength="32" maxlength="32" required>
							<br>
							<input type="submit" name="submit" id="submit" value="Decrypt">
							<br>
							<br>
							<br>
							<label for="plaintext">Plaintext :</label><br>
							<textarea name="plaintext" id="plaintext" readonly>%s</textarea>
			
						</form>
					</div>
				</div>
			</body>
`, plaintext)
		if err != nil {
			fmt.Println("error occur when executing if decryption page", err)
		}
	} else {
		_, err := fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en">
		<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<link rel="preconnect" href="https://fonts.googleapis.com">
		<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
		<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@500&family=Pacifico&display=swap" rel="stylesheet">
 		<link rel="stylesheet" href="/static/css/enc.css">
 		<link rel="stylesheet" href="/static/css/nav.css">
		<title>Decrypt Cipher</title>
		</head>
		<body>
		<div class="container">
		
		<div class="encryptionHeader">
		<div class="nav-logo">
		<a href="/" ><img src='/static/img/logo.jpg'  alt="image"></a>
		</div>

		<div class="nav-title">
			<h1>Encryption World</h1>
		</div>

		<ul class="nav-list">
			<li class="nav-item">
				<a href="/" >Home</a>
			</li>

			<li class="nav-item">
				<a href="/about" >About</a>
			</li>
			<li class="nav-item">
				<a href="#contactus" >Contact Us</a>
			</li>
			<li class="nav-item">
				<a href="#" >Account</a>
			</li>
		</ul>
	</div>

		<div class="formbox">
		<h1 style="text-align: center">Decrypt Message</h1>
		<hr style="color: #5d0000; width: 4in">
		<form id="enc-form" method="POST">
		<label for="message">Cipher Text :</label><br>
		<input style="height: 0.7in; " name="cipher" id="cipher" required>
		<br>
		<label for="key">Key :</label>
		<br>
		<input type="text" name="key" id="key" minlength="32" maxlength="32" required>
		<br>
		<input type="submit" name="submit" id="submit" value="Decrypt">
		<br>
		<br>
		<br>
		</form>
		</div>
		</div>
		</body>
		`)
		if err != nil {
			fmt.Println("error occur when executing else in decryption page", err)
		}
	}
}

func KeyGen(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		keyType := r.FormValue("dropdown")
		if keyType == "aes" {

			key, err := GenerateAESKey(128)
			if err != nil {
				fmt.Println("failed to generate key", err)
			}

			data := fmt.Sprintf("%x", key)

			email := r.FormValue("email")
			var mail []string
			mail = append(mail, email)

			SendAESKey(mail, data)
		} else {
			publicKey, privateKey := GenerateRSAKey()

			email := r.FormValue("email")
			var mail []string
			mail = append(mail, email)

			SendRSAKey(mail, publicKey, &privateKey)
		}

		email := r.FormValue("email")
		var mail []string
		mail = append(mail, email)

		//filename := "keygen.html"
		str := "key successfully generated and sent"

		_, err := fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en">
		<head>
		   <meta charset="UTF-8">
		   <meta http-equiv="X-UA-Compatible" content="IE=edge">
		   <meta name="viewport" content="width=device-width, initial-scale=1.0">
			<link rel="preconnect" href="https://fonts.googleapis.com">
			<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
			<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@500&family=Pacifico&display=swap" rel="stylesheet">
			<link rel="stylesheet" href="/static/css/enc.css">
			<link rel="stylesheet" href="/static/css/nav.css">
		   <title>Key Generation</title>
		</head>
		<body>
		<div class="container">
		   
				<div class="encryptionHeader">
				<div class="nav-logo">
				<a href="/" ><img src='/static/img/logo.jpg'  alt="image"></a>
				</div>

				<div class="nav-title">
					<h1>Encryption World</h1>
				</div>
	
				<ul class="nav-list">
					<li class="nav-item">
						<a href="/" >Home</a>
					</li>

					<li class="nav-item">
						<a href="/about" >About</a>
					</li>
					<li class="nav-item">
						<a href="#contactus" >Contact Us</a>
					</li>
					<li class="nav-item">
						<a href="#" >Account</a>
					</li>
				</ul>
			</div>

		   <div class="formbox">
		
		       <h1>Generate Key</h1>
		       <hr style="color: black; width: 4in">
		
		
		       <form id="enc-form" method="GET">
		           <br>
		           <br>
		           <br>
		           <br>
                   <h3 style="color: white; text-align:right ; margin-right:35px">%s to %s<h3>
		           <br>
		           <input type="submit" name="submit" id="submit" value="Go Back">
		           <br>
					
		
		       </form>
		   </div>
		</div>
		</body>
		</html>`, str, mail[0])
		if err != nil {
			fmt.Println("error occur when executing if condition in key generation page", err)
		}
	} else {
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
}

func GenerateRSAKey() (rsa.PublicKey, rsa.PrivateKey) {

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err.Error())
	}

	pk := key.PublicKey

	return pk, *key
}

func AboutPage(w http.ResponseWriter) {
	filename := "about.html"
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

func EncryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		message := r.FormValue("message")
		key := r.FormValue("key")
		ciphertext, err := Encrypt([]byte(key), message)
		if err != nil {
			fmt.Println("failed to encrypt the message", err)
		}
		_, err = fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta http-equiv="X-UA-Compatible" content="IE=edge">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<link rel="preconnect" href="https://fonts.googleapis.com">
			<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
			<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@500&family=Pacifico&display=swap" rel="stylesheet">
			<title>Encrypt Message</title>
			<link rel="stylesheet" href="/static/css/enc.css">
			<link rel="stylesheet" href="/static/css/nav.css">
		</head>
	
		<body >
		<div class="container">
			
		<div class="encryptionHeader">
		<div class="nav-logo">
		<a href="/" ><img src='/static/img/logo.jpg'  alt="image"></a>
		</div>

		<div class="nav-title">
			<h1>Encryption World</h1>
		</div>

		<ul class="nav-list">
			<li class="nav-item">
				<a href="/" >Home</a>
			</li>

			<li class="nav-item">
				<a href="/about" >About</a>
			</li>
			<li class="nav-item">
				<a href="#contactus" >Contact Us</a>
			</li>
			<li class="nav-item">
				<a href="#" >Account</a>
			</li>
		</ul>
	</div>

			<div class="formbox">
				<h1 style="text-align: center">Encrypt Message</h1>
				<hr style="color: black; width: 4in">
				<form id="enc-form" method="POST">
					<label for="message">Message :</label><br>
					<input style="height: 0.7in; " name="message" id="message" required>
					<br>
					<label for="key">Key :</label>
					<br>
					<input type="text" name="key" id="key" minlength="32" maxlength="32" required>
					<br>
					<input type="submit"  name="submit" id="submit" value="Encrypt">
					<br>
					<br>
					<br>
					<label for="ciphertext">Encrypted Message :</label><br>
					<input type="text" name="ciphertext" id="ciphertext" value="%s" readonly>
				</form>
			</div>
		</div>
		</body>
		</html>
	`, ciphertext)
		if err != nil {
			fmt.Println("error occur when executing if condition in encryption page", err)
		}
	} else {

		_, err := fmt.Fprintf(w, `<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta http-equiv="X-UA-Compatible" content="IE=edge">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<link rel="preconnect" href="https://fonts.googleapis.com">
			<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
			<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@500&family=Pacifico&display=swap" rel="stylesheet">
			<title>Encrypt Message </title>
			<link rel="stylesheet" href="/static/css/enc.css">
			<link rel="stylesheet" href="/static/css/nav.css">
		</head>
		
		<body>
		<div class="container">
			
		<div class="encryptionHeader">
		<div class="nav-logo">
		<a href="/" ><img src='/static/img/logo.jpg'  alt="image"></a>
		</div>

		<div class="nav-title">
			<h1>Encryption World</h1>
		</div>

		<ul class="nav-list">
			<li class="nav-item">
				<a href="/" >Home</a>
			</li>

			<li class="nav-item">
				<a href="about" >About</a>
			</li>
			<li class="nav-item">
				<a href="#contactus" >Contact Us</a>
			</li>
			<li class="nav-item">
				<a href="#" >Account</a>
			</li>
		</ul>
	</div>

			<div class="formbox">
				<h1 style="text-align: center">Encrypt Message</h1>
				<hr style="color: black; width: 4in">
				<form id="enc-form" method="POST">
					<label for="message">Message :</label><br>
					<input style="height: 0.7in; " name="message" id="message" required>
					<br>
					<label for="key">Key :</label>
					<br>
					<input type="text" name="key" id="key" minlength="32" maxlength="32" required>
					<br>
					<input type="submit"  name="submit" id="submit" value="Encrypt">
					<br>
					<br>
					<br>
				</form>
			</div>
		</div>
		</body>
		</html>`)
		if err != nil {
			fmt.Println("error occur when executing else condition in encryption page", err)
		}
	}

}

func EncryptMessage(w http.ResponseWriter, r *http.Request) {
	message := r.FormValue("message")
	key := r.FormValue("key")
	encryptedMessage, err := Encrypt([]byte(key), message)
	if err != nil {
		fmt.Println("failed to encrypt the message", err)
	}
	_, err = fmt.Fprintln(w, encryptedMessage)
	if err != nil {
		panic(err)
	}
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

func SendAESKey(receiverEmail []string, key string) {
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

func SendRSAKey(receiverEmail []string, pubKey rsa.PublicKey, priKey *rsa.PrivateKey) {
	var to = receiverEmail
	from := "saurabhbgp9693@gmail.com"
	password := "ycdwztmuofrelctr"
	msg := "Subject: Hello!\n\nYour RSA Keys are:\n\n"

	priKeyString, err := RSAPriKeyToString(priKey)
	if err != nil {
		panic(err)
	}

	pubKeyString, err := RSAPubKeyToString(pubKey)
	if err != nil {
		panic(err)
	}

	msg = msg + pubKeyString + "\n" + priKeyString

	err = smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, password, "smtp.gmail.com"),
		from, []string{to[0]}, []byte(msg))

	if err != nil {
		panic(err)
	}
}

func RSAPubKeyToString(pubKey rsa.PublicKey) (string, error) {
	// Convert the public key to bytes
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		fmt.Println("Error converting public key to bytes:", err)
		return "nil", err
	}

	// Create a PEM encoded public key string
	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Convert the PEM encoded public key to a string
	publicKeyString := string(publicKeyPem)
	return publicKeyString, nil

}

func RSAPriKeyToString(priKey *rsa.PrivateKey) (string, error) {

	// Convert the private key to bytes
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(priKey) // or x509.MarshalPKCS8PrivateKey(privateKey)

	// Create a PEM encoded private key string
	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY", // or "PRIVATE KEY" for PKCS8
		Bytes: privateKeyBytes,
	})

	// Convert the PEM encoded private key to a string
	privateKeyString := string(privateKeyPem)

	return privateKeyString, nil
}
