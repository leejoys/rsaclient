package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Data struct {
	ID   int
	Text string
}

type Result struct {
	Type ResultType
	Text string
}

type ResultType int

const (
	ResultTypeError ResultType = iota
	ResultTypeRedirect
	ResultTypeMessage
)

type Env struct {
	PrivateKey      string `json:"private_key"`
	PublicKey       string `json:"public_key"`
	ServerPublicKey string `json:"server_public_key"`
}

type ServerResponse struct {
	Processed string `json:"processed"`
	Code      int    `json:"code"`
	Reason    string `json:"reason"`
	Signature string `json:"signature"`
}

// getPrivateKey is a function that converts env.PrivateKey to *rsa.PrivateKey
func getPrivateKey(env Env) (*rsa.PrivateKey, error) {
	// Decode the string env.PrivateKey from base64 to bytes
	privateKeyBytes, err := base64.StdEncoding.DecodeString(env.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Error when decoding the PrivateKey string: %s", err.Error())
	}

	// Parse the bytes into a *rsa.PrivateKey
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("Error when parsing PKCS1PrivateKey: %s", err.Error())
	}

	// Return *rsa.PrivateKey
	return privateKey, nil
}

// getServerPublicKey is a function that converts env.ClientPublicKey to *rsa.PublicKey
func getServerPublicKey(env Env) (*rsa.PublicKey, error) {
	// Decode the string env.ClientPublicKey from base64 to bytes
	clientPublicKeyBytes, err := base64.StdEncoding.DecodeString(env.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Error when decoding the ClientPublicKey string: %s", err.Error())
	}

	// Parse the bytes into a PKIXPublicKey structure
	clientPublicKey, err := x509.ParsePKCS1PublicKey(clientPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("Error when parsing PKIXPublicKey: %s", err.Error())
	}

	// Return *rsa.PublicKey
	return clientPublicKey, nil
}

func Process(data Data, env Env) Result {

	apiUrl := "http://localhost:3828/checkout/insert"

	reqParams := map[string]string{
		"id":   strconv.Itoa(data.ID),
		"text": data.Text,
	}

	keys := make([]string, 0, len(reqParams))
	for k := range reqParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var str strings.Builder
	for _, key := range keys {
		str.WriteString(key + ":" + reqParams[key] + ";")
	}

	rsaPrivateKey, err := getPrivateKey(env)
	if err != nil {
		return Result{
			Type: ResultTypeError,
			Text: "getPrivateKey error: " + err.Error(),
		}
	}

	// Создаем хеш из строки с помощью алгоритма SHA256
	hashed := sha256.Sum256([]byte(str.String()))
	// Подписываем хеш с помощью RSA приватного ключа
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return Result{
			Type: ResultTypeError,
			Text: "rsa.SignPKCS1v15 error: " + err.Error(),
		}
	}

	// Добавляем подпись к данным запроса в виде base64 строки
	reqParams["signature"] = base64.StdEncoding.EncodeToString(signature)

	bParams, _ := json.Marshal(reqParams)
	fmt.Println("params", string(bParams))

	requestBody := url.Values{}
	for k, v := range reqParams {
		requestBody.Add(k, v)
	}

	fmt.Println("requestBody", requestBody)

	serverRequest, err := http.NewRequest("POST", apiUrl, strings.NewReader(requestBody.Encode()))
	if err != nil {
		return Result{
			Type: ResultTypeError,
			Text: "http.NewRequest error: " + err.Error(),
		}
	}
	serverRequest.Header.Set("User-Agent", "Golang")
	serverRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	resp, err := http.DefaultClient.Do(serverRequest)
	if err != nil {
		return Result{
			Type: ResultTypeError,
			Text: "http.DefaultClient.Do error: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	fmt.Println(err)
	fmt.Println("resp", string(b))

	if resp.StatusCode != http.StatusOK {
		return Result{
			Type: ResultTypeError,
			Text: "!= http.StatusOK",
		}
	}

	var respData ServerResponse
	if err := json.Unmarshal(b, &respData); err != nil {
		return Result{
			Type: ResultTypeError,
			Text: "Unmarshal error: " + err.Error(),
		}
	}

	switch respData.Code {
	case http.StatusOK:

		respParams := map[string]string{
			"processed": respData.Processed,
			"code":      fmt.Sprint(respData.Code),
			"reason":    respData.Reason,
		}

		keys = make([]string, 0, len(respParams))
		for k := range respParams {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		str.Reset()
		for _, key := range keys {
			str.WriteString(key + ":" + respParams[key] + ";")
		}

		// Декодируем подпись из данных ответа в виде base64 строки
		signature, err := base64.StdEncoding.DecodeString(respData.Signature)
		if err != nil {
			return Result{
				Type: ResultTypeError,
				Text: "base64.StdEncoding.DecodeString error: " + err.Error(),
			}
		}

		// Создаем хеш из данных ответа с помощью алгоритма SHA256
		hashed := sha256.Sum256([]byte(str.String()))

		rsaServerPublicKey, err := getServerPublicKey(env)
		if err != nil {
			return Result{
				Type: ResultTypeError,
				Text: "getServerPublicKey error: " + err.Error(),
			}
		}

		// Проверяем подпись с помощью RSA публичного ключа и хеша
		err = rsa.VerifyPKCS1v15(rsaServerPublicKey, crypto.SHA256, hashed[:], signature)
		if err != nil {
			return Result{
				Type: ResultTypeError,
				Text: "rsa.VerifyPKCS1v15 error: " + err.Error(),
			}
		}
		return Result{
			Type: ResultTypeMessage,
			Text: respData.Processed,
		}

	case http.StatusInternalServerError:
		return Result{
			Type: ResultTypeError,
			Text: "server error: " + respData.Reason,
		}
	}

	return Result{
		Type: ResultTypeError,
		Text: "Out of case. respData.Reason = " + respData.Reason,
	}
}

func main() {
	env, err := readEnv()
	if err != nil {
		log.Fatal(err)
	}

	err = validateKeyPair(env)
	if err != nil {
		log.Fatal(err)
	}

	data := Data{
		ID:   1,
		Text: "soME text",
	}

	result := Process(data, env)

	switch result.Type {
	case ResultTypeMessage:
		fmt.Println("Got text: ", result.Text)
	case ResultTypeError:
		fmt.Println("Got error: ", result.Text)
	}
}

// readEnv is a function that reads env.json and returns an Env struct
func readEnv() (Env, error) {
	// Declare an Env variable
	var env Env

	// Read the file content
	content, err := os.ReadFile("env.json")
	if err != nil {
		return env, fmt.Errorf("Error when opening file: %s", err.Error())
	}

	// Unmarshal the JSON data into the Env variable
	err = json.Unmarshal(content, &env)
	if err != nil {
		return env, fmt.Errorf("Error during Unmarshal(): %s", err.Error())
	}

	// Return the Env variable
	return env, nil
}

func validateKeyPair(env Env) error {

	// Decode the string env.PrivateKey from base64 to bytes
	privateKeyBytes, err := base64.StdEncoding.DecodeString(env.PrivateKey)
	if err != nil {
		return fmt.Errorf("Error when decoding the PrivateKey string: %s", err.Error())
	}

	// Decode the string env.ClientPublicKey from base64 to bytes
	PublicKeyBytes, err := base64.StdEncoding.DecodeString(env.PublicKey)
	if err != nil {
		return fmt.Errorf("Error when decoding the PublicKey string: %s", err.Error())
	}

	// Decode the string env.ServerPublicKey from base64 to bytes
	serverPublicKeyBytes, err := base64.StdEncoding.DecodeString(env.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("Error when decoding the ClientPublicKey string: %s", err.Error())
	}

	priv, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("Error when parsing the PrivateKey bytes: %s", err.Error())
	}

	pub, err := x509.ParsePKCS1PublicKey(PublicKeyBytes)
	if err != nil {
		return fmt.Errorf("Error when parsing the PublicKey string: %s", err.Error())
	}

	serverPub, err := x509.ParsePKCS1PublicKey(serverPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("Error when parsing the ClientPublicKey string: %s", err.Error())
	}

	// Сравниваем публичные ключи с теми, которые можно получить из приватных ключей
	if !(priv.PublicKey.Equal(pub) && !pub.Equal(serverPub)) {
		return fmt.Errorf("!(priv.PublicKey.Equal(pub) && !pub.Equal(serverPub))")
	}

	return nil
}
