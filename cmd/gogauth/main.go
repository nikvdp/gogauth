package main

import (
	// "encoding/json"
	"encoding/json"
	"fmt"
	"github.com/pquerna/otp/totp"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func main() {
	fmt.Print("hey again\n")
	decrypted := doDecrypt()
	var totpKeys map[string]interface{}
	json.Unmarshal([]byte(decrypted), &totpKeys)
	re, _ := regexp.Compile("[ -]+")
	for key, val := range totpKeys {
		keyStr := fmt.Sprintf("%s", val)
		keyStr = strings.ToUpper(re.ReplaceAllString(keyStr, ""))

		code, _ := totp.GenerateCode(keyStr, time.Now())
		fmt.Printf("%s = %s\n", key, code)
	}
	// fmt.Println("Unmarshalled: ", totpKeys)
}

func doDecrypt() string {
	filename := "./auth_keys.json.ncrypt"
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Something went wrong!")
		os.Exit(1)
	}

	ncryptPath := "/home/nik/.vim/bundle/nikcrypt/ncrypt.Linux"
	pw := os.Getenv("DECRYPT_PASSWORD")
	decryptCmd := exec.Command(ncryptPath, "-d", "-b", "-p", pw)
	// decryptCmd := exec.Command("cat")
	decryptIn, _ := decryptCmd.StdinPipe()
	decryptOut, _ := decryptCmd.StdoutPipe()
	// decryptErr, _ := decryptCmd.StderrPipe()

	decryptCmd.Start()
	decryptIn.Write(file)
	decryptIn.Close()
	decryptBytes, _ := ioutil.ReadAll(decryptOut)
	// decryptErrBytes, _ := ioutil.ReadAll(decryptErr)
	decryptCmd.Wait()
	decryptedStr := string(decryptBytes)
	// block("bytes", decryptedString)
	// block("ERROR", string(decryptErrBytes))
	return decryptedStr
}

func block(caption string, text string) {
	fmt.Printf("--- %s ---\n", caption)
	fmt.Println(text)
	fmt.Printf("--- /%s ---\n", caption)
}
