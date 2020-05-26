package main

import (
	// "encoding/json"
	sio "bitbucket.org/nikvdp/sia-ncrypt"
	// ncrypt "bitbucket.org/nikvdp/sia-ncrypt/cmd/ncrypt"
	"encoding/json"
	"fmt"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/scrypt"
	"io"
	// "io/ioutil"
	"os"
	// "os/exec"
	"bufio"
	"bytes"
	"encoding/base64"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	decrypted := doDecrypt()
	var totpKeys map[string]string
	json.Unmarshal([]byte(decrypted), &totpKeys)
	re, _ := regexp.Compile("[ -]+")
	writer := tabwriter.NewWriter(os.Stdout, 2, 1, 3, ' ', 0)
	for key, val := range totpKeys {
		keyStr := fmt.Sprintf("%s", val)
		keyStr = strings.ToUpper(re.ReplaceAllString(keyStr, ""))

		code, _ := totp.GenerateCode(keyStr, time.Now())
		fmt.Fprintf(writer, "%s\t%s\n", key, code)
	}
	writer.Flush()
}

func doDecrypt() string {
	pw := os.Getenv("DECRYPT_PASSWORD")
	filename := "auth_keys.json.ncrypt"
	var absFilename string
	if _, err := os.Stat(fmt.Sprint("./", filename)); err == nil {
		absFilename, _ = filepath.Abs(fmt.Sprint("./", filename))
	} else if _, err := os.Stat(fmt.Sprint("../../", filename)); err == nil {
		absFilename, _ = filepath.Abs(fmt.Sprint("../../", filename))
	}
	// inputData, err := ioutil.ReadFile(filename)
	origInFile, err := os.Open(absFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Couldn't open file '%s'", absFilename))
		os.Exit(1)
	}
	inFile := base64.NewDecoder(base64.StdEncoding, origInFile)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read salt from '%s'\n", filename)
		os.Exit(2)
	}

	key, err := scrypt.Key([]byte(pw), salt, 32768, 16, 1, 32)

	// ncryptPath := "/home/nik/.vim/bundle/nikcrypt/ncrypt.Linux"
	sioConfig := sio.Config{Key: key}
	var buff bytes.Buffer
	decrypted := bufio.NewWriter(&buff)
	_, err = sio.Decrypt(decrypted, inFile, sioConfig)
	// bytesWritten, err := sio.Decrypt(os.Stdout, inFile, sioConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Decryption error!", err)
		os.Exit(3)
	}

	// decryptCmd := exec.Command(ncryptPath, "-d", "-b", "-p", pw)

	// decryptIn, _ := decryptCmd.StdinPipe()
	// decryptOut, _ := decryptCmd.StdoutPipe()
	// decryptErr, _ := decryptCmd.StderrPipe()

	// decryptCmd.Start()
	// decryptIn.Write(inputData)
	// decryptIn.Close()
	// decryptBytes, _ := ioutil.ReadAll(decryptOut)
	// decryptErrBytes, _ := ioutil.ReadAll(decryptErr)
	// decryptCmd.Wait()
	// decryptedStr := string(decryptBytes)
	// block("bytes", decryptedString)
	// block("ERROR", string(decryptErrBytes))
	decrypted.Flush()
	return buff.String()
}

func block(caption string, text string) {
	fmt.Printf("--- %s ---\n", caption)
	fmt.Println(text)
	fmt.Printf("--- /%s ---\n", caption)
}
