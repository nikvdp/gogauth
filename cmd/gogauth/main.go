package main

import (
	"github.com/minio/sio"
	"encoding/json"
	"fmt"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
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


	sioConfig := sio.Config{Key: key}
	var buff bytes.Buffer
	decrypted := bufio.NewWriter(&buff)
	_, err = sio.Decrypt(decrypted, inFile, sioConfig)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Decryption error!", err)
		os.Exit(3)
	}

	decrypted.Flush()
	return buff.String()
}

func block(caption string, text string) {
	fmt.Printf("--- %s ---\n", caption)
	fmt.Println(text)
	fmt.Printf("--- /%s ---\n", caption)
}
