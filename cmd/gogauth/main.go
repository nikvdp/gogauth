package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/minio/sio"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	displayDecryptedKeys()
}

func displayDecryptedKeys() {
	decrypted := cleanTotpKeys(doDecrypt())
	writer := tabwriter.NewWriter(os.Stdout, 2, 1, 3, ' ', 0)
	for key, val := range decrypted {
		code, _ := totp.GenerateCode(val, time.Now())
		fmt.Fprintf(writer, "%s\t%s\n", key, code)
	}
	writer.Flush()
}

func doDecrypt() map[string]string {
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

	var totpKeys map[string]string
	json.Unmarshal([]byte(buff.String()), &totpKeys)
	return totpKeys
}

func cleanTotpKeys(totpKeys map[string]string) map[string]string {
	// this totp lib doesn't like
	re, _ := regexp.Compile("[ -]+")
	cleanedKeys := make(map[string]string)
	for key, val := range totpKeys {
		valStr := fmt.Sprintf("%s", val)
		// tquerna/otp requires uppercased values
		valStr = strings.ToUpper(re.ReplaceAllString(valStr, ""))
		cleanedKeys[key] = valStr
	}

	return cleanedKeys
}

func block(caption string, text string) {
	fmt.Printf("--- %s ---\n", caption)
	fmt.Println(text)
	fmt.Printf("--- /%s ---\n", caption)
}
