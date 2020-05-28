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

var keyCleanRegex, _ = regexp.Compile("[ -]+")

var TOTPKEYS_FILE = "auth_keys.json.ncrypt"

var rootCmd = &cobra.Command{
	Use:   "gogauth",
	Short: "google auth compatible cli",
	Long:  "Long google auth compatible cli",
	Run: func(cmd *cobra.Command, args []string) {
		decryptAndDisplay()
	},
}

func main() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "show codes",
		Run: func(cmd *cobra.Command, args []string) {
			decryptAndDisplay()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "add",
		Short: "add a new code",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// fmt.Println("Add a key")
			// fmt.Println("arg 1: ", args[0], " arg 2: ", args[1])
			addKey(args[0], args[1])
		},
	})

	rootCmd.Execute()
	// displayDecryptedKeys()
}

func verifyTotpIsValid(key string) bool {
	_, err := totp.GenerateCode(key, time.Now())
	return err == nil
}

func addKey(name string, totp string) {
	totpClean := cleanTotpKey(totp)
	totpKeys := doDecrypt()

	if !verifyTotpIsValid(totpClean) {
		fmt.Fprintf(os.Stderr, "Key '%s' doesn't seem to be a valid totp key!\n", totp)
		os.Exit(1)
	}

	totpKeys[name] = totpClean
	jsoned, _ := json.MarshalIndent(totpKeys, "", "    ")
	fmt.Printf("Added key '%s' with code '%s' to db!", name, totpClean)
	fmt.Println("New json: ")
	fmt.Println(string(jsoned))
}

func decryptAndDisplay() {
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
	var absFilename string
	if _, err := os.Stat(fmt.Sprint("./", TOTPKEYS_FILE)); err == nil {
		absFilename, _ = filepath.Abs(fmt.Sprint("./", TOTPKEYS_FILE))
	} else if _, err := os.Stat(fmt.Sprint("../../", TOTPKEYS_FILE)); err == nil {
		absFilename, _ = filepath.Abs(fmt.Sprint("../../", TOTPKEYS_FILE))
	}

	origInFile, err := os.Open(absFilename)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Couldn't open file '%s'", absFilename))
		os.Exit(1)
	}
	inFile := base64.NewDecoder(base64.StdEncoding, origInFile)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read salt from '%s'\n", TOTPKEYS_FILE)
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

func cleanTotpKey(totpKey string) string {
	return strings.ToUpper(keyCleanRegex.ReplaceAllString(totpKey, ""))
}

func cleanTotpKeys(totpKeys map[string]string) map[string]string {
	// this totp lib doesn't like
	cleanedKeys := make(map[string]string)
	for key, val := range totpKeys {
		valStr := fmt.Sprintf("%s", val)
		// tquerna/otp requires uppercased values
		cleanedKeys[key] = cleanTotpKey(valStr)
	}

	return cleanedKeys
}

func block(caption string, text string) {
	fmt.Printf("--- %s ---\n", caption)
	fmt.Println(text)
	fmt.Printf("--- /%s ---\n", caption)
}
