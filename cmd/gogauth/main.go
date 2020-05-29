package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/minio/sio"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

var (
	pw string

	keyCleanRegex, _ = regexp.Compile("[ -]+")

	totpKeyFile = findTotpKeyFile()

	rootCmd = &cobra.Command{
		Use:   "gogauth",
		Short: "google auth compatible cli",
		Long:  "google auth compatible cli tool",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

func runCliParser() {
	rootCmd.AddCommand(&cobra.Command{
		// TODO: add an 'ls' alias
		Use:   "list",
		Short: "show codes for all stored totp keys",
		Run: func(cmd *cobra.Command, args []string) {
			decryptAndDisplayCodes()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "add",
		Short: "add a new totp key",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// fmt.Println("Add a key")
			// fmt.Println("arg 1: ", args[0], " arg 2: ", args[1])
			addKey(args[0], args[1])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		// TODO: add a 'remove' alias
		Use:   "rm",
		Short: "remove a totp key",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			removeKey(args[0])
		},
	})

	rootCmd.Execute()
}

func getPassword() string {
	// TODO: refactor, this approach is clunky
	if pw != "" {
		return pw
	}

	password := os.Getenv("GOGAUTH_PASSWORD")

	if password == "" {
		fmt.Print("Enter decryption password: ")
		passwordBytes, _ := terminal.ReadPassword(int(syscall.Stdin))
		password = string(passwordBytes)
		fmt.Print("\n")
	}
	pw = password
	return password
}
func main() {
	runCliParser()
}

func findTotpKeyFile() string {
	totpKeysFile := "auth_keys.json.ncrypt"
	var absFilename = ""
	if _, err := os.Stat(fmt.Sprint("./", totpKeysFile)); err == nil {
		absFilename, _ = filepath.Abs(fmt.Sprint("./", totpKeysFile))
	} else if _, err := os.Stat(fmt.Sprint("../../", totpKeysFile)); err == nil {
		absFilename, _ = filepath.Abs(fmt.Sprint("../../", totpKeysFile))
	} else {
		absFilename, _ = filepath.Abs(fmt.Sprint("./", totpKeysFile))
	}
	return absFilename
}

func verifyTotpIsValid(key string) bool {
	_, err := totp.GenerateCode(key, time.Now())
	return err == nil
}

func addKey(name string, totp string) {
	totpClean := cleanTotpKey(totp)
	totpKeys, err := doDecrypt()
	if err != nil {
		fmt.Println("No totp key db found! Creating...")
		totpKeys = make(map[string]string)
	}

	if !verifyTotpIsValid(totpClean) {
		fmt.Fprintf(os.Stderr, "Key '%s' doesn't seem to be a valid totp key!\n", totp)
		os.Exit(1)
	}

	totpKeys[name] = totpClean

	if _, err := doEncrypt(totpKeys); err != nil {
		fmt.Printf("Unable to encrypt! Error: %s", err)
	}

	fmt.Printf("Added key '%s' with code '%s' to db!\n", name, totpClean)
}

func removeKey(name string) {
	totpKeys, err := doDecrypt()
	if err != nil {
		fmt.Println("Decryption error!")
	}
	delete(totpKeys, name)

	_, err = doEncrypt(totpKeys)
	if err != nil {
		fmt.Printf("Failed to encrypt! Error: %s", err)
		os.Exit(1)
	}

	fmt.Printf("Removed key '%s'!\n", name)
}

func decryptAndDisplayCodes() {
	decryptedKeys, _ := doDecrypt()
	decrypted := cleanTotpKeys(decryptedKeys)
	writer := tabwriter.NewWriter(os.Stdout, 2, 1, 3, ' ', 0)

	codes := make(map[string]string)

	keys := make([]string, 0, len(decrypted)) // to sort on

	for key, val := range decrypted {
		keys = append(keys, key)
		code, _ := totp.GenerateCode(val, time.Now())
		codes[key] = code
	}
	sort.Strings(keys)

	// print out keys in columnar form in alphabetic order
	for _, k := range keys {
		fmt.Fprintf(writer, "%s\t%s\n", k, codes[k])
	}
	writer.Flush()
}

func doDecrypt() (map[string]string, error) {
	origInFile, err := os.Open(totpKeyFile)
	if err != nil {
		msg := fmt.Sprintf("Couldn't open file '%s'", totpKeyFile)
		fmt.Fprintln(os.Stderr, msg)
		return nil, err
	}
	inFile := base64.NewDecoder(base64.StdEncoding, origInFile)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read salt from '%s'\n", totpKeyFile)
		os.Exit(2)
	}
	defer origInFile.Close()

	sioConfig, _ := buildSioConfig(getPassword(), salt)

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
	return totpKeys, err
}

func buildSioConfig(pw string, salt []byte) (sio.Config, error) {
	key, err := scrypt.Key([]byte(pw), salt, 32768, 16, 1, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Key error: %s", err)
	}
	config := sio.Config{
		Key:          key,
		CipherSuites: []byte{sio.CHACHA20_POLY1305},
		// MinVersion:   sio.Version20,
		// MaxVersion:   sio.Version20,
	}
	return config, err
}

func doEncrypt(totpKeys map[string]string) (int64, error) {
	/** WARNING: This *overwrites* `totpKeyFile!` **/

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate random salt!\n")
		os.Exit(1)
	}

	// TODO: pick up from here, verify that you can encrypt
	jsonTotpKeys, _ := json.Marshal(totpKeys)

	sioConfig, err := buildSioConfig(getPassword(), salt)
	if err != nil {
		fmt.Println("sio config error!", err)
		return 0, err
	}

	outfileHandle, err := os.Create(totpKeyFile)
	if err != nil {
		fmt.Println("Error creating totp file!", err)
	}
	outFile := base64.NewEncoder(base64.StdEncoding, outfileHandle)

	outFile.Write(salt)

	toEncrypt := string(jsonTotpKeys)

	bytesWritten, err := sio.Encrypt(outFile, strings.NewReader(toEncrypt), sioConfig)
	if err != nil {
		fmt.Println("Sio cmae back with error: ", err)
	}

	outFile.Close()
	outfileHandle.Close()
	return bytesWritten, err
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
