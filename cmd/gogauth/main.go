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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"
)

var (
	pw = os.Getenv("DECRYPT_PASSWORD")

	keyCleanRegex, _ = regexp.Compile("[ -]+")

	totpKeyFile = findTotpKeyFile()

	rootCmd = &cobra.Command{
		Use:   "gogauth",
		Short: "google auth compatible cli",
		Long:  "google auth compatible cli tool",
		Run: func(cmd *cobra.Command, args []string) {
			decryptAndDisplayCodes()
		},
	}
)

func main() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "show codes",
		Run: func(cmd *cobra.Command, args []string) {
			decryptAndDisplayCodes()
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

	rootCmd.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "test encryption",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var buff bytes.Buffer
			fmt.Println("Going to attempt to encrypt the following:")
			fmt.Println("---")
			fmt.Println(args[0])
			fmt.Println("---")

			buff.WriteString(args[0])
			// cfg := sio.Config(Key: )

		},
	})

	rootCmd.Execute()
	// displayDecryptedKeys()
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
		totpKeys = make(map[string]string)
	}

	if !verifyTotpIsValid(totpClean) {
		fmt.Fprintf(os.Stderr, "Key '%s' doesn't seem to be a valid totp key!\n", totp)
		os.Exit(1)
	}

	totpKeys[name] = totpClean
	// jsoned, _ := json.MarshalIndent(totpKeys, "", "    ")

	if _, err := doEncrypt(totpKeys); err != nil {
		fmt.Printf("Unable to encrypt! Error: %s", err)
	}

	// fmt.Printf("Added key '%s' with code '%s' to db!", name, totpClean)
	// fmt.Println("New json: ")
	// fmt.Println(string(jsoned))
}

func decryptAndDisplayCodes() {
	decryptedKeys, _ := doDecrypt()
	decrypted := cleanTotpKeys(decryptedKeys)
	writer := tabwriter.NewWriter(os.Stdout, 2, 1, 3, ' ', 0)
	for key, val := range decrypted {
		code, _ := totp.GenerateCode(val, time.Now())
		fmt.Fprintf(writer, "%s\t%s\n", key, code)
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

	sioConfig, _ := buildSioConfig(pw, salt)

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
		Key: key,
		// CipherSuites: []byte{sio.AES_256_GCM},
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
	fmt.Println("Salt is: ", salt)
	fmt.Println("Json totp keys: ", string(jsonTotpKeys))
	fmt.Println("---")

	sioConfig, err := buildSioConfig(pw, salt)
	if err != nil {
		fmt.Println("sio config error!", err)
		return 0, err
	}

	outfileHandle, err := os.Create(totpKeyFile)
	if err != nil {
		fmt.Println("What the fuck mang, fcreate error", err)
	}
	outFile := base64.NewEncoder(base64.StdEncoding, outfileHandle)

	outFile.Write(salt)
	// bytesWritten, err := sio.Encrypt(outFile, strings.NewReader(string(jsonTotpKeys)), sioConfig)
	// toEncrypt := fmt.Sprintf("hello there my friend: %s", time.Now())
	toEncrypt := string(jsonTotpKeys)
	fmt.Println("Trying to encrypt ", toEncrypt)
	bytesWritten, err := sio.Encrypt(outFile, strings.NewReader(toEncrypt), sioConfig)
	if err != nil {
		fmt.Println("Sio cmae back with error: ", err)
	}
	fmt.Printf("Wrote %d bytes\n", bytesWritten)

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
