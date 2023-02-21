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

type gogauthConfig struct {
	pw             string
	passwordDbFile string
}

var (
	cfg gogauthConfig

	keyCleanRegex, _ = regexp.Compile("[ -]+")

	rootCmd = &cobra.Command{
		Use:   "gogauth",
		Short: "google auth compatible cli",
		Long:  "google auth compatible cli tool",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stderr,
				"No command specified, running `gogauth list`. Run `gogauth help` for usage.\n")
			decryptAndDisplayCodes()
		},
	}
)

func runCliParser() {
	rootCmd.AddCommand(&cobra.Command{
		// TODO: add an 'ls' alias
		Use:   "list",
		Short: "Show codes for all stored totp keys",
		Run: func(cmd *cobra.Command, args []string) {
			decryptAndDisplayCodes(args...)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "add",
        Short: "Add a new totp key. Args: (name, totp)",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			addKey(args[0], args[1])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		// TODO: add a 'remove' alias
		Use:   "rm",
		Short: "Remove a totp key",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			removeKey(args[0])
		},
	})

	rootCmd.Execute()
}

func getPassword() string {
	// TODO: refactor, this approach is clunky
	if cfg.pw != "" {
		return cfg.pw
	}

	password := os.Getenv("GOGAUTH_PASSWORD")

	if password == "" {
		fmt.Fprint(os.Stderr, "Enter decryption password: ")
		passwordBytes, _ := terminal.ReadPassword(int(syscall.Stdin))
		password = string(passwordBytes)
		fmt.Print("\n")
	}
	cfg.pw = password
	return password
}

func initConfig() {

	cfg = gogauthConfig{
		passwordDbFile: findTotpKeyFile(),
		pw:             "",
	}

	rootCmd.PersistentFlags().StringVarP(
		&cfg.passwordDbFile,
		"keydb",
		"d",
		findTotpKeyFile(),
		"path to totp db file (or use env var GOGAUTH_DB)",
	)

	rootCmd.PersistentFlags().StringVarP(
		&cfg.pw,
		"password",
		"p",
		"",
		"encryption password (or use env var GOGAUTH_PASSWORD)",
	)
}

func main() {
	initConfig()
	runCliParser()
}

func findTotpKeyFile() string {
	totpKeysFile := cfg.passwordDbFile

	if envDb, found := os.LookupEnv("GOGAUTH_DB"); found {
		totpKeysFile = envDb
	} else {
		// TODO: properly join paths and get homedir so we don't break windows
		absFilename, _ := filepath.Abs(fmt.Sprintf("%s/%s", os.Getenv("HOME"), ".gogauthdb"))
		totpKeysFile = absFilename
	}

	cfg.passwordDbFile = totpKeysFile
	return totpKeysFile
}

func verifyTotpIsValid(key string) bool {
	_, err := totp.GenerateCode(key, time.Now())
	return err == nil
}

func addKey(name string, totp string) {
	totpClean := cleanTotpKey(totp)
	totpKeys, err := doDecrypt()
	if err != nil {
		fmt.Printf("No totp key db found! Creating '%s'\n", cfg.passwordDbFile)
		totpKeys = make(map[string]string)
	}

	if !verifyTotpIsValid(totpClean) {
		fmt.Fprintf(os.Stderr, "Key '%s' doesn't seem to be a valid totp key!\n", totp)
		os.Exit(1)
	}

	totpKeys[name] = totpClean

	if _, err := doEncrypt(totpKeys); err != nil {
		fmt.Println("Unable to encrypt! Error: ", err)
	}

	fmt.Printf("Added key '%s' with code '%s' to db!\n", name, totpClean)
}

func removeKey(name string) {
	totpKeys, err := doDecrypt()
	if err != nil {
		fmt.Printf("Decryption error: %s\n", err)
		os.Exit(1)
	}
	delete(totpKeys, name)

	_, err = doEncrypt(totpKeys)
	if err != nil {
		fmt.Printf("Failed to encrypt! Error: %s", err)
		os.Exit(1)
	}

	fmt.Printf("Removed key '%s'!\n", name)
}

func grepFilter(array []string, filter string) []string {
	var output []string
	for _, str := range array {
		if strings.Contains(str, filter) {
			output = append(output, str)
		}
	}
	return output
}

func decryptCodes(filters ...string) (codes map[string]string, keys []string ){
	decryptedKeys, err := doDecrypt()
	if err != nil {
		msg := fmt.Sprintf(
			"Couldn't open totp db '%s'.\nTry creating one first with `gogauth add`",
			cfg.passwordDbFile,
		)
		fmt.Fprintln(os.Stderr, msg)
	}
	decrypted := cleanTotpKeys(decryptedKeys)

	codes = make(map[string]string)

	keys = make([]string, 0, len(decrypted)) // to sort on

	for key, val := range decrypted {
		code, _ := totp.GenerateCode(val, time.Now())
		codes[key] = code
		keys = append(keys, key)
	}
	for _, filter := range filters {
		for key := range codes {
			if !strings.Contains(key, filter) {
				delete(codes, key)
			}
		}
	}

    keys = make([]string, 0, len(codes)) // to sort on
    for key := range codes {
        keys = append(keys, key)
    }
    return codes, keys
}

func decryptAndDisplayCodes(filters ...string) {
    codes, keys := decryptCodes(filters...)
    displayCodes(codes, keys)
}

func displayCodes(codes map[string]string, keys []string) {
	sort.Strings(keys)

	// print out keys in columnar form in alphabetic order
	writer := tabwriter.NewWriter(os.Stdout, 2, 1, 3, ' ', 0)
	if len(keys) > 1 {
		for _, key := range keys {
			fmt.Fprintf(writer, "%s\t%s\n", key, codes[key])
		}
	} else if len(keys) > 0 {
		// if we only have one result, fancily print the name to stderr, but
		// print the code to stdout. This allows piping to to e.g.
		// `pbcopy`/`xsel` to only copy the code. e.g.: `gogauth list gmail |
		// pbcopy`
		fmt.Fprintf(os.Stderr, "%s\t", keys[0])
		fmt.Printf(codes[keys[0]])
        fmt.Fprintf(os.Stderr, "\n")
	}
	writer.Flush()
}

func doDecrypt() (map[string]string, error) {
	totpKeyFile := cfg.passwordDbFile
	origInFile, err := os.Open(totpKeyFile)
	if err != nil {
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

	outfileHandle, err := os.Create(cfg.passwordDbFile)
	if err != nil {
		fmt.Println("Error creating totp file!", err)
	}
	outFile := base64.NewEncoder(base64.StdEncoding, outfileHandle)

	outFile.Write(salt)

	toEncrypt := string(jsonTotpKeys)

	bytesWritten, err := sio.Encrypt(outFile, strings.NewReader(toEncrypt), sioConfig)
	if err != nil {
		fmt.Println("Sio encryption error: ", err)
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
