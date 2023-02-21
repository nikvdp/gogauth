# Gogauth

`gogauth` is a simple cli based tool to let you use 2FA codes (TOTP) for apps like Authy and Google Authenticator from the CLI.

There are only three commands: `list`, `add`, and `rm`. Each does what it says on the tin. Running the program with no arguments is equivalent to running `list`.

## Why would you want this?

You probably don't. But on the off chance that you're like me, this is a handy way to get access to your TOTP codes without having to pull out a phone or having your TOTP codes locked into a proprietary app.

## Quickstart

- Download from the [releases](https://github.com/nikvdp/gogauth/releases) page, and if on *nix run `chmod +x <bin-name>`, then put the file on your path. `/usr/local/bin` is a good choice.
- Enable 2FA on your favorite website, and get the secret. Choose an option like "I can't read QR codes" to get the text secret, which should be a string of letters (e.g. `WIAT 3ZBH GTGV CWKF`)
- Type `gogauth add <website-name> <secret>` to create a db+password and add this code
- When you need a code to login to a website, run `gogauth` and re-enter your password.
- Optionally, add `export GOGAUTH_PASSWORD=<your-pw>` and/or `export GOGAUTH_DB=<path-to-db-file>` to your `~/.bashrc` / `~/.zshrc` files so that you don't have to retype your password every time

## Features

- Simple and lightweight
- "search" function (add one or more search phrases via the `list`command, e.g.:  `gogauth list github`) in case you have many 2FA accounts.
- DB is an encrypted single file that you can backup and manage yourself.
- Codes are encrypted at rest at all times via [minio/sio](https://github.com/minio/sio), but can be easily decrypted if you want to move to another 2FA solution
- Password and db location can be customized via command line switches or env vars if you don't want to type them in.

## Build 
- `go mod tidy`
- `go build -o gogauth cmd/gogauth/main.go`

## Usage

```
google auth compatible cli tool

Usage:
  gogauth [flags]
  gogauth [command]

Available Commands:
  add         <name> <totp> - Add a new totp key
  help        Help about any command
  list        Show codes for all stored totp keys
  rm          Remove a totp key

Flags:
  -h, --help              help for gogauth
  -d, --keydb string      path to totp db file (or use env var GOGAUTH_DB) (default "/home/nik/.gogauthdb")
  -p, --password string   encryption password (or use env var GOGAUTH_PASSWORD)

Use "gogauth [command] --help" for more information about a command.
```

### TODO

- [ ] Add a `decrypt` command to allow easy exporting of the database. If you need this functionality in the meantime, install [minio/sio](https://github.com/minio/sio)'s `ncrypt` command, and use this command to decrypt the db: `cat ~/.gogauthdb | base64 --decode | ncrypt -cipher C20P1305 -d`
- [ ] Read TOTP codes from QR code images (in order to paste a screenshot into `gogauth` via `pbcopy`/`xsel`)
- [ ] Automatically copy generated codes to clipboard if only one code is outputted

## Alternatives / prior art

- [pcarrier/gauth](https://github.com/pcarrier/gauth)
