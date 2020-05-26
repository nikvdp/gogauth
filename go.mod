module github.com/nikvdp/gogauth

go 1.14

require (
	bitbucket.org/nikvdp/sia-ncrypt v0.0.0-20190209075517-761241b0bd71
	//	github.com/minio/sio v0.2.0 // indirect
	github.com/pquerna/otp v1.2.0
	golang.org/x/crypto v0.0.0-20181106171534-e4dc69e5b2fd
)

// replace  bitbucket.org/nikvdp/sia-ncrypt => github.com/minio/sio v0.2.0
replace bitbucket.org/nikvdp/sia-ncrypt => /home/nik/Code/personal/go/Linux/src/bitbucket.org/nikvdp/sia-ncrypt/nothing
