module github.com/nikvdp/gogauth

go 1.14

require (
	//	github.com/minio/sio v0.2.0 // indirect
	github.com/pquerna/otp v1.2.0
	bitbucket.org/nikvdp/sia-ncrypt v0.0.0-20190209075517-761241b0bd71
)

// require (
//     bitbucket.org/nikvdp/sia-ncrypt 761241b0bd71dd608f3789bcfe2c27806ad9f780
// )
//
// replace  bitbucket.org/nikvdp/sia-ncrypt => github.com/minio/sio 761241b0bd71dd608f3789bcfe2c27806ad9f780

// require (
//         bitbucket.org/nikvdp/sia-ncrypt v0.0.0-20190401055205-025f82420c42
// )
// from `go get`
replace bitbucket.org/nikvdp/sia-ncrypt => github.com/minio/sio v0.2.0
