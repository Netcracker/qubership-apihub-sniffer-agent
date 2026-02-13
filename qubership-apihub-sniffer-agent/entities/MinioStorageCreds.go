package entities

type MinioStorageCreds struct {
	BucketName           string // minio bucket name
	IsActive             bool   // a flag indicates full-fledged interface
	Endpoint             string // minio endpoint address
	Crt                  string // minio certificate
	AccessKeyId          string // minio access key ID
	SecretAccessKey      string // secret minio access key
	CompressBeforeUpload bool   // compress file before upload it to S3/minio
}
