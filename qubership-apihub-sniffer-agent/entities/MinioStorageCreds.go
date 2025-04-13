// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
