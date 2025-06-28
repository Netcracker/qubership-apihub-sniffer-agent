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

package cloud_storage

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	"github.com/minio/minio-go/v7"
	log "github.com/sirupsen/logrus"
)

type CloudStorage interface {
	StoreFile(fileName string)
}

type Request struct {
	FilePath string
}

type cloudStorage struct {
	inputQueue         chan Request
	lock               sync.Mutex
	storageCredentials entities.MinioStorageCreds
	minioClient        *minioClient
	productionMode     bool
}

type minioClient struct {
	client *minio.Client
	error  error
}

const BreakTheLoop = "BREAK!"
const TableName = "PacketCaptures"
const FileBlockSize = 8192

// common functions

// mustGetSystemCertPool
// acquires certification pool
func mustGetSystemCertPool() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return x509.NewCertPool()
	}
	return pool
}

// createMinioClient
// creates minio instance
func createMinioClient(minioCredentials *entities.MinioStorageCreds) *minioClient {
	if !minioCredentials.IsActive {
		return nil // inactive storage does not require full fledged client
	}
	client := new(minioClient)
	var err error
	tr, err := minio.DefaultTransport(true)
	if err != nil {
		log.Warnf("error creating the minio connection: error creating the default transport layer: %v", err)
		client.error = err
		return client
	}
	crt, err := os.CreateTemp("", "minio.cert")
	if err != nil {
		log.Warn(err.Error())
		client.error = err
		return client
	}
	decodeSamlCert, err := base64.StdEncoding.DecodeString(minioCredentials.Crt)
	if err != nil {
		log.Warn(err.Error())
		client.error = err
		return client
	}

	_, err = crt.WriteString(string(decodeSamlCert))
	if err != nil {
		log.Warn(err.Error())
		client.error = err
	}
	rootCAs := mustGetSystemCertPool()
	data, err := os.ReadFile(crt.Name())
	if err == nil {
		rootCAs.AppendCertsFromPEM(data)
	}
	tr.TLSClientConfig.RootCAs = rootCAs

	minioClient, err := minio.New(minioCredentials.Endpoint, &minio.Options{
		Creds:     credentials.NewStaticV4(minioCredentials.AccessKeyId, minioCredentials.SecretAccessKey, ""),
		Secure:    true,
		Transport: tr,
	})
	if err != nil {
		log.Warn(err.Error())
		client.error = err
		return client
	}
	log.Infof("MINIO instance initialized")
	client.client = minioClient
	return client
}

// NewCloudStorage
// creates interface instance
func NewCloudStorage(minioCredentials entities.MinioStorageCreds, productionMode bool) CloudStorage {
	ret := &cloudStorage{
		inputQueue:         make(chan Request),
		lock:               sync.Mutex{},
		storageCredentials: minioCredentials,
		minioClient:        createMinioClient(&minioCredentials),
		productionMode:     productionMode,
	}
	utils.SafeAsync(func() {
		storeProcedure(ret, ret.inputQueue)
	}) // +SafeAsync
	return ret
}

func (s3 *cloudStorage) compressFile(req Request) (string, error) {
	inputFile, err := os.Open(req.FilePath)
	outputFileName := req.FilePath + view.GzipSuffix
	if err == nil {
		outputFile, err := os.Create(outputFileName)
		if err == nil {
			wz := gzip.NewWriter(outputFile)
			bEof := false // read input file until eof
			if wz != nil {
				wz.Name = filepath.Base(req.FilePath) // set filename in archive metadata
				fileBuf := make([]byte, FileBlockSize)
				filePos := 0
				for {
					l, e := inputFile.Read(fileBuf)
					if e == nil {
						filePos += l
						_, we := wz.Write(fileBuf[0:l])
						if we != nil {
							log.Errorf("unable to write %d bytes into compressed stream. Error: '%v'", l, we)
							break
						}
						if l != FileBlockSize {
							bEof = true
							break
						}
					} else {
						log.Errorf("unable to read bytes from input stream after position: %d. Error: '%v'", filePos, e)
						break
					}
				}
				err := wz.Close()
				if err != nil {
					log.Warnf("unable to close compressed stream for output file '%s'. Error: %v", req.FilePath, err)
				}
			} else {
				log.Errorf("unable to open compressed data stream for file '%s'. Error: %v", outputFileName, err)
			}
			if outputFile != nil {
				err = outputFile.Close()
				if err != nil {
					log.Warnf("unable to close output file '%s'. Error: %v", req.FilePath, err)
				}
			}
			if bEof {
				err = nil
				if s3.productionMode {
					err := os.Remove(req.FilePath)
					if err != nil {
						log.Errorf("unable to delete uncompressed input file '%s'. Error: %v", req.FilePath, err)
					}
				} else {
					log.Debugf("file '%s' was not deleted in non-production mode", req.FilePath)
				}
				req.FilePath = outputFileName

			} else {
				err := os.Remove(outputFileName)
				if err != nil {
					log.Errorf("unable to improperly uncompressed input file '%s'. Error: %v", outputFileName, err)
				}
			}
		} else {
			log.Warnf("unable to create compressed file '%s'. Error: %v", outputFileName, err)
		}
		if inputFile != nil {
			err = inputFile.Close()
			if err != nil {
				log.Warnf("unable to close input file '%s'. Error: %v", req.FilePath, err)
			}
		}
	} else {
		log.Warnf("unable to open file '%s' to compress it. Error: %v", req.FilePath, err)
	}
	return req.FilePath, err
}

// storeProcedure
// goroutine to serve file storing
func storeProcedure(s3 *cloudStorage, inputQueue chan Request) {
	for {
		req := <-inputQueue
		if req.FilePath == view.EmptyString {
			continue
		}
		if req.FilePath == BreakTheLoop {
			break
		}
		if !s3.storageCredentials.IsActive {
			log.Printf("storage inactive. do not store file %s", req.FilePath)
			continue
		}
		// compress file contents
		if s3.storageCredentials.CompressBeforeUpload && !strings.HasSuffix(req.FilePath, view.GzipSuffix) {
			s1, err := s3.compressFile(req)
			if err != nil || req.FilePath == s1 {
				continue
			} else {
				err := os.Remove(req.FilePath)
				if err != nil {
					log.Warnf("unable to delete uncompressed file %s. Error: %v", req.FilePath, err)
				}
				req.FilePath = s1
			}
		}
		// let's make a couple attempts to store file
		for i := 0; i < 3; i++ {
			fileBytes, err := os.ReadFile(req.FilePath)
			if err == nil {
				ctx := context.Background()
				err := s3.createBucketIfNotExists(ctx)
				if err != nil {
					log.Errorf("unable to acquire bucket for file '%s'. Error: '%v'", req.FilePath, err)
					continue
				}
				err = s3.UploadFile(ctx, TableName, filepath.Base(req.FilePath), fileBytes)
				if err != nil {
					log.Errorf("unable to store file '%s'. Error: %v", req.FilePath, err)
				} else {
					log.Printf("stored %d byte(s) from file '%s' in s3/minio", len(fileBytes), req.FilePath)
					err := os.Remove(req.FilePath)
					if err != nil {
						log.Warnf("unable to delete stored file %s. Error: %v", req.FilePath, err)
					}
					break
				}
			} else {
				log.Errorf("unable to read file '%s'. Error: %v", req.FilePath, err)
			}
		}
		if s3.productionMode {
			err := os.Remove(req.FilePath)
			if err != nil {
				log.Errorf("unable to delete input file '%s'. Error: %v", req.FilePath, err)
			}
		} else {
			log.Debugf("file '%s' was not deleted in non-production mode", req.FilePath)
		}
	}
}

func bucketExists(ctx context.Context, minioClient *minio.Client, bucketName string) (bool, error) {
	exists, err := minioClient.BucketExists(ctx, bucketName)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func buildFileName(tableName, entityId string) string {
	return fmt.Sprintf("%s/%s", tableName, entityId)
}

// interface implementation

// StoreFile
// function to receive file store requests
func (s3 *cloudStorage) StoreFile(fileName string) {
	s3.inputQueue <- Request{FilePath: fileName}
	log.Debugf("requested to store file: %s", fileName)
}

// functions

func (s3 *cloudStorage) createBucketIfNotExists(ctx context.Context) error {
	exists, err := bucketExists(ctx, s3.minioClient.client, s3.storageCredentials.BucketName)
	if err != nil {
		return err
	}
	if exists {
		log.Debugf("Using S3/Minio bucket '%s'", s3.storageCredentials.BucketName)
	} else {
		err = s3.minioClient.client.MakeBucket(ctx, s3.storageCredentials.BucketName, minio.MakeBucketOptions{})
		if err != nil {
			return err
		}
		exists, err = bucketExists(ctx, s3.minioClient.client, s3.storageCredentials.BucketName)
		if err != nil {
			return err
		}
		if exists {
			log.Debugf("S3/Minio bucket '%s' has been created", s3.storageCredentials.BucketName)
		}
	}
	return nil
}

func (s3 *cloudStorage) UploadFile(ctx context.Context, tableName, entityId string, content []byte) error {
	err := s3.putObject(ctx, buildFileName(tableName, entityId), content)
	if err != nil {
		return err
	}
	return nil
}

func (s3 *cloudStorage) putObject(ctx context.Context, fileName string, content []byte) error {
	_, err := s3.minioClient.client.PutObject(ctx, s3.storageCredentials.BucketName, fileName, bytes.NewReader(content), int64(len(content)), minio.PutObjectOptions{})
	if err != nil {
		return err
	}
	return nil
}
