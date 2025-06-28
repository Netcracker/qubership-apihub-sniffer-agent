Installation notes

# Prerequisites

## PaaS Compatibility list

Thу following PaaS versions are supported:

| PaaS type  | Versions      | Support type |
|------------|---------------|--------------|
| kubernetes | 1.21.x-1.29.x | Full support |

## Preinstalled software

The following software should be installed before APIHUB installation:

| Dependency       | Minimal version                               | Mandatory/Optional | Comments                                  |
|------------------|-----------------------------------------------|--------------------|-------------------------------------------|
| PCAP library dev | -                                             | Mandatory          |                                           |
| Minio            | 1.2.3                                         | Optional           | For store cold data and reduce load to PG |


# HWE

## APIHUB sniffer agent

|              | CPU request | CPU limit | RAM request | RAM limit |
|--------------|-------------|-----------|-------------|-----------|
| Dev profile  | 300m        | 1         | 500Mi       | 500Mi     |
| Prod profile | 600m        | 2         | 1024Mi      | 1024Mi    |


# Deploy parameters

## Parameters description

| Deploy Parameter name      | Default Value                  | Description                                                                                                                                                                                    |
|----------------------------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **qubership-apihub-sniffer-agent**   |                                |                                                                                                                                                                                                |
| CAPTURE_INTERFACE          |                                | An interface to capture packets on. If not set then will be selected as first non-loopback/non-tunnel interface with IPv4 or IPv6 address. Set to 'any' to capture on all available interfaces | 
| CAPTURE_DIRECTORY          | /tmp                           | A local filesystem directory for intermediate files (captured packets,address list, metadata)                                                                                                  |
| CAPTURE_SNAPSHOT_LEN       | 262144                         | Capture snapshot (packet buffer) size                                                                                                                                                          |
| INSECURE_PROXY             | false                          | Set to true to enable apihub playground work without authorization.                                                                                                                            |
| KUBECONFIG                 | on                             | A non production parameter to turn off the cloud configuration                                                                                                                                 |
| KUBE_NODE_PREFIX           |                                | A cloud node name prefix to distinct apihub-sniffer-agent nodes  among the others                                                                                                              |
| LISTEN_ADDRESS             | :8080                          | An endpoint address to receive commands                                                                                                                                                        |
| MINIO_STORAGE_ACTIVE       | true                           | Set to true to enable S3 integration. Used for store cold data                                                                                                                                 |
| MONITORING_ENABLED         | true                           | Set to true to enable Prometheus metrics                                                                                                                                                       |
| NAMESPACE                  |                                | A cloud namespace name                                                                                                                                                                         |
| ORIGIN_ALLOWED             |                                | An additional origins to be added for the service                                                                                                                                              |
| PAAS_PLATFORM              |                                | A cloud type for PaaS library                                                                                                                                                                  |
| PAAS_VERSION               |                                | A cloud version for PaaS library                                                                                                                                                               |
| PRODUCTION_MODE            | false                          | Enables production mode - login under local apihub users is prohibited in this mode                                                                                                            |
| SNIFFER_API_KEY            |                                | An API key to protect instance from non authorized access                                                                                                                                      |
| SNIFFER_INTERNAL_KEY       |                                | An internal key to protect internal communications from breaking in                                                                                                                            |
| STORAGE_SERVER_USERNAME    |                                | Access Key ID (user name) from Minio/S3 storage                                                                                                                                                |
| STORAGE_SERVER_BUCKET_NAME | api-hub-prod                   | Bucket name in Minio/S3 storage                                                                                                                                                                |
| STORAGE_SERVER_CRT         |                                | Certificate for accessing Minio/S3 storage                                                                                                                                                     |
| STORAGE_SERVER_URL         | s3.example.com                 | S3/Minio endpoint for client connection                                                                                                                                                        |
| STORAGE_SERVER_PASSWORD    |                                | Secret access key (password) for Minio/S3 storage                                                                                                                                              |
| SYSTEM_NOTIFICATION        |                                | If set - footer with this text is shown for all APIHUB users in APIHUB UI. Designed for maintenance windows.                                                                                   |

