# Documentation

## Documentation

Please refer to:
* [interface description](api/interface.yaml)
* [file structure](File_storage.md) 
* [usage scenario](usage-scenario.md) 

## Configuration documentation

The runtime configuration will be extracted from runtime environment at startup.
Configuration consists of:

* [Capture configuration](#capture-configuration)
* [Controller configuration](#controller-configuration)
  * [Keys for controller interfaces](#keys-for-controller-interfaces)
* [Kubernetes (Neighbours discovery and notifications) configuration](#kubernetes-neighbours-discovery-and-notifications-configuration)
* [S3/Minio configuration](#s3minio-configuration)

### Production mode

Production mode configuration required the following to be set:

* [Keys for controller interfaces](#keys-for-controller-interfaces)
* [S3/Minio configuration](#s3minio-configuration)
* [Kubernetes (Neighbours discovery and notifications) configuration](#kubernetes-neighbours-discovery-and-notifications-configuration)

| name            | Type        | default value | description                  |
|-----------------|-------------|---------------|------------------------------|
| PRODUCTION_MODE | bool string | 'true'        | Indicates a production mode. |

### Capture static configuration

| name                     | Type        | default value | description                                                                                                                     |
|--------------------------|-------------|---------------|---------------------------------------------------------------------------------------------------------------------------------|
| CAPTURE_INTERFACE        | string      |               | An interface name to capture packets on or empty string for auto select                                                         |
| CAPTURE_DIRECTORY        | string      |               | An local directory to store capture results before store it in S3/Minio                                                         |
| CAPTURE_SNAPSHOT_LEN     | int         | 262144        | A snapshot buffer length to store currently captured packet. All the packets bigger than this size will be discarded            |
| CAPTURE_FILE_COMPRESSION | bool string | 'false'       | Compress capture data during writing a local file when 'true'. However, file will be compressed before sending it into S3/Minio |

### Capture dynamic configuration (can be requested through controller)

Capture is expected to be relatively short (e.g. hours). When capture requested with no dynamic configuration it will cause capture on configured interface (CAPTURE_INTERFACE) with no filter and one monite long. Less than 10 MB will be written on S3/Minio in the worst case.  

| name            | Type                        | default value                                  | description                                                                                                                                                    |
|-----------------|-----------------------------|------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| capture_device  | string                      | CAPTURE_INTERFACE from static configuration    | A network interface to capture packets on                                                                                                                      |
| duration        | a Go-styled duration string | 1m                                             | A limit of time for capture. Capture will stop when the duration passed                                                                                        |
| file_size       | int                         | 681574400                                      | The limit of locally created file. When the limit reached - current file will be closed and new file opened. Once file is closed - it will be sent to S3/Minio |
| filter          | string                      |                                                | A eBPF filter exression to receive only required packets                                                                                                       |
| namespace       | string                      |                                                | A namespace to catch. All the nodes will be listed before capture start and appended to the filter                                                             |
| packet_count    | int                         |                                                | A limit for packet count to capture. Capture will stop when the captured packet count exceeds the limit                                                        |
| snapshot_len    | int                         | CAPTURE_SNAPSHOT_LEN from static configuration | A snapshot buffer length to store currently captured packet. All the packets bigger than this size will be discarded                                           |

### Controller configuration

| name           | Type        | default value | description                                                                                                                                   |
|----------------|-------------|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| LISTEN_ADDRESS | string      |               | A listen endpoint address \[(http:// or https://)\<host address\>\]\[:\<port number\>\]. May include protocol and port. At least port number. |
| ORIGIN_ALLOWED | bool string | 'false'       |                                                                                                                                               |

#### Keys for controller interfaces

All the keys must be defined in production mode

| name                 | Type   | default value | description                                                                                                    |
|----------------------|--------|---------------|----------------------------------------------------------------------------------------------------------------|
| SNIFFER_API_KEY      | string |               | An API key to access to the interface. This is a mandatory parameter in production mode.                       |
| SNIFFER_INTERNAL_KEY | string |               | An internal key for sending notifications to the neighbours. This is a mandatory parameter in production mode. |

### Kubernetes (Neighbours discovery and notifications) configuration

| name             | Type   | default value | description                                                                                                                        |
|------------------|--------|---------------|------------------------------------------------------------------------------------------------------------------------------------|
| NAMESPACE        | string |               | Kubernetes name space where the daemon set installed.  When not set - default namespace will be used                               |
| KUBECONFIG       | string |               | Kubernetes configuration file location. When not set - no notification to neighbours will send                                     |
| KUBE_CONTEXT     | string |               | Kubernetes security context from configuration file location. When not set - default context will be selected                      |
| KUBE_NODE_PREFIX | string |               | Kubernetes node names in the cluster must begin with the prefix to be placed in the neighbour list. This is a mandatory parameter. |

### S3/Minio configuration

The complete configuration required for production mode and when Kubernetes configured.

| name                       | Type        | default value | description                                       |
|----------------------------|-------------|---------------|---------------------------------------------------|
| STORAGE_SERVER_USERNAME    | string      |               | Access Key ID (user name) from Minio/S3 storage   |
| STORAGE_SERVER_PASSWORD    | string      |               | Secret access key (password) for Minio/S3 storage |
| STORAGE_SERVER_CRT         | string      |               | Certificate for accessing Minio/S3 storage        |
| STORAGE_SERVER_URL         | string      |               | S3/Minio endpoint for client connection           |
| STORAGE_SERVER_BUCKET_NAME | string      |               | S3/Minio API bucket name                          |
| MINIO_STORAGE_ACTIVE       | bool string | 'false'       | data will be stored in S3/Minio when 'true'       |
