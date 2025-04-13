# apihub-sniffer-agent usage scenario

## Prerequisites

apihub-sniffer-agent must be installed with proper access rights and configuration. See [installation notes](installation-notes.md) for details.

## Usage cycle

Expected usage cycle:

* Start (open) capture
* Stop (finish) capture. If capture has got proper parameters then it will stop automatically without any further assistance.

### Start (open) capture

Capture is expected to be relatively short (e.g. hours). When capture requested with no dynamic configuration it will cause capture on configured interface (CAPTURE_INTERFACE) with no filter and one monite long. Less than 10 MB will be written on S3/Minio in the worst case.
Please consult [interface description](api/interface.yaml) for details. Capture can be configured with the parameters:

| Parameter       | Type   | Example                                                                   | Description                                                                                                                                                                                                          |
|-----------------|--------|---------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| capture_device  | string | CAPTURE_INTERFACE from static configuration                               | A network interface to capture packets on                                                                                                                      |
| duration        | string | ```1m30s```                                                               | A Go-styled duration string. Set time limit for capture. Capture will stop when the limit reached. Default limit 1 minute.                                                                                           |
| file_size       | int    | ```681574400```                                                           | A file size in bytes to limit captured packet file size on local disk. Can be specified as a positive integer value in decimal notation. A new file will be created when the limit reached. Default value: 681574400 |
| filter          | String | ```tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)``` | A valid eBPF filter expression to reduce received packet count. Has no default value.                                                                                                                                |
| namespace       | string | ```api-hub-dev```                                                         | Packet will be capture for the specified namespace only. All the IPs from the namespace will be added to *Filter*. Has no default value.                                                                             |
| packet_count    | int    | ```10000```                                                               | A limit for packet count to be captured. Can be specified as a positive integer value in decimal notation. Capture will stop when the limit reached. Not limited by default.                                         | 
| snapshot_len    | int    | CAPTURE_SNAPSHOT_LEN from static configuration                            | A snapshot buffer length to store currently captured packet. All the packets bigger than this size will be discarded                                           |

### Stop (finish) capture

Please consult [interface description](api/interface.yaml) for details.
If capture has got proper parameters then it will stop automatically without any further assistance.
A capture id needs to be specified to stop capture. 