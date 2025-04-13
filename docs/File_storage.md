# File storage structure

Capture result stored in the files at local file system during capture and then move on S3/minio cloud storage.

## File name parts

The file name constructed with the following parts:

| Name            | Format        | Description                                                     |
|-----------------|---------------|-----------------------------------------------------------------|
| Capture Id      | MD5 string    | A unique identifier of capture process                          |
| Instance Id     | MD5 string    | A unique process instance Id to make file names unique          |
| Sequence number | int, 2 digits | A file sequence number to make file names unique within capture |

## File names

The file types are:

| Name                         | Mask                                                   | Description                                                                                               |
|------------------------------|--------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Metadata                     | \<Capture Id\>_metadata.json                           | Contains capture metadata                                                                                 |
| Captured packets             | \<Capture Id\>_\<Instance Id\>_\<Sequence number>.pcap | Contains captured packets data in tcpdump/Wireshark file format                                           |
| Resolved address for capture | \<Capture Id\>_\<Instance Id\>_address_list.txt        | Contains a resolved address list (IP addresses to service names) in hosts format \<IP\>\t\<Service name\> |

If it is configured then files will be compressed with GZip algorithm.