# qubership-apihub-sniffer-agent

**Under development, alpha quality, not ready for usage**

A k8s service (DaemonSet) which works on k8s nodes network level and able to capture all network traffic and store to S3 storage for further analysis and generating various reports. 

Qubership Sniffer Agent only collects traffic. Separate service - [qubership-apihub-traffic-analyzer](https://github.com/Netcracker/qubership-apihub-traffic-analyzer) - used for analysis of captured data.

**NOTE** this service requires high priveledges. Working on k8s network level is not possible without set of root permissions.

## Arch diagramm

![APIHUB Sniffer arch](./docs/images/APIHUB-sniffer.drawio.png)

## High Level operation sequence

- Start capture for specified time range via REST call
- Complete capture. If capture has got proper parameters then it will stop automatically without any further assistance.
- Upload collected RAW data to S3 storage for further processing


## Documentation

See [here](./docs/README.md)


## Installation

Please refer to [Helm chart folder](./helm-templates/)


## Build

Just run build.cmd(sh) file from this repository
