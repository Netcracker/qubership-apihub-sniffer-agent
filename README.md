# qubership-apihub-sniffer-agent

Under development.

A service (DaemonSet) which works on k8s nodes network level and able to capture all network traffic and store to S3 storage for further analysis and generating various reports. 

Qubership Sniffer Agent only collects traffic. Separate service - qubership-apihub-traffic-analyzer - used for analysis of captured data.

## Arch diagramm

todo

## Installation

Please refer to [Helm chart folder](./helm-templates/)


## Build

Just run build.cmd(sh) file from this repository
