# Qubership APIHUB Sniffer Agent Helm Chart

## Prerequisites

1. kubectl installed and configured for k8s cluster access. Namespace admin permissions required.
1. Helm installed
1. Supported k8s version - 1.23+

# 3rd party dependencies

| Name | Version | Mandatory/Optional | Comment |
| ---- | ------- |------------------- | ------- |
| S3 | Any | Mandatory | For store captured data |

## HWE

|     | CPU request | CPU limit | RAM request | RAM limit |
| --- | ----------- | --------- | ----------- | --------- |
| Minimal level        | 30m | 300m   | 256Mi | 256Mi |
| Average load level   | 30m | 1      | 1Gi   | 1Gi   |

## Security requirements

Qubership APIHUB Sniffer Agent work on k8s nodes network level and requires high priveledges.

As soon as this tool is not for production usage - it is fine. 


## Set up values.yml

1. Download Qubership APIHUB Sniffer Agent helm chart
1. Fill `values.yaml` with corresponding deploy parameters. `values.yaml` is self-documented, so please refer to it

## Execute helm install

In order to deploy Qubership APIHUB to your k8s cluster execute the following command:

```
helm install qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent --create-namespace -f ./helm-templates/qubership-apihub-sniffer-agent/values.yaml ./helm-templates/qubership-apihub-sniffer-agent
```

In order to uninstall Qubership APIHUB Sniffer Agent from your k8s cluster execute the following command:

```
helm uninstall qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent
```