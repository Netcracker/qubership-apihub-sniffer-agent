# Qubership APIHUB Sniffer Agent utilities for quick deployment to local k8s cluster

For local k8s cluster set up please Please refer to [Qubership APIHUB quickstart Installation on local k8s cluster](https://github.com/Netcracker/qubership-apihub/tree/main/helm-templates/local-k8s-quickstart)

## Prerequisites

1. Helm
2. Bash (GitBash, Cygwin, etc)

Assumptions:

1. local k8s cluter is set up, up and running, kubectl configured

## Deployment

Deployment phases represented by scripts in `scripts` folder, so you can see what happens on each step in them:

- `0-lib.sh` - just set of utility functions, no deployment logic here
- `1-deploy-minio-operator.sh` - deploy of official Minio operator
- `2-deploy-minio-tenant.sh` - deploy of Minio CR which is handled by Minio operator - this step creates Minio instance for Sniffer Agent. This script includes Minio secrets generation.
- `3-deploy-sniffer-agent.sh` - deploy Sniffer Agent itself. This script includes Sniffer Agent secrets generation.

One-liners:

1. `quickstart.sh` - Minio + Sniffer Agent.

## Uninstallation

```
helm uninstall qubership-apihub-sniffer-agent -n qubership-apihub-sniffer-agent
helm uninstall minio-tenant -n minio-tenant
helm uninstall minio-operator -n minio-operator
```