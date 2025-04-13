# Internal service components

The folder contains service components implementing internal functions required during run time

## Files

* [capture.go](capture/capture.go) implements a capture agent to get packets from network and save it to a local file
* [cloud_storage.go](cloud_storage/cloud_storage.go) stores local files into S3/minio
* [disk_cache/DiskCache.go](disk_cache/DiskCache.go) fast cache using local disk storage to reduce memory consumption
* [disk_cache/DiskCache_test.go](disk_cache/DiskCache_test.go) a test for DiskCache
* [kube_service/KubeService.go](kube_service/KubeService.go) common code for kubernetes
* [kube_service/NamespacePods.go](kube_service/NamespacePods.go) code related to namespace PODs
* [kube_service/NamespaceUtils.go](kube_service/NamespaceUtils.go) code related to namespaces general
* [name_resolver/NameResolver.go](name_resolver/NameResolver.go) name resolution code to get service names and versions for a particular IP address
* [neighbour/notifier.go](neighbour/notifier.go) sends notifications to a neighbours
* [service/SystemInfoService.go](service/SystemInfoService.go) reads and validates configuration at startup. See more about configuration at [configuration section](../../docs/README.md#configuration-documentation)
