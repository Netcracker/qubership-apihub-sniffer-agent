# Internal (private) data types and constants

The folder contains internal (private) data types and constants which were not be exposed outside the module

## Files

* [CachedItem.go](CachedItem.go) An common properties for cached items
* [CaptureConfig.go](CaptureConfig.go) Capture service static configuration. Contains the configuration options that would never change during run time.
* [CaptureControllerConfig.go](CaptureControllerConfig.go) a configuration for controller (web interface) implementation
* [CaptureRequestInternal.go](CaptureRequestInternal.go) an internal representation of capture request to use in capture service. Converted from/to human-readable type received by controller.
* [CaptureRequestInternal_test.go](CaptureRequestInternal_test.go) a test for internal capture configuration and conversion.
* [CloudService.go](CloudService.go) a cloud (kubernetes) service configuration
* [Constants.go](Constants.go) common package constants
* [DiscoveryConfig.go](DiscoveryConfig.go) Discovery service configuration. Contains options to discover neighbour PODs for notifying them about requests received via controller. Since indeterministic approach request can be received and served by any POD from namespace, but the other PODs need to be notified.
* [MinioStorageCreds.go](MinioStorageCreds.go) Cloud storage service configuration. Configuration for accessing S3/Minio storage.
