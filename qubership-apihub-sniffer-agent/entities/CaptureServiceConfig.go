package entities

type CaptureServiceConfig struct {
	NetworkInterface      string // a network interface to gather packets on
	WorkDirectory         string // local path to store capture data
	SnapshotLen           int    // capture snapshot length (262144 by default)
	OutputFileCompression bool   // if true then capture data will be compressed during writing
	InstanceId            string // process instance ID for making distinctive capture files from different PODs
}
