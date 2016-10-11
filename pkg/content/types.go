package content

//chrootCommandFunc provides an injectable way to chroot and execute for testing.
type chrootCommandFunc func(string)

//chrootGetBlobFunc provides an injectable way to chroot and execute for testing
type chrootGetBlobFunc func() error

// Inspector is the interface for all image inspectors.
type Inspector interface {
	// Inspect inspects and serves the image based on the ImageInspectorOptions.
	Inspect(mountPath string) error
	//GetPackages
	GetPackages() []packages
}
