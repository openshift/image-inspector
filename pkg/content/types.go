package content

// chrootContentFunc provides an injectable way to chroot and execute for testing.
type chrootContentFunc func(string) error

//chrootCommandFunc provides an injectable way to chroot and execute for testing.
type chrootCommandFunc func(string)

// Inspector is the interface for all image inspectors.
type Inspector interface {
	// Inspect inspects and serves the image based on the ImageInspectorOptions.
	Inspect(mountPath string) error
}
