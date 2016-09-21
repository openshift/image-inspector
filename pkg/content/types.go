package content

const (
	//DefaultUserFilePath specifies where users are listed
	DefaultUserFilePath = "/etc/passwd"
	//DefaultGroupFilePath specifies where groups are listed
	DefaultGroupFilePath = "/etc/group"
	//DefaultReleasePath specifies where *-release file can be found
	DefaultReleasePath = "/etc/"
)

// chrootContentFunc provides an injectable way to chroot and execute oscap for testing.
type chrootContentFunc func(string) error

// Inspector is the interface for all image inspectors.
type Inspector interface {
	// Inspect inspects and serves the image based on the ImageInspectorOptions.
	Inspect(mountPath string) error
}
