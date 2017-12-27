package inspector

import (
	"testing"

	iicmd "github.com/openshift/image-inspector/pkg/cmd"
)

func TestAcquiringInInspect(t *testing.T) {
	for k, v := range map[string]struct {
		opts           iicmd.ImageInspectorOptions
		shouldFail     bool
		expectedAcqErr string
	}{
		"Invalid docker daemon endpoint": {
			opts:           iicmd.ImageInspectorOptions{URI: "No such file"},
			shouldFail:     true,
			expectedAcqErr: "Unable to connect to docker daemon: invalid endpoint",
		},
	} {
		ii := NewDefaultImageInspector(v.opts).(*defaultImageInspector)
		err := ii.Inspect()
		if v.shouldFail && err == nil {
			t.Errorf("%s should have failed but it didn't!", k)
		}
		if !v.shouldFail {
			if err != nil {
				t.Errorf("%s should have succeeded but failed with %v", k, err)
			}
		}
		if ii.meta.ImageAcquireError != v.expectedAcqErr {
			t.Errorf("%s acquire error is not matching.\nExtected: %v\nReceived: %v\n", k, v.expectedAcqErr, ii.meta.ImageAcquireError)
		}
	}
}
