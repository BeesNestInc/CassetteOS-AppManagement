package docker_test

import (
	"testing"

	"github.com/BeesNestInc/CassetteOS-AppManagement/pkg/docker"
	"gotest.tools/v3/assert"
)

func TestCurrentArchitecture(t *testing.T) {
	a, err := docker.CurrentArchitecture()
	assert.NilError(t, err)
	assert.Assert(t, a != "")
}
