package docker_test

import (
	"fmt"
	"testing"

	"github.com/BeesNestInc/CassetteOS-AppManagement/pkg/docker"
)

func TestGetDir(t *testing.T) {
	fmt.Println(docker.GetDir("", "config"))
}
