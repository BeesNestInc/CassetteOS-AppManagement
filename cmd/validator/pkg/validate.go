package pkg

import (
	"github.com/BeesNestInc/CassetteOS-AppManagement/codegen"
	"github.com/BeesNestInc/CassetteOS-AppManagement/common"
	"github.com/BeesNestInc/CassetteOS-AppManagement/service"
	"github.com/compose-spec/compose-go/loader"
)

func VaildDockerCompose(yaml []byte) (err error) {
	err = nil
	// recover
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	docker, err := service.NewComposeAppFromYAML(yaml, false, false)

	ex, ok := docker.Extensions[common.ComposeExtensionNameXCasaOS]
	if !ok {
		return service.ErrComposeExtensionNameXCasaOSNotFound
	}

	var storeInfo codegen.ComposeAppStoreInfo
	if err = loader.Transform(ex, &storeInfo); err != nil {
		return
	}

	return
}
