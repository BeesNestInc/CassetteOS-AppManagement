package v2

import (
	"net/http"

	"github.com/BeesNestInc/CassetteOS-AppManagement/codegen"
	"github.com/BeesNestInc/CassetteOS-AppManagement/pkg/docker"
	"github.com/BeesNestInc/CassetteOS-Common/utils"
	"github.com/labstack/echo/v4"
)

func (a *AppManagement) Info(ctx echo.Context) error {
	architecture, err := docker.CurrentArchitecture()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: utils.Ptr(err.Error()),
		})
	}

	return ctx.JSON(http.StatusOK, codegen.InfoOK{
		Architecture: utils.Ptr(architecture),
	})
}
