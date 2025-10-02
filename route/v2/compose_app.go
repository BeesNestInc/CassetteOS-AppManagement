package v2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/BeesNestInc/CassetteOS-AppManagement/codegen"
	"github.com/BeesNestInc/CassetteOS-AppManagement/common"
	"github.com/BeesNestInc/CassetteOS-AppManagement/service"
	"github.com/BeesNestInc/CassetteOS-Common/utils"
	"github.com/BeesNestInc/CassetteOS-Common/utils/logger"
	"github.com/BeesNestInc/CassetteOS-AppManagement/pkg/config" 
	"github.com/compose-spec/compose-go/types"
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var ErrComposeAppIDNotProvided = errors.New("compose AppID (compose project name) is not provided")

func (a *AppManagement) MyComposeAppList(ctx echo.Context) error {
	composeAppsWithStoreInfo, err := composeAppsWithStoreInfo(ctx.Request().Context(), composeAppsWithStoreInfoOpts{
		checkIsUpdateAvailable: true,
	})
	if err != nil {
		message := err.Error()
		logger.Error("failed to list compose apps with store info", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	return ctx.JSON(http.StatusOK, codegen.ComposeAppListOK{
		Data: &composeAppsWithStoreInfo,
	})
}

func (a *AppManagement) MyComposeApp(ctx echo.Context, id codegen.ComposeAppID) error {
	if id == "" {
		message := ErrComposeAppIDNotProvided.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	composeApps, err := service.MyService.Compose().List(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	composeApp, ok := composeApps[id]
	if !ok {
		message := fmt.Sprintf("compose app `%s` not found", id)
		return ctx.JSON(http.StatusNotFound, codegen.ResponseNotFound{Message: &message})
	}

	accept := ctx.Request().Header.Get(echo.HeaderAccept)
	if accept == common.MIMEApplicationYAML {
		// generate yaml should to replace all yaml.Marshal. But for now, we just use it Setting Page API
		yaml, err := service.GenerateYAMLFromComposeApp(*composeApp)
		if err != nil {
			message := err.Error()
			return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
				Message: &message,
			})
		}

		return ctx.String(http.StatusOK, string(yaml))
	}

	storeInfo, err := composeApp.StoreInfo(true)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}

	status, err := service.MyService.Compose().Status(ctx.Request().Context(), composeApp.Name)
	if err != nil {
		status = "unknown"
		logger.Error("failed to get compose app status", zap.Error(err), zap.String("composeAppID", id))
	}

	// disable the because performance issue
	// check update is hard and cost a lot of time. specially when the tag is latest
	// such as Stable Diffusion. the check by ZimaOS GPU Application by @LinkLeong
	// Alought @LinkLeong Didn't need the field.
	// We should add a new API to get app info without update info
	// and restore the following code

	// check if updateAvailable
	// updateAvailable := service.MyService.AppStoreManagement().IsUpdateAvailable(composeApp)

	message := fmt.Sprintf("!! JSON format is for debugging purpose only - use `Accept: %s` HTTP header to get YAML instead !!", common.MIMEApplicationYAML)
	return ctx.JSON(http.StatusOK, codegen.ComposeAppOK{
		// extension properties aren't marshalled - https://github.com/golang/go/issues/6213
		Message: &message,
		Data: &codegen.ComposeAppWithStoreInfo{
			StoreInfo: storeInfo,
			Compose:   (*types.Project)(composeApp),
			Status:    &status,

			// see above comment
			UpdateAvailable: nil,
		},
	})
}

func (a *AppManagement) IsNewComposeUncontrolled(newComposeApp *service.ComposeApp) (bool, error) {
	// to check if the new compose app is uncontrolled
	newTag, err := newComposeApp.MainTag()
	if err != nil {
		return false, err
	}

	// TODO refactor this. because if user not update. the status will be uncontrolled.
	if lo.Contains(common.NeedCheckDigestTags, newTag) {
		return false, nil
	}

	// compare store info
	StoreApp, err := service.MyService.AppStoreManagement().ComposeApp(newComposeApp.Name)
	if err != nil {
		return false, err
	}

	if StoreApp == nil {
		logger.Error("store app not found", zap.String("composeAppID", newComposeApp.Name))
		return false, nil
	}

	StableTag, err := StoreApp.MainTag()
	if err != nil {
		return false, err
	}

	return StableTag != newTag, nil
}

func (a *AppManagement) ApplyComposeAppSettings(ctx echo.Context, id codegen.ComposeAppID, params codegen.ApplyComposeAppSettingsParams) error {
	if id == "" {
		message := ErrComposeAppIDNotProvided.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	composeApps, err := service.MyService.Compose().List(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	composeApp, ok := composeApps[id]
	if !ok {
		message := fmt.Sprintf("compose app `%s` not found", id)
		return ctx.JSON(http.StatusNotFound, codegen.ResponseNotFound{Message: &message})
	}

	buf, err := YAMLfromRequest(ctx)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	// validate new compose yaml
	newComposeApp, err := service.NewComposeAppFromYAML(buf, true, true)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	uncontrolled, err := a.IsNewComposeUncontrolled(newComposeApp)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}

	_ = newComposeApp.SetUncontrolled(uncontrolled)
	buf, err = service.GenerateYAMLFromComposeApp(*newComposeApp)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}

	if params.CheckPortConflict == nil || *params.CheckPortConflict {

		// validation 1 - check if there are ports in use
		validation, err := newComposeApp.GetPortsInUse()
		if err != nil {
			message := err.Error()
			return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
				Message: &message,
			})
		}

		if validation != nil && validation.PortsInUse != nil {
			// we want to ignore the ports being used by current compose app
			for _, service := range composeApp.Services {
				for _, portToSkip := range service.Ports {
					if validation.PortsInUse.TCP != nil {
						tcpPortsInUse := []string{}
						for _, tcpPort := range *validation.PortsInUse.TCP {
							if tcpPort != portToSkip.Published {
								tcpPortsInUse = append(tcpPortsInUse, tcpPort)
							}
						}
						validation.PortsInUse.TCP = &tcpPortsInUse
					}

					if validation.PortsInUse.UDP != nil {
						udpPortsInUse := []string{}
						for _, udpPort := range *validation.PortsInUse.UDP {
							if udpPort != portToSkip.Published {
								udpPortsInUse = append(udpPortsInUse, udpPort)
							}
						}
						validation.PortsInUse.UDP = &udpPortsInUse
					}
				}
			}

			if (validation.PortsInUse.TCP != nil && len(*validation.PortsInUse.TCP) > 0) ||
				(validation.PortsInUse.UDP != nil && len(*validation.PortsInUse.UDP) > 0) {

				validationErrors := codegen.ComposeAppValidationErrors{}
				if err := validationErrors.FromComposeAppValidationErrorsPortsInUse(*validation); err != nil {
					message := err.Error()
					return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
						Message: &message,
					})
				}

				message := "there are ports in use"
				return ctx.JSON(http.StatusBadRequest, codegen.ComposeAppBadRequest{
					Message: &message,
					Data:    &validationErrors,
				})
			}
		}
	}

	if params.DryRun != nil && *params.DryRun {
		return ctx.JSON(http.StatusOK, codegen.ComposeAppInstallOK{
			Message: lo.ToPtr("only validation has been done because `dry_run` is specified - skipping compose app installation"),
		})
	}

	// attach context key/value pairs from upstream
	backgroundCtx := common.WithProperties(context.Background(), PropertiesFromQueryParams(ctx))

	if err := composeApp.Apply(backgroundCtx, buf); err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}

	return ctx.JSON(http.StatusOK, codegen.ComposeAppUpdateSettingsOK{
		Message: utils.Ptr("compose app is being applied with changes asynchroniously"),
	})
}

func (a *AppManagement) InstallComposeApp(ctx echo.Context, params codegen.InstallComposeAppParams) error {
	buf, err := YAMLfromRequest(ctx)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	// validate new compose yaml
	composeApp, err := service.NewComposeAppFromYAML(buf, false, true)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	// Create a new user for the app
	// Generate Username
	randomBytesUsername := make([]byte, 4)
	if _, err := rand.Read(randomBytesUsername); err != nil {
		message := fmt.Sprintf("failed to generate random string for username: %s", err.Error())
		logger.Error("failed to generate random bytes for username", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}
	usernameSuffix := hex.EncodeToString(randomBytesUsername)
	username := fmt.Sprintf("%s_%s", composeApp.Name, usernameSuffix)

	// Generate Password
	randomBytesPassword := make([]byte, 16)
	if _, err := rand.Read(randomBytesPassword); err != nil {
		message := fmt.Sprintf("failed to generate random password: %s", err.Error())
		logger.Error("failed to generate random bytes for password", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}
	password := hex.EncodeToString(randomBytesPassword)

	// Step 1: As db_admin_user, call a stored procedure to create a new user with CREATEDB privilege.
	// IMPORTANT: The user must ensure the 'create_docker_app_user' procedure exists and runs:
	// 'CREATE ROLE ' || username || ' WITH LOGIN PASSWORD ''' || password || ''' CREATEDB;'
	cmd := exec.Command("psql", "-h", "localhost", "-U", "db_admin_user", "-d", "postgres", "-c", fmt.Sprintf("SELECT create_docker_app_user('%s', '%s');", username, password))
	cmd.Env = append(os.Environ(), "PGPASSWORD="+ config.AppInfo.DBAdminPassword) 
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := fmt.Sprintf("failed to create docker app user role: %s - %s", err.Error(), string(output))
		logger.Error("failed to create docker app user role", zap.Error(err), zap.String("output", string(output)))
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}
	

	// Step 2: As the newly created user, create the database.
	cmd = exec.Command("psql", "-h", "localhost", "-U", username, "-d", "postgres", "-c", fmt.Sprintf("CREATE DATABASE %s;", username))
	cmd.Env = append(os.Environ(), "PGPASSWORD="+password) // Set password for non-interactive login
	output, err = cmd.CombinedOutput()
	if err != nil {
		message := fmt.Sprintf("failed to create docker app database: %s - %s", err.Error(), string(output))
		logger.Error("failed to create docker app database", zap.Error(err), zap.String("output", string(output)))
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}

	// Inject database credentials into the compose app
	if err := injectDatabaseCredentials(composeApp, username, password, username); err != nil {
		message := fmt.Sprintf("failed to inject database credentials: %s", err.Error())
		logger.Error("failed to inject database credentials", zap.Error(err))
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}

	// Manually perform environment variable substitution after credential injection.
	// This allows variables like DATABASE_URL to be constructed from credentials
	// like PGUSER, PGPASSWORD, etc.
	for i := range composeApp.Services {
		service := &composeApp.Services[i]

		// Create a simple mapping of the environment for substitution.
		// The preceding injectDatabaseCredentials function ensures the Environment map is not nil.
		envMap := make(map[string]string)
		for k, v := range service.Environment {
			if v != nil {
				envMap[k] = *v
			} else {
				envMap[k] = "" // Ensure keys exist even if value is nil
			}
		}

		// Re-iterate and substitute variables using the map we just created.
		for k, v := range service.Environment {
			if v == nil {
				continue
			}

			// os.Expand uses the ${var} or $var format for substitution.
			newValue := os.Expand(*v, func(key string) string {
				// Lookup the variable in the service's own environment map.
				return envMap[key]
			})

			if newValue != *v {
				service.Environment[k] = &newValue
			}
		}
	}

	uncontrolled, err := a.IsNewComposeUncontrolled(composeApp)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
			Message: &message,
		})
	}

	_ = composeApp.SetUncontrolled(uncontrolled)

	if params.CheckPortConflict == nil || *params.CheckPortConflict {
		// validation 1 - check if there are ports in use
		validation, err := composeApp.GetPortsInUse()
		if err != nil {
			message := err.Error()
			return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
				Message: &message,
			})
		}

		if validation != nil {
			validationErrors := codegen.ComposeAppValidationErrors{}
			if err := validationErrors.FromComposeAppValidationErrorsPortsInUse(*validation); err != nil {
				message := err.Error()
				return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{
					Message: &message,
				})
			}

			message := "there are ports in use"
			return ctx.JSON(http.StatusBadRequest, codegen.ComposeAppBadRequest{
				Message: &message,
				Data:    &validationErrors,
			})
		}
	}

	if params.DryRun != nil && *params.DryRun {
		return ctx.JSON(http.StatusOK, codegen.ComposeAppInstallOK{
			Message: lo.ToPtr("only validation has been done because `dry_run` is specified - skipping compose app installation"),
		})
	}

	if service.MyService.Compose().IsInstalling(composeApp.Name) {
		message := fmt.Sprintf("compose app `%s` is already being installed", composeApp.Name)
		return ctx.JSON(http.StatusConflict, codegen.ComposeAppBadRequest{Message: &message})
	}

	// attach context key/value pairs from upstream
	backgroundCtx := common.WithProperties(context.Background(), PropertiesFromQueryParams(ctx))

	if err := service.MyService.Compose().Install(backgroundCtx, composeApp); err != nil {
		logger.Error("failed to start compose app installation", zap.Error(err))

		message := err.Error()
		if err == service.ErrComposeExtensionNameXCasaOSNotFound {
			return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{Message: &message})
		}

		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	return ctx.JSON(http.StatusOK, codegen.ComposeAppInstallOK{
		Message: lo.ToPtr("compose app is being installed asynchronously"),
	})
}

func (a *AppManagement) UninstallComposeApp(ctx echo.Context, id codegen.ComposeAppID, params codegen.UninstallComposeAppParams) error {
	if id == "" {
		message := ErrComposeAppIDNotProvided.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	appList, err := service.MyService.Compose().List(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	composeApp, ok := appList[id]
	if !ok {
		message := fmt.Sprintf("compose app `%s` not found", id)
		return ctx.JSON(http.StatusNotFound, codegen.ResponseNotFound{Message: &message})
	}

	// attach context key/value pairs from upstream
	backgroundCtx := common.WithProperties(context.Background(), PropertiesFromQueryParams(ctx))

	deleteConfigFolder := true
	if params.DeleteConfigFolder != nil {
		deleteConfigFolder = *params.DeleteConfigFolder
	}

	if err := service.MyService.Compose().Uninstall(backgroundCtx, composeApp, deleteConfigFolder); err != nil {
		logger.Error("failed to uninstall compose app", zap.Error(err), zap.String("appID", id))
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	return ctx.JSON(http.StatusOK, codegen.ComposeAppUninstallOK{
		Message: utils.Ptr("compose app is being uninstalled asynchronously"),
	})
}

func (a *AppManagement) UpdateComposeApp(ctx echo.Context, id codegen.ComposeAppID, params codegen.UpdateComposeAppParams) error {
	if id == "" {
		message := ErrComposeAppIDNotProvided.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	composeApps, err := service.MyService.Compose().List(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	composeApp, ok := composeApps[id]
	if !ok {
		message := fmt.Sprintf("compose app `%s` not found", id)
		return ctx.JSON(http.StatusNotFound, codegen.ResponseNotFound{Message: &message})
	}

	if params.Force != nil && !*params.Force {
		// check if updateAvailable
		if !service.MyService.AppStoreManagement().IsUpdateAvailable(composeApp) {
			message := fmt.Sprintf("compose app `%s` is up to date", id)
			return ctx.JSON(http.StatusOK, codegen.ComposeAppUpdateOK{Message: &message})
		}
	}

	backgroundCtx := common.WithProperties(context.Background(), PropertiesFromQueryParams(ctx))

	if err := composeApp.Update(backgroundCtx); err != nil {
		logger.Error("failed to update compose app", zap.Error(err), zap.String("appID", id))
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	message := fmt.Sprintf("compose app `%s` is being updated asynchronously", id)
	return ctx.JSON(http.StatusOK, codegen.ComposeAppUpdateOK{
		Message: &message,
	})
}

func (a *AppManagement) SetComposeAppStatus(ctx echo.Context, id codegen.ComposeAppID) error {
	if id == "" {
		message := ErrComposeAppIDNotProvided.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	var action codegen.RequestComposeAppStatus
	if err := ctx.Bind(&action); err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{Message: &message})
	}

	composeApps, err := service.MyService.Compose().List(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	composeApp, ok := composeApps[id]
	if !ok {
		message := fmt.Sprintf("compose app `%s` not found", id)
		return ctx.JSON(http.StatusNotFound, codegen.ResponseNotFound{Message: &message})
	}

	backgroundCtx := common.WithProperties(context.Background(), PropertiesFromQueryParams(ctx))
	if err := composeApp.SetStatus(backgroundCtx, action); err != nil {
		message := err.Error()

		if err == service.ErrInvalidComposeAppStatus {
			return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{Message: &message})
		}

		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	return ctx.JSON(http.StatusOK, codegen.RequestComposeAppStatusOK{
		Message: utils.Ptr("compose app status is being changed asynchronously"),
	})
}

func (a *AppManagement) ComposeAppLogs(ctx echo.Context, id codegen.ComposeAppID, params codegen.ComposeAppLogsParams) error {
	if id == "" {
		message := ErrComposeAppIDNotProvided.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	composeApps, err := service.MyService.Compose().List(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	composeApp, ok := composeApps[id]
	if !ok {
		message := fmt.Sprintf("compose app `%s` not found", id)
		return ctx.JSON(http.StatusNotFound, codegen.ResponseNotFound{Message: &message})
	}

	lines := lo.If(params.Lines == nil, 1000).Else(*params.Lines)
	logs, err := composeApp.Logs(ctx.Request().Context(), lines)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	return ctx.JSON(http.StatusOK, codegen.ComposeAppLogsOK{Data: utils.Ptr(string(logs))})
}

func (a *AppManagement) ComposeAppContainers(ctx echo.Context, id codegen.ComposeAppID) error {
	if id == "" {
		message := ErrComposeAppIDNotProvided.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	composeApps, err := service.MyService.Compose().List(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	composeApp, ok := composeApps[id]
	if !ok {
		message := fmt.Sprintf("compose app `%s` not found", id)
		return ctx.JSON(http.StatusNotFound, codegen.ResponseNotFound{Message: &message})
	}

	containerLists, err := composeApp.Containers(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	storeInfo, err := composeApp.StoreInfo(false)
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	// Because of a stupid design by @tigerinus, the `composeApp.Containers(...)` func above was returning a map
	// of docker compose `service` to a single container:
	//
	//     `map[string]codegen.ContainerSummary`
	//
	// However, it is possible a `service` contains multiple containers. Thus as a fix, the func has now been updated
	// to return
	//
	//     `map[string][]codegen.ContainerSummary`
	//
	// Just so that @zhanghengxin does not need to change the frontend last minute before releasing v0.4.4, here is
	// an ugly workaround :(
	containersWorkaround := map[string]codegen.ContainerSummary{}
	for service, containerList := range containerLists {
		containersWorkaround[service] = containerList[0]
	}

	return ctx.JSON(http.StatusOK, codegen.ComposeAppContainersOK{
		Data: &codegen.ComposeAppContainers{
			Main:       storeInfo.Main,
			Containers: &containersWorkaround, // TODO: Remove `containersWorkaround` and use `containerLists` instead in future - requires frontend changes
		},
	})
}

func (a *AppManagement) CheckComposeAppHealthByID(ctx echo.Context, id codegen.ComposeAppID) error {
	if id == "" {
		message := ErrComposeAppIDNotProvided.Error()
		return ctx.JSON(http.StatusBadRequest, codegen.ResponseBadRequest{
			Message: &message,
		})
	}

	composeApps, err := service.MyService.Compose().List(ctx.Request().Context())
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusInternalServerError, codegen.ResponseInternalServerError{Message: &message})
	}

	composeApp, ok := composeApps[id]
	if !ok {
		message := fmt.Sprintf("compose app `%s` not found", id)
		return ctx.JSON(http.StatusNotFound, codegen.ResponseNotFound{Message: &message})
	}

	result, err := composeApp.HealthCheck()
	if err != nil {
		message := err.Error()
		return ctx.JSON(http.StatusServiceUnavailable, codegen.ResponseServiceUnavailable{Message: &message})
	}

	if !result {
		return ctx.JSON(http.StatusServiceUnavailable, codegen.ResponseServiceUnavailable{})
	}

	message := fmt.Sprintf("compose app `%s` passed the health check", id)
	return ctx.JSON(http.StatusOK, codegen.ComposeAppHealthCheckOK{
		Message: &message,
	})
}

func YAMLfromRequest(ctx echo.Context) ([]byte, error) {
	var buf []byte

	switch ctx.Request().Header.Get(echo.HeaderContentType) {
	case common.MIMEApplicationYAML:

		_buf, err := io.ReadAll(ctx.Request().Body)
		if err != nil {
			return nil, err
		}

		buf = _buf

	default:
		var c codegen.ComposeApp
		if err := ctx.Bind(&c); err != nil {
			return nil, err
		}

		_buf, err := yaml.Marshal(c)
		if err != nil {
			return nil, err
		}
		buf = _buf
	}

	return buf, nil
}

type composeAppsWithStoreInfoOpts struct {
	checkIsUpdateAvailable bool
	// The /web/appgrid endpoint does not require information about whether the application can be updated, so we added an option.
	// This endpoint is called as soon as CasaOS is opened, and we don't have time to cache it in advance.
	// We must ensure that this endpoint responds as quickly as possible.
}

func composeAppsWithStoreInfo(ctx context.Context, opts composeAppsWithStoreInfoOpts) (map[string]codegen.ComposeAppWithStoreInfo, error) {
	composeApps, err := service.MyService.Compose().List(ctx)
	if err != nil {
		return nil, err
	}

	return lo.MapValues(composeApps, func(composeApp *service.ComposeApp, id string) codegen.ComposeAppWithStoreInfo {
		if composeApp == nil {
			return codegen.ComposeAppWithStoreInfo{}
		}

		composeAppWithStoreInfo := codegen.ComposeAppWithStoreInfo{
			Compose:         (*codegen.ComposeApp)(composeApp),
			StoreInfo:       nil,
			Status:          utils.Ptr("unknown"),
			UpdateAvailable: utils.Ptr(false),
			IsUncontrolled:  utils.Ptr(false),
		}

		storeInfo, err := composeApp.StoreInfo(true)
		if err != nil {
			logger.Error("failed to get store info", zap.Error(err), zap.String("composeAppID", id))
			return composeAppWithStoreInfo
		}

		composeAppWithStoreInfo.StoreInfo = storeInfo

		if opts.checkIsUpdateAvailable {
			// check if updateAvailable
			updateAvailable := service.MyService.AppStoreManagement().IsUpdateAvailable(composeApp)
			composeAppWithStoreInfo.UpdateAvailable = &updateAvailable
		}

		// status
		if storeInfo.Main == nil {
			logger.Error("failed to get main app", zap.String("composeAppID", id))
			return composeAppWithStoreInfo
		}

		containerLists, err := composeApp.Containers(ctx)
		if err != nil {
			logger.Error("failed to get containers", zap.Error(err), zap.String("composeAppID", id))
			return composeAppWithStoreInfo
		}

		mainContainers, ok := containerLists[*storeInfo.Main]
		if !ok {
			logger.Error("failed to get main app container", zap.String("composeAppID", id))
			return composeAppWithStoreInfo
		}

		isUncontrolled, ok := composeApp.Extensions[common.ComposeExtensionNameXCasaOS].(map[string]interface{})[common.ComposeExtensionPropertyNameIsUncontrolled].(bool)
		if ok {
			composeAppWithStoreInfo.IsUncontrolled = &isUncontrolled
		}

		// Because of a stupid design by @tigerinus, the `composeApp.Containers(...)` func above was returning a map
		// of docker compose `service` to a single container:
		//
		//     `map[string]codegen.ContainerSummary`
		//
		// However, it is possible a `service` contains multiple containers. Thus as a fix, the func has now been updated
		// to return
		//
		//     `map[string][]codegen.ContainerSummary`
		//
		// Apparently, this impacts the downstream logic, like the embarrassing need to use `mainContainers[0]` below.
		//
		// In order words, the status of the compose app is determined by the status of the first main container. Silly...
		//
		// TODO: This needs a re-design in future.
		composeAppWithStoreInfo.Status = &mainContainers[0].State

		return composeAppWithStoreInfo
	}), nil
}

const (
	DBUserVar     = "user_var"
	DBPasswordVar = "password_var"
	DBNameVar     = "db_name_var"
)

func injectDatabaseCredentials(composeApp *service.ComposeApp, user, password, dbName string) error {
	userVar, passwordVar, nameVar := getDBEnvVarNames(composeApp)

	if userVar == "" || passwordVar == "" || nameVar == "" {
		return errors.New("could not determine database credential environment variables")
	}

	for i := range composeApp.Services {
		if composeApp.Services[i].Environment == nil {
			composeApp.Services[i].Environment = make(types.MappingWithEquals)
		}
		composeApp.Services[i].Environment[userVar] = &user
		composeApp.Services[i].Environment[passwordVar] = &password
		composeApp.Services[i].Environment[nameVar] = &dbName
	}

	return nil
}

func getDBEnvVarNames(composeApp *service.ComposeApp) (string, string, string) {
	// Primary method: Check for x-cassetteos -> db-credentials extension
	if xCassetteOS, ok := composeApp.Extensions["x-cassetteos"].(map[string]interface{}); ok {
		if creds, ok := xCassetteOS["db-credentials"].(map[string]interface{}); ok {
			userVar, _ := creds[DBUserVar].(string)
			passwordVar, _ := creds[DBPasswordVar].(string)
			dbNameVar, _ := creds[DBNameVar].(string)
			if userVar != "" && passwordVar != "" && dbNameVar != "" {
				return userVar, passwordVar, dbNameVar
			}
		}
	}

	// Fallback method: Heuristic scan of environment variables
	return findDBEnvVarNamesHeuristically(composeApp)
}

func findDBEnvVarNamesHeuristically(composeApp *service.ComposeApp) (string, string, string) {
	var userVar, passwordVar, nameVar string

	for _, service := range composeApp.Services {
		for key := range service.Environment {
			keyUpper := strings.ToUpper(key)
			if (strings.Contains(keyUpper, "DB_USER") || strings.Contains(keyUpper, "POSTGRES_USER")) && userVar == "" {
				userVar = key
			}
			if (strings.Contains(keyUpper, "DB_PASSWORD") || strings.Contains(keyUpper, "POSTGRES_PASSWORD")) && passwordVar == "" {
				passwordVar = key
			}
			if (strings.Contains(keyUpper, "DB_NAME") || strings.Contains(keyUpper, "POSTGRES_DB")) && nameVar == "" {
				nameVar = key
			}
		}
	}

	return userVar, passwordVar, nameVar
}
