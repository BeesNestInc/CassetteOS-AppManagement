package main

import (
	"github.com/BeesNestInc/CassetteOS-AppManagement/codegen/message_bus"
	"github.com/BeesNestInc/CassetteOS-AppManagement/common"
	"github.com/BeesNestInc/CassetteOS-Common/external"
	"github.com/samber/lo"
)

func main() {
	eventTypes := lo.Map(common.EventTypes, func(item message_bus.EventType, _ int) external.EventType {
		return external.EventType{
			Name:     item.Name,
			SourceID: item.SourceID,
			PropertyTypeList: lo.Map(
				item.PropertyTypeList, func(item message_bus.PropertyType, _ int) external.PropertyType {
					return external.PropertyType{
						Name:        item.Name,
						Description: item.Description,
						Example:     item.Example,
					}
				},
			),
		}
	})

	external.PrintEventTypesAsMarkdown(common.AppManagementServiceName, common.AppManagementVersion, eventTypes)
}
