package helper

import (
	"gakuren-system.com/pkg/db"
	"gakuren-system.com/pkg/model"
)

func GetRoleByUUID(uuid string) (*model.StatusModel, error) {
	selectedData, err := db.GetSingleDataByQuery[model.StatusModel]("select * from public.role where uuid = $1", uuid)
	if err != nil {
		return nil, err
	}

	return selectedData, nil
}

func GetUserRolePermissionCodeList(uuid string) (*[]string, error) {
	selectedData, err := db.GetMultipleDataByQuery[model.PermissionModel](`
	SELECT p.code FROM public.user u
		JOIN public.role r on u.role_uuid = r.uuid
		JOIN public.role_permission rp on r.uuid = rp.role_uuid
		JOIN public.permission p on rp.permission_uuid = p.uuid
		JOIN public.menu m on m.uuid = p.menu_uuid
	WHERE u.uuid = $1
	GROUP BY p.code, m.order
	ORDER BY m.order asc;
	`, uuid)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(*selectedData))
	for i, permission := range *selectedData {
		result[i] = permission.Code
	}

	return &result, nil
}

func GetUserMenuList(uuid string) (*[]string, error) {
	selectedData, err := db.GetMultipleDataByQuery[model.MenuModel](`
	SELECT m.name FROM public.user u
		JOIN public.role r on u.role_uuid = r.uuid
		JOIN public.role_permission rp on r.uuid = rp.role_uuid
		JOIN public.permission p on rp.permission_uuid = p.uuid
		JOIN public.menu m on m.uuid = p.menu_uuid
	WHERE u.uuid = $1
	GROUP BY m.name, m.order
	ORDER BY m.order asc;
	`, uuid)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(*selectedData))
	for i, permission := range *selectedData {
		result[i] = permission.Name
	}

	return &result, nil
}
