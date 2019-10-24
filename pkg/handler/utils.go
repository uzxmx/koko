package handler

import (
	"fmt"
	"strings"

	"github.com/gliderlabs/ssh"
	"github.com/jumpserver/koko/pkg/model"
	"github.com/jumpserver/koko/pkg/service"
	"github.com/jumpserver/koko/pkg/utils"
)

func parseSessionEnvironment(sess ssh.Session) map[string]string {
	options := make(map[string]string)
	for _, env := range sess.Environ() {
		ary := strings.Split(env, "=")
		switch ary[0] {
		case "Interactive", "AssetID", "SystemUserName":
			options[ary[0]] = ary[1]
		}
	}
	return options
}

func getAssetAndSystemUserForNoInteractiveMode(sess ssh.Session, user *model.User, options map[string]string) (asset *model.Asset, su *model.SystemUser) {
	assetID, ok := options["AssetID"]
	if !ok || len(assetID) == 0 {
		utils.IgnoreErrWriteString(sess, "AssetID must be provided for non-interactive mode")
		return
	}
	assets := service.GetUserAssetByID(user.ID, assetID)
	if len(assets) > 0 {
		asset = &assets[0]
	} else {
		utils.IgnoreErrWriteString(sess, fmt.Sprintf("Cannot find asset with ID %s", assetID))
		return
	}

	systemUsers := service.GetUserAssetSystemUsers(user.ID, asset.ID)
	switch len(systemUsers) {
	case 0:
		su = &model.SystemUser{}
	case 1:
		su = &systemUsers[0]
	default:
		systemUserName, ok := options["SystemUserName"]
		if !ok || len(systemUserName) == 0 {
			su = &systemUsers[0]
		} else {
			for _, systemUser := range systemUsers {
				if systemUser.Name == systemUserName {
					su = &systemUser
					break
				}
			}
			if su == nil {
				utils.IgnoreErrWriteString(sess, fmt.Sprintf("Cannot find system user with name %s", systemUserName))
				return
			}
		}
	}
	return
}
