package authutils

import (
	"sso/internal/app/interfaces"
)

func MergeUserData(us interfaces.UserService, sessionID int, userID int) error {
	err := us.MergeUserData(sessionID, userID)
	if err != nil {
		return err
	}
	return nil
}
