// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

//go:build windows

package scheduler

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func checkScheduleFileOwner(f *os.File, path string) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read schedule file owner: %w", err)
	}
	return checkScheduleSecurityOwner(sd, path)
}

func checkScheduleDirectoryOwner(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read schedule directory owner: %w", err)
	}
	return checkScheduleSecurityOwner(sd, path)
}

func checkScheduleDirectoryPermissions(string, os.FileInfo) error {
	// Windows permissions are ACL-based; FileMode.Perm does not represent them.
	return nil
}

func checkScheduleSecurityOwner(sd *windows.SECURITY_DESCRIPTOR, path string) error {
	if sd == nil {
		return fmt.Errorf("schedule path %s has no security descriptor", path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read schedule path owner: %w", err)
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("read current user: %w", err)
	}
	user, userErr := token.GetTokenUser()
	closeErr := token.Close()
	if userErr != nil {
		return fmt.Errorf("read current user: %w", userErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close current user token: %w", closeErr)
	}
	if !owner.Equals(user.User.Sid) {
		return fmt.Errorf("schedule path %s is not owned by the current user", path)
	}
	return nil
}
