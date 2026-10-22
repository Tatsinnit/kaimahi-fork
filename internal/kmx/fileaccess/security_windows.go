//go:build windows

package fileaccess

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckPrivate requires a local NTFS regular file or directory owned by the
// current token user with a present, protected DACL containing only explicit
// ordinary allow ACEs for that user. It never repairs or rewrites security.
func CheckPrivate(ctx context.Context, object Object, root bool) error {
	if err := checkContext(ctx); err != nil {
		return wrapAccess("check privacy", err)
	}
	err := withHandle(rawObject(object), func(handle windows.Handle) error {
		if err := qualifyHandleAny(ctx, handle); err != nil {
			return err
		}
		if err := checkContext(ctx); err != nil {
			return err
		}
		if root {
			if err := qualifyHandle(ctx, handle, true); err != nil {
				return err
			}
		}
		if err := checkContext(ctx); err != nil {
			return err
		}
		user, err := currentUser(ctx)
		if err != nil {
			return err
		}
		owner, control, dacl, err := securityOf(ctx, handle)
		if err != nil {
			return err
		}
		if err := checkContext(ctx); err != nil {
			return err
		}
		return checkPrivateSecurity(ctx, owner, control, dacl, user)
	})
	return wrapAccess("check privacy", err)
}

const readOnlyDirectoryRights = windows.FILE_LIST_DIRECTORY | windows.FILE_READ_EA | windows.FILE_TRAVERSE |
	windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE |
	windows.GENERIC_READ | windows.GENERIC_EXECUTE

const fileAddSubdirectory = 0x4

// CheckSafeDirectory applies the existing public-ancestor policy to a local
// NTFS directory. Trusted system owners retain their access; other principals
// may only list, read, and traverse, plus create a subdirectory on a
// non-immediate ancestor.
func CheckSafeDirectory(ctx context.Context, directory *Directory, immediate bool) error {
	if err := checkContext(ctx); err != nil {
		return wrapAccess("check ancestor", err)
	}
	err := withHandle(rawObject(directory), func(handle windows.Handle) error {
		if err := qualifyHandle(ctx, handle, true); err != nil {
			return err
		}
		if err := checkContext(ctx); err != nil {
			return err
		}
		owner, _, dacl, err := securityOf(ctx, handle)
		if err != nil {
			return err
		}
		if err := checkPublicSecurity(ctx, owner, dacl, immediate); err != nil {
			return err
		}
		return checkContext(ctx)
	})
	return wrapAccess("check ancestor", err)
}

func checkPublicSecurity(ctx context.Context, owner *windows.SID, dacl *windows.ACL, immediate bool) error {
	trusted, err := trustedPrincipals(ctx)
	if err != nil {
		return err
	}
	if !anyEqual(trusted, owner) {
		return unsafeCause("directory owner is not trusted")
	}
	allowed := uint32(readOnlyDirectoryRights)
	if !immediate {
		allowed |= fileAddSubdirectory
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		if err := checkContext(ctx); err != nil {
			return err
		}
		ace, sid, err := aceAt(dacl, i)
		if err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return unsafeCause("directory has an unsupported ACE")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || anyEqual(trusted, sid) {
			continue
		}
		if uint32(ace.Mask)&^allowed != 0 {
			return unsafeCause("directory grants untrusted write access")
		}
	}
	return nil
}

func checkPrivateSecurity(ctx context.Context, owner *windows.SID, control windows.SECURITY_DESCRIPTOR_CONTROL, dacl *windows.ACL, user *windows.SID) error {
	if owner == nil || user == nil || !owner.Equals(user) {
		return unsafeCause("private object owner is not the current user")
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return unsafeCause("private object DACL is not protected")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		if err := checkContext(ctx); err != nil {
			return err
		}
		ace, sid, err := aceAt(dacl, i)
		if err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return unsafeCause("private object has an unsupported or inherited ACE")
		}
		if !sid.Equals(owner) {
			return unsafeCause("private object has a non-owner grant")
		}
	}
	return nil
}

func currentUser(ctx context.Context) (*windows.SID, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, unreadableError(err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

func trustedPrincipals(ctx context.Context) ([]*windows.SID, error) {
	user, err := currentUser(ctx)
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, unreadableError(err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, unreadableError(err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	installer, err := windows.StringToSid(trustedInstaller)
	if err != nil {
		return nil, unreadableError(err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return []*windows.SID{user, system, admins, installer}, nil
}

func anyEqual(sids []*windows.SID, sid *windows.SID) bool {
	for _, candidate := range sids {
		if candidate.Equals(sid) {
			return true
		}
	}
	return false
}

func securityOf(ctx context.Context, handle windows.Handle) (*windows.SID, windows.SECURITY_DESCRIPTOR_CONTROL, *windows.ACL, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, 0, nil, unreadableError(err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, 0, nil, err
	}
	if !sd.IsValid() {
		return nil, 0, nil, unsafeCause("invalid security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, 0, nil, unreadableError(err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, 0, nil, err
	}
	if owner == nil || !owner.IsValid() {
		return nil, 0, nil, unsafeCause("missing or invalid owner")
	}
	control, _, err := sd.Control()
	if err != nil {
		return nil, 0, nil, unreadableError(err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, 0, nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, 0, nil, unreadableError(err)
	}
	if err := checkContext(ctx); err != nil {
		return nil, 0, nil, err
	}
	if control&windows.SE_DACL_PRESENT == 0 || dacl == nil {
		return nil, 0, nil, unsafeCause("missing or null DACL")
	}
	return owner, control, dacl, nil
}

func aceAt(dacl *windows.ACL, i uint32) (*windows.ACCESS_ALLOWED_ACE, *windows.SID, error) {
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, i, &ace); err != nil {
		return nil, nil, unreadableError(err)
	}
	if ace == nil || ace.Header.AceFlags&^uint8(windows.VALID_INHERIT_FLAGS) != 0 {
		return nil, nil, unsafeCause("unsupported ACE")
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
		return ace, nil, nil
	}
	if ace.Header.AceSize < uint16(unsafe.Offsetof(ace.SidStart))+8 {
		return nil, nil, unsafeCause("malformed ACE")
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.IsValid() || int(unsafe.Offsetof(ace.SidStart))+sid.Len() > int(ace.Header.AceSize) {
		return nil, nil, unsafeCause("ACE has an invalid SID")
	}
	return ace, sid, nil
}
