package gatekeeper

import (
	"errors"
	"strings"
)

var ErrInvalidName = errors.New("Name required")
var ErrInvalidID = errors.New("ID required")
var ErrUserNotFound = errors.New("User not found")
var ErrRoleNotFound = errors.New("Role not found")
var ErrPermissionNotFound = errors.New("Permission not found")
var ErrRoleAlreadyAssigned = errors.New("Role  already assigned")
var ErrPermissionAlreadyAssigned = errors.New("Permission already assigned")
var ErrRoleNotAssigned = errors.New("Role not Assigned")
var ErrPermissionNotAssigned = errors.New("Permission not Assigned")

type UserID uint64
type RoleID uint64
type PermissionID uint64

type User struct {
	ID    UserID
	Name  string
	Roles []RoleID
}

type Role struct {
	ID          RoleID
	Name        string
	Permissions []PermissionID
}

type Permission struct {
	ID       PermissionID
	Resource string
	Action   string
}

type Engine struct {
	users       map[UserID]*User
	roles       map[RoleID]*Role
	permissions map[PermissionID]*Permission

	nextUserID       UserID
	nextRoleID       RoleID
	nextPermissionID PermissionID
}

func New() *Engine {
	return &Engine{
		users:       make(map[UserID]*User),
		roles:       make(map[RoleID]*Role),
		permissions: make(map[PermissionID]*Permission),

		nextUserID:       1,
		nextRoleID:       1,
		nextPermissionID: 1,
	}
}

func (e *Engine) CreateUser(name string) (UserID, error) {
	if strings.TrimSpace(name) == "" {
		return 0, ErrInvalidName
	}
	id := e.nextUserID
	e.users[UserID(id)] = &User{
		ID:   id,
		Name: name,
	}
	e.nextUserID++
	return id, nil
}

func (e *Engine) CreateRole(name string) (RoleID, error) {
	if strings.TrimSpace(name) == "" {
		return 0, ErrInvalidName
	}
	id := e.nextRoleID

	e.roles[RoleID(id)] = &Role{
		ID:   id,
		Name: name,
	}
	e.nextRoleID++
	return id, nil
}

func (e *Engine) CreatePermission(resource, action string) (PermissionID, error) {
	if strings.TrimSpace(resource) == "" {
		return 0, ErrInvalidName
	}
	if strings.TrimSpace(action) == "" {
		return 0, ErrInvalidName
	}
	id := e.nextPermissionID

	e.permissions[PermissionID(id)] = &Permission{
		ID:       id,
		Resource: resource,
		Action:   action,
	}
	e.nextPermissionID++
	return id, nil
}
func copyUser(u *User) User {
	cp := *u
	cp.Roles = append([]RoleID(nil), u.Roles...)
	return cp
}

func copyRole(r *Role) Role {
	cp := *r
	cp.Permissions = append([]PermissionID(nil), r.Permissions...)
	return cp
}

func (e *Engine) GetUser(userid UserID) (User, error) {
	if userid == 0 {
		return User{}, ErrInvalidID
	}
	user, exists := e.users[userid]
	if !exists {
		return User{}, ErrUserNotFound
	}

	return copyUser(user), nil
}

func (e *Engine) GetRole(roleid RoleID) (Role, error) {
	if roleid == 0 {
		return Role{}, ErrInvalidID
	}
	role, exists := e.roles[roleid]
	if !exists {
		return Role{}, ErrRoleNotFound
	}
	return copyRole(role), nil
}

func (e *Engine) GetPermission(permissionid PermissionID) (Permission, error) {
	if permissionid == 0 {
		return Permission{}, ErrInvalidID
	}
	permission, exists := e.permissions[permissionid]
	if !exists {
		return Permission{}, ErrPermissionNotFound
	}
	return *permission, nil
}

func (e *Engine) AssignRole(userid UserID, roleid RoleID) error {
	if userid == 0 {
		return ErrInvalidID
	}
	if roleid == 0 {
		return ErrInvalidID
	}
	if _, exists := e.roles[roleid]; !exists {
		return ErrRoleNotFound
	}
	user, exists := e.users[userid]
	if !exists {
		return ErrUserNotFound
	}
	for _, r := range user.Roles {
		if r == roleid {
			return ErrRoleAlreadyAssigned
		}
	}
	user.Roles = append(user.Roles, roleid)
	return nil
}

func (e *Engine) RemoveRole(userid UserID, roleid RoleID) error {
	if userid == 0 {
		return ErrInvalidID
	}
	if roleid == 0 {
		return ErrInvalidID
	}
	if _, exists := e.roles[roleid]; !exists {
		return ErrRoleNotFound
	}
	user, userExists := e.users[userid]
	if !userExists {
		return ErrUserNotFound
	}
	found := false
	newroles := make([]RoleID, 0, len(user.Roles))
	for _, r := range user.Roles {
		if r != roleid {
			newroles = append(newroles, r)
		} else {
			found = true
		}
	}
	if !found {
		return ErrRoleNotAssigned
	}
	user.Roles = newroles
	return nil
}

func (e *Engine) AssignPermission(roleid RoleID, permissionid PermissionID) error {
	if roleid == 0 {
		return ErrInvalidID
	}
	if permissionid == 0 {
		return ErrInvalidID
	}
	role, roleexists := e.roles[roleid]
	if roleexists {
		_, exists := e.permissions[permissionid]
		if exists {
			for _, p := range role.Permissions {
				if p == permissionid {
					return ErrPermissionAlreadyAssigned
				}
			}
			role.Permissions = append(role.Permissions, permissionid)
		} else {
			return ErrPermissionNotFound
		}
	} else {
		return ErrRoleNotFound
	}
	return nil
}

func (e *Engine) RemovePermission(roleid RoleID, permissionid PermissionID) error {
	if roleid == 0 {
		return ErrInvalidID
	}
	if permissionid == 0 {
		return ErrInvalidID
	}
	_, exists := e.permissions[permissionid]
	if !exists {
		return ErrPermissionNotFound
	}
	role, roleexists := e.roles[roleid]
	if !roleexists {
		return ErrRoleNotFound
	}
	found := false
	newpermisson := make([]PermissionID, 0, len(role.Permissions))
	for _, p := range role.Permissions {
		if p != permissionid {
			newpermisson = append(newpermisson, p)
		} else {
			found = true
		}
	}
	if !found {
		return ErrPermissionNotAssigned
	}
	role.Permissions = newpermisson
	return nil
}

func (e *Engine) Can(userID UserID, resource, action string) (bool, error) {
	if userID == 0 {
		return false, ErrInvalidID
	}
	if strings.TrimSpace(resource) == "" {
		return false, ErrInvalidName
	}
	if strings.TrimSpace(action) == "" {
		return false, ErrInvalidName
	}
	user, exists := e.users[userID]
	if !exists {
		return false, ErrUserNotFound
	}
	for _, roleID := range user.Roles {
		role, exists := e.roles[roleID]
		if !exists {
			return false, ErrRoleNotFound
		}
		for _, permissionID := range role.Permissions {
			permission, exists := e.permissions[permissionID]
			if !exists {
				return false, ErrPermissionNotFound
			}
			if permission.Resource == resource &&
				permission.Action == action {
				return true, nil
			}
		}
	}
	return false, nil
}

func (e *Engine) DeleteUser(userid UserID) error {
	if userid == 0 {
		return ErrInvalidID
	}
	_, exists := e.users[userid]
	if exists {
		delete(e.users, userid)
	} else {
		return ErrUserNotFound
	}
	return nil
}

func (e *Engine) DeleteRole(roleID RoleID) error {
	if roleID == 0 {
		return ErrInvalidID
	}
	_, exists := e.roles[roleID]
	if !exists {
		return ErrRoleNotFound
	}
	for _, user := range e.users {
		for i, r := range user.Roles {
			if r == roleID {
				user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
				break
			}
		}
	}
	delete(e.roles, roleID)
	return nil
}

func (e *Engine) DeletePermission(permissionID PermissionID) error {
	if permissionID == 0 {
		return ErrInvalidID
	}
	_, exists := e.permissions[permissionID]
	if !exists {
		return ErrPermissionNotFound
	}
	for _, role := range e.roles {
		for i, p := range role.Permissions {
			if p == permissionID {
				role.Permissions = append(role.Permissions[:i], role.Permissions[i+1:]...)
				break
			}
		}
	}
	delete(e.permissions, permissionID)
	return nil
}

func (e *Engine) RenameUser(userid UserID, Newname string) error {
	if strings.TrimSpace(Newname) == "" {
		return ErrInvalidName
	}
	if userid == 0 {
		return ErrInvalidID
	}
	user, exists := e.users[userid]
	if exists {
		user.Name = Newname
	} else {
		return ErrUserNotFound
	}
	return nil
}

func (e *Engine) RenameRole(roleid RoleID, Newname string) error {
	if strings.TrimSpace(Newname) == "" {
		return ErrInvalidName
	}
	if roleid == 0 {
		return ErrInvalidID
	}
	role, exists := e.roles[roleid]
	if exists {
		role.Name = Newname
	} else {
		return ErrRoleNotFound
	}
	return nil
}
