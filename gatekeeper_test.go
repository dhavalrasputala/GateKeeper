package gatekeeper

import "testing"

// helper to build an engine with one user, one role, one permission.
func setup(t *testing.T) (*Engine, UserID, RoleID, PermissionID) {
	t.Helper()
	e := New()

	uid, err := e.CreateUser("alice")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	rid, err := e.CreateRole("admin")
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}
	pid, err := e.CreatePermission("documents", "read")
	if err != nil {
		t.Fatalf("CreatePermission failed: %v", err)
	}
	return e, uid, rid, pid
}

func TestCreateUser(t *testing.T) {
	e := New()
	if _, err := e.CreateUser(""); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName, got %v", err)
	}
	if _, err := e.CreateUser("   "); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName for whitespace-only name, got %v", err)
	}
	id, err := e.CreateUser("bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 1 {
		t.Errorf("expected first user id 1, got %d", id)
	}
}

func TestCreateRole(t *testing.T) {
	e := New()
	if _, err := e.CreateRole(""); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName, got %v", err)
	}
	id, err := e.CreateRole("editor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 1 {
		t.Errorf("expected first role id 1, got %d", id)
	}
}

func TestCreatePermission(t *testing.T) {
	e := New()
	if _, err := e.CreatePermission("", "read"); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName for empty resource, got %v", err)
	}
	if _, err := e.CreatePermission("docs", ""); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName for empty action, got %v", err)
	}
	id, err := e.CreatePermission("docs", "write")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 1 {
		t.Errorf("expected first permission id 1, got %d", id)
	}
}

func TestGetUserRoleGetRolePermission(t *testing.T) {
	e, uid, rid, pid := setup(t)

	if _, err := e.GetUser(0); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if _, err := e.GetUser(999); err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
	u, err := e.GetUser(uid)
	if err != nil || u.Name != "alice" {
		t.Errorf("unexpected user/err: %+v %v", u, err)
	}

	if _, err := e.GetRole(0); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if _, err := e.GetRole(999); err != ErrRoleNotFound {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
	r, err := e.GetRole(rid)
	if err != nil || r.Name != "admin" {
		t.Errorf("unexpected role/err: %+v %v", r, err)
	}

	if _, err := e.GetPermission(0); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if _, err := e.GetPermission(999); err != ErrPermissionNotFound {
		t.Errorf("expected ErrPermissionNotFound, got %v", err)
	}
	p, err := e.GetPermission(pid)
	if err != nil || p.Resource != "documents" || p.Action != "read" {
		t.Errorf("unexpected permission/err: %+v %v", p, err)
	}
}

// This is the key regression test: assigning a role to a user that has no
// roles yet must actually attach the role. The original implementation's
// AssignRole ranged over user.Roles to decide whether to append, so a user
// with zero roles never got the role assigned at all.
func TestAssignRole_FirstAssignmentSticks(t *testing.T) {
	e, uid, rid, _ := setup(t)

	if err := e.AssignRole(uid, rid); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	u, err := e.GetUser(uid)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if len(u.Roles) != 1 || u.Roles[0] != rid {
		t.Fatalf("expected user to have role %d assigned, got %+v", rid, u.Roles)
	}
}

func TestAssignRole_DuplicateRejected(t *testing.T) {
	e, uid, rid, _ := setup(t)

	if err := e.AssignRole(uid, rid); err != nil {
		t.Fatalf("first AssignRole failed: %v", err)
	}
	if err := e.AssignRole(uid, rid); err != ErrRoleAlreadyAssigned {
		t.Fatalf("expected ErrRoleAlreadyAssigned, got %v", err)
	}

	u, _ := e.GetUser(uid)
	if len(u.Roles) != 1 {
		t.Fatalf("expected exactly one role assigned, got %+v", u.Roles)
	}
}

func TestAssignRole_MultipleRolesAllStick(t *testing.T) {
	e, uid, rid1, _ := setup(t)
	rid2, err := e.CreateRole("viewer")
	if err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	if err := e.AssignRole(uid, rid1); err != nil {
		t.Fatalf("AssignRole rid1 failed: %v", err)
	}
	if err := e.AssignRole(uid, rid2); err != nil {
		t.Fatalf("AssignRole rid2 failed: %v", err)
	}

	u, _ := e.GetUser(uid)
	if len(u.Roles) != 2 {
		t.Fatalf("expected 2 roles assigned, got %+v", u.Roles)
	}
}

func TestAssignRole_Errors(t *testing.T) {
	e, uid, rid, _ := setup(t)

	if err := e.AssignRole(0, rid); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID for zero userid, got %v", err)
	}
	if err := e.AssignRole(uid, 0); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID for zero roleid, got %v", err)
	}
	if err := e.AssignRole(uid, 999); err != ErrRoleNotFound {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
	if err := e.AssignRole(999, rid); err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestRemoveRole(t *testing.T) {
	e, uid, rid, _ := setup(t)

	if err := e.AssignRole(uid, rid); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}
	if err := e.RemoveRole(uid, rid); err != nil {
		t.Fatalf("RemoveRole failed: %v", err)
	}
	u, _ := e.GetUser(uid)
	if len(u.Roles) != 0 {
		t.Fatalf("expected no roles after removal, got %+v", u.Roles)
	}

	// Removing again should now report that the role isn't assigned.
	if err := e.RemoveRole(uid, rid); err != ErrRoleNotAssigned {
		t.Fatalf("expected ErrRoleNotAssigned removing already-absent role, got %v", err)
	}
}

func TestRemoveRole_NeverAssigned(t *testing.T) {
	e, uid, rid, _ := setup(t)

	if err := e.RemoveRole(uid, rid); err != ErrRoleNotAssigned {
		t.Fatalf("expected ErrRoleNotAssigned, got %v", err)
	}
}

func TestAssignPermissionAndCan(t *testing.T) {
	e, uid, rid, pid := setup(t)

	if err := e.AssignPermission(rid, pid); err != nil {
		t.Fatalf("AssignPermission failed: %v", err)
	}
	if err := e.AssignRole(uid, rid); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	ok, err := e.Can(uid, "documents", "read")
	if err != nil {
		t.Fatalf("Can returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected user to be able to perform documents:read")
	}

	ok, err = e.Can(uid, "documents", "delete")
	if err != nil {
		t.Fatalf("Can returned error: %v", err)
	}
	if ok {
		t.Fatalf("expected user NOT to be able to perform documents:delete")
	}
}

func TestAssignPermission_Errors(t *testing.T) {
	e, _, rid, pid := setup(t)

	if err := e.AssignPermission(0, pid); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if err := e.AssignPermission(rid, 0); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if err := e.AssignPermission(rid, 999); err != ErrPermissionNotFound {
		t.Errorf("expected ErrPermissionNotFound, got %v", err)
	}
	if err := e.AssignPermission(999, pid); err != ErrRoleNotFound {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestAssignPermission_DuplicateRejected(t *testing.T) {
	e, _, rid, pid := setup(t)

	if err := e.AssignPermission(rid, pid); err != nil {
		t.Fatalf("first AssignPermission failed: %v", err)
	}
	if err := e.AssignPermission(rid, pid); err != ErrPermissionAlreadyAssigned {
		t.Fatalf("expected ErrPermissionAlreadyAssigned, got %v", err)
	}

	r, _ := e.GetRole(rid)
	if len(r.Permissions) != 1 {
		t.Fatalf("expected exactly one permission assigned, got %+v", r.Permissions)
	}
}

func TestRemovePermission(t *testing.T) {
	e, _, rid, pid := setup(t)

	if err := e.AssignPermission(rid, pid); err != nil {
		t.Fatalf("AssignPermission failed: %v", err)
	}
	if err := e.RemovePermission(rid, pid); err != nil {
		t.Fatalf("RemovePermission failed: %v", err)
	}
	r, _ := e.GetRole(rid)
	if len(r.Permissions) != 0 {
		t.Fatalf("expected no permissions after removal, got %+v", r.Permissions)
	}

	// Removing again should now report that the permission isn't assigned.
	if err := e.RemovePermission(rid, pid); err != ErrPermissionNotAssigned {
		t.Fatalf("expected ErrPermissionNotAssigned, got %v", err)
	}
}

func TestRemovePermission_NeverAssigned(t *testing.T) {
	e, _, rid, pid := setup(t)

	if err := e.RemovePermission(rid, pid); err != ErrPermissionNotAssigned {
		t.Fatalf("expected ErrPermissionNotAssigned, got %v", err)
	}
}

func TestCan_Errors(t *testing.T) {
	e, uid, _, _ := setup(t)

	if _, err := e.Can(0, "docs", "read"); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if _, err := e.Can(uid, "", "read"); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName for empty resource, got %v", err)
	}
	if _, err := e.Can(uid, "docs", ""); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName for empty action, got %v", err)
	}
	if _, err := e.Can(999, "docs", "read"); err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestDeleteUserRolePermission(t *testing.T) {
	e, uid, rid, pid := setup(t)

	if err := e.DeleteUser(uid); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	if _, err := e.GetUser(uid); err != ErrUserNotFound {
		t.Errorf("expected user to be gone, got %v", err)
	}

	if err := e.DeleteRole(rid); err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}
	if _, err := e.GetRole(rid); err != ErrRoleNotFound {
		t.Errorf("expected role to be gone, got %v", err)
	}

	if err := e.DeletePermission(pid); err != nil {
		t.Fatalf("DeletePermission failed: %v", err)
	}
	if _, err := e.GetPermission(pid); err != ErrPermissionNotFound {
		t.Errorf("expected permission to be gone, got %v", err)
	}
}

func TestDeleteUser_Errors(t *testing.T) {
	e, _, _, _ := setup(t)

	if err := e.DeleteUser(0); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if err := e.DeleteUser(999); err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestDeleteRole_Errors(t *testing.T) {
	e, _, _, _ := setup(t)

	if err := e.DeleteRole(0); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if err := e.DeleteRole(999); err != ErrRoleNotFound {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestDeletePermission_Errors(t *testing.T) {
	e, _, _, _ := setup(t)

	if err := e.DeletePermission(0); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
	if err := e.DeletePermission(999); err != ErrPermissionNotFound {
		t.Errorf("expected ErrPermissionNotFound, got %v", err)
	}
}

// Regression test: deleting a role that a user holds must also detach it
// from that user, otherwise the user is left with a dangling RoleID and
// Can() starts returning ErrRoleNotFound for a user who should simply no
// longer have that role.
func TestDeleteRole_CascadesToUsers(t *testing.T) {
	e, uid, rid, pid := setup(t)

	if err := e.AssignPermission(rid, pid); err != nil {
		t.Fatalf("AssignPermission failed: %v", err)
	}
	if err := e.AssignRole(uid, rid); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	if err := e.DeleteRole(rid); err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}

	u, err := e.GetUser(uid)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if len(u.Roles) != 0 {
		t.Fatalf("expected deleted role to be detached from user, got %+v", u.Roles)
	}

	// Can() must not error out on a dangling reference; the user simply no
	// longer has any permission.
	ok, err := e.Can(uid, "documents", "read")
	if err != nil {
		t.Fatalf("Can returned unexpected error after role deletion: %v", err)
	}
	if ok {
		t.Fatalf("expected user to lose access after role deletion")
	}
}

// Regression test: deleting a permission that a role holds must also
// detach it from that role, otherwise the role is left with a dangling
// PermissionID and Can() starts returning ErrPermissionNotFound instead of
// simply reporting no access.
func TestDeletePermission_CascadesToRoles(t *testing.T) {
	e, uid, rid, pid := setup(t)

	if err := e.AssignPermission(rid, pid); err != nil {
		t.Fatalf("AssignPermission failed: %v", err)
	}
	if err := e.AssignRole(uid, rid); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	if err := e.DeletePermission(pid); err != nil {
		t.Fatalf("DeletePermission failed: %v", err)
	}

	r, err := e.GetRole(rid)
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}
	if len(r.Permissions) != 0 {
		t.Fatalf("expected deleted permission to be detached from role, got %+v", r.Permissions)
	}

	ok, err := e.Can(uid, "documents", "read")
	if err != nil {
		t.Fatalf("Can returned unexpected error after permission deletion: %v", err)
	}
	if ok {
		t.Fatalf("expected user to lose access after permission deletion")
	}
}

func TestRenameUserRole(t *testing.T) {
	e, uid, rid, _ := setup(t)

	if err := e.RenameUser(uid, ""); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName, got %v", err)
	}
	if err := e.RenameUser(uid, "alice2"); err != nil {
		t.Fatalf("RenameUser failed: %v", err)
	}
	u, _ := e.GetUser(uid)
	if u.Name != "alice2" {
		t.Errorf("expected renamed user, got %s", u.Name)
	}

	if err := e.RenameRole(rid, ""); err != ErrInvalidName {
		t.Errorf("expected ErrInvalidName, got %v", err)
	}
	if err := e.RenameRole(rid, "superadmin"); err != nil {
		t.Fatalf("RenameRole failed: %v", err)
	}
	r, _ := e.GetRole(rid)
	if r.Name != "superadmin" {
		t.Errorf("expected renamed role, got %s", r.Name)
	}
}

func TestRenameUser_NotFound(t *testing.T) {
	e := New()
	if err := e.RenameUser(999, "someone"); err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
	if err := e.RenameUser(0, "someone"); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
}

func TestRenameRole_NotFound(t *testing.T) {
	e := New()
	if err := e.RenameRole(999, "someone"); err != ErrRoleNotFound {
		t.Errorf("expected ErrRoleNotFound, got %v", err)
	}
	if err := e.RenameRole(0, "someone"); err != ErrInvalidID {
		t.Errorf("expected ErrInvalidID, got %v", err)
	}
}

// GetUser must return an independent copy: mutating the returned struct,
// including its Roles slice, must never affect engine state.
func TestGetUser_Immutability(t *testing.T) {
	e, uid, rid, _ := setup(t)
	if err := e.AssignRole(uid, rid); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	u, err := e.GetUser(uid)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	u.Name = "hacker"
	if len(u.Roles) > 0 {
		u.Roles[0] = 999
	}
	u.Roles = append(u.Roles, 42)

	u2, err := e.GetUser(uid)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if u2.Name == "hacker" {
		t.Fatalf("mutating returned User leaked into engine state (Name)")
	}
	if len(u2.Roles) != 1 || u2.Roles[0] != rid {
		t.Fatalf("mutating returned User's Roles slice leaked into engine state, got %+v", u2.Roles)
	}
}

// GetRole must return an independent copy: mutating the returned struct,
// including its Permissions slice, must never affect engine state.
func TestGetRole_Immutability(t *testing.T) {
	e, _, rid, pid := setup(t)
	if err := e.AssignPermission(rid, pid); err != nil {
		t.Fatalf("AssignPermission failed: %v", err)
	}

	r, err := e.GetRole(rid)
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}

	r.Name = "hacker"
	if len(r.Permissions) > 0 {
		r.Permissions[0] = 999
	}
	r.Permissions = append(r.Permissions, 42)

	r2, err := e.GetRole(rid)
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}
	if r2.Name == "hacker" {
		t.Fatalf("mutating returned Role leaked into engine state (Name)")
	}
	if len(r2.Permissions) != 1 || r2.Permissions[0] != pid {
		t.Fatalf("mutating returned Role's Permissions slice leaked into engine state, got %+v", r2.Permissions)
	}
}
