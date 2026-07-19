# GateKeeper

A lightweight, in-memory Role-Based Access Control (RBAC) engine for Go.

GateKeeper lets you manage **users**, **roles**, and **permissions**, and answer a single question fast: *"Can this user do this action on this resource?"*

```go
allowed, err := engine.Can(userID, "invoices", "delete")
```

## Features

- Simple, dependency-free RBAC model: `User` → `Role` → `Permission`
- Create, rename, and delete users, roles, and permissions
- Assign / remove roles on users and permissions on roles
- Permission checks via `Can(userID, resource, action)`
- Defensive copies on reads (`GetUser`, `GetRole`) so callers can't mutate internal state
- Clear, typed sentinel errors for every failure case
- Zero external dependencies

## Installation

```bash
go get github.com/dhavalrasputala/GateKeeper_v1
```

## Quick Start

```go
package main

import (
	"fmt"

	gatekeeper "github.com/dhavalrasputala/GateKeeper_v1"
)

func main() {
	engine := gatekeeper.New()

	// Create a user, a role, and a permission
	userID, _ := engine.CreateUser("Alice")
	roleID, _ := engine.CreateRole("Editor")
	permID, _ := engine.CreatePermission("articles", "publish")

	// Wire them together
	_ = engine.AssignRole(userID, roleID)
	_ = engine.AssignPermission(roleID, permID)

	// Check access
	allowed, err := engine.Can(userID, "articles", "publish")
	if err != nil {
		panic(err)
	}
	fmt.Println("Alice can publish articles:", allowed) // true
}
```

## API Overview

### Creating the engine

```go
engine := gatekeeper.New()
```

### Users

| Method | Description |
|---|---|
| `CreateUser(name string) (UserID, error)` | Creates a new user |
| `GetUser(id UserID) (User, error)` | Fetches a user (copy) |
| `RenameUser(id UserID, newName string) error` | Renames a user |
| `DeleteUser(id UserID) error` | Deletes a user |

### Roles

| Method | Description |
|---|---|
| `CreateRole(name string) (RoleID, error)` | Creates a new role |
| `GetRole(id RoleID) (Role, error)` | Fetches a role (copy) |
| `RenameRole(id RoleID, newName string) error` | Renames a role |
| `DeleteRole(id RoleID) error` | Deletes a role (and unassigns it from all users) |

### Permissions

| Method | Description |
|---|---|
| `CreatePermission(resource, action string) (PermissionID, error)` | Creates a new permission |
| `GetPermission(id PermissionID) (Permission, error)` | Fetches a permission |
| `DeletePermission(id PermissionID) error` | Deletes a permission (and unassigns it from all roles) |

### Assignments

| Method | Description |
|---|---|
| `AssignRole(userID UserID, roleID RoleID) error` | Grants a role to a user |
| `RemoveRole(userID UserID, roleID RoleID) error` | Revokes a role from a user |
| `AssignPermission(roleID RoleID, permID PermissionID) error` | Grants a permission to a role |
| `RemovePermission(roleID RoleID, permID PermissionID) error` | Revokes a permission from a role |

### Authorization

| Method | Description |
|---|---|
| `Can(userID UserID, resource, action string) (bool, error)` | Checks whether the user has a role with a matching permission |

## Errors

GateKeeper returns typed sentinel errors so you can handle failures with `errors.Is`:

```go
var (
	ErrInvalidName               = errors.New("Name required")
	ErrInvalidID                 = errors.New("ID required")
	ErrUserNotFound               = errors.New("User not found")
	ErrRoleNotFound               = errors.New("Role not found")
	ErrPermissionNotFound         = errors.New("Permission not found")
	ErrRoleAlreadyAssigned        = errors.New("Role already assigned")
	ErrPermissionAlreadyAssigned  = errors.New("Permission already assigned")
	ErrRoleNotAssigned            = errors.New("Role not Assigned")
	ErrPermissionNotAssigned      = errors.New("Permission not Assigned")
)
```

## Design Notes

- **In-memory only.** State lives in Go maps inside the `Engine` struct; nothing is persisted. This makes GateKeeper great for embedding in a service, testing authorization logic, or prototyping — but you'll need to add your own persistence layer (e.g. a database-backed store) for production use across restarts.
- **Not concurrency-safe out of the box.** The `Engine` does not use a mutex internally, so concurrent reads/writes from multiple goroutines should be synchronized by the caller (e.g. wrap it with your own `sync.RWMutex`) if used across goroutines.
- **Additive RBAC model.** A user is authorized for `(resource, action)` if *any* of their roles has a permission matching it — there's no explicit deny.

## Running Tests

```bash
go test ./...
```

## Requirements

- Go 1.25+

## Contributing

Issues and pull requests are welcome. If you're adding a feature, please include tests in `gatekeeper_test.go`.

## License

This project is licensed under the [MIT License](LICENSE).
