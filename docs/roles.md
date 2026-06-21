# Roles

Roles are a bitmask stored in the `rolemask` column on `{prefix}accounts`.

## Custom roles

Define your own roles with `defineRoles`. It assigns sequential powers of two and returns a frozen object.

```js
import { defineRoles } from "@prsm/auth"

const Roles = defineRoles("admin", "owner", "editor", "viewer", "billing")
// { admin: 1, owner: 2, editor: 4, viewer: 8, billing: 16 }
```

Pass it into your auth config:

```js
const authConfig = {
  db: pool,
  roles: Roles,
}
```

This does two things:

- `getRoleNames()` returns your custom names instead of the built-in defaults
- The [@prsm/devtools](https://github.com/prsmjs/devtools) admin panel reads roles from the bound context, so your custom roles show up automatically

Names are preserved exactly as provided, with no transformation. The maximum is 31 roles, since PostgreSQL `INTEGER` is 32-bit signed. Order matters: do not reorder or remove roles from the middle, or existing users' rolemasks will map to the wrong names.

## Built-in roles

If you don't set `config.roles`, the built-in `AuthRole` enum is used. It has 21 predefined roles (Admin, Author, Collaborator, and so on).

```js
import { AuthRole } from "@prsm/auth"

await req.auth.addRoleForUserBy({ email: "user@example.com" }, AuthRole.Admin | AuthRole.Editor)
```

## Assign and check

```js
await req.auth.addRoleForUserBy({ email: "user@example.com" }, Roles.editor)
await req.auth.removeRoleForUserBy({ email: "user@example.com" }, Roles.editor)

const canEdit = await req.auth.hasRole(Roles.editor)
const isAdmin = await req.auth.isAdmin()
const names = req.auth.getRoleNames()
```

## Standalone role functions

For use outside of Express routes:

```js
import { addRoleToUser, removeRoleFromUser, setUserRoles, getUserRoles } from "@prsm/auth"

await addRoleToUser(authConfig, { email: "user@example.com" }, Roles.editor)
await removeRoleFromUser(authConfig, { email: "user@example.com" }, Roles.editor)
await setUserRoles(authConfig, { email: "user@example.com" }, Roles.admin | Roles.owner)
const mask = await getUserRoles(authConfig, { email: "user@example.com" })
```

## Why bitmasks

- A single integer column, no join tables
- Fast bitwise checks
- Easy to combine: `Roles.admin | Roles.editor` gives a user both roles
- Easy to check: `(rolemask & Roles.admin) === Roles.admin`
