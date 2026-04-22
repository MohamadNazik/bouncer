package postgres

// SQL query constants for permission management.

const (
	// QueryCreateResource inserts a resource with an optional parent relationship.
	QueryCreateResource = `
		INSERT INTO resources (id, name, parent)
		VALUES ($1, $2, $3)
	`

	// QueryDeleteResource removes a resource by ID.
	QueryDeleteResource = `
		DELETE FROM resources
		WHERE id = $1
	`

	// QueryHasPermission checks if a permission grant exists.
	QueryHasPermission = `
		SELECT EXISTS(
			SELECT 1 FROM permission_grants
			WHERE subject_id = $1 AND resource_id = $2 AND permission_name = $3
		)
	`

	// QueryGrantPermission inserts a permission grant, ignoring duplicates.
	QueryGrantPermission = `
		INSERT INTO permission_grants (subject_id, resource_id, permission_name)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`

	// QueryRevokePermission removes a permission grant.
	QueryRevokePermission = `
		DELETE FROM permission_grants
		WHERE subject_id = $1 AND resource_id = $2 AND permission_name = $3
	`
)
