CREATE TABLE IF NOT EXISTS resources (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	parent TEXT NULL,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (parent) REFERENCES resources(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS permission_grants (
	subject_id TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	permission_name TEXT NOT NULL,
	PRIMARY KEY (subject_id, resource_id, permission_name),
	FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE
);
