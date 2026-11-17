// src/vulnflow/knowledge/graph/schema.cypher
// Defines constraints and relationship schema for the Neo4j dependency graph.

// Node uniqueness constraints
CREATE CONSTRAINT unique_repo_name IF NOT EXISTS
FOR (r:Repo) REQUIRE r.name IS UNIQUE;

CREATE CONSTRAINT unique_service_name IF NOT EXISTS
FOR (s:Service) REQUIRE s.name IS UNIQUE;

CREATE CONSTRAINT unique_package_name IF NOT EXISTS
FOR (p:Package) REQUIRE (p.ecosystem, p.name) IS UNIQUE;

CREATE CONSTRAINT unique_package_version IF NOT EXISTS
FOR (pv:PackageVersion) REQUIRE (pv.ecosystem, pv.name, pv.version) IS UNIQUE;

CREATE CONSTRAINT unique_cve_id IF NOT EXISTS
FOR (c:CVE) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT unique_policy_entry IF NOT EXISTS
FOR (pe:PolicyEntry) REQUIRE (pe.ecosystem, pe.package_name) IS UNIQUE;

CREATE CONSTRAINT unique_artifact_name IF NOT EXISTS
FOR (a:Artifact) REQUIRE a.name IS UNIQUE;

CREATE CONSTRAINT unique_fix_id IF NOT EXISTS
FOR (f:Fix) REQUIRE f.id IS UNIQUE;

// Indexes for fast lookup
CREATE INDEX index_package_version_name IF NOT EXISTS
FOR (pv:PackageVersion) ON (pv.name);

CREATE INDEX index_cve_severity IF NOT EXISTS
FOR (c:CVE) ON (c.severity);

CREATE INDEX index_artifact_expiry IF NOT EXISTS
FOR (a:Artifact) ON (a.expiry_date);
