// Run each numbered query separately in your ATT&CK database.
// All queries are read-only. Expected results come from enterprise-attack.json.

// 1. Count nodes. Expected: 1842 in a database containing only this import.
MATCH (node)
RETURN count(node) AS nodes;

// 2. Count relationships. Expected: 21838.
MATCH ()-[relationship]->()
RETURN count(relationship) AS relationships;

// 3. Which software does APT29 use?
// Expected first five: AADInternals, AdFind, BloodHound, BoomBox, CloudDuke.
MATCH (:Group {name: 'APT29'})-[:GROUP_USES_SOFTWARE]->(software:Software)
RETURN DISTINCT software.name AS software, software.software_type AS type
ORDER BY software
LIMIT 5;

// 4. How does APT29 use techniques, and which tactics do they serve?
// The procedure is the usage relationship's description; source URLs are evidence.
MATCH (:Group {name: 'APT29'})-[usage:GROUP_USES_TECHNIQUE]->(technique:Technique)
MATCH (technique)-[:HAS_TACTIC]->(tactic:Tactic)
RETURN technique.attack_id AS technique_id,
       technique.name AS technique,
       tactic.name AS tactic,
       usage.description AS procedure,
       usage.source_urls AS sources
ORDER BY technique_id, tactic
LIMIT 5;

// 5. What is the parent technique of T1003.001?
// Expected: LSASS Memory -> OS Credential Dumping.
MATCH (child:Technique {attack_id: 'T1003.001'})-[:SUBTECHNIQUE_OF]->(parent:Technique)
RETURN child.name AS subtechnique, parent.name AS parent_technique;

// 6. Which mitigations address LSASS Memory credential dumping?
// Expected: seven different mitigations.
MATCH (mitigation:Mitigation)-[:MITIGATES]->(technique:Technique {attack_id: 'T1003.001'})
RETURN DISTINCT mitigation.name AS mitigation, mitigation.description AS description
ORDER BY mitigation;
