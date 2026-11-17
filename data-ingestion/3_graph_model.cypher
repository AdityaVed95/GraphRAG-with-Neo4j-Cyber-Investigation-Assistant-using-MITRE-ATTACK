// MITRE ATT&CK investigation graph: six node types.
// Requires Neo4j Enterprise 2026.02+ and Cypher 25.
// Run in the new ATT&CK database. SET replaces its graph type and constraints.
// This defines the schema; it does not import the JSON records.
//
// Import mappings:
// intrusion-set -> Group; malware/tool -> Software; attack-pattern -> Technique;
// x-mitre-tactic -> Tactic; course-of-action -> Mitigation; campaign -> Campaign.
// id is the original STIX ID. attack_id and source_url come from the
// external_references entry whose source_name is "mitre-attack".
// references_json preserves the entire external_references array as JSON text.
// aliases comes from aliases (Group/Campaign) or x_mitre_aliases (Software).
// platforms comes from x_mitre_platforms. software_type is "tool" or "malware".
// shortname comes from x_mitre_shortname; is_subtechnique from
// x_mitre_is_subtechnique. Campaign date citations use the corresponding
// x_mitre_first_seen_citation / x_mitre_last_seen_citation fields.
// Convert timestamps with datetime() during import. created/modified describe
// ATT&CK record changes; first_seen/last_seen describe campaign observations.
// The current Python result serializer uses json.dumps: return dates using
// toString() in queries until the serializer supports Neo4j temporal values.
//
// Import only records where revoked and x_mitre_deprecated are absent or false.
// Import a relationship only when both endpoint records were imported.
// Preserve each STIX relationship ID, description, timestamps, and references.
// source_urls is the list of URLs present in its external_references.
// Map STIX "uses" to the explicit relationship name for its endpoint pair.
// Map "mitigates", "attributed-to", and "subtechnique-of" as shown below.
// HAS_TACTIC is derived from each technique's kill_chain_phases: match
// kill_chain_name = "mitre-attack" and phase_name = Tactic.shortname.
// HAS_TACTIC has no source STIX relationship ID. Preserve all tactic matches.
// Do not create direct usage edges from inferred multi-hop paths.
//
// Sources:
// https://mitre-attack.github.io/attack-data-model/schemas/
// https://mitre-attack.github.io/attack-data-model/schemas/relationship-types/
// https://neo4j.com/docs/cypher-manual/current/schema/graph-types/set-graph-types/

CYPHER 25
ALTER CURRENT GRAPH TYPE SET {
  (:Group => {
    id :: STRING IS KEY,
    attack_id :: STRING,
    name :: STRING NOT NULL,
    description :: STRING,
    aliases :: LIST<STRING NOT NULL>,
    source_url :: STRING,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }),

  (:Software => {
    id :: STRING IS KEY,
    attack_id :: STRING,
    name :: STRING NOT NULL,
    description :: STRING,
    software_type :: STRING,
    aliases :: LIST<STRING NOT NULL>,
    platforms :: LIST<STRING NOT NULL>,
    source_url :: STRING,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }),

  (:Technique => {
    id :: STRING IS KEY,
    attack_id :: STRING,
    name :: STRING NOT NULL,
    description :: STRING,
    is_subtechnique :: BOOLEAN,
    platforms :: LIST<STRING NOT NULL>,
    source_url :: STRING,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }),

  (:Tactic => {
    id :: STRING IS KEY,
    attack_id :: STRING,
    name :: STRING NOT NULL,
    description :: STRING,
    shortname :: STRING,
    source_url :: STRING,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }),

  (:Mitigation => {
    id :: STRING IS KEY,
    attack_id :: STRING,
    name :: STRING NOT NULL,
    description :: STRING,
    source_url :: STRING,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }),

  (:Campaign => {
    id :: STRING IS KEY,
    attack_id :: STRING,
    name :: STRING NOT NULL,
    description :: STRING,
    aliases :: LIST<STRING NOT NULL>,
    first_seen :: ZONED DATETIME,
    last_seen :: ZONED DATETIME,
    first_seen_citation :: STRING,
    last_seen_citation :: STRING,
    source_url :: STRING,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }),

  (:Group)-[:GROUP_USES_SOFTWARE => {
    id :: STRING IS KEY,
    description :: STRING,
    source_urls :: LIST<STRING NOT NULL>,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }]->(:Software),

  (:Group)-[:GROUP_USES_TECHNIQUE => {
    id :: STRING IS KEY,
    description :: STRING,
    source_urls :: LIST<STRING NOT NULL>,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }]->(:Technique),

  (:Software)-[:SOFTWARE_USES_TECHNIQUE => {
    id :: STRING IS KEY,
    description :: STRING,
    source_urls :: LIST<STRING NOT NULL>,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }]->(:Technique),

  (:Campaign)-[:CAMPAIGN_USES_SOFTWARE => {
    id :: STRING IS KEY,
    description :: STRING,
    source_urls :: LIST<STRING NOT NULL>,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }]->(:Software),

  (:Campaign)-[:CAMPAIGN_USES_TECHNIQUE => {
    id :: STRING IS KEY,
    description :: STRING,
    source_urls :: LIST<STRING NOT NULL>,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }]->(:Technique),

  (:Campaign)-[:ATTRIBUTED_TO => {
    id :: STRING IS KEY,
    description :: STRING,
    source_urls :: LIST<STRING NOT NULL>,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }]->(:Group),

  (:Mitigation)-[:MITIGATES => {
    id :: STRING IS KEY,
    description :: STRING,
    source_urls :: LIST<STRING NOT NULL>,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }]->(:Technique),

  (:Technique)-[:SUBTECHNIQUE_OF => {
    id :: STRING IS KEY,
    description :: STRING,
    source_urls :: LIST<STRING NOT NULL>,
    references_json :: STRING,
    created :: ZONED DATETIME,
    modified :: ZONED DATETIME
  }]->(:Technique),

  (:Technique)-[:HAS_TACTIC =>]->(:Tactic)
};

// Run separately after setting the graph type:
// CYPHER 25 SHOW CURRENT GRAPH TYPE;
