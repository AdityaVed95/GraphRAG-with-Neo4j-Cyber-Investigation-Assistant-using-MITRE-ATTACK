The script will be called `7_creating_relationships.py`. Run it after the node script.

1. **Read** `enterprise-attack.json`.
2. **Select** relationship objects supported by our graph model: `uses`, `mitigates`, `attributed-to`, and `subtechnique-of`.
3. **Skip inactive records:** Skip relationships if `revoked` or `x_mitre_deprecated` is `true`. Also skip relationships whose source or target object was excluded by the node script.
4. **Map relationship types** to `3_graph_model.cypher` using the source and target node types. For example, a Group using Software becomes `GROUP_USES_SOFTWARE`. Preserve the direction from `source_ref` to `target_ref`.
5. **Map properties:** Keep the original relationship STIX ID, description, and source URLs. Convert timestamps to dates with time zones and store references as JSON text. Technique usage descriptions contain the procedure examples.
6. **Connect** to Neo4j using the existing settings in `config.py`.
7. **Create or update relationships:** Find existing nodes using their labels and the IDs in `source_ref` and `target_ref`. Use `MERGE` for the relationship type and original STIX ID, then set its properties. Skip connections when either node is missing. This avoids duplicates when rerunning the script.
8. **Connect techniques to tactics:** For each active technique, read `kill_chain_phases`. Where `kill_chain_name` is `mitre-attack`, match `phase_name` to an existing Tactic's `shortname`. Use `MERGE` to create `Technique → HAS_TACTIC → Tactic` for every match. These connections have no STIX relationship ID or additional properties.
9. **Print** how many relationships were processed for each type, counting only connections whose nodes were found.

Keep the code simple: top-level functions, imports at the top, and no extra validation, custom retry logic, or command-line options.

Build the relationship script only after these steps are approved.
