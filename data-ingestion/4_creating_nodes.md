The script will be called `5_creating_nodes.py`.

1. **Read** `enterprise-attack.json`.
2. **Select** objects for our six node types: Group, Software, Technique, Tactic, Mitigation, and Campaign.
3. **Skip inactive objects:** Skip an object if `revoked` is `true` or `x_mitre_deprecated` is `true`. Keep it when both fields are false or absent. This filter is part of preparing the data.
4. **Map properties** to `3_graph_model.cypher`. Keep the original STIX ID, map the other fields, convert timestamps to dates with time zones, and store references as JSON text.
5. **Connect** to Neo4j using the existing settings in `config.py`.
6. **Create or update nodes** using `MERGE` on each node's label and original STIX ID. Set its mapped properties. This avoids duplicates when rerunning the script.
7. **Print** how many nodes were processed for each type.

Keep the code simple: top-level functions, imports at the top, and no extra validation, custom retry logic, or command-line options.

Relationships will come afterward in a separate script. Build the node script only after these steps are approved.
