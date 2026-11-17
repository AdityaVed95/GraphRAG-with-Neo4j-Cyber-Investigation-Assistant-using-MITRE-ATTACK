"""Import MITRE ATT&CK relationships after running 5_creating_nodes.py."""

import json
import sys
from datetime import datetime
from pathlib import Path

from neo4j import GraphDatabase

# Make the project's config.py available when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import NEO4J_DATABASE, NEO4J_PASSWORD, NEO4J_URI, NEO4J_USERNAME


NODE_LABELS = {
    "intrusion-set": "Group",
    "malware": "Software",
    "tool": "Software",
    "attack-pattern": "Technique",
    "x-mitre-tactic": "Tactic",
    "course-of-action": "Mitigation",
    "campaign": "Campaign",
}

# (source label, STIX relationship type, target label) -> Neo4j relationship type.
RELATIONSHIP_TYPES = {
    ("Group", "uses", "Software"): "GROUP_USES_SOFTWARE",
    ("Group", "uses", "Technique"): "GROUP_USES_TECHNIQUE",
    ("Software", "uses", "Technique"): "SOFTWARE_USES_TECHNIQUE",
    ("Campaign", "uses", "Software"): "CAMPAIGN_USES_SOFTWARE",
    ("Campaign", "uses", "Technique"): "CAMPAIGN_USES_TECHNIQUE",
    ("Campaign", "attributed-to", "Group"): "ATTRIBUTED_TO",
    ("Mitigation", "mitigates", "Technique"): "MITIGATES",
    ("Technique", "subtechnique-of", "Technique"): "SUBTECHNIQUE_OF",
}


def read_objects(file_path: Path) -> list[dict]:
    """Read the objects inside the STIX bundle."""
    with file_path.open(encoding="utf-8") as file:
        return json.load(file)["objects"]


def select_active_nodes(objects: list[dict]) -> dict[str, dict]:
    """Index the objects selected by the node importer using their STIX IDs."""
    return {
        obj["id"]: obj
        for obj in objects
        if obj["type"] in NODE_LABELS
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    }


def map_properties(obj: dict) -> dict:
    """Keep relationship details, procedure descriptions, and citations."""
    references = obj.get("external_references", [])
    properties = {
        "id": obj["id"],
        "description": obj.get("description"),
        "source_urls": [ref["url"] for ref in references if "url" in ref],
        "references_json": json.dumps(references, ensure_ascii=False),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
    }

    for field in ("created", "modified"):
        if properties[field] is not None:
            properties[field] = datetime.fromisoformat(
                properties[field].replace("Z", "+00:00")
            )

    return properties


def prepare_relationships(objects: list[dict], active_nodes: dict[str, dict]) -> dict:
    """Select supported relationships between active nodes and map their properties."""
    relationships_by_type = {key: [] for key in RELATIONSHIP_TYPES}

    for obj in objects:
        if obj["type"] != "relationship":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        source = active_nodes.get(obj["source_ref"])
        target = active_nodes.get(obj["target_ref"])
        if source is None or target is None:
            continue

        key = (
            NODE_LABELS[source["type"]],
            obj["relationship_type"],
            NODE_LABELS[target["type"]],
        )
        if key not in RELATIONSHIP_TYPES:
            continue

        relationships_by_type[key].append({
            "source_id": source["id"],
            "target_id": target["id"],
            "properties": map_properties(obj),
        })

    return relationships_by_type


def prepare_tactic_links(active_nodes: dict[str, dict]) -> list[dict]:
    """Read technique-to-tactic connections from kill_chain_phases."""
    tactic_names = {
        obj["x_mitre_shortname"]
        for obj in active_nodes.values()
        if obj["type"] == "x-mitre-tactic"
    }
    links = []

    for obj in active_nodes.values():
        if obj["type"] != "attack-pattern":
            continue
        for phase in obj.get("kill_chain_phases", []):
            if phase["kill_chain_name"] == "mitre-attack" and phase["phase_name"] in tactic_names:
                links.append({
                    "technique_id": obj["id"],
                    "tactic_shortname": phase["phase_name"],
                })

    return links


def write_relationships(driver, database: str, relationships_by_type: dict) -> None:
    """Match existing nodes, then create or update their STIX relationships."""
    with driver.session(database=database) as session:
        for key, relationships in relationships_by_type.items():
            source_label, _, target_label = key
            relationship_type = RELATIONSHIP_TYPES[key]
            # Labels and types come from our fixed mappings; values are parameters.
            query = f"""
                UNWIND $relationships AS row
                MATCH (source:{source_label} {{id: row.source_id}})
                MATCH (target:{target_label} {{id: row.target_id}})
                MERGE (source)-[relationship:{relationship_type} {{id: row.properties.id}}]->(target)
                SET relationship += row.properties
                RETURN count(relationship) AS processed
            """
            record = session.run(query, relationships=relationships).single()
            print(f"{relationship_type}: {record['processed']} relationships processed")


def write_tactic_links(driver, database: str, links: list[dict]) -> None:
    """Connect existing techniques to tactics without a STIX relationship ID."""
    query = """
        UNWIND $links AS row
        MATCH (technique:Technique {id: row.technique_id})
        MATCH (tactic:Tactic {shortname: row.tactic_shortname})
        MERGE (technique)-[relationship:HAS_TACTIC]->(tactic)
        RETURN count(relationship) AS processed
    """
    with driver.session(database=database) as session:
        record = session.run(query, links=links).single()
        print(f"HAS_TACTIC: {record['processed']} relationships processed")


def main() -> None:
    file_path = Path(__file__).resolve().parent / "enterprise-attack.json"
    objects = read_objects(file_path)
    active_nodes = select_active_nodes(objects)
    relationships_by_type = prepare_relationships(objects, active_nodes)
    tactic_links = prepare_tactic_links(active_nodes)

    with GraphDatabase.driver(
        NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
    ) as driver:
        write_relationships(driver, NEO4J_DATABASE, relationships_by_type)
        write_tactic_links(driver, NEO4J_DATABASE, tactic_links)


if __name__ == "__main__":
    main()
