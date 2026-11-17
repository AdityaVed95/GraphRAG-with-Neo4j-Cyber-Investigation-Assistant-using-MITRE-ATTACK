"""Import MITRE ATT&CK nodes using the connection settings in config.py."""

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


def read_objects(file_path: Path) -> list[dict]:
    """Read the objects inside the STIX bundle."""
    with file_path.open(encoding="utf-8") as file:
        return json.load(file)["objects"]


def map_properties(obj: dict) -> dict:
    """Map one ATT&CK object to the properties in our graph model."""
    references = obj.get("external_references", [])
    attack_reference = next(
        (ref for ref in references if ref["source_name"] == "mitre-attack"),
        {},
    )

    # Properties shared by all six node types.
    properties = {
        "id": obj["id"],
        "attack_id": attack_reference.get("external_id"),
        "name": obj["name"],
        "description": obj.get("description"),
        "source_url": attack_reference.get("url"),
        "references_json": json.dumps(references, ensure_ascii=False),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
    }

    # Properties specific to each node type.
    object_type = obj["type"]
    if object_type == "intrusion-set":
        properties["aliases"] = obj.get("aliases", [])

    elif object_type in ("malware", "tool"):
        properties["software_type"] = object_type
        properties["aliases"] = obj.get("x_mitre_aliases", [])
        properties["platforms"] = obj.get("x_mitre_platforms", [])

    elif object_type == "attack-pattern":
        properties["is_subtechnique"] = obj.get("x_mitre_is_subtechnique", False)
        properties["platforms"] = obj.get("x_mitre_platforms", [])

    elif object_type == "x-mitre-tactic":
        properties["shortname"] = obj.get("x_mitre_shortname")

    elif object_type == "campaign":
        properties["aliases"] = obj.get("aliases", [])
        properties["first_seen"] = obj.get("first_seen")
        properties["last_seen"] = obj.get("last_seen")
        properties["first_seen_citation"] = obj.get("x_mitre_first_seen_citation")
        properties["last_seen_citation"] = obj.get("x_mitre_last_seen_citation")

    # The driver stores these Python values as Neo4j ZONED DATETIME properties.
    for field in ("created", "modified", "first_seen", "last_seen"):
        if properties.get(field) is not None:
            properties[field] = datetime.fromisoformat(
                properties[field].replace("Z", "+00:00")
            )

    return properties


def prepare_nodes(objects: list[dict]) -> dict[str, list[dict]]:
    """Select active objects and group their mapped properties by node label."""
    nodes_by_label = {label: [] for label in NODE_LABELS.values()}

    for obj in objects:
        if obj["type"] not in NODE_LABELS:
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        label = NODE_LABELS[obj["type"]]
        nodes_by_label[label].append(map_properties(obj))

    return nodes_by_label


def write_nodes(driver, database: str, nodes_by_label: dict[str, list[dict]]) -> None:
    """Create or update each node, using its original STIX ID."""
    with driver.session(database=database) as session:
        for label, nodes in nodes_by_label.items():
            # Labels come from our fixed mapping; node values are parameters.
            query = f"""
                UNWIND $nodes AS properties
                MERGE (node:{label} {{id: properties.id}})
                SET node += properties
            """
            session.run(query, nodes=nodes).consume()
            print(f"{label}: {len(nodes)} nodes processed")


def main() -> None:
    file_path = Path(__file__).resolve().parent / "enterprise-attack.json"
    objects = read_objects(file_path)
    nodes_by_label = prepare_nodes(objects)

    with GraphDatabase.driver(
        NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
    ) as driver:
        write_nodes(driver, NEO4J_DATABASE, nodes_by_label)


if __name__ == "__main__":
    main()
