"""Read data from Neo4j."""

from neo4j import Driver, Record


def get_graph_schema(driver: Driver, database: str) -> str:
    """Return the graph data model as text."""
    # Ask Neo4j for the graph model.
    records, _, _ = driver.execute_query(
        "CYPHER 25 SHOW CURRENT GRAPH TYPE",
        database_=database,
        routing_="r",
    )
    # Read the schema text from the first row.
    return records[0]["specification"]


def run_cypher_query(driver: Driver, database: str, cypher_query: str) -> list[Record]:
    """Run the Cypher query and return its records."""
    records, _, _ = driver.execute_query(
        cypher_query,
        database_=database,
        routing_="r",
    )
    return records
