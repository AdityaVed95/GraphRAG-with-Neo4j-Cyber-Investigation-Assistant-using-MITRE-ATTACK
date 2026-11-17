"""Run the graph RAG pipeline."""

from neo4j import GraphDatabase
from openai import OpenAI

from config import (
    NEO4J_DATABASE,
    NEO4J_PASSWORD,
    NEO4J_URI,
    NEO4J_USERNAME,
    OPENAI_API_KEY,
)
from generate_answer import generate_answer
from generate_cypher import generate_cypher
from graph_db import get_graph_schema, run_cypher_query
from process_records import records_to_query_result


def main() -> None:
    # Set the user's question.
    question = "How does APT29 use PowerShell, and which mitigations address that technique?"
    print("\nQuestion:")
    print(question)

    # Create the OpenAI client.
    client = OpenAI(api_key=OPENAI_API_KEY)

    # Close the driver automatically when finished.
    with GraphDatabase.driver(
        NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
    ) as driver:
        # Get the graph's data model.
        schema = get_graph_schema(driver, NEO4J_DATABASE)

        # Ask LLM1 to write the Cypher query.
        cypher_query = generate_cypher(client, question, schema)
        print("\nCypher Query Generated:")
        print(cypher_query)

        # Run the query against Neo4j.
        records = run_cypher_query(driver, NEO4J_DATABASE, cypher_query)

    # Prepare the query result for LLM2.
    query_result = records_to_query_result(records)
    print("\nQuery Result:")
    print(query_result)

    # Ask LLM2 to answer the user's question.
    answer = generate_answer(client, question, cypher_query, query_result)
    print("\nFinal LLM Answer:")
    print(answer)


if __name__ == "__main__":
    main()
