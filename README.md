# GraphRAG-with-Neo4j-Cyber-Investigation-Assistant-using-MITRE-ATTACK

This is a learning project that uses GraphRAG to answers questions using MITRE ATT&CK data stored in Neo4j. One LLM call writes a Cypher query. A second LLM call explains the data returned by the graph.

## How the pipeline works

[main.py](main.py) connects these steps:

1. **Read the schema.** [graph_db.py](graph_db.py) asks Neo4j for its node types, properties, and relationships.
2. **Write the query.** [generate_cypher.py](generate_cypher.py) gives LLM1 the schema and the user's question. LLM1 is instructed to return a read-only Cypher query.
3. **Search the graph.** [graph_db.py](graph_db.py) runs the generated query and returns the matching records.
4. **Prepare the results.** [process_records.py](process_records.py) converts the records into JSON text.
5. **Write the answer.** [generate_answer.py](generate_answer.py) gives LLM2 the question, query, and results. LLM2 is instructed to answer from those results and include source links when available.

LLM1 and LLM2 are two separate calls using the same model settings.

## Example

“How does APT29 use PowerShell, and which mitigations address that technique?”

The query finds the APT29 group, its connection to the PowerShell technique, and the mitigations connected to that technique. The usage relationship describes how APT29 used PowerShell. LLM2 turns this evidence into a short answer.

## Run it

The Neo4j graph must already contain the schema and imported data. The setup files are in [data-ingestion](data-ingestion/). The pipeline reads the schema using `CYPHER 25 SHOW CURRENT GRAPH TYPE`, so the database must support that command.

With the `neo4j` and `openai` Python packages installed, use the connection details, API key, and model settings in [config.py](config.py). Set the question in [main.py](main.py), then run:

```bash
python main.py
```

The program prints the question, generated query, retrieved records, and final answer.

## V1 scope

LLM1 currently infers which node type each term belongs to. There is no separate entity lookup before query generation. This version demonstrates a usable pipeline for GraphRAG.

## Future updates beyond V1 for production grade GraphRAG

1. **Add vector search.** Create text chunks from nodes and relationships and store their embeddings in a vector database. Retrieve the chunks most similar to the user's question. Include their graph IDs, node labels, and relationship types as context for LLM1 to help it identify relevant entities and write the query.

2. **Look up extracted terms.** Add an LLM0 call to extract key terms from the question. Use a fixed Python lookup to match these terms against stored names, aliases, and IDs. Pass the matching entities and their node types to LLM1 before it generates Cypher.

3. **Handle ambiguous matches.** If a term matches several entities, use the question's context to choose the relevant one or ask the user to clarify. If nothing matches, report that the term could not be resolved.

4. **Control query execution.** Use a database account with read-only permissions. Set query timeouts and result limits to keep execution and response sizes manageable.

5. **Handle failed queries.** Allow a limited correction attempt when a generated query fails. Distinguish an invalid query from a valid query that returns no results.

6. **Evaluate answer quality.** Keep sample questions with expected entities and results. Check that answers and citations are supported by the retrieved evidence.
