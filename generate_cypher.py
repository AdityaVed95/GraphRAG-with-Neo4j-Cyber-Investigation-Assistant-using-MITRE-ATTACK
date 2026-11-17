"""Turn a question into Cypher."""

from openai import OpenAI

from config import OPENAI_MODEL, OPENAI_REASONING_EFFORT


# Rules for writing Cypher.
CYPHER_INSTRUCTIONS = """Write one read-only Cypher query for Neo4j graph database using only the given schema.
Your entire response will be sent directly to Neo4j for execution.
Return only one executable Cypher query.
Do not include reasoning, explanations, comments, Markdown, or text before or after the query.
Use literal values, not $parameters.
Match names without case sensitivity.
Return named properties, not whole nodes or paths.
"""

# Rules for the MITRE ATT&CK dataset.
GRAPH_DATASET_SPECIFIC_INSTRUCTIONS = """The query results will be sent to LLM2 to answer the user's question.
Return only the data needed for an accurate answer to avoid unnecessary tokens.
Match the user's entity name or ID against stored name, aliases, and attack_id values. Do not invent or assume alternative names.
When the user asks which items match, return their names and attack_id values.
When the user asks for an explanation, also return the descriptions needed to answer.
To explain how an attacker uses a technique, read the description on the relationship connecting them.
Return source_url or source_urls so the answer can include supporting links.
created and modified show when a record was created or updated, not when an attack happened.
Campaign first_seen and last_seen show when the campaign was first and last observed.
"""

TEXT_TO_CYPHER_INSTRUCTIONS = f"""<cypher_instructions>
{CYPHER_INSTRUCTIONS.strip()}
</cypher_instructions>

<graph_dataset_specific_instructions>
{GRAPH_DATASET_SPECIFIC_INSTRUCTIONS.strip()}
</graph_dataset_specific_instructions>"""


def generate_cypher(client: OpenAI, question: str, graph_schema: str) -> str:
    """Ask LLM1 to write a query."""
    # Send the question and schema to LLM1.
    response = client.responses.create(
        model=OPENAI_MODEL,
        reasoning={"effort": OPENAI_REASONING_EFFORT},
        instructions=TEXT_TO_CYPHER_INSTRUCTIONS,
        input=f"Graph schema:\n{graph_schema}\n\nQuestion:\n{question}",
    )
    # Return the query text.
    return response.output_text.strip()
