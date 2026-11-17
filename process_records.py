"""Prepare Neo4j records for LLM2."""

import json

from neo4j import Record
from neo4j.time import Date, DateTime, Time


def serialize_date(value):
    """Convert Neo4j dates and times into ISO-formatted text for JSON."""
    if isinstance(value, (Date, DateTime, Time)):
        return value.iso_format()
    raise TypeError(f"Cannot serialize {type(value).__name__} to JSON")


def records_to_query_result(records: list[Record]) -> str:
    """Convert records to a JSON string."""
    results = [record.data() for record in records]
    return json.dumps(results, default=serialize_date)
