import os
from langchain_qdrant import QdrantVectorStore
from langchain_mistralai import MistralAIEmbeddings
from qdrant_client.models import Filter, FieldCondition, MatchAny
from langchain.tools import tool
from langchain_qdrant import QdrantVectorStore
from dotenv import load_dotenv
from fastmcp import FastMCP

from helpers.preprocessing import run_dependency_check


load_dotenv()


COLLECTION_NAME = os.getenv('COLLECTION_NAME')
QDRANT_URL = os.getenv('QDRANT_URL', '')

security_server = FastMCP('Security')
embeddings = MistralAIEmbeddings(model=os.getenv('EMBED_MODEL'))
store = None

def get_store():
    global store
    if store is None:
        store = QdrantVectorStore.from_existing_collection(
            embedding=embeddings,
            collection_name=COLLECTION_NAME,
            url=QDRANT_URL
        )
    return store

@security_server.resource("security://dependencies/vulnerabilities")
def dependency_vulnerability_analysis():
    """
    Check project dependencies for known security vulnerabilities using authoritative CWE data.

    Runs a dependency audit, extracts CWE IDs from the results, then fetches
    matching CWE records from the vector store. Use this for third-party libraries only —
    not for analysing custom application code.

    Args:
        _: Unused. Pass an empty string or omit entirely.

    Returns:
        list[dict]: List of CWE records for each matched vulnerability, each containing
                    CWE metadata payload from the vector store (e.g. cweID, name, description,
                    potential_mitigations). Returns an empty list if no matches are found.
    """
    print("TOOL CALLED: investigate_vulnerabilities")
    print()
    cwe_ids = run_dependency_check()
    qdrant_client = get_store().client

    results, _ = qdrant_client.scroll(
        collection_name=COLLECTION_NAME,
        scroll_filter=Filter(
            must=[
                FieldCondition(key="metadata.cweID", match=MatchAny(any=cwe_ids))
            ]
        ),
        with_payload=True,
        with_vectors=False
    )

    clean_results = []
    for r in results:
        print(r)
        payload = r.payload or {}
        clean_results.append(payload)
    print(clean_results)
    return clean_results


@security_server.tool
def map_vulnerabilities_to_cwe(vulns):
    """
    Map a list of detected vulnerabilities to authoritative CWE entries with mitigation data.

    Performs a semantic search for each vulnerability against the CWE vector store
    and returns the closest match. Call this once with all detected vulnerabilities
    together — do not call per-vulnerability. The returned mappings are complete
    and do not require further retrieval.

    Args:
        vulns: List of vulnerability descriptions (strings) to map,
               e.g. ["SQL injection in user input", "hardcoded credentials"].

    Returns:
        list[dict]: One entry per matched vulnerability, each containing:
                    - input_vulnerability (str): The original description passed in.
                    - cwe_id (str): Matched CWE identifier, e.g. "CWE-89".
                    - cwe_name (str): Human-readable CWE name.
                    - description (str): Full CWE description from the vector store.
                    - mitigations (list[str]): Recommended mitigations from CWE data.
                    Vulnerabilities with no vector store match are omitted from results.
    """
    print("TOOL CALLED: map_vulnerabilities_to_cwe")
    results = []
    retriever = get_store().as_retriever(search_kwargs={'k': 3})
    for vuln in vulns:
        docs = retriever.invoke(vuln)
        if not docs:
            continue
        best = docs[0]
        results.append({
            "input_vulnerability": vuln,
            "cwe_id": best.metadata.get("cweID"),
            "cwe_name": best.metadata.get("name"),
            "description": best.page_content,
            "mitigations": best.metadata.get("potential_mitigations", [])
        })

    return results
