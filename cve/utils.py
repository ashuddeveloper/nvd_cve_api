import aiohttp
from pymongo import InsertOne
from pymongo.errors import BulkWriteError
import logging
from datetime import datetime, timezone, timedelta
from .models import cve_collection
from bson import ObjectId
import ssl
import certifi
import asyncio

logger = logging.getLogger(__name__)

# Global variable to keep track of the last synchronization timestamp
last_sync_timestamp = None

# Global lock to prevent concurrent synchronization
sync_lock = asyncio.Lock()

async def fetch_data(session, base_url, params):
    """
    Asynchronously fetch data from the given URL with the specified parameters.

    Args:
        session (aiohttp.ClientSession): The aiohttp client session.
        base_url (str): The base URL for the API request.
        params (dict): The parameters for the API request.

    Returns:
        dict: The JSON response from the API, or None if an error occurs.
    """
    try:
        async with session.get(base_url, params=params) as response:
            if response.status == 200:
                return await response.json()
            else:
                logger.error(f"Error fetching data: HTTP {response.status}")
                return None
    except aiohttp.ClientError as e:
        logger.error(f"Request error: {e}")
        return None

async def fetch_and_store_cve_data(
    start_index=0,
    results_per_page=2000,
    last_mod_start_date=None,
    last_mod_end_date=None,
):
    """
    Asynchronously fetch CVE data from the NVD API and store it in MongoDB.

    Args:
        start_index (int): The index of the first record to fetch.
        results_per_page (int): The number of results per page.
        last_mod_start_date (str, optional): Start date for filtering by last modified date.
        last_mod_end_date (str, optional): End date for filtering by last modified date.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    total_results = float("inf")

    ssl_context = ssl.create_default_context(cafile=certifi.where())
    connector = aiohttp.TCPConnector(ssl=ssl_context)

    async with aiohttp.ClientSession(connector=connector) as session:
        while start_index < total_results:
            params = {"startIndex": start_index, "resultsPerPage": results_per_page}
            if last_mod_start_date and last_mod_end_date:
                params.update(
                    {
                        "lastModStartDate": last_mod_start_date,
                        "lastModEndDate": last_mod_end_date,
                    }
                )

            data = await fetch_data(session, base_url, params)
            if not data:
                break

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                logger.info("No vulnerabilities found.")
                break

            bulk_operations = prepare_bulk_operations(vulnerabilities)

            if bulk_operations:
                # Run in executor if MongoDB operations are blocking
                await asyncio.get_event_loop().run_in_executor(None, execute_bulk_operations, bulk_operations)

            start_index += results_per_page
            logger.info(
                "Processed data from index %d to %d",
                start_index - results_per_page,
                start_index,
            )

async def synchronize_cve_data(last_mod_start_date=None, last_mod_end_date=None):
    """
    Asynchronously synchronize CVE data by fetching and storing it.

    Args:
        last_mod_start_date (str, optional): ISO 8601 start date for filtering by last modified date.
        last_mod_end_date (str, optional): ISO 8601 end date for filtering by last modified date.
    """
    global last_sync_timestamp

    async with sync_lock:
        logger.info("Starting CVE data synchronization.")

        if last_mod_start_date and last_mod_end_date:
            # Ensure the date range is valid (<= 120 days)
            try:
                start_date = datetime.fromisoformat(
                    last_mod_start_date.replace("Z", "+00:00")
                )
                end_date = datetime.fromisoformat(last_mod_end_date.replace("Z", "+00:00"))
                if end_date - start_date > timedelta(days=120):
                    logger.error(
                        "Date range exceeds the maximum allowable range of 120 days."
                    )
                    return
            except ValueError as e:
                logger.error("Invalid date format: %s", e)
                return

        if last_sync_timestamp and not (last_mod_start_date and last_mod_end_date):
            # Incremental sync: fetch only modified records since the last_sync_timestamp
            last_mod_start_date = last_sync_timestamp
            last_mod_end_date = datetime.now(timezone.utc).isoformat()

        await fetch_and_store_cve_data(
            last_mod_start_date=last_mod_start_date, last_mod_end_date=last_mod_end_date
        )

        # Update the last synchronization timestamp
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl.create_default_context(cafile=certifi.where()))) as session:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            data = await fetch_data(session, base_url, {})
            if data:
                last_sync_timestamp = data.get("timestamp")
                logger.info("Updated last synchronization timestamp: %s", last_sync_timestamp)

def prepare_bulk_operations(vulnerabilities):
    """
    Prepare bulk operations for inserting CVE data into MongoDB.

    Args:
        vulnerabilities (list): A list of vulnerabilities to process.

    Returns:
        list: A list of MongoDB bulk operations.
    """
    bulk_operations = []
    for vulnerability in vulnerabilities:
        cve_data = vulnerability.get("cve", {})
        if is_valid_cve(cve_data):
            cve_data = clean_cve_data(cve_data)
            bulk_operations.append(InsertOne(cve_data))
    return bulk_operations

def is_valid_cve(cve_data):
    """
    Check if the given CVE data is valid for insertion.

    Args:
        cve_data (dict): The CVE data to validate.

    Returns:
        bool: True if the CVE data is valid, False otherwise.
    """
    cve_id = cve_data.get("id")
    if not cve_id:
        return False
    if cve_collection.count_documents({"id": cve_id}, limit=1) > 0:
        return False
    return True

def execute_bulk_operations(bulk_operations):
    """
    Execute bulk operations to insert CVE data into MongoDB.

    Args:
        bulk_operations (list): A list of MongoDB bulk operations.
    """
    if not bulk_operations:
        return
    try:
        cve_collection.bulk_write(bulk_operations)
        logger.info("Bulk operations executed successfully.")
    except BulkWriteError as bwe:
        logger.error("Bulk write error: %s", bwe.details)

def clean_cve_data(cve_data):
    """
    Clean CVE data by processing date fields.

    Args:
        cve_data (dict): The CVE data to clean.

    Returns:
        dict: The cleaned CVE data.
    """
    date_fields = ["published", "lastModified"]
    for date_field in date_fields:
        if date_field in cve_data:
            try:
                cve_data[date_field] = cve_data[date_field].split("T")[0]
            except Exception as e:
                logger.error("Error cleaning date field %s: %s", date_field, e)
                cve_data[date_field] = None
    return cve_data

async def fetch_filtered_cve_data(cve_id=None, base_score=None, last_modified_days=None):
    """
    Asynchronously fetch filtered CVE data from MongoDB based on query parameters.

    Args:
        cve_id (str, optional): The CVE ID to filter by.
        base_score (float, optional): The base score to filter by.
        last_modified_days (int, optional): Number of days to filter by last modified date.

    Returns:
        list: A list of filtered CVE data.
    """
    query = {}

    if cve_id:
        query["id"] = cve_id

    if base_score:
        query["$or"] = [
            {"metrics.cvssMetricV2.cvssData.baseScore": float(base_score)},
            {"metrics.cvssMetricV3.cvssData.baseScore": float(base_score)},
        ]

    if last_modified_days is not None:
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=int(last_modified_days))
        query["lastModified"] = {
            "$gte": start_date.isoformat(),
            "$lte": end_date.isoformat(),
        }

    # Log the query for debugging
    logger.info(f"Query: {query}")

    try:
        cursor = cve_collection.find(query)
        results = list(cursor)
        return results
    except Exception as e:
        logger.error("Error fetching filtered CVE data: %s", e)
        return []

def serialize_mongo_data(data):
    """
    Convert MongoDB data to a JSON serializable format.

    Args:
        data (list or dict): The MongoDB data to convert.

    Returns:
        list or dict: The JSON serializable data.
    """
    if isinstance(data, list):
        return [serialize_mongo_document(item) for item in data]
    elif isinstance(data, dict):
        return serialize_mongo_document(data)
    return data

def serialize_mongo_document(document):
    """
    Convert a single MongoDB document to a JSON serializable format.

    Args:
        document (dict): The MongoDB document to convert.

    Returns:
        dict: The JSON serializable document.
    """
    if isinstance(document, dict):
        for key, value in document.items():
            if isinstance(value, ObjectId):
                document[key] = str(value)  # Convert ObjectId to string
            elif isinstance(value, dict) or isinstance(value, list):
                document[key] = serialize_mongo_data(
                    value
                )  # Recursively handle nested structures
    elif isinstance(document, list):
        document = [serialize_mongo_data(item) for item in document]
    return document
