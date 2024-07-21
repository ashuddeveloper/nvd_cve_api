# CVE Data Synchronization API

## Overview

The CVE Data Synchronization API is a Django-based application designed to fetch Common Vulnerabilities and Exposures (CVE) data from the National Vulnerability Database (NVD) API and store it in MongoDB. It supports background synchronization of CVE data and provides endpoints for updating and querying CVE information.

## Features

- **Asynchronous Data Fetching:** Efficiently fetches data from the NVD API using `aiohttp`.
- **Background Synchronization:** Automatically synchronizes CVE data every 24 hours using `APScheduler`.
- **Data Filtering:** Provides endpoints to filter CVE data based on ID, base score, and last modified date.
- **Data Storage:** Stores CVE data in MongoDB for quick retrieval and querying.

## API Description

### Endpoints

1. **Update CVE Data**
   - **URL:** `/update-cve-data/`
   - **Method:** `GET`
   - **Description:** Triggers an update to fetch and store CVE data from the NVD API into MongoDB.
   - **Response:**
     ```json
     {
       "status": "success",
       "message": "CVE data updated successfully."
     }
     ```
   - **Errors:**
     ```json
     {
       "status": "error",
       "message": "Error updating CVE data: <error-message>"
     }
     ```

2. **Filter CVE Data**
   - **URL:** `/filter-cve-data/`
   - **Method:** `GET`
   - **Query Parameters:**
     - `cveId` (optional): The CVE ID to filter by.
     - `baseScore` (optional): The base score to filter by.
     - `lastModifiedDays` (optional): Number of days to filter by last modified date.
   - **Description:** Retrieves filtered CVE data from MongoDB based on the provided query parameters.
   - **Response:**
     ```json
     [
       {
         "id": "CVE-XXXX-YYYY",
         "published": "YYYY-MM-DD",
         "lastModified": "YYYY-MM-DD",
         ...
       }
     ]
     ```
   - **Errors:**
     ```json
     {
       "status": "error",
       "message": "Error filtering CVE data: <error-message>"
     }
     ```

## Change Log

    ```
    NA
    ```

## Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.7 or higher
- Django 4.x
- MongoDB
- Docker (optional, if using Docker for setup)

## Setup

### Clone the Repository

1. Clone the repository using Git:

   ```sh
   git clone <repository-url>
   cd <project-directory>
   ```

2. Create a virtual environment:

    ```sh
    Copy code
    python -m venv venv
    Activate the virtual environment:
    ```

3. Install the project dependencies:

    ```sh
    Copy code
    pip install -r requirements.txt
    Configure M
    ```

4. Configure MongoDB

    Ensure MongoDB is running on localhost:27017 or update the connection details in db_connections.py accordingly.

5. Start the Django development server:

    ```sh
    python manage.py runserver
    ```

## Usage

1. Update CVE Data: Send a GET request to /update-cve-data/ to trigger synchronization of CVE data.
2. Filter CVE Data: Send a GET request to /filter-cve-data/ with optional query parameters to retrieve filtered CVE data.
