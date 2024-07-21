from django.http import JsonResponse
from django.views import View
from .utils import fetch_and_store_cve_data, fetch_filtered_cve_data, serialize_mongo_data
import logging

# Set up logger
logger = logging.getLogger(__name__)


class UpdateCveDataView(View):
    """
    View to update CVE data by fetching from the NVD API and storing it in MongoDB.
    """

    async def get(self, request, *args, **kwargs):
        """
        Handle GET requests to update CVE data.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            JsonResponse: JSON response with the status of the update operation.
        """
        try:
            await fetch_and_store_cve_data()
            return JsonResponse(
                {
                    'status': 'success',
                    'message': 'CVE data updated successfully.'
                }
            )
        except Exception as e:
            logger.error(f"Error updating CVE data: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


class FilterCveDataView(View):
    """
    View to filter CVE data based on query parameters.
    """

    async def get(self, request, *args, **kwargs):
        """
        Handle GET requests to filter CVE data.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            JsonResponse: JSON response with the filtered CVE data.
        """
        # Get query parameters from the request
        cve_id = request.GET.get('cveId')
        base_score = request.GET.get('baseScore')
        last_modified_days = request.GET.get('lastModifiedDays')

        try:
            # Fetch filtered CVE data from MongoDB
            cve_data = await fetch_filtered_cve_data(cve_id, base_score, last_modified_days)
            # Convert MongoDB data to a JSON serializable format
            serialized_data = serialize_mongo_data(cve_data)
            return JsonResponse(serialized_data, safe=False)
        except Exception as e:
            logger.error(f"Error filtering CVE data: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
