from django.urls import path
from .views import UpdateCveDataView, FilterCveDataView

# Define URL patterns for the CVE data app
urlpatterns = [
    path('update-cve-data/', UpdateCveDataView.as_view(), name='update_cve_data'),
    path('filter-cve-data/', FilterCveDataView.as_view(), name='filter_cve_data'),
]
