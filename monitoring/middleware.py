from .services import get_client_ip, log_activity

class ActivityAuditMiddleware:
    """
    Middleware that captures client network parameters and logs access anomalies.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.client_ip = get_client_ip(request)
        response = self.get_response(request)

        # Log unauthorized access attempts (HTTP 403)
        if response.status_code == 403:
            log_activity(
                request=request,
                event_type='UNAUTHORIZED_ACCESS',
                resource_id=request.path,
                description=f"Forbidden access attempt to path {request.path}",
                status='BLOCKED'
            )

        return response
