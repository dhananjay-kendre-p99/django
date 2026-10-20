from django.conf import settings
from django.middleware import MiddlewareMixin
from django.utils.csp import (
    CSP,
    LazyNonce,
    _csp_policy_has_nonce_only_directive,
    build_policy,
)


def get_nonce(request):
    return getattr(request, "_csp_nonce", None)


class ContentSecurityPolicyMiddleware(MiddlewareMixin):
    async_capable = False

    def process_request(self, request):
        request._csp_nonce = LazyNonce()

    def process_response(self, request, response):
        nonce = get_nonce(request)

        sentinel = object()
        if (csp_config := getattr(response, "_csp_config", sentinel)) is sentinel:
            csp_config = settings.SECURE_CSP
        if (csp_ro_config := getattr(response, "_csp_ro_config", sentinel)) is sentinel:
            csp_ro_config = settings.SECURE_CSP_REPORT_ONLY

        for header, config in [
            (CSP.HEADER_ENFORCE, csp_config),
            (CSP.HEADER_REPORT_ONLY, csp_ro_config),
        ]:
            # If headers are already set on the response, don't overwrite them.
            # This allows for views to set their own CSP headers as needed.
            # An empty config means CSP headers are not added to the response.
            if config and header not in response:
                if nonce is not None and _csp_policy_has_nonce_only_directive(config):
                    # A directive whose only source is CSP.NONCE is omitted
                    # from the header when the nonce is never used, failing
                    # open. Generate the nonce eagerly so the directive is
                    # always included and enforced.
                    str(nonce)
                response.headers[str(header)] = build_policy(config, nonce)

        return response
