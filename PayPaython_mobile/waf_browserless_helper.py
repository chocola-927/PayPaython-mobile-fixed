import time
import json
import urllib.parse
from typing import Optional
from requests.utils import dict_from_cookiejar

# If your project provides a solve_aws_waf helper, we can import it optionally.
try:
    # adjust import path if your waf helper is in a different module name
    from .waf_helper import solve_aws_waf
except Exception:
    solve_aws_waf = None

def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return None

def attempt_par_check_without_browser(session, request_uri: str, web_headers: dict, api_headers: dict, proxy: Optional[dict]=None, max_retries: int=3, wait: float=0.6):
    """
    Try to get par/check result WITHOUT running a real browser.
    Strategies:
     - GET par/check with params={'request_uri': request_uri}
     - GET par/check without params (some servers accept cookie only)
     - POST par/check with JSON body {'requestUri': request_uri} (some endpoints accept POST)
     - On failure, try calling solve_aws_waf (if available) to refresh awswaf cookie, then retry
     - If server sets __Secure-request_uri cookie in session, ensure it's URL-encoded form is present
    Returns: dict (parsed JSON) on success, or raises Exception with last response detail on failure.
    """
    last_resp = None
    # ensure headers exist
    api_headers = dict(api_headers or {})
    web_headers = dict(web_headers or {})

    # helper to try one request and evaluate result
    def try_request(method,
