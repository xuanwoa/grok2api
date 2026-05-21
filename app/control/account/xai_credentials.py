"""Best-effort xAI credential exchange via lightweight HTTP.

The application stores xAI SSO cookie values as account tokens.  This module
tries to turn an email/password pair into an ``sso`` or ``sso-rw`` cookie
without adding a browser runtime.  It intentionally stops on challenges such as
Turnstile, MFA, OTP, or upstream page-shape changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

from app.control.proxy.models import (
    ProxyFeedback,
    ProxyFeedbackKind,
    ProxyScope,
    RequestKind,
)
from app.dataplane.proxy import get_proxy_runtime
from app.dataplane.proxy.adapters.profile import resolve_proxy_profile
from app.dataplane.proxy.adapters.session import build_session_kwargs
from app.platform.errors import UpstreamError
from app.platform.logging.logger import logger


ACCOUNTS_ORIGIN = "https://accounts.x.ai"
SIGN_IN_URL = f"{ACCOUNTS_ORIGIN}/sign-in"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_CHALLENGE_RE = re.compile(
    r"turnstile|captcha|challenge|cloudflare|cf-chl|verification failed",
    re.I,
)
_MFA_RE = re.compile(r"\bmfa\b|2fa|two-factor|authenticator|passkey", re.I)
_OTP_RE = re.compile(r"otp|one-time|verification code|email code|input[^>]+code", re.I)
_INVALID_RE = re.compile(
    r"invalid|incorrect|wrong|bad credentials|unauthorized|not match",
    re.I,
)


@dataclass(slots=True)
class XaiCredentialExchangeResult:
    token: str
    cookie_name: str


class XaiCredentialExchangeError(Exception):
    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(message or reason)
        self.reason = reason
        self.message = message or reason


class _Form:
    def __init__(self, attrs: dict[str, str]) -> None:
        self.attrs = attrs
        self.inputs: list[dict[str, str]] = []
        self.buttons: list[dict[str, str]] = []


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_Form] = []
        self._current: _Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): v or "" for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            self._current = _Form(attr_map)
            self.forms.append(self._current)
            return
        if self._current is None:
            return
        if tag == "input":
            self._current.inputs.append(attr_map)
        elif tag == "button":
            self._current.buttons.append(attr_map)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current = None


def _redact_email(email: str) -> str:
    local, _, domain = str(email or "").partition("@")
    if not local or not domain:
        return "<email>"
    return f"{local[:1]}***@{domain[:1]}***"


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(str(value or "").strip()))


def _classify_body(body: str, status: int = 0) -> str:
    text = (body or "")[:20000]
    if status == 429 or "rate limit" in text.lower():
        return "rate_limited"
    if _CHALLENGE_RE.search(text):
        return "challenge_required"
    if _MFA_RE.search(text):
        return "mfa_required"
    if _OTP_RE.search(text):
        return "email_verification_required"
    if status in (401, 403) or _INVALID_RE.search(text):
        return "invalid_credentials"
    if status >= 500:
        return "upstream_error"
    return "upstream_changed"


def _cookies_from_session(session: Any) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    jar = getattr(session, "cookies", None)
    if jar is None:
        return pairs
    try:
        for cookie in jar.jar:
            pairs.append((str(cookie.name), str(cookie.value)))
        return pairs
    except Exception:
        pass
    try:
        for name, value in jar.items():
            pairs.append((str(name), str(value)))
    except Exception:
        pass
    return pairs


def _pick_sso_cookie(session: Any) -> XaiCredentialExchangeResult | None:
    cookies = _cookies_from_session(session)
    for wanted in ("sso", "sso-rw"):
        for name, value in cookies:
            if name == wanted and value:
                return XaiCredentialExchangeResult(token=value, cookie_name=name)
    return None


def _parse_forms(html: str) -> list[_Form]:
    parser = _FormParser()
    try:
        parser.feed(html or "")
    except Exception:
        return []
    return parser.forms


def _find_input_name(form: _Form, *needles: str) -> str:
    for inp in form.inputs:
        haystack = " ".join(
            str(inp.get(k, "")) for k in ("name", "id", "type", "autocomplete", "placeholder")
        ).lower()
        if any(needle in haystack for needle in needles):
            name = inp.get("name") or inp.get("id")
            if name:
                return name
    return ""


def _form_payload(form: _Form) -> dict[str, str]:
    payload: dict[str, str] = {}
    for inp in form.inputs:
        name = inp.get("name") or inp.get("id")
        if not name:
            continue
        input_type = (inp.get("type") or "").lower()
        if input_type in {"button", "file", "image", "reset"}:
            continue
        payload[name] = inp.get("value") or ""
    return payload


def _select_form(forms: list[_Form], *needles: str) -> tuple[_Form, str] | None:
    for form in forms:
        field = _find_input_name(form, *needles)
        if field:
            return form, field
    return None


async def _post_form(session: Any, form: _Form, current_url: str, payload: dict[str, str], headers: dict[str, str], timeout_s: float):
    action = form.attrs.get("action") or current_url
    method = (form.attrs.get("method") or "post").lower()
    url = urljoin(current_url, action)
    if method == "get":
        return await session.get(url, params=payload, headers=headers, timeout=timeout_s, allow_redirects=True)
    return await session.post(url, data=payload, headers=headers, timeout=timeout_s, allow_redirects=True)


async def exchange_xai_credentials(
    email: str,
    password: str,
    *,
    timeout_s: float = 30.0,
) -> XaiCredentialExchangeResult:
    email = str(email or "").strip()
    password = str(password or "")
    if not is_email(email):
        raise XaiCredentialExchangeError("invalid_email", "Invalid email")
    if not password:
        raise XaiCredentialExchangeError("missing_password", "Missing password")

    try:
        from curl_cffi.requests import AsyncSession
    except Exception as exc:  # pragma: no cover - depends on installed runtime
        raise XaiCredentialExchangeError("dependency_missing", "curl_cffi is unavailable") from exc

    proxy = await get_proxy_runtime()
    lease = await proxy.acquire(
        scope=ProxyScope.APP,
        kind=RequestKind.HTTP,
        clearance_origin=ACCOUNTS_ORIGIN,
    )
    profile = resolve_proxy_profile(lease)
    user_agent = profile.user_agent or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": ACCOUNTS_ORIGIN,
        "Referer": SIGN_IN_URL,
        "User-Agent": user_agent,
    }
    session_kwargs = build_session_kwargs(
        lease=lease,
        extra={"headers": headers, "impersonate": profile.browser or "chrome120"},
    )

    feedback = ProxyFeedbackKind.TRANSPORT_ERROR
    status_code: int | None = None
    reason = ""
    session = AsyncSession(**session_kwargs)
    try:
        response = await session.get(SIGN_IN_URL, timeout=timeout_s, allow_redirects=True)
        status_code = int(getattr(response, "status_code", 0) or 0)
        if found := _pick_sso_cookie(session):
            feedback = ProxyFeedbackKind.SUCCESS
            return found

        body = str(getattr(response, "text", "") or "")
        if status_code >= 400:
            reason = _classify_body(body, status_code)
            raise XaiCredentialExchangeError(reason)

        forms = _parse_forms(body)
        selected = _select_form(forms, "email", "username")
        if not selected:
            reason = _classify_body(body, status_code)
            raise XaiCredentialExchangeError(reason)
        form, email_field = selected
        payload = _form_payload(form)
        payload[email_field] = email
        response = await _post_form(session, form, str(getattr(response, "url", SIGN_IN_URL)), payload, headers, timeout_s)
        status_code = int(getattr(response, "status_code", 0) or 0)
        if found := _pick_sso_cookie(session):
            feedback = ProxyFeedbackKind.SUCCESS
            return found

        body = str(getattr(response, "text", "") or "")
        if status_code >= 400:
            reason = _classify_body(body, status_code)
            raise XaiCredentialExchangeError(reason)

        forms = _parse_forms(body)
        selected = _select_form(forms, "password", "passwd")
        if not selected:
            reason = _classify_body(body, status_code)
            raise XaiCredentialExchangeError(reason)
        form, password_field = selected
        payload = _form_payload(form)
        payload[password_field] = password
        if email_name := _find_input_name(form, "email", "username"):
            payload[email_name] = email
        response = await _post_form(session, form, str(getattr(response, "url", SIGN_IN_URL)), payload, headers, timeout_s)
        status_code = int(getattr(response, "status_code", 0) or 0)
        if found := _pick_sso_cookie(session):
            feedback = ProxyFeedbackKind.SUCCESS
            return found

        body = str(getattr(response, "text", "") or "")
        reason = _classify_body(body, status_code)
        raise XaiCredentialExchangeError(reason)
    except XaiCredentialExchangeError:
        if reason == "rate_limited":
            feedback = ProxyFeedbackKind.RATE_LIMITED
        elif reason in {"challenge_required", "mfa_required", "email_verification_required"}:
            feedback = ProxyFeedbackKind.CHALLENGE
        elif reason == "invalid_credentials":
            feedback = ProxyFeedbackKind.FORBIDDEN
        else:
            feedback = ProxyFeedbackKind.UPSTREAM_5XX if (status_code or 0) >= 500 else ProxyFeedbackKind.FORBIDDEN
        raise
    except UpstreamError:
        feedback = ProxyFeedbackKind.TRANSPORT_ERROR
        raise
    except Exception as exc:
        reason = "network_error"
        logger.debug("xai credential exchange transport error: email={} error={}", _redact_email(email), exc)
        raise XaiCredentialExchangeError("network_error", "Network error") from exc
    finally:
        try:
            await session.close()
        except Exception:
            pass
        try:
            await proxy.feedback(
                lease,
                ProxyFeedback(kind=feedback, status_code=status_code, reason=reason),
            )
        except Exception:
            pass


__all__ = [
    "XaiCredentialExchangeError",
    "XaiCredentialExchangeResult",
    "exchange_xai_credentials",
    "is_email",
]
