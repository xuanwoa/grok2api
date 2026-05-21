"""Admin token CRUD — list, import, delete, replace pool.

Performance notes:
  - DI-injected repo (no try/except per call)
  - orjson direct output (bypasses stdlib json)
  - Quota dict: zero deserialization — reads r.quota directly
  - Import refresh: reuses app.state.refresh_service singleton
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, asdict
from typing import TYPE_CHECKING, Any

import orjson
from fastapi import APIRouter, Body, Depends
from fastapi.responses import Response
from pydantic import BaseModel, Field, RootModel

from app.platform.errors import AppError, ErrorKind, ValidationError
from app.platform.logging.logger import logger
from app.platform.runtime.clock import now_ms
from app.control.account.commands import (
    AccountPatch,
    AccountUpsert,
    BulkReplacePoolCommand,
    ListAccountsQuery,
)
from app.control.account.enums import AccountStatus
from app.control.account.xai_credentials import (
    XaiCredentialExchangeError,
    exchange_xai_credentials,
    is_email,
)

if TYPE_CHECKING:
    from app.control.account.refresh import AccountRefreshService
    from app.control.account.repository import AccountRepository

from . import get_refresh_svc, get_repo

router = APIRouter(tags=["Admin - Tokens"])

# ---------------------------------------------------------------------------
# Token sanitisation
# ---------------------------------------------------------------------------

_TOKEN_TRANS = str.maketrans({
    "\u2010": "-", "\u2011": "-", "\u2012": "-",
    "\u2013": "-", "\u2014": "-", "\u2212": "-",
    "\u00a0": " ", "\u2007": " ", "\u202f": " ",
    "\u200b": "", "\u200c": "", "\u200d": "", "\ufeff": "",
})
_STRIP_RE = re.compile(r"\s+")


def _sanitize(value: str) -> str:
    tok = str(value or "").translate(_TOKEN_TRANS)
    tok = _STRIP_RE.sub("", tok)
    if tok.startswith("sso="):
        tok = tok[4:]
    return tok.encode("ascii", errors="ignore").decode("ascii")


def _mask(token: str) -> str:
    return f"{token[:8]}...{token[-8:]}" if len(token) > 20 else token


def _mask_email(email: str) -> str:
    local, _, domain = str(email or "").partition("@")
    if not local or not domain:
        return "<email>"
    return f"{local[:1]}***@{domain[:1]}***"


def _merge_tags(*groups: list[str]) -> list[str]:
    seen: list[str] = []
    for group in groups:
        for raw in group or []:
            tag = str(raw or "").strip()
            if tag and tag not in seen:
                seen.append(tag)
    return seen


def _parse_credential_line(value: str) -> tuple[str, str] | None:
    line = str(value or "").strip()
    if not line or line.startswith("#"):
        return None
    if "----" in line:
        left, right, *_ = line.split("----")
        email, password = left.strip(), right.strip()
        return (email, password) if is_email(email) and password else None
    parts = _CREDENTIAL_SPLIT_RE.split(line, maxsplit=1)
    if len(parts) != 2:
        return None
    email, password = parts[0].strip(), parts[1].strip()
    return (email, password) if is_email(email) and password else None


def _failure_counts(failures: list["ImportFailure"]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for failure in failures:
        counts[failure.reason] = counts.get(failure.reason, 0) + 1
    return counts


def _failure_payloads(failures: list["ImportFailure"]) -> list[dict[str, str]]:
    return [asdict(failure) for failure in failures[:50]]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ReplacePoolRequest(BaseModel):
    pool: str
    tokens: list[str]
    tags: list[str] = []


class TokenImportItem(BaseModel):
    token: str = ""
    email: str = ""
    password: str = ""
    tags: list[str] = []
    ext: dict[str, Any] = Field(default_factory=dict)


class AddTokensRequest(BaseModel):
    tokens: list[str | TokenImportItem]
    pool: str = "basic"
    tags: list[str] = []


class EditTokenRequest(BaseModel):
    old_token: str
    token: str
    pool: str = "basic"


class ToggleTokenDisabledRequest(BaseModel):
    token: str
    disabled: bool


class ToggleTokensDisabledRequest(BaseModel):
    tokens: list[str]
    disabled: bool


class SaveTokensRequest(RootModel[dict[str, list[str | TokenImportItem]]]):
    """Bulk-save payload keyed by pool name."""


@dataclass(slots=True)
class ImportFailure:
    source: str
    reason: str


@dataclass(slots=True)
class ResolvedImportItem:
    token: str
    tags: list[str]
    ext: dict[str, Any]


@dataclass(slots=True)
class ImportResolution:
    items: list[ResolvedImportItem]
    failures: list[ImportFailure]


_CREDENTIAL_SPLIT_RE = re.compile(r"\s+")


def _import_item_from_raw(raw: str | TokenImportItem, inherited_tags: list[str]) -> tuple[str, str, list[str], dict[str, Any]] | ResolvedImportItem | None:
    if isinstance(raw, str):
        if parsed := _parse_credential_line(raw):
            email, password = parsed
            return email, password, list(inherited_tags or []), {}
        token = _sanitize(raw)
        return ResolvedImportItem(token=token, tags=list(inherited_tags or []), ext={}) if token else None

    data = raw.model_dump()
    tags = _merge_tags(inherited_tags, data.get("tags") or [])
    ext = dict(data.get("ext") or {})

    token = _sanitize(data.get("token", ""))
    if token:
        return ResolvedImportItem(token=token, tags=tags, ext=ext)

    email = str(data.get("email") or "").strip()
    password = str(data.get("password") or "")
    if email or password:
        return email, password, tags, ext
    return None


async def _resolve_import_items(
    raw_items: list[str | TokenImportItem],
    *,
    tags: list[str] | None = None,
) -> ImportResolution:
    inherited_tags = list(tags or [])
    direct: list[ResolvedImportItem] = []
    credentials: list[tuple[str, str, list[str], dict[str, Any]]] = []
    failures: list[ImportFailure] = []

    for raw in raw_items:
        item = _import_item_from_raw(raw, inherited_tags)
        if item is None:
            continue
        if isinstance(item, ResolvedImportItem):
            direct.append(item)
            continue
        email, password, item_tags, ext = item
        if not is_email(email):
            failures.append(ImportFailure(source=_mask_email(email), reason="invalid_email"))
            continue
        if not password:
            failures.append(ImportFailure(source=_mask_email(email), reason="missing_password"))
            continue
        credentials.append((email, password, item_tags, ext))

    if not credentials:
        return ImportResolution(items=direct, failures=failures)

    limit_raw = os.getenv("XAI_CREDENTIAL_IMPORT_CONCURRENCY", "2").strip()
    try:
        limit = max(1, min(10, int(limit_raw or "2")))
    except ValueError:
        limit = 2
    semaphore = asyncio.Semaphore(limit)

    async def _one(email: str, password: str, item_tags: list[str], ext: dict[str, Any]):
        async with semaphore:
            try:
                result = await exchange_xai_credentials(email, password)
            except XaiCredentialExchangeError as exc:
                return None, ImportFailure(source=_mask_email(email), reason=exc.reason)
            except Exception:
                return None, ImportFailure(source=_mask_email(email), reason="network_error")
            item_ext = dict(ext)
            item_ext.setdefault("source_email", email)
            item_ext.setdefault("credential_import", "xai_http")
            item_ext.setdefault("credential_cookie", result.cookie_name)
            return ResolvedImportItem(token=result.token, tags=item_tags, ext=item_ext), None

    results = await asyncio.gather(*[_one(*credential) for credential in credentials])
    for resolved, failure in results:
        if resolved is not None:
            direct.append(resolved)
        if failure is not None:
            failures.append(failure)

    deduped: list[ResolvedImportItem] = []
    seen: set[str] = set()
    for item in direct:
        if item.token and item.token not in seen:
            seen.add(item.token)
            deduped.append(item)
    return ImportResolution(items=deduped, failures=failures)


# ---------------------------------------------------------------------------
# Serialisation — zero-copy quota extraction
# ---------------------------------------------------------------------------

def _quota_brief(q: dict) -> dict:
    """Extract {auto, fast, expert, heavy} with only remaining/total from stored quota dict."""
    out = {}
    for mode in ("auto", "fast", "expert", "heavy"):
        v = q.get(mode)
        if isinstance(v, dict):
            out[mode] = {
                "remaining": int(v.get("remaining", 0) or 0),
                "total": int(v.get("total", 0) or 0),
            }
    return out


def _serialize_record(r) -> dict:
    return {
        "token":       r.token,
        "pool":        r.pool or "basic",
        "status":      r.status,
        "quota":       _quota_brief(r.quota) if isinstance(r.quota, dict) else {},
        "use_count":   r.usage_use_count or 0,
        "last_used_at": r.last_use_at,
        "tags":        r.tags or [],
    }


def _json(data) -> Response:
    """orjson fast-path response."""
    return Response(content=orjson.dumps(data), media_type="application/json")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/tokens")
async def list_tokens(repo: "AccountRepository" = Depends(get_repo)):
    """Return flat token list."""
    all_items: list = []
    page_num = 1
    while True:
        page = await repo.list_accounts(ListAccountsQuery(page=page_num, page_size=2000))
        all_items.extend(page.items)
        if page_num * 2000 >= page.total:
            break
        page_num += 1

    return _json({"tokens": [_serialize_record(r) for r in all_items]})


@router.post("/tokens")
async def save_tokens(
    req: SaveTokensRequest,
    repo: "AccountRepository" = Depends(get_repo),
    refresh_svc: "AccountRefreshService" = Depends(get_refresh_svc),
):
    """Full pool replace — accepts {pool_name: [token_objects]} dict."""
    total_upserted = 0
    all_tokens: list[str] = []
    failures: list[ImportFailure] = []

    for pool_name, items in req.root.items():
        resolved = await _resolve_import_items(items)
        failures.extend(resolved.failures)
        upserts = [
            AccountUpsert(
                token=item.token,
                pool=pool_name,
                tags=item.tags,
                ext=item.ext,
            )
            for item in resolved.items
        ]
        if upserts:
            await repo.replace_pool(BulkReplacePoolCommand(pool=pool_name, upserts=upserts))
            all_tokens.extend(u.token for u in upserts)
            total_upserted += len(upserts)

    logger.info(
        "admin tokens saved across pools: saved_count={} failed_count={}",
        total_upserted,
        len(failures),
    )
    if all_tokens:
        asyncio.create_task(_refresh_imported(refresh_svc, all_tokens))
    return _json({
        "status": "success",
        "count": total_upserted,
        "failed": len(failures),
        "failure_counts": _failure_counts(failures),
        "failures": _failure_payloads(failures),
    })


@router.post("/tokens/add")
async def add_tokens(
    req: AddTokensRequest,
    repo: "AccountRepository" = Depends(get_repo),
    refresh_svc: "AccountRefreshService" = Depends(get_refresh_svc),
):
    requested_pool = (req.pool or "basic").strip().lower()
    sync_auto_detect = requested_pool == "auto"

    resolved = await _resolve_import_items(req.tokens, tags=req.tags)
    if not resolved.items and not resolved.failures:
        raise ValidationError("No valid tokens provided", param="tokens")
    if not resolved.items:
        return _json({
            "status": "success",
            "count": 0,
            "skipped": 0,
            "failed": len(resolved.failures),
            "failure_counts": _failure_counts(resolved.failures),
            "failures": _failure_payloads(resolved.failures),
            "synced": False,
        })
    cleaned = [item.token for item in resolved.items]

    # Only upsert tokens that are not already active — avoids overwriting quota/status.
    # Soft-deleted tokens are treated as non-existing so they can be restored.
    existing = {r.token for r in await repo.get_accounts(cleaned) if not r.is_deleted()}
    new_items = [item for item in resolved.items if item.token not in existing]

    if not new_items:
        return _json({
            "status": "success",
            "count": 0,
            "skipped": len(cleaned),
            "failed": len(resolved.failures),
            "failure_counts": _failure_counts(resolved.failures),
            "failures": _failure_payloads(resolved.failures),
            "synced": False,
        })

    upserts = [
        AccountUpsert(
            token=item.token,
            pool=requested_pool,
            tags=item.tags,
            ext=item.ext,
        )
        for item in new_items
    ]
    result = await repo.upsert_accounts(upserts)
    logger.info(
        "admin tokens added: pool={} added_count={} skipped_count={} failed_count={}",
        requested_pool,
        len(new_items),
        len(existing),
        len(resolved.failures),
    )

    new_tokens = [item.token for item in new_items]
    if sync_auto_detect:
        try:
            refresh_result = await refresh_svc.refresh_on_import(new_tokens)
            logger.info(
                "admin auto-detect quota sync completed: token_count={} refreshed={} failed={}",
                len(new_tokens), refresh_result.refreshed, refresh_result.failed,
            )
        except Exception as exc:
            logger.warning("admin auto-detect quota sync failed: token_count={} error={}", len(new_tokens), exc)
    else:
        asyncio.create_task(_refresh_imported(refresh_svc, new_tokens))

    return _json({
        "status": "success",
        "count": result.upserted or len(new_tokens),
        "skipped": len(existing),
        "failed": len(resolved.failures),
        "failure_counts": _failure_counts(resolved.failures),
        "failures": _failure_payloads(resolved.failures),
        "synced": sync_auto_detect,
    })


@router.delete("/tokens")
async def delete_tokens(
    tokens: list[str] = Body(...),
    repo: "AccountRepository" = Depends(get_repo),
):
    cleaned = [t for t in (_sanitize(t) for t in tokens) if t]
    if not cleaned:
        raise ValidationError("No valid tokens provided", param="tokens")
    await repo.delete_accounts(cleaned)
    logger.info("admin tokens deleted: deleted_count={}", len(cleaned))
    return _json({"deleted": len(cleaned)})


@router.put("/tokens/edit")
async def edit_token(
    req: EditTokenRequest,
    repo: "AccountRepository" = Depends(get_repo),
):
    old_token = _sanitize(req.old_token)
    new_token = _sanitize(req.token)
    pool = (req.pool or "basic").strip().lower()

    if not old_token or not new_token:
        raise ValidationError("Token is required", param="token")

    records = await repo.get_accounts([old_token])
    if not records:
        raise AppError(
            "Account not found",
            kind=ErrorKind.VALIDATION,
            code="account_not_found",
            status=404,
        )
    record = records[0]

    if old_token != new_token:
        existing = await repo.get_accounts([new_token])
        if existing:
            raise AppError(
                "Target token already exists",
                kind=ErrorKind.VALIDATION,
                code="token_conflict",
                status=409,
            )

    await repo.upsert_accounts([AccountUpsert(
        token=new_token,
        pool=pool,
        tags=record.tags,
        ext=record.ext,
    )])

    if old_token == new_token:
        logger.info("admin token updated: token={} pool={}", _mask(new_token), pool)
        return _json({"status": "success", "token": new_token, "pool": pool})

    qs = record.quota_set()
    await repo.patch_accounts([AccountPatch(
        token=new_token,
        status=record.status,
        tags=record.tags,
        quota_auto=qs.auto.to_dict(),
        quota_fast=qs.fast.to_dict(),
        quota_expert=qs.expert.to_dict(),
        usage_use_delta=record.usage_use_count,
        usage_fail_delta=record.usage_fail_count,
        usage_sync_delta=record.usage_sync_count,
        last_use_at=record.last_use_at,
        last_fail_at=record.last_fail_at,
        last_fail_reason=record.last_fail_reason,
        last_sync_at=record.last_sync_at,
        last_clear_at=record.last_clear_at,
        state_reason=record.state_reason,
        ext_merge=record.ext,
    )])
    await repo.delete_accounts([old_token])

    logger.info("admin token replaced: previous_token={} current_token={} pool={}", _mask(old_token), _mask(new_token), pool)
    return _json({"status": "success", "token": new_token, "pool": pool})


@router.post("/tokens/disabled")
async def toggle_token_disabled(
    req: ToggleTokenDisabledRequest,
    repo: "AccountRepository" = Depends(get_repo),
):
    token = _sanitize(req.token)
    if not token:
        raise ValidationError("Token is required", param="token")

    records = await repo.get_accounts([token])
    if not records:
        raise AppError(
            "Account not found",
            kind=ErrorKind.VALIDATION,
            code="account_not_found",
            status=404,
        )
    record = records[0]

    if req.disabled:
        await repo.patch_accounts([AccountPatch(
            token=token,
            status=AccountStatus.DISABLED,
            state_reason="operator_disabled",
            ext_merge={
                **record.ext,
                "disabled_at": now_ms(),
                "disabled_reason": "operator_disabled",
            },
        )])
        logger.info("admin token disabled: token={}", _mask(token))
        return _json({"status": "success", "token": token, "disabled": True})

    await repo.patch_accounts([AccountPatch(
        token=token,
        status=AccountStatus.ACTIVE,
        clear_failures=True,
    )])
    logger.info("admin token restored: token={}", _mask(token))
    return _json({"status": "success", "token": token, "disabled": False})


@router.post("/tokens/disabled/batch")
async def toggle_tokens_disabled(
    req: ToggleTokensDisabledRequest,
    repo: "AccountRepository" = Depends(get_repo),
):
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in req.tokens:
        token = _sanitize(raw)
        if token and token not in seen:
            seen.add(token)
            cleaned.append(token)
    if not cleaned:
        raise ValidationError("No valid tokens provided", param="tokens")

    records = await repo.get_accounts(cleaned)
    if not records:
        raise AppError(
            "No matching accounts found",
            kind=ErrorKind.VALIDATION,
            code="account_not_found",
            status=404,
        )

    ts = now_ms()
    patches: list[AccountPatch] = []
    for record in records:
        if req.disabled:
            patches.append(AccountPatch(
                token=record.token,
                status=AccountStatus.DISABLED,
                state_reason="operator_disabled",
                ext_merge={
                    **record.ext,
                    "disabled_at": ts,
                    "disabled_reason": "operator_disabled",
                },
            ))
        else:
            patches.append(AccountPatch(
                token=record.token,
                status=AccountStatus.ACTIVE,
                clear_failures=True,
            ))

    result = await repo.patch_accounts(patches)
    logger.info(
        "admin tokens disabled batch updated: disabled={} requested_count={} patched_count={}",
        req.disabled,
        len(cleaned),
        result.patched,
    )
    return _json({
        "status": "success",
        "disabled": req.disabled,
        "summary": {
            "total": len(cleaned),
            "ok": result.patched,
            "fail": max(0, len(cleaned) - result.patched),
        },
    })


@router.put("/tokens/pool")
async def replace_pool(
    req: ReplacePoolRequest,
    repo: "AccountRepository" = Depends(get_repo),
    refresh_svc: "AccountRefreshService" = Depends(get_refresh_svc),
):
    cleaned = [t for t in (_sanitize(t) for t in req.tokens) if t]
    upserts = [AccountUpsert(token=t, pool=req.pool, tags=req.tags) for t in cleaned]
    await repo.replace_pool(BulkReplacePoolCommand(pool=req.pool, upserts=upserts))
    logger.info("admin pool replaced: pool={} token_count={}", req.pool, len(cleaned))
    if cleaned:
        asyncio.create_task(_refresh_imported(refresh_svc, cleaned))
    return _json({"pool": req.pool, "count": len(cleaned)})


# ---------------------------------------------------------------------------
# Fire-and-forget import refresh
# ---------------------------------------------------------------------------

async def _refresh_imported(svc: "AccountRefreshService", tokens: list[str]) -> None:
    try:
        await svc.refresh_on_import(tokens)
        logger.info("admin import quota sync completed: token_count={}", len(tokens))
    except Exception as exc:
        logger.warning("admin import quota sync failed: token_count={} error={}", len(tokens), exc)
