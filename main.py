"""A FastAPI version of the supplied Cloudflare Worker MEGA link indexer.

Run with:  uvicorn mega_indexer:app --host 127.0.0.1 --port 8000
"""

import asyncio
import base64
import html
import json
import random
import re
import time
from dataclasses import dataclass, field
from typing import AsyncIterator
from urllib.parse import quote

import httpx
from Crypto.Cipher import AES
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse

app = FastAPI(title="MEGA Link Indexer")
MEGA_API = "https://g.api.mega.co.nz/cs"
CACHE_TTL_SECONDS = 300
CHUNK_SIZE = 32 * 1024 * 1024
tree_cache: dict[tuple[str, str], tuple[float, "PublicTree"]] = {}
cache_lock = asyncio.Lock()


@dataclass
class Node:
    hash: str
    parent: str | None
    type: int  # 0=file, 1=folder
    name: str
    size: int = 0
    timestamp: int | None = None
    key: bytes = b""
    iv: bytes | None = None
    children: list["Node"] = field(default_factory=list)


@dataclass
class PublicTree:
    nodes: dict[str, Node]
    root_hash: str


def b64decode(value: str) -> bytes:
    """Decode MEGA's URL-safe, usually unpadded base64 strings."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def parse_mega_public_link(link: str) -> dict[str, str] | None:
    link = link.strip()
    patterns = (
        (r"mega(?:\.co)?\.nz/(folder|file)/([\w-]+)#([\w-]+)", None),
        (r"mega(?:\.co)?\.nz/#F!([\w-]+)!([\w-]+)", "folder"),
        (r"mega(?:\.co)?\.nz/#!([\w-]+)!([\w-]+)", "file"),
    )
    for pattern, fixed_type in patterns:
        match = re.search(pattern, link)
        if match:
            if fixed_type:
                return {"type": fixed_type, "handle": match[1], "key": match[2]}
            return {"type": match[1], "handle": match[2], "key": match[3]}
    return None


def decrypt_attributes(key: bytes, encrypted_attributes: str | None) -> dict:
    if not encrypted_attributes:
        return {}
    plaintext = AES.new(key, AES.MODE_CBC, iv=bytes(16)).decrypt(b64decode(encrypted_attributes))
    if not plaintext.startswith(b"MEGA"):
        raise ValueError("Invalid MEGA attribute signature")
    text = plaintext[4:].decode("utf-8", errors="replace").replace("\0", "")
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("Invalid MEGA attribute JSON")
    return json.loads(text[start : end + 1])


def decrypt_public_node(raw: dict, share_key: bytes) -> Node | None:
    try:
        # MEGA gives each node key as "ownerHandle:encryptedKey[/...]".
        key_piece = raw["k"].split(":", 1)[1].split("/", 1)[0]
        decrypted = AES.new(share_key, AES.MODE_ECB).decrypt(b64decode(key_piece))
        if raw["t"] == 0:
            key = bytes(a ^ b for a, b in zip(decrypted[:16], decrypted[16:32]))
            iv = decrypted[16:24] + bytes(8)
        elif raw["t"] == 1:
            key, iv = decrypted, None
        else:
            return None
        attributes = decrypt_attributes(key, raw.get("a"))
        return Node(
            hash=raw["h"], parent=raw.get("p"), type=raw["t"],
            name=attributes.get("n", "Unnamed item"), size=raw.get("s", 0),
            timestamp=raw.get("ts"), key=key, iv=iv,
        )
    except (KeyError, ValueError, IndexError, json.JSONDecodeError):
        return None


async def mega_api(client: httpx.AsyncClient, payload: list[dict], folder_handle: str | None = None) -> list | dict:
    params = {"id": str(random.randrange(2_147_483_647))}
    if folder_handle:
        params["n"] = folder_handle
    response = await client.post(MEGA_API, params=params, json=payload)
    response.raise_for_status()
    data = response.json()
    if isinstance(data, int) or (isinstance(data, list) and data and isinstance(data[0], int)):
        raise HTTPException(404, f"MEGA API error: {data}. The link may be invalid or unavailable.")
    return data


async def fetch_public_tree(folder_handle: str, key_b64: str) -> PublicTree:
    share_key = b64decode(key_b64)
    if len(share_key) != 16:
        raise HTTPException(400, "A public folder key must decode to 16 bytes.")
    async with httpx.AsyncClient(timeout=30) as client:
        data = await mega_api(client, [{"a": "f", "c": 1, "r": 1, "ca": 1}], folder_handle)
    raw_nodes = data[0].get("f", [])
    nodes = {
        node.hash: node
        for raw in raw_nodes
        if raw.get("t") in (0, 1)
        if (node := decrypt_public_node(raw, share_key)) is not None
    }
    for node in nodes.values():
        if node.parent in nodes:
            nodes[node.parent].children.append(node)
    root_hash = folder_handle if folder_handle in nodes else next(
        (node.hash for node in nodes.values() if node.type == 1 and node.parent not in nodes), None
    )
    if not root_hash:
        raise HTTPException(502, "Could not determine the public folder root.")
    return PublicTree(nodes, root_hash)


async def get_public_tree(folder_handle: str, key_b64: str, refresh: bool = False) -> PublicTree:
    cache_key = (folder_handle, key_b64)
    async with cache_lock:
        cached = tree_cache.get(cache_key)
        if cached and not refresh and time.monotonic() - cached[0] < CACHE_TTL_SECONDS:
            return cached[1]
    tree = await fetch_public_tree(folder_handle, key_b64)
    async with cache_lock:
        tree_cache[cache_key] = (time.monotonic(), tree)
    return tree


def parse_range(header: str | None, size: int) -> tuple[int, int, bool]:
    if not header or not header.startswith("bytes="):
        return 0, size - 1, False
    first = header[6:].split(",", 1)[0].strip()
    start_s, _, end_s = first.partition("-")
    try:
        if start_s:
            start, end = int(start_s), int(end_s) if end_s else size - 1
        elif end_s:
            suffix = int(end_s)
            start, end = max(0, size - suffix), size - 1
        else:
            raise ValueError
    except ValueError:
        raise HTTPException(416, "Requested Range Not Satisfiable")
    if start < 0 or start >= size or end < start:
        raise HTTPException(416, "Requested Range Not Satisfiable")
    return start, min(end, size - 1), True


async def decrypted_bytes(download_url: str, key: bytes, iv: bytes, start: int, end: int) -> AsyncIterator[bytes]:
    aes_start = start // 16 * 16
    discard = start - aes_start
    position = aes_start
    async with httpx.AsyncClient(timeout=None) as client:
        while position <= end:
            chunk_end = min(position + CHUNK_SIZE - 1, end)
            response = await client.get(download_url, headers={"Range": f"bytes={position}-{chunk_end}"})
            response.raise_for_status()
            # MEGA CTR: first 8 bytes are nonce; last 8 bytes are a big-endian block counter.
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=position // 16)
            plaintext = cipher.decrypt(response.content)
            if discard:
                plaintext, discard = plaintext[discard:], 0
            yield plaintext
            position = chunk_end + 1


async def download_response(request: Request, node: Node, download_url: str) -> StreamingResponse:
    start, end, partial = parse_range(request.headers.get("range"), node.size)
    headers = {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(node.name)}",
        "Accept-Ranges": "bytes",
        "Content-Length": str(end - start + 1),
    }
    if partial:
        headers["Content-Range"] = f"bytes {start}-{end}/{node.size}"
    return StreamingResponse(decrypted_bytes(download_url, node.key, node.iv or bytes(16), start, end), status_code=206 if partial else 200, headers=headers)


async def public_file_info(file_handle: str, key_b64: str, want_download: bool) -> tuple[Node, str | None]:
    key_material = b64decode(key_b64)
    if len(key_material) != 32:
        raise HTTPException(400, "A public file key must decode to 32 bytes.")
    key = bytes(a ^ b for a, b in zip(key_material[:16], key_material[16:]))
    iv = key_material[16:24] + bytes(8)
    payload = {"a": "g", "g": 1, "p": file_handle} if want_download else {"a": "g", "p": file_handle}
    async with httpx.AsyncClient(timeout=30) as client:
        data = await mega_api(client, [payload])
    info = data[0]
    attributes = decrypt_attributes(key, info.get("at"))
    node = Node(file_handle, None, 0, attributes.get("n", "download.bin"), info.get("s", 0), key=key, iv=iv)
    return node, info.get("g")


def size_text(size: int) -> str:
    units = ("Bytes", "KB", "MB", "GB", "TB")
    index = 0
    value = float(size)
    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1
    return f"{value:.2f} {units[index]}" if index else f"{size} Bytes"


def page(title: str, content: str) -> HTMLResponse:
    return HTMLResponse(f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title><style>body{{font:16px system-ui;max-width:900px;margin:3rem auto;padding:0 1rem;background:#0b1020;color:#e8edff}}a{{color:#8bc5ff}}input,button{{font:inherit;padding:.7rem}}.card{{background:#141c33;padding:1.25rem;border-radius:12px;margin:1rem 0}}.item{{display:flex;justify-content:space-between;gap:1rem;padding:.8rem 0;border-bottom:1px solid #293453}}small{{color:#aab6d4}}</style></head><body>{content}</body></html>""")


@app.get("/", response_class=HTMLResponse)
async def landing() -> HTMLResponse:
    return page("MEGA Link Indexer", """<h1>MEGA Link Indexer</h1><div class='card'><p>Paste a public MEGA folder or file link.</p><form action='/open'><input name='link' required style='width:70%' placeholder='https://mega.nz/folder/HANDLE#KEY'><button>Open</button></form></div>""")


@app.get("/open")
async def open_link(link: str = "") -> RedirectResponse:
    parsed = parse_mega_public_link(link)
    if not parsed:
        raise HTTPException(400, "Invalid MEGA public link.")
    prefix = "p" if parsed["type"] == "folder" else "pf"
    return RedirectResponse(f"/{prefix}/{parsed['handle']}/{parsed['key']}")


@app.get("/p/{folder_handle}/{key_b64}", response_class=HTMLResponse)
async def folder_index(folder_handle: str, key_b64: str, sub: str | None = None, refresh: int = 0) -> HTMLResponse:
    tree = await get_public_tree(folder_handle, key_b64, refresh == 1)
    current = tree.nodes.get(sub or tree.root_hash)
    if not current or current.type != 1:
        raise HTTPException(404, "Folder not found.")
    items = sorted(current.children, key=lambda n: (n.type == 0, n.name.casefold()))
    rows = []
    for item in items:
        label = html.escape(item.name)
        if item.type == 1:
            target = f"/p/{folder_handle}/{key_b64}?sub={quote(item.hash)}"
            detail = "Folder"
        else:
            target = f"/p/{folder_handle}/{key_b64}/download/{item.hash}"
            detail = f"File · {size_text(item.size)}"
        rows.append(f"<div class='item'><span><a href='{target}'>{label}</a><br><small>{detail}</small></span><a href='{target}'>Open</a></div>")
    parent = tree.nodes.get(current.parent or "")
    up = f"<p><a href='/p/{folder_handle}/{key_b64}?sub={quote(parent.hash)}'>← Up</a></p>" if parent else ""
    return page(current.name, f"<h1>{html.escape(current.name)}</h1><p><a href='/'>Home</a> · <a href='/p/{folder_handle}/{key_b64}?refresh=1'>Refresh</a></p>{up}<div class='card'>{''.join(rows) or '<p>This folder is empty.</p>'}</div>")


@app.get("/p/{folder_handle}/{key_b64}/download/{node_hash}")
async def folder_download(request: Request, folder_handle: str, key_b64: str, node_hash: str) -> StreamingResponse:
    tree = await get_public_tree(folder_handle, key_b64)
    node = tree.nodes.get(node_hash)
    if not node or node.type != 0:
        raise HTTPException(404, "File not found.")
    async with httpx.AsyncClient(timeout=30) as client:
        data = await mega_api(client, [{"a": "g", "g": 1, "n": node_hash}], folder_handle)
    if not data[0].get("g"):
        raise HTTPException(502, "MEGA did not provide a download URL.")
    return await download_response(request, node, data[0]["g"])


@app.get("/pf/{file_handle}/{key_b64}", response_class=HTMLResponse)
async def file_index(file_handle: str, key_b64: str) -> HTMLResponse:
    node, _ = await public_file_info(file_handle, key_b64, False)
    path = f"/pf/{file_handle}/{key_b64}/download"
    return page(node.name, f"<h1>Public MEGA File</h1><div class='card'><h2>{html.escape(node.name)}</h2><p>{size_text(node.size)}</p><p><a href='{path}'>Download</a></p></div>")


@app.get("/pf/{file_handle}/{key_b64}/download")
async def file_download(request: Request, file_handle: str, key_b64: str) -> StreamingResponse:
    node, download_url = await public_file_info(file_handle, key_b64, True)
    if not download_url:
        raise HTTPException(502, "MEGA did not provide a download URL.")
    return await download_response(request, node, download_url)


@app.exception_handler(Exception)
async def unexpected_error(_: Request, exc: Exception) -> Response:
    if isinstance(exc, HTTPException):
        return Response(exc.detail, status_code=exc.status_code)
    return Response("Server error: " + str(exc), status_code=500)
