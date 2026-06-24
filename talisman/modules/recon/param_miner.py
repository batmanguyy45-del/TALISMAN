"""Parameter Discovery — identifies hidden GET/POST parameters efficiently."""
from __future__ import annotations
import asyncio
from typing import Any
from talisman.utils.http_client import TalismanHTTPClient
from talisman.utils.logger import get_logger, console, print_finding

log = get_logger(__name__)

COMMON_PARAMS = [
    "debug", "test", "admin", "user", "id", "file", "url", "path", "redirect", 
    "next", "return", "q", "query", "search", "token", "key", "api_key", "secret",
    "password", "email", "username", "cmd", "exec", "command", "config", "cfg",
    "dir", "download", "log", "host", "port", "env", "name", "action", "page"
]

async def run(
    target: str,
    session: Any = None,
    wordlist: str | None = None,
    chunk_size: int = 25,
    proxy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    console.print(f"\n[module] Parameter Discovery (ParamMiner)[/module] → [target]{target}[/target]")
    
    words = COMMON_PARAMS
    if wordlist:
        try:
            with open(wordlist) as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            console.print(f"  [red]Failed to load wordlist: {e}[/red]")
            return {"target": target, "parameters": []}
            
    async with TalismanHTTPClient(proxy=proxy, timeout=10, max_retries=2) as client:
        try:
            baseline = await client.get(target)
            base_len = len(baseline.content)
            base_status = baseline.status_code
        except Exception as e:
            console.print(f"  [red]Failed baseline request: {e}[/red]")
            return {"target": target, "parameters": []}
            
        found_params = []
        chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
        
        console.print(f"  Testing {len(words)} parameters in {len(chunks)} parallel chunks...")
        
        for idx, chunk in enumerate(chunks):
            params = {param: f"talisman{i}" for i, param in enumerate(chunk)}
            try:
                resp = await client.get(target, params=params)
                if abs(len(resp.content) - base_len) > 50 or resp.status_code != base_status or b"talisman" in resp.content:
                    # Narrow down which parameter caused the change
                    for p, v in params.items():
                        verify_resp = await client.get(target, params={p: v})
                        if abs(len(verify_resp.content) - base_len) > 50 or verify_resp.status_code != base_status or v.encode() in verify_resp.content:
                            console.print(f"  [success]✓ Hidden parameter discovered:[/success] [cyan]{p}[/cyan]")
                            found_params.append(p)
                            if session:
                                await session.add_finding(
                                    target=target, module="param_miner", vuln_type="hidden_parameter",
                                    severity="low", confidence="confirmed",
                                    title=f"Hidden Parameter Discovered: {p}",
                                    description=f"The parameter '{p}' significantly altered the response size or status code."
                                )
            except Exception:
                continue
                
    console.print(f"  Total hidden parameters found: {len(found_params)}")
    return {"target": target, "parameters": found_params}
