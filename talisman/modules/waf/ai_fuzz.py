"""AI Fuzzer — Generates novel WAF bypass payloads using LLMs."""
import os
import json
import httpx
from typing import Any
from talisman.utils.logger import get_logger, console

log = get_logger(__name__)

async def run(target: str, param: str, waf_vendor: str = "Generic", proxy: str | None = None) -> dict[str, Any]:
    api_key = os.environ.get("TALISMAN_AI_KEY")
    if not api_key:
        console.print("[red]Error: TALISMAN_AI_KEY environment variable not set.[/red]")
        console.print("  [dim]export TALISMAN_AI_KEY=sk-...[/dim]")
        return {"error": "Missing AI key"}
        
    console.print(f"\n[module]🤖 AI Payload Generator[/module] → [target]{target}[/target]")
    console.print(f"  Target Parameter: {param}")
    console.print(f"  Target WAF: {waf_vendor}")
    
    prompt = f"Generate 5 novel, highly obfuscated XSS payloads specifically designed to bypass the {waf_vendor} WAF. Return ONLY a JSON list of strings."
    
    console.print("  [dim]Contacting AI for payload generation...[/dim]")
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4",
                    "messages": [
                        {"role": "system", "content": "You are a red team security researcher. Return valid JSON lists of strings only. No markdown, no intro."},
                        {"role": "user", "content": prompt}
                    ]
                },
                timeout=30.0
            )
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                # Clean markdown block if present
                content = content.replace("```json", "").replace("```", "").strip()
                try:
                    payloads = json.loads(content)
                    console.print(f"  [success]✓ Generated {len(payloads)} AI Payloads:[/success]")
                    for p in payloads:
                        console.print(f"    [yellow]{p}[/yellow]")
                    return {"target": target, "payloads": payloads}
                except json.JSONDecodeError:
                    console.print(f"  [warning]AI returned invalid JSON:[/warning]\n{content}")
            else:
                console.print(f"  [warning]AI API returned error {resp.status_code}: {resp.text}[/warning]")
    except Exception as e:
        console.print(f"  [red]Failed to generate AI payloads: {e}[/red]")
        
    return {"target": target, "payloads": []}
