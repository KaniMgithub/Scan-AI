"""Scan session persistence — save, load, export scan results."""

import json
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime


class ScanSession:
    """Manages persistent scan sessions."""

    SESSIONS_DIR = os.path.expanduser("~/.scanai/sessions")

    def __init__(self) -> None:
        os.makedirs(self.SESSIONS_DIR, exist_ok=True)

    def save(self, results: Dict[str, Any], query: str = "", name: Optional[str] = None) -> str:
        """Save scan results to a session file. Returns session ID."""
        session_id = name or f"scan_{int(time.time())}"
        session_data = {
            'id': session_id,
            'query': query,
            'timestamp': datetime.utcnow().isoformat(),
            'target': results.get('target', ''),
            'domain': results.get('domain', ''),
            'duration': results.get('duration', 0),
            'risk_level': results.get('level', 'unknown'),
            'scanners': list(results.get('details', {}).keys()),
            'results': results,
        }

        filepath = os.path.join(self.SESSIONS_DIR, f"{session_id}.json")
        with open(filepath, 'w') as f:
            json.dump(session_data, f, indent=2, default=str)

        return session_id

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load a saved session by ID."""
        filepath = os.path.join(self.SESSIONS_DIR, f"{session_id}.json")
        if not os.path.isfile(filepath):
            # Try partial match
            for f in os.listdir(self.SESSIONS_DIR):
                if session_id in f:
                    filepath = os.path.join(self.SESSIONS_DIR, f)
                    break
            else:
                return None

        with open(filepath, 'r') as f:
            return json.load(f)

    def list_sessions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List saved sessions, most recent first."""
        sessions = []
        for filename in sorted(os.listdir(self.SESSIONS_DIR), reverse=True):
            if not filename.endswith('.json'):
                continue
            filepath = os.path.join(self.SESSIONS_DIR, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                sessions.append({
                    'id': data.get('id', filename.replace('.json', '')),
                    'target': data.get('target', '?'),
                    'timestamp': data.get('timestamp', '?'),
                    'scanners': data.get('scanners', []),
                    'risk_level': data.get('risk_level', '?'),
                    'query': data.get('query', ''),
                })
            except Exception:
                continue
            if len(sessions) >= limit:
                break
        return sessions

    def delete(self, session_id: str) -> bool:
        """Delete a saved session."""
        filepath = os.path.join(self.SESSIONS_DIR, f"{session_id}.json")
        if os.path.isfile(filepath):
            os.remove(filepath)
            return True
        return False

    def export_markdown(self, session_id: str) -> Optional[str]:
        """Export session as markdown report."""
        data = self.load(session_id)
        if not data:
            return None

        results = data.get('results', {})
        lines = [
            f"# ScanAI Penetration Test Report",
            f"",
            f"**Target:** {data.get('target', 'N/A')}",
            f"**Date:** {data.get('timestamp', 'N/A')}",
            f"**Query:** {data.get('query', 'N/A')}",
            f"**Risk Level:** {data.get('risk_level', 'N/A')}",
            f"**Duration:** {results.get('duration', 0):.1f}s",
            f"**Scanners:** {', '.join(data.get('scanners', []))}",
            f"",
            f"---",
            f"",
        ]

        details = results.get('details', {})
        summaries = results.get('summaries', {})

        # Summaries
        if summaries:
            lines.append("## Summary")
            lines.append("")
            for scanner, summary in summaries.items():
                lines.append(f"### {scanner}")
                if isinstance(summary, str):
                    lines.append(summary)
                elif isinstance(summary, dict):
                    for k, v in summary.items():
                        lines.append(f"- **{k}:** {v}")
                lines.append("")

        # Detailed findings
        for scanner, data_block in details.items():
            lines.append(f"## {scanner.upper()} Results")
            lines.append("")
            if isinstance(data_block, dict):
                lines.append(f"```json\n{json.dumps(data_block, indent=2, default=str)[:3000]}\n```")
            lines.append("")

        return "\n".join(lines)

    def export_html(self, session_id: str) -> Optional[str]:
        """Export session as HTML report."""
        md = self.export_markdown(session_id)
        if not md:
            return None

        # Simple MD → HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ScanAI Report - {session_id}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff41; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #ff0040; border-bottom: 2px solid #ff0040; }}
        h2 {{ color: #00ffff; }}
        h3 {{ color: #ffff00; }}
        pre {{ background: #1a1a1a; padding: 15px; border: 1px solid #333; overflow-x: auto; }}
        code {{ background: #1a1a1a; padding: 2px 6px; }}
        strong {{ color: #ff6600; }}
        hr {{ border: 1px solid #333; }}
    </style>
</head>
<body>
<pre>{md}</pre>
</body>
</html>"""
        return html
