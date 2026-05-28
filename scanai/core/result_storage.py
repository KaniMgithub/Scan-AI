"""Scan result storage and retrieval system."""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from ..utils.config import config


class ResultStorage:
    """Handles storage and retrieval of scan results."""

    def __init__(self) -> None:
        """Initialize result storage."""
        self.storage_dir = Path(config.storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.max_age_days = 7  # Keep results for 7 days

    def save_result(self, target: str, result: Dict[str, Any]) -> str:
        """Save scan result and return result ID.

        Args:
            target: Target that was scanned
            result: Complete scan result

        Returns:
            Result ID for later retrieval
        """
        # Create a unique ID based on target and timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        clean_target = target.replace('/', '_').replace(':', '_').replace('.', '_')
        result_id = f"{clean_target}_{timestamp}"

        # Add metadata
        result_with_meta = {
            'id': result_id,
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'result': result
        }

        # Save to file
        result_file = self.storage_dir / f"{result_id}.json"
        with open(result_file, 'w') as f:
            json.dump(result_with_meta, f, indent=2, default=str)

        # Clean up old results
        self._cleanup_old_results()

        return result_id

    def get_result(self, result_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan result by ID.

        Args:
            result_id: Result ID

        Returns:
            Scan result data or None if not found
        """
        result_file = self.storage_dir / f"{result_id}.json"

        if not result_file.exists():
            return None

        try:
            with open(result_file, 'r') as f:
                data = json.load(f)
            return data
        except Exception:
            return None

    def get_latest_result(self, target: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get the most recent scan result, optionally filtered by target.

        Args:
            target: Optional target to filter by

        Returns:
            Most recent scan result or None
        """
        result_files = list(self.storage_dir.glob("*.json"))

        if not result_files:
            return None

        # Sort by modification time (newest first)
        result_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        for result_file in result_files:
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)

                # If target specified, check if it matches
                if target and data.get('target') != target:
                    continue

                return data
            except Exception:
                continue

        return None

    def list_results(self, target: Optional[str] = None) -> list[Dict[str, Any]]:
        """List all stored scan results, optionally filtered by target.

        Args:
            target: Optional target to filter by

        Returns:
            List of scan result summaries
        """
        results = []
        result_files = list(self.storage_dir.glob("*.json"))

        for result_file in result_files:
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)

                # If target specified, check if it matches
                if target and data.get('target') != target:
                    continue

                # Create summary
                summary = {
                    'id': data.get('id'),
                    'target': data.get('target'),
                    'timestamp': data.get('timestamp'),
                    'status': data.get('result', {}).get('status', 'unknown'),
                    'duration': data.get('result', {}).get('duration', 0),
                    'file': str(result_file)
                }
                results.append(summary)

            except Exception:
                continue

        # Sort by timestamp (newest first)
        results.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return results

    def get_last_result_id(self) -> Optional[str]:
        """Get the ID of the most recently saved scan result.

        Returns:
            Result ID of the latest scan or None if no results exist
        """
        latest_result = self.get_latest_result()
        if latest_result:
            return latest_result.get('id')
        return None

    def delete_result(self, result_id: str) -> bool:
        """Delete a scan result by ID.

        Args:
            result_id: Result ID to delete

        Returns:
            True if deleted successfully, False otherwise
        """
        result_file = self.storage_dir / f"{result_id}.json"

        if result_file.exists():
            try:
                result_file.unlink()
                return True
            except Exception:
                return False

        return False

    def _cleanup_old_results(self) -> None:
        """Clean up scan results older than max_age_days."""
        cutoff_date = datetime.now() - timedelta(days=self.max_age_days)

        for result_file in self.storage_dir.glob("*.json"):
            try:
                # Check file modification time
                if datetime.fromtimestamp(result_file.stat().st_mtime) < cutoff_date:
                    result_file.unlink()
            except Exception:
                continue


# Global instance
result_storage = ResultStorage()