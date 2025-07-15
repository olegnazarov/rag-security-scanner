"""
Security test payloads for RAG systems
"""

import json
from pathlib import Path
from typing import Dict, List


def load_payloads() -> Dict[str, List[str]]:
    """Load all payload files from the payloads directory"""
    payloads_dir = Path(__file__).parent
    payloads = {}

    for payload_file in payloads_dir.glob("*.json"):
        category = payload_file.stem
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Flatten nested structure to match expected format
                if isinstance(data, dict):
                    flattened = []
                    for subcategory, items in data.items():
                        if isinstance(items, list):
                            flattened.extend(items)
                    payloads[category] = flattened
                else:
                    payloads[category] = data
        except Exception as e:
            print(f"Warning: Failed to load {payload_file}: {e}")

    return payloads


__all__ = ["load_payloads"]