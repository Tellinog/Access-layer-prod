from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("platform_check", ROOT / "scripts/platform_check.py")
assert SPEC and SPEC.loader
platform_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = platform_check
SPEC.loader.exec_module(platform_check)


class GardenContrastTests(unittest.TestCase):
    def test_primary_button_contrast(self) -> None:
        self.assertGreaterEqual(platform_check.contrast_ratio("#001D2C", "#00B27F"), 4.5)

    def test_white_on_navy_contrast(self) -> None:
        self.assertGreaterEqual(platform_check.contrast_ratio("#FFFFFF", "#003A57"), 4.5)

    def test_white_on_green_is_not_body_text_pair(self) -> None:
        self.assertLess(platform_check.contrast_ratio("#FFFFFF", "#00B27F"), 4.5)


if __name__ == "__main__":
    unittest.main()
