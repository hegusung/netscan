import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lib.httpscan.dir_bruteforce import (  # noqa: E402
    dir_bruteforce_generator,
    dir_file_count,
)


class DirectoryBruteforceTests(unittest.TestCase):
    def test_count_matches_generated_targets(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as wordlist:
            wordlist.write("admin\n")
            wordlist.write("# comment\n")
            wordlist.write("bitrix/rk.php?goto=http://evil.example\n")
            wordlist.write("login # inline comment\n")
            wordlist.flush()

            target = {
                "method": "https",
                "hostname": "example.test",
                "port": 443,
                "path": "/",
            }
            generated = list(
                dir_bruteforce_generator(target, wordlist.name, ["", "php"])
            )

            self.assertEqual(dir_file_count(wordlist.name), 2)
            self.assertEqual(len(generated), dir_file_count(wordlist.name) * 2)


if __name__ == "__main__":
    unittest.main()
