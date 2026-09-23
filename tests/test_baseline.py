import unittest
from pathlib import Path

class BaselineTest(unittest.TestCase):
    def test_backend_and_sqlite_configuration_exist(self):
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / 'app' / 'main.py').is_file())
        self.assertIn('sqlite:///', (root / 'app' / 'database.py').read_text(encoding='utf-8'))
        self.assertTrue((root / 'requirements.txt').is_file())

if __name__ == '__main__':
    unittest.main()
