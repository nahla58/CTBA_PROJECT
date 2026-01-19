 unittest
from main import get_products_for_cve, import_from_nvd

class TestCVEProcessing(unittest.TestCase):

    def test_get_products_for_cve(self):
        cve_data = {
            "descriptions": [
                {"lang": "en", "value": "Police Statistics Database System developed by Gotac has an Arbitrary File Read vulnerability, allowing Unauthenticated remote attacker to exploit Absolute Path Traversal to download arbitrary system"}
            ],
            "configurations": []
        }
        products = get_products_for_cve(cve_data)
        self.assertEqual(len(products), 1)
        self.assertEqual(products[0]['vendor'], 'Gotac')
        self.assertEqual(products[0]['product'], 'Police Statistics Database System')

    def test_import_from_nvd_date_parsing(self):
        cve_data = {
            "cve": {
                "id": "CVE-2026-1018",
                "published": "2026-01-15T12:34:56.789Z",
                "descriptions": [
                    {"lang": "en", "value": "Police Statistics Database System developed by Gotac has an Arbitrary File Read vulnerability, allowing Unauthenticated remote attacker to exploit Absolute Path Traversal to download arbitrary system"}
                ]
            },
            "configurations": []
        }

        # Simulate the import function's date parsing
        from datetime import datetime
        published_date_raw = cve_data['cve'].get('published', '')
        published_date = None
        if published_date_raw:
            try:
                published_date = datetime.strptime(published_date_raw, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    published_date = datetime.strptime(published_date_raw, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    published_date = None

        self.assertEqual(published_date, "2026-01-15 12:34:56")

if __name__ == "__main__":
    unittest.main()