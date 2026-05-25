import unittest
from unittest.mock import patch, MagicMock
from enrichment.virustotal import check_hash_vt
from enrichment.whois_check import check_whois

class TestCheckHashVt(unittest.TestCase):

    @patch('enrichment.virustotal.requests.get')
    def test_check_hash_vt(self, mock_get):
        # set up fake response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 0,
                        "harmless": 50,
                        "undetected": 10
                    },
                    "reputation": -1,
                    "meaningful_name": "malware.exe",
                    "type_description": "PE32",
                    "total_votes": {"harmless": 0, "malicious": 5}
                }
            }
        }
        mock_get.return_value = mock_response    
        # call the real function
        result = check_hash_vt("fakehash123")    
        # assert on the result
        self.assertEqual(result["malicious"], 3)

    @patch('enrichment.virustotal.api_key', '')
    def test_no_api_key(self):
        result = check_hash_vt("fakehash123")
        self.assertEqual(result["error"], "No VT API key found in .env")

    @patch('enrichment.virustotal.requests.get')
    def test_bad_response_structure(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {"unexpected": "structure"}
        mock_get.return_value = mock_response
        result = check_hash_vt("fakehash123")
        self.assertIn("error", result)
        
class TestCheckWhois(unittest.TestCase):

    @patch('enrichment.whois_check.whois.whois')
    def test_whois_error_returns_error_dict(self, mock_whois):
        mock_whois.side_effect = Exception("Connection timeout")
        result = check_whois("malicious.com")
        self.assertIn("error", result)
        self.assertEqual(result["error"], "Connection timeout")

if __name__ == "__main__":
    unittest.main()