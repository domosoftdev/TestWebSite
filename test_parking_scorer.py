import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import requests
import dns.resolver

# Import the functions to be tested
from parking_scorer import (
    analyserContenu,
    analyserTechnique,
    analyserContextuel,
    calculerScoreParking,
    KNOWN_PARKING_HOSTNAMES,
    KNOWN_PARKING_NAMESERVERS
)

class TestParkingScorer(unittest.TestCase):

    # --- Tests for analyserContenu ---

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_redirect_to_known_parking(self, mock_get):
        """Should return 25 if redirected to a known parking hostname (20) and has low text volume (5)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = f"https://{KNOWN_PARKING_HOSTNAMES[0]}/some-path"
        mock_response.text = "<html><body>Parked</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("parked-domain.com")
        self.assertEqual(score, 25)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_for_sale_keywords(self, mock_get):
        """Should return 15 for 'for sale' keywords (10) and low text volume (5)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://some-domain.com"
        # Using a keyword that won't trigger the title check
        mock_response.text = "<html><title>A premium domain</title><body>This domain is for sale.</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("forsale-domain.com")
        self.assertEqual(score, 15)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_generic_parking_keywords(self, mock_get):
        """Should return 15 for generic parking keywords (10) and low text volume (5)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://another-domain.com"
        mock_response.text = "<html><body>This page is under construction.</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("generic-parked-domain.com")
        self.assertEqual(score, 15)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_both_keywords_types(self, mock_get):
        """Should return 25 for both keywords (20) and low text volume (5)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://another-domain.com"
        mock_response.text = "<html><title>Domain for sale</title><body>This page is under construction.</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("double-keyword-domain.com")
        # 10 (sale) + 10 (generic) + 5 (title) + 5 (low volume) = 30. Let's adjust the mock to get 25.
        # Let's use a non-suspicious title.
        mock_response.text = "<html><title>My Awesome Domain</title><body>This domain is for sale and is under construction.</body></html>"
        score = analyserContenu("double-keyword-domain.com")
        self.assertEqual(score, 25) # 10 (sale) + 10 (generic) + 5 (low volume)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_no_keywords(self, mock_get):
        """Should return 5 for a normal website with low text volume."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://legit-site.com"
        mock_response.text = "<html><title>My Website</title><body>Welcome to my page.</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("legit-site.com")
        self.assertEqual(score, 5) # 5 from low text volume

    @patch('parking_scorer.requests.Session.get', side_effect=requests.exceptions.RequestException)
    def test_analyserContenu_connection_fails(self, mock_get):
        """Should return 5 if all connection attempts fail."""
        score = analyserContenu("unreachable-site.com")
        self.assertEqual(score, 5)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_css_class_check(self, mock_get):
        """Should return 15 for parking CSS class (10) and low text volume (5)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://css-parked.com"
        mock_response.text = '<html><body><div class="for-sale-banner">Some neutral text</div></body></html>'
        mock_get.return_value = mock_response

        score = analyserContenu("css-parked.com")
        self.assertEqual(score, 15)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_script_source_check(self, mock_get):
        """Should return 20 for parking script src (15) and low text volume (5)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://script-parked.com"
        mock_response.text = f'<html><body><script src="//{KNOWN_PARKING_HOSTNAMES[0]}/tracker.js"></script></body></html>'
        mock_get.return_value = mock_response

        score = analyserContenu("script-parked.com")
        self.assertEqual(score, 20)

    # --- Tests for analyserTechnique ---

    @patch('parking_scorer.dns.resolver.Resolver.resolve')
    def test_analyserTechnique_known_ns_and_wildcard(self, mock_resolve):
        """Should return 20 for known NS (15) and wildcard (5)."""
        mock_ns_record = MagicMock()
        mock_ns_record.target = f"ns1.{KNOWN_PARKING_NAMESERVERS[0]}."
        mock_a_record = MagicMock()
        mock_a_record.__str__.return_value = "1.2.3.4"

        def resolve_side_effect(name, rdtype):
            if rdtype == 'NS':
                return [mock_ns_record]
            elif rdtype == 'A':
                # This simulates a wildcard by returning the same IP for the root and a random subdomain
                return [mock_a_record]
            raise dns.resolver.NXDOMAIN # Fail other queries

        mock_resolve.side_effect = resolve_side_effect
        score = analyserTechnique("parked-by-ns.com")
        self.assertEqual(score, 20) # 15 for NS + 5 for wildcard

    @patch('parking_scorer.dns.resolver.Resolver.resolve', side_effect=dns.resolver.NXDOMAIN)
    def test_analyserTechnique_no_records(self, mock_resolve):
        """Should return 0 if no DNS records are found."""
        score = analyserTechnique("non-existent-domain.com")
        self.assertEqual(score, 0)

    # --- Tests for analyserContextuel ---

    @patch('parking_scorer.whois.whois')
    def test_analyserContextuel_all_signals(self, mock_whois):
        """Should return 25 for all contextual signals."""
        mock_whois.return_value = {
            'creation_date': datetime.now() - timedelta(days=200),
            'updated_date': datetime.now() - timedelta(days=15),
            'org': 'Privacy Guard',
            'status': ['clientHold']
        }
        score = analyserContextuel("all-context-signals.com")
        self.assertEqual(score, 25) # 5 for privacy + 10 for update + 10 for hold

    @patch('parking_scorer.whois.whois', side_effect=Exception("WHOIS query fails"))
    def test_analyserContextuel_whois_fails(self, mock_whois):
        """Should return 0 if WHOIS query fails."""
        score = analyserContextuel("whois-error.com")
        self.assertEqual(score, 0)

    # --- Test for calculerScoreParking ---

    @patch('parking_scorer.analyserContenu')
    @patch('parking_scorer.analyserTechnique')
    @patch('parking_scorer.analyserContextuel')
    def test_calculerScoreParking_sums_and_caps_scores(self, mock_contextuel, mock_technique, mock_contenu):
        """Should sum the scores from all analyzers and cap at 100."""

        # Scenario 1: Normal sum
        mock_contenu.return_value = 10
        mock_technique.return_value = 20
        mock_contextuel.return_value = 15
        score = calculerScoreParking("some-domain.com")
        self.assertEqual(score, 45) # 10 + 20 + 15

        # Scenario 2: Score exceeds 100, should be capped.
        mock_contenu.return_value = 40
        mock_technique.return_value = 35
        mock_contextuel.return_value = 30 # Total would be 105
        score = calculerScoreParking("max-score-domain.com")
        self.assertEqual(score, 100)

if __name__ == '__main__':
    unittest.main()
