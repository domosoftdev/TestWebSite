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
    KEYWORDS_FOR_SALE,
    KEYWORDS_PARKING_GENERIC,
    KNOWN_PARKING_HOSTNAMES,
    KNOWN_PARKING_NAMESERVERS
)

class TestParkingScorer(unittest.TestCase):

    # --- Tests for analyserContenu ---

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_redirect_to_known_parking(self, mock_get):
        """Should return 20 if redirected to a known parking hostname."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = f"https://{KNOWN_PARKING_HOSTNAMES[0]}/some-path"
        mock_response.text = "<html><body>Parked</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("parked-domain.com")
        self.assertEqual(score, 20)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_for_sale_keywords(self, mock_get):
        """Should return 10 for 'for sale' keywords."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://some-domain.com"
        mock_response.text = f"<html><title>{KEYWORDS_FOR_SALE[0]}</title><body>Content here.</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("forsale-domain.com")
        self.assertEqual(score, 10)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_generic_parking_keywords(self, mock_get):
        """Should return 10 for generic parking keywords."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://another-domain.com"
        mock_response.text = f"<html><body>This page is {KEYWORDS_PARKING_GENERIC[0]}.</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("generic-parked-domain.com")
        self.assertEqual(score, 10)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_both_keywords_types(self, mock_get):
        """Should return 20 for both types of keywords."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://another-domain.com"
        mock_response.text = f"<html><title>{KEYWORDS_FOR_SALE[0]}</title><body>This page is {KEYWORDS_PARKING_GENERIC[0]}.</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("double-keyword-domain.com")
        self.assertEqual(score, 20)

    @patch('parking_scorer.requests.Session.get')
    def test_analyserContenu_no_keywords(self, mock_get):
        """Should return 0 for a normal website."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.url = "https://legit-site.com"
        mock_response.text = "<html><title>My Website</title><body>Welcome to my page.</body></html>"
        mock_get.return_value = mock_response

        score = analyserContenu("legit-site.com")
        self.assertEqual(score, 0)

    @patch('parking_scorer.requests.Session.get', side_effect=requests.exceptions.RequestException)
    def test_analyserContenu_connection_fails(self, mock_get):
        """Should return 0 if connection fails."""
        score = analyserContenu("unreachable-site.com")
        self.assertEqual(score, 0)

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
                return [mock_a_record]
            raise ValueError(f"Unexpected DNS query in test: {name} {rdtype}")

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

    @patch('parking_scorer.whois.whois', side_effect=Exception("WHOIS query failed"))
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
        mock_technique.return_value = 30
        mock_contextuel.return_value = 35 # Total would be 105
        score = calculerScoreParking("max-score-domain.com")
        self.assertEqual(score, 100)

if __name__ == '__main__':
    unittest.main()
