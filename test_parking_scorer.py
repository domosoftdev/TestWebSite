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
    def test_analyserTechnique_known_ns(self, mock_resolve):
        """Should return 15 for known parking nameservers."""
        mock_ns_record = MagicMock()
        mock_ns_record.target = f"ns1.{KNOWN_PARKING_NAMESERVERS[0]}."
        mock_resolve.return_value = [mock_ns_record]

        score = analyserTechnique("parked-by-ns.com")
        self.assertEqual(score, 15)
        mock_resolve.assert_called_once_with("parked-by-ns.com", 'NS')

    @patch('parking_scorer.dns.resolver.Resolver.resolve')
    def test_analyserTechnique_wildcard_dns(self, mock_resolve):
        """Should return 5 for a wildcard DNS setup."""
        mock_a_record = MagicMock()
        mock_a_record.__str__.return_value = "1.2.3.4"
        mock_a_records_answer = [mock_a_record]

        def resolve_side_effect(name, rdtype):
            if rdtype == 'NS':
                raise dns.resolver.NXDOMAIN
            elif rdtype == 'A':
                return mock_a_records_answer
            raise ValueError(f"Unexpected DNS query in test: {name} {rdtype}")

        mock_resolve.side_effect = resolve_side_effect
        score = analyserTechnique("wildcard-domain.com")
        self.assertEqual(score, 5)

    @patch('parking_scorer.dns.resolver.Resolver.resolve', side_effect=dns.resolver.NXDOMAIN)
    def test_analyserTechnique_no_records(self, mock_resolve):
        """Should return 0 if no DNS records are found."""
        score = analyserTechnique("non-existent-domain.com")
        self.assertEqual(score, 0)

    # --- Tests for analyserContextuel ---

    @patch('parking_scorer.whois.whois')
    def test_analyserContextuel_client_hold(self, mock_whois):
        """Should return 10 for 'clientHold' status."""
        mock_whois.return_value = {
            'creation_date': datetime.now() - timedelta(days=200),
            'status': ['clientHold', 'someOtherStatus']
        }
        score = analyserContextuel("on-hold.com")
        self.assertEqual(score, 10)

    @patch('parking_scorer.whois.whois')
    def test_analyserContextuel_recent_update(self, mock_whois):
        """Should return 10 for a recent update."""
        mock_whois.return_value = {
            'creation_date': datetime.now() - timedelta(days=200),
            'updated_date': datetime.now() - timedelta(days=15)
        }
        score = analyserContextuel("recently-updated.com")
        self.assertEqual(score, 10)

    @patch('parking_scorer.whois.whois')
    def test_analyserContextuel_recent_creation(self, mock_whois):
        """Should return 5 for recent creation (if not recently updated)."""
        mock_whois.return_value = {
            'creation_date': datetime.now() - timedelta(days=60),
            'updated_date': datetime.now() - timedelta(days=100)
        }
        score = analyserContextuel("recently-created.com")
        self.assertEqual(score, 5)

    @patch('parking_scorer.whois.whois')
    def test_analyserContextuel_privacy_protection(self, mock_whois):
        """Should return 5 for WHOIS privacy."""
        mock_whois.return_value = {
            'creation_date': datetime.now() - timedelta(days=200),
            'org': 'WHOISGUARD, INC.'
        }
        score = analyserContextuel("privacy-domain.com")
        self.assertEqual(score, 5)

    @patch('parking_scorer.whois.whois', side_effect=Exception("WHOIS query failed"))
    def test_analyserContextuel_whois_fails(self, mock_whois):
        """Should return 0 if WHOIS query fails."""
        score = analyserContextuel("whois-error.com")
        self.assertEqual(score, 0)

    # --- Test for calculerScoreParking ---

    @patch('parking_scorer.analyserContenu')
    @patch('parking_scorer.analyserTechnique')
    @patch('parking_scorer.analyserContextuel')
    def test_calculerScoreParking_logic(self, mock_contextuel, mock_technique, mock_contenu):
        """Should correctly sum scores or exit early based on strong signals."""

        # Scenario 1: Strong content signal (>=20), should exit early.
        mock_contenu.return_value = 20
        score = calculerScoreParking("strong-content.com")
        self.assertEqual(score, 20)
        mock_technique.assert_not_called()

        # Scenario 2: Strong technical signal (>=15), should exit early.
        mock_contenu.return_value = 10
        mock_technique.return_value = 15
        score = calculerScoreParking("strong-tech.com")
        self.assertEqual(score, 15)
        mock_contextuel.assert_not_called()

        # Reset mocks for next scenario
        mock_technique.reset_mock()
        mock_contextuel.reset_mock()

        # Scenario 3: No strong signals, should sum all scores.
        mock_contenu.return_value = 10
        mock_technique.return_value = 5
        mock_contextuel.return_value = 10
        score = calculerScoreParking("weak-signals.com")
        self.assertEqual(score, 25)

        # Scenario 4: Sum exceeds 100, should be capped.
        mock_contenu.return_value = 10
        mock_technique.return_value = 10
        mock_contextuel.return_value = 90
        score = calculerScoreParking("max-score.com")
        self.assertEqual(score, 100)

if __name__ == '__main__':
    unittest.main()
