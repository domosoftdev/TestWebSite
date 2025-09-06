import unittest
from unittest.mock import patch, MagicMock
from cookie_analyzer import CookieAnalyzer

class TestGDPR(unittest.TestCase):

    @patch('cookie_analyzer.webdriver.Chrome')
    def test_check_consent_banner_found(self, mock_chrome):
        """
        Test that the consent banner is found when present.
        """
        # Mock the entire driver and its methods
        mock_driver_instance = MagicMock()
        mock_chrome.return_value = mock_driver_instance

        # Mock the find_elements method to return a non-empty list
        mock_element = MagicMock()
        mock_driver_instance.find_elements.return_value = [mock_element]

        analyzer = CookieAnalyzer()
        result = analyzer.analyze("https://example.com")

        # Check that driver methods were called
        mock_driver_instance.get.assert_called_with("https://example.com")
        self.assertTrue(mock_driver_instance.find_elements.called)

        # Check the result
        self.assertTrue(result['consent_banner']['present'])
        self.assertIsNotNone(result['consent_banner']['selector'])

    @patch('cookie_analyzer.webdriver.Chrome')
    def test_check_consent_banner_not_found(self, mock_chrome):
        """
        Test that the consent banner is not found when absent.
        """
        mock_driver_instance = MagicMock()
        mock_chrome.return_value = mock_driver_instance

        # Mock the find_elements method to return an empty list
        mock_driver_instance.find_elements.return_value = []

        analyzer = CookieAnalyzer()
        result = analyzer.analyze("https://example.com")

        # Check that driver methods were called
        mock_driver_instance.get.assert_called_with("https://example.com")
        self.assertTrue(mock_driver_instance.find_elements.called)

        # Check the result
        self.assertFalse(result['consent_banner']['present'])
        self.assertIsNone(result['consent_banner']['selector'])

if __name__ == '__main__':
    unittest.main()
