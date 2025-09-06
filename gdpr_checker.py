#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module principal pour l'audit de conformité RGPD.
"""

from datetime import datetime
from cookie_analyzer import CookieAnalyzer

class GDPRChecker:
    def __init__(self):
        self.cookie_analyzer = CookieAnalyzer()

    def check_gdpr_compliance(self, url):
        """Point d'entrée principal pour l'audit RGPD."""
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'cookies': self.cookie_analyzer.analyze(url),
        }
        return results
