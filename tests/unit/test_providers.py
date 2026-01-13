"""Unit tests for DNS providers."""

from unittest.mock import MagicMock, patch

import pytest

from hardwired.providers.base import DnsProvider
from hardwired.providers.test import TestProvider


class TestDnsProviderInterface:
    """Tests for DnsProvider abstract interface."""

    def test_provider_implements_interface(self):
        """TestProvider should implement DnsProvider interface."""
        provider = TestProvider(challtestsrv_url="http://localhost:8055")
        assert isinstance(provider, DnsProvider)

    def test_provider_has_required_methods(self):
        """Provider should have all required methods."""
        provider = TestProvider(challtestsrv_url="http://localhost:8055")

        assert hasattr(provider, "create_txt_record")
        assert hasattr(provider, "delete_txt_record")
        assert hasattr(provider, "wait_for_propagation")
        assert callable(provider.create_txt_record)
        assert callable(provider.delete_txt_record)
        assert callable(provider.wait_for_propagation)


class TestTestProvider:
    """Tests for TestProvider (pebble-challtestsrv)."""

    @patch("httpx.post")
    def test_create_txt_record_calls_api(self, mock_post: MagicMock):
        """create_txt_record should POST to /set-txt endpoint."""
        mock_post.return_value = MagicMock(status_code=200)
        provider = TestProvider(challtestsrv_url="http://localhost:8055")

        provider.create_txt_record("example.com", "test-token-value")

        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert "/set-txt" in call_url

    @patch("httpx.post")
    def test_create_txt_record_formats_domain(self, mock_post: MagicMock):
        """create_txt_record should format domain as _acme-challenge.domain."""
        mock_post.return_value = MagicMock(status_code=200)
        provider = TestProvider(challtestsrv_url="http://localhost:8055")

        provider.create_txt_record("example.com", "test-token")

        call_json = mock_post.call_args[1]["json"]
        assert call_json["host"] == "_acme-challenge.example.com."

    @patch("httpx.post")
    def test_delete_txt_record_calls_api(self, mock_post: MagicMock):
        """delete_txt_record should POST to /clear-txt endpoint."""
        mock_post.return_value = MagicMock(status_code=200)
        provider = TestProvider(challtestsrv_url="http://localhost:8055")

        provider.delete_txt_record("example.com", "test-token")

        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert "/clear-txt" in call_url

    def test_wait_for_propagation_returns_true(self):
        """wait_for_propagation should return True immediately for test provider."""
        provider = TestProvider(challtestsrv_url="http://localhost:8055")

        result = provider.wait_for_propagation("example.com", "token", timeout=1)

        assert result is True

    @patch("httpx.post")
    def test_create_txt_record_raises_on_error(self, mock_post: MagicMock):
        """create_txt_record should raise on API error."""
        mock_post.return_value = MagicMock(
            status_code=500,
            raise_for_status=MagicMock(side_effect=Exception("Server error")),
        )
        provider = TestProvider(challtestsrv_url="http://localhost:8055")

        with pytest.raises(Exception, match="Server error"):
            provider.create_txt_record("example.com", "token")

    def test_provider_stores_url(self):
        """Provider should store challtestsrv URL."""
        url = "http://custom:9999"
        provider = TestProvider(challtestsrv_url=url)

        assert provider.challtestsrv_url == url
