import ssl
import urllib.error

from proverka_bot.tls import describe_network_error, https_context


def test_context_verifies_certificates():
    ctx = https_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_cert_error_explained():
    exc = urllib.error.URLError(ssl.SSLCertVerificationError("CERTIFICATE_VERIFY_FAILED"))
    assert "Install Certificates" in describe_network_error(exc)


def test_other_error_has_type_only():
    assert describe_network_error(urllib.error.URLError(TimeoutError())) == "сеть недоступна (TimeoutError)"
