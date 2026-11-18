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


def test_rate_limiter_is_thread_safe():
    import threading
    from proverka_bot.ratelimit import RateLimiter

    limiter, allowed = RateLimiter(per_minute=50, max_users=5), []
    def hammer():
        for _ in range(100):
            allowed.append(limiter.allow(1, now=0.0))
    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert sum(allowed) == 50
