import pytest

from vulnhound.scope import check_target


def test_localhost_is_allowed():
    check_target("http://localhost:8080")


def test_remote_is_blocked_by_default():
    with pytest.raises(ValueError):
        check_target("https://example.com")


def test_remote_allowed_with_permission():
    check_target("https://example.com", allow_remote=True)


def test_non_http_scheme_is_blocked():
    with pytest.raises(ValueError):
        check_target("ftp://localhost")