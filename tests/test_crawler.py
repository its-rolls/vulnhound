from vulnhound.crawler import dedup_key, in_scope, is_dangerous, parse_page

HTML = """
<a href="/about.php">About</a>
<a href="https://evil.example/">Off-site</a>
<a href="search.php?q=test#results">Search</a>
<form action="/login.php" method="post">
  <input name="username"><input type="password" name="password">
  <input type="submit" value="Login">
</form>
"""


def test_parse_page_finds_links_and_forms():
    links, forms = parse_page("http://localhost:8080/index.php", HTML)
    assert "http://localhost:8080/about.php" in links
    assert "http://localhost:8080/search.php?q=test" in links  # fragment removed
    assert len(forms) == 1
    assert forms[0].method == "POST"
    assert forms[0].action == "http://localhost:8080/login.php"
    assert [i.name for i in forms[0].inputs] == ["username", "password"]


def test_scope():
    base = "http://localhost:8080/"
    assert in_scope("http://localhost:8080/a.php", base)
    assert not in_scope("https://evil.example/", base)
    assert not in_scope("http://localhost:3000/", base)  # different port = different app


def test_dangerous_links_are_flagged():
    assert is_dangerous("http://localhost:8080/logout.php")
    assert not is_dangerous("http://localhost:8080/about.php")


def test_dedup_ignores_parameter_values():
    assert dedup_key("http://x/p.php?id=1") == dedup_key("http://x/p.php?id=2")
    assert dedup_key("http://x/p.php?id=1") != dedup_key("http://x/p.php?name=1")