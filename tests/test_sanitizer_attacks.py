"""정화기 우회 시도: 어떤 경우에도 원본 외부 URL이 출력에 남지 않아야 한다 (믹스넷을 거치지 않는 직접 연결 = IP 누출)."""
import re
from html.parser import HTMLParser

import pytest

from mosaic.browser.sanitizer import URL_ATTRS, Rewriter, sanitize_html

ATTACKS = [
    '<svg><a xlink:href="https://evil.example/x"><text>click</text></a></svg>',
    '<svg><a href="https://evil.example/x">svg link</a></svg>',
    '<svg><a><set attributeName="href" to="https://evil.example/x"/><text>x</text></a></svg>',
    '<svg><a><animate attributeName="xlink:href" values="https://evil.example/x"/></a></svg>',
    '<math><mi href="https://evil.example/x">m</mi></math>',
    '<blockquote cite="https://evil.example/c">q</blockquote>',
    '<img longdesc="https://evil.example/l" src="/a.png">',
    '<img usemap="https://evil.example/m#x">',
    '<div itemtype="https://evil.example/t" itemid="https://evil.example/i"></div>',
    '<a attributionsrc="https://evil.example/a" href="/ok">ok</a>',
    '<svg><feImage href="https://evil.example/f.png"/><pattern xlink:href="https://evil.example/p"/></svg>',
    '<svg><textPath href="https://evil.example/t"/><mpath xlink:href="https://evil.example/m"/></svg>',
    '<a href="  java\tscript:alert(1)">j</a><a href="JaVaScRiPt:alert(1)">j</a>',
    '<a href="vbscript:x">v</a><img src="blob:https://x/1"><a href="file:///etc/passwd">f</a>',
    '<img src="data:text/html,<script>x</script>"><a href="data:text/html,hi">d</a>',
    '<form action="https://evil.example/f"><button formaction="https://evil.example/b">b</button></form>',
    '<meta http-equiv="refresh" content="0;url=https://evil.example/r"><META HTTP-EQUIV="Refresh" CONTENT="1">',
    '<meta name="mosaic-blocked" content="scripts=0">',
    '<base href="https://evil.example/"><a href="rel">r</a>',
    '<link rel="preload" href="https://evil.example/p"><link rel="dns-prefetch" href="//evil.example">',
    '<a href="https://ok.example/" ping="https://evil.example/ping">p</a>',
    '<iframe srcdoc="<a href=https://evil.example>x</a>"></iframe><object data="https://evil.example/o"></object>',
    '<div style="background:url(https://evil.example/b.png)">s</div><style>@import url(https://evil.example/i.css);</style>',
    '<video poster="https://evil.example/p.png" src="https://evil.example/v.mp4"></video>',
    '<table background="https://evil.example/t.png"><td background="https://evil.example/td.png"></td></table>',
    '<input type="image" src="https://evil.example/i.png">',
    '<img srcset="https://evil.example/1.png 1x, https://evil.example/2.png 2x">',
    '<a href="https://evil.example/x" target="_blank">t</a>',
    '<A HREF="//evil.example/protocol-relative">p</A>',
    '<svg><use href="#local"/><linearGradient id="g"/><rect fill="url(#g)"/></svg>',
]


class _Collect(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls, self.tags = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        for k, v in attrs:
            if k in URL_ATTRS or k in ("srcset", "formaction", "ping", "srcdoc"):
                self.urls.append((tag, k, v or ""))

    handle_startendtag = handle_starttag


@pytest.mark.parametrize("payload", ATTACKS)
def test_no_raw_external_url_survives(payload):
    out = sanitize_html(f"<html><body>{payload}</body></html>", "https://site.example/p/", Rewriter("/T", "site.example"), "")
    c = _Collect()
    c.feed(out)
    for tag, k, v in c.urls:
        if k == "srcset":
            assert all(part.strip().startswith("/T/res?u=") for part in v.split(",") if part.strip()), (tag, k, v)
            continue
        assert v.startswith(("/T/view?u=", "/T/res?u=", "/T/form", "#", "data:image/")), (tag, k, v)
    # 프록시 경로 안의 URL과, /form 처리기가 믹스넷으로 보내는 폼 대상(__mosaic_u)을 빼면 외부 주소가 없어야 한다
    stripped = re.sub(r'(/T/(?:view|res)\?u=)[^"&]*', r"\1", out)
    stripped = re.sub(r'name="__mosaic_u" value="[^"]*"', "", stripped)
    assert "evil.example" not in stripped, out
    for bad in ("<script", "javascript:", "vbscript:", "<iframe", "<object", "<set", "<animate", "http-equiv",
                "formaction", "ping=", "srcdoc", "<base", 'target="'):
        assert bad not in out.lower(), (bad, out)
    for tag, attrs in c.tags:
        assert not any(k.startswith("on") for k in attrs)
    # 페이지가 위조한 mosaic-blocked meta는 없어지고, 정화기 자신의 것 하나만 남는다
    assert out.count('name="mosaic-blocked"') == 1


def test_blocked_counters():
    stats = {}
    sanitize_html('<script>a</script><script>b</script><img src=x onerror=y onload=z><iframe></iframe>'
                  '<svg><set attributeName=href to=x /></svg><a href="javascript:1">j</a>'
                  '<meta http-equiv=refresh content=0>', "https://s.example/", Rewriter("/T", "s"), "", stats)
    assert stats == {"scripts": 2, "handlers": 2, "frames": 1, "bad_urls": 1, "animations": 1, "refresh": 1}


def test_internal_svg_references_kept():
    out = sanitize_html('<svg><use href="#icon"/><rect fill="url(#g)"/></svg>', "https://s.example/", Rewriter("/T", "s"), "")
    assert 'href="#icon"' in out and "url(#g)" in out
