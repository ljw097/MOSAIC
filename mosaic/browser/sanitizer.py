"""HTML/CSS 정화기와 URL 재작성기.

목표: 렌더링하는 브라우저가 MOSAIC을 거치지 않고는 단 한 바이트도 외부로 보내지 못하게
하고, 지문채취(fingerprinting) 수단인 스크립트를 실행하지 못하게 하는 것.
- <script>, 이벤트 핸들러(on*), iframe/object/embed, <base>, meta refresh를 없앤다.
- javascript:/vbscript: URL을 없앤다. data: URL은 이미지에만 허용한다.
- 모든 링크와 리소스 URL을 로컬 프록시 경로로 재작성한다.
- 추가 방어선으로 서버가 CSP `default-src 'self'; script-src 'none'`을 붙인다.
  정화기를 빠져나간 것이 있더라도 실행되거나 밖으로 나가지 못한다.
"""
from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlsplit

DROP_WITH_CONTENT = {"script", "iframe", "frame", "frameset", "object", "applet", "noembed", "template",
                     "portal", "fencedframe"}
DROP_TAG = {"embed", "base", "param"}
UNWRAP = {"noscript"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
        "track", "wbr"}
URL_ATTRS_NAV = {("a", "href"), ("area", "href")}
URL_ATTRS_RES = {("img", "src"), ("source", "src"), ("video", "src"), ("video", "poster"), ("audio", "src"),
                 ("track", "src"), ("input", "src"), ("link", "href"), ("image", "href"), ("use", "href"),
                 ("body", "background"), ("table", "background"), ("td", "background")}
DROP_ATTRS = {"srcdoc", "formaction", "ping", "integrity", "nonce", "xmlns:xlink", "download", "manifest",
              "http-equiv", "dynsrc", "lowsrc"}
BAD_SCHEMES = ("javascript:", "vbscript:", "livescript:", "file:", "blob:", "filesystem:")

_css_url = re.compile(r"""url\(\s*(['"]?)(.*?)\1\s*\)""", re.I | re.S)
_css_import = re.compile(r"""@import\s+(['"])(.*?)\1""", re.I)
_css_bad = re.compile(r"expression\s*\(|behavior\s*:|-moz-binding", re.I)


class Rewriter:
    def __init__(self, prefix: str, top: str):
        self.prefix, self.top = prefix, top

    def nav(self, url: str) -> str:
        return f"{self.prefix}/view?u={quote(url, safe='')}"

    def res(self, url: str) -> str:
        return f"{self.prefix}/res?u={quote(url, safe='')}&top={quote(self.top, safe='')}"


def _clean_url(raw: str, base: str) -> str | None:
    u = "".join(ch for ch in html.unescape(raw).strip() if ch >= " ")
    low = u.lower().replace(" ", "")
    if not u or low.startswith(BAD_SCHEMES):
        return None
    if low.startswith("#"):
        return u
    absu = urljoin(base, u)
    if urlsplit(absu).scheme not in ("http", "https", "data"):
        return None
    return absu


def rewrite_css(css: str, base: str, rw: Rewriter) -> str:
    css = _css_bad.sub("/*blocked*/", css)

    def sub(m):
        u = _clean_url(m.group(2), base)
        if u is None or u.startswith("data:") and not u.startswith("data:image/"):
            return "url()"
        if u.startswith("data:"):
            return m.group(0)
        return f'url("{rw.res(u)}")'

    css = _css_url.sub(sub, css)
    css = _css_import.sub(lambda m: f'@import "{rw.res(u)}"' if (u := _clean_url(m.group(2), base)) else "", css)
    return css


class _Sanitizer(HTMLParser):
    def __init__(self, base: str, rw: Rewriter, toolbar: str):
        super().__init__(convert_charrefs=True)
        self.base, self.rw, self.toolbar = base, rw, toolbar
        self.out: list[str] = []
        self.skip = 0
        self.in_style = False
        self.injected = False

    def _inject(self):
        if not self.injected:
            self.out.append(self.toolbar)
            self.injected = True

    def handle_decl(self, decl):
        if not self.out:
            self.out.append(f"<!{html.escape(decl)}>")

    def handle_starttag(self, tag, attrs):
        self._start(tag, attrs, False)

    def handle_startendtag(self, tag, attrs):
        self._start(tag, attrs, True)

    def _start(self, tag, attrs, selfclose):
        if self.skip:
            if tag in DROP_WITH_CONTENT and not selfclose:
                self.skip += 1
            return
        if tag in DROP_WITH_CONTENT:
            if not selfclose:
                self.skip = 1
            return
        if tag in DROP_TAG or tag in UNWRAP:
            if tag == "base":
                for k, v in attrs:
                    if k == "href" and v and (u := _clean_url(v, self.base)) and not u.startswith("data:"):
                        self.base = u
            return
        if tag == "meta":
            d = {k: (v or "") for k, v in attrs}
            if "http-equiv" in d or "charset" in d:
                return
        if tag == "link":
            rel = (dict(attrs).get("rel") or "").lower()
            if not any(r in rel for r in ("stylesheet", "icon")):
                return
        out_attrs = []
        for k, v in attrs:
            k = k.lower()
            v = v or ""
            if k.startswith("on") or k in DROP_ATTRS:
                continue
            if k == "target":
                continue
            if (tag, k) in URL_ATTRS_NAV:
                u = _clean_url(v, self.base)
                if u is None:
                    continue
                v = u if u.startswith("#") else self.rw.nav(u)
            elif (tag, k) in URL_ATTRS_RES or (k in ("href", "xlink:href") and tag in ("image", "use")):
                u = _clean_url(v, self.base)
                if u is None or u.startswith("#"):
                    continue
                if u.startswith("data:"):
                    if tag != "img" or not u.startswith("data:image/"):
                        continue
                else:
                    u = self.rw.res(u)
                v = u
            elif k in ("srcset", "imagesrcset"):
                parts = []
                for item in v.split(","):
                    bits = item.strip().split()
                    if not bits:
                        continue
                    u = _clean_url(bits[0], self.base)
                    if u and not u.startswith("data:"):
                        parts.append(" ".join([self.rw.res(u)] + bits[1:]))
                v = ", ".join(parts)
            elif k == "style":
                v = rewrite_css(v, self.base, self.rw)
            elif k == "action" and tag == "form":
                continue
            elif k in ("href", "src", "data", "codebase", "cite", "background", "poster", "action"):
                u = _clean_url(v, self.base)
                if u is None:
                    continue
                v = self.rw.nav(u) if not u.startswith("#") else u
            out_attrs.append((k, v))
        if tag == "form":
            action = _clean_url(dict(attrs).get("action") or self.base, self.base) or self.base
            method = (dict(attrs).get("method") or "get").lower()
            out_attrs = [(k, v) for k, v in out_attrs if k != "method"]
            out_attrs += [("action", f"{self.rw.prefix}/form"), ("method", "post" if method == "post" else "get")]
        a = "".join(f' {k}="{html.escape(v, quote=True)}"' for k, v in out_attrs)
        self.out.append(f"<{tag}{a}{' /' if selfclose and tag in VOID else ''}>")
        if tag == "form":
            action = _clean_url(dict(attrs).get("action") or self.base, self.base) or self.base
            self.out.append(f'<input type="hidden" name="__mosaic_u" value="{html.escape(action, quote=True)}">')
        if tag == "style" and not selfclose:
            self.in_style = True
        if tag == "body":
            self._inject()

    def handle_endtag(self, tag):
        if self.skip:
            if tag in DROP_WITH_CONTENT:
                self.skip -= 1
            return
        if tag in DROP_TAG or tag in UNWRAP or tag in VOID:
            return
        if tag == "style":
            self.in_style = False
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if self.skip:
            return
        if self.in_style:
            self.out.append(rewrite_css(data, self.base, self.rw).replace("</", "<\\/"))
        else:
            self.out.append(html.escape(data, quote=False))

    def handle_comment(self, data):
        pass

    def handle_pi(self, data):
        pass


def sanitize_html(doc: str, base: str, rw: Rewriter, toolbar: str) -> str:
    p = _Sanitizer(base, rw, toolbar)
    p.feed(doc)
    p.close()
    if not p.injected:
        p.out.insert(1 if p.out and p.out[0].startswith("<!") else 0, toolbar)
    return "".join(p.out)
