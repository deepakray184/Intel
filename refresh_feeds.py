#!/usr/bin/env python3
"""Build a browser-ready snapshot of the configured public RSS feeds."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET


FEEDS = [
    ("CISA Alerts", "https://www.cisa.gov/uscert/ncas/alerts.xml", "attacks"),
    ("CISA Advisories", "https://www.cisa.gov/uscert/ncas/current-activity.xml", "attacks"),
    ("MS-ISAC Advisories", "https://www.cisecurity.org/feed/advisories", "vulnerabilities"),
    ("CIS Security Blog", "https://www.cisecurity.org/feed/blog", "news"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "attacks"),
    ("BleepingComputer Security", "https://www.bleepingcomputer.com/feed/", "news"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news"),
    ("Cisco Talos Intelligence", "https://blog.talosintelligence.com/rss/", "attacks"),
    ("Google Online Security Blog", "https://security.googleblog.com/feeds/posts/default", "vulnerabilities"),
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/", "news"),
    ("Microsoft Learn Blog", "https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftLearnBlog", "news"),
    ("NVD CVE feed", "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "vulnerabilities"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", "news"),
    ("Schneier on Security", "https://www.schneier.com/feed/atom/", "news"),
]


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def local_name(tag):
    return tag.rsplit("}", 1)[-1].lower()


def child_text(element, *names):
    for child in element.iter():
        if child is element or local_name(child.tag) not in names:
            continue
        text = " ".join(t.strip() for t in child.itertext() if t.strip())
        if text:
            return text
    return ""


def clean_html(value):
    parser = TextOnly()
    try:
        parser.feed(unescape(value))
        value = " ".join(parser.parts)
    except Exception:
        pass
    return re.sub(r"\s+", " ", value).strip()


def article_link(entry, feed_url):
    for child in entry.iter():
        if local_name(child.tag) == "link":
            href = child.attrib.get("href")
            if href and child.attrib.get("rel", "alternate") == "alternate":
                return href
            if child.text and child.text.strip():
                return child.text.strip()
    return feed_url


def parse_date(value):
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def fetch_feed(name, url, category):
    request = urllib.request.Request(url, headers={"User-Agent": "SignalSecurityFeed/1.0 (+GitHub Actions RSS reader)", "Accept": "application/atom+xml, application/rss+xml, application/xml, text/xml, */*"})
    with urllib.request.urlopen(request, timeout=20) as response:
        root = ET.fromstring(response.read())

    rows = []
    for entry in (node for node in root.iter() if local_name(node.tag) in ("item", "entry")):
        title = child_text(entry, "title")
        if not title:
            continue
        raw_date = child_text(entry, "pubdate", "published", "updated", "date")
        published = parse_date(raw_date)
        age = max(0, (datetime.now(timezone.utc) - published).days) if published else 0
        content = child_text(entry, "description", "summary", "encoded", "content")
        text = clean_html(content)
        description = text[:230] or "Open the source article for details."
        searchable = f"{title} {text}"
        severity = "critical" if re.search(r"critical|actively exploited|zero.day", searchable, re.I) else "high" if re.search(r"exploit|ransomware|breach|attack|phishing", searchable, re.I) else "medium"
        rows.append({
            "id": f"{url}|{article_link(entry, url)}",
            "source": name,
            "category": category,
            "severity": severity,
            "time": published.strftime("%b %d, %Y") if published else "Recent",
            "title": clean_html(title),
            "desc": description,
            "tags": [{"news": "News", "vulnerabilities": "Vulnerabilities", "attacks": "Attacks & exploitation"}[category]],
            "age": age,
            "publishedAt": published.isoformat() if published else None,
            "url": article_link(entry, url),
        })
        if len(rows) >= 12:
            break
    return rows


def main():
    articles = []
    successful = []
    for name, url, category in FEEDS:
        try:
            items = fetch_feed(name, url, category)
            articles.extend(items)
            successful.append({"name": name, "url": url, "category": category})
            print(f"Loaded {len(items)} items from {name}")
        except (urllib.error.URLError, TimeoutError, ET.ParseError, OSError, ValueError) as error:
            print(f"Skipped {name}: {error}")

    deduped = {}
    for article in articles:
        deduped.setdefault(article["url"] or article["id"], article)
    snapshot = {
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "sources": successful,
        "advisories": list(deduped.values())[:150],
    }
    output = "window.FEED_DATA = " + json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) + ";\n"
    Path("feed-data.js").write_text(output, encoding="utf-8")
    print(f"Wrote {len(snapshot['advisories'])} advisories from {len(successful)} feeds")


if __name__ == "__main__":
    main()
