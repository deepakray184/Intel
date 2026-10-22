# Signal Security Intelligence

A single-page security feed dashboard for news, vulnerabilities, and attacks or exploitation. It includes the Microsoft Learn Blog feed, lets visitors add RSS or Atom sources in their own browser, and stores saved items and added sources locally in that browser.

## Preview

Live feeds are fetched by GitHub Actions, not by each visitor's browser. Opening `index.html` directly with a `file://` URL skips the generated feed snapshot and depends on browser RSS proxies, which may be blocked. The scheduled snapshot is served by the published GitHub Pages site.

## Publish with GitHub Pages

1. Put `index.html`, `refresh_feeds.py`, `README.md`, and `.github/workflows/pages.yml` in a GitHub repository.
2. In repository **Settings → Pages**, choose **GitHub Actions** as the deployment source.
3. Push to `main`. The workflow downloads the configured RSS feeds, builds a same-site `feed-data.js` snapshot, and deploys it with the page. It also refreshes the site about every 30 minutes.
4. Open the Actions tab and confirm **Refresh feeds and publish GitHub Pages** completed successfully. GitHub Pages will publish the site at `https://OWNER.github.io/REPOSITORY/`.

Visitors can add their own sources, which remain private to that browser. Those custom feeds still require a browser-accessible RSS proxy; the scheduled shared feed list is maintained in `refresh_feeds.py`.
