# Signal Security Intelligence

Signal is a static, single-page cybersecurity intelligence dashboard. It brings together public RSS/Atom updates and recent CVEs, then presents them in one searchable interface.

**Live site:** [https://deepakray184.github.io/Intel/](https://deepakray184.github.io/Intel/)

## Features

- **Security feed:** Browse news, vulnerabilities, and attacks or exploitation reports. Advisories are sorted newest first, with source, date, category, severity, and a link to the original article.
- **Filters and trend:** Search advisories, filter by source and time range, select a category or critical/high severity, and view the daily advisory trend for the selected time window.
- **Saved advisories:** Save items in the current browser. Saved items are stored in that browser's local storage.
- **Personal RSS sources:** Visitors can add an RSS/Atom source for their own browser. These additions are not shared with other visitors and are stored locally in that browser.
- **IOC reputation lookup:** Submit an IP address, domain, URL, or 32/40/64-character hexadecimal file hash to open relevant public searches. The lookup links to VirusTotal, AlienVault OTX, and URLhaus; IPs also get AbuseIPDB and GreyNoise, and hashes also get MalwareBazaar. If the browser blocks multiple pop-up tabs, use the provider links shown below the form.

The IOC tool opens public provider search pages; it does not call their APIs or show an aggregate verdict inside Signal. Submitting an IOC sends it to those providers. Only search indicators you are permitted to share, and follow each provider's own terms and rate limits.

## How feeds work

The site uses two paths to load advisories:

1. [`refresh_feeds.py`](refresh_feeds.py) fetches the configured public feeds and writes a generated `feed-data.js` snapshot.
2. The [GitHub Actions workflow](.github/workflows/pages.yml) runs on pushes to `main`, can be started manually, and is scheduled at minute 17 and 47 of each hour. It generates the snapshot and deploys `index.html` plus `feed-data.js` to GitHub Pages.

The snapshot currently keeps up to 12 recent items per feed before deduplication and caps the published set at 150 advisories. NVD is queried for CVEs modified during the previous seven days. A source that errors or times out is skipped for that run; the workflow can still publish the feeds that succeeded. The page refreshes the snapshot in the browser periodically while open.

Feed names, URLs, and default categories are maintained in the `FEEDS` list in [`refresh_feeds.py`](refresh_feeds.py). Use `news`, `vulnerabilities`, or `attacks` as the category values.

## Run locally

Requirements: Python 3 and a network connection for fetching feeds. The feed collector uses only Python's standard library.

```sh
python3 refresh_feeds.py
python3 -m http.server 8000
```

Then open [http://localhost:8000/](http://localhost:8000/). Run the first command from the project directory so it creates `feed-data.js` there. A local `file://` URL does not provide the generated shared snapshot and may not be able to load remote feeds.

## Publish or update GitHub Pages

The repository is configured to deploy through GitHub Actions. Commit and push changes to `main`, or start **Refresh feeds and publish GitHub Pages** from the repository's **Actions** tab. Confirm that the run completed successfully, then visit the Pages site. Scheduled updates run about every 30 minutes; a push or a manual workflow run publishes code changes sooner.

For a browser-only update, open the file in the repository, click **Edit** (pencil), make the change, and commit it. For a complete local replacement, copy the updated local file contents into GitHub's editor before committing. Avoid replacing or deleting the workflow or feed collector unless you intend to change how publishing and feed refresh work.

## Repository files

| File | Purpose |
| --- | --- |
| `index.html` | Dashboard UI, filters, chart, personal source management, and IOC lookup. |
| `refresh_feeds.py` | Downloads, parses, categorizes, and deduplicates feed items; creates `feed-data.js`. |
| `.github/workflows/pages.yml` | Scheduled and push-triggered feed refresh and GitHub Pages deployment. |
| `feed-data.js` | Generated snapshot. Created by the workflow or by running the collector locally; not a source/configuration file. |

## Troubleshooting

- **No advisories on the hosted site:** Check the latest workflow run in **Actions**. A failed feed is skipped and may show no recent items; a failed workflow prevents the latest deployment.
- **A code change is not visible:** Confirm the Pages deployment succeeded, wait a few minutes, and reload the site without a cached copy.
- **No feeds in a local preview:** Run `python3 refresh_feeds.py` from the project directory, then serve the directory over HTTP as above. Opening the HTML directly with `file://` is not a reliable feed test.
- **A custom visitor feed does not load:** The browser needs to access that feed through a compatible public RSS proxy. Some publishers block proxy access or browser cross-origin requests; those feeds may not load.
- **IOC searches do not open:** Allow pop-ups for the site or click the provider links displayed under the lookup box.

## Notes

This dashboard is an aggregation and navigation aid, not a substitute for validating advisories with the original publisher. Severity and categories are assigned from the source feed or basic text matching; verify details at the source before acting.
