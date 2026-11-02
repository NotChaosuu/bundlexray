# Changelog

## 1.0.0 (2026-11-02)

First public release.

- Scans a site's JavaScript for leaked secrets, the endpoints it calls and exposed source maps, and rebuilds the original source from those maps with `--dump`.
- Follows what a page loads: imports and import maps, workers, Vite, Next.js, React Router and Remix, VitePress, Astro, Qwik, Parcel, SystemJS, module federation and webpack-style chunk loaders.
- Never reports a clean result for a scan that could not read everything: unread scripts, unreadable loaders, bot challenges, limits and refused maps make the scan incomplete, with the reason, and `--exit-code` exits 3.
- Groups endpoints by what the code does with them: router paths and links are listed as app routes, apart from the requests the app makes.
- Retries a page, script or map refused to the default user agent once as a browser; `--user-agent` turns this off.
- Decodes gzip and deflate bodies the server sends unasked.
- Prints paths with forward slashes on every OS, in text and JSON output.
- CI gate (`--exit-code`), JSON output, `--same-site` scope and a private-address guard.
