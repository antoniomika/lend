# Lend docs

The docs use [pdocs](https://github.com/picosh/pdocs), the same static-site generator as sish. The layout follows sish's documentation, with a home page, a sitemap column beside each guide, syntax highlighting, and light and dark themes. All CSS and icons are served locally. The site needs no JavaScript or frontend package manager.

## Build and preview

From the repository root, with Go 1.24 or later:

```sh
make ssg
make docs-serve
```

Open `http://127.0.0.1:3000`. Restart the preview after changing a source file. `make docs` also builds without serving. The generated files live in `docs/public` and are ignored by Git. Each successful build replaces that directory.

Validate the site with Go and Python 3:

```sh
make docs-check
```

The checker verifies local links, heading fragments, assets, page metadata, and example JSON without making network requests. Documentation dependencies live in `docs/go.mod` and `docs/go.sum`. They do not affect the CLI module or binary.

## Edit content

- `posts/*.md` contains the guides, with YAML frontmatter for the title and description.
- `protocol.md` and `releasing.md` remain the sources for those reference pages. The generator adds site metadata during the build.
- `cmd/main.go` defines navigation order and groups. Add each new page to this list.
- `tmpl/*.tmpl` defines Go HTML templates.
- `static/` contains styles and the favicon. The smol, theme, and syntax styles follow the copies in sish.
- `../examples/*.json` is copied into the output for downloadable policy examples.

Use root-relative links such as `/ssh-keys.html` and `/examples/policy.json`. Explicit `.html` URLs work on a plain static server without rewrite rules. The site expects to be served at the root of a hostname.

## CI and publishing

`.github/workflows/docs.yml` builds and checks the site for relevant pull requests and pushes to `main`. It uploads `docs/public` as the `lend-docs` artifact. These runs do not publish the site.

For pgs.sh, configure the same Actions secrets used by sish:

- `PRIVATE_KEY`: deployment SSH private key.
- `CERT_PUBKEY`: its SSH certificate, if used by the account.

Each stable release publishes the docs from its tag after the release assets are uploaded. To publish between releases, manually run the Docs workflow from `main` with `publish` enabled. It uploads a versioned `lend-COMMIT` project and promotes it to `lend-prod`. The action retains Lend projects by the `lend-` prefix. The hosting account and its DNS configuration determine the public URL.

Building the documentation does not publish it. To use a different static host, upload the contents of `docs/public` to that host's document root.
