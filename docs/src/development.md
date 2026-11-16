# Development and documentation

## Contributing

Read [CONTRIBUTING.md](https://github.com/Busnes-app/KyIdentity-server/blob/master/CONTRIBUTING.md) before changing the product.
It owns the contribution process, build prerequisites and required product checks.
Read the repository's AGENTS.md chain when working with an agent. Native builds and tests
require their documented operating systems, SDKs and devices.

## Build this manual

Install mdBook 0.5.4 and Python 3. From the repository root:

```sh
mdbook build docs
python3 docs/check-links.py
```

Open `docs/book/index.html` to read the generated manual. Search and the printable
whole-book view are built in. Run the same two commands after editing chapters or links.
The generated `docs/book/` directory is ignored; commit the Markdown sources and configuration.

## Documentation checks

The documentation workflow builds the book, checks generated local links and anchors,
then uploads the complete book as a `documentation-book` artifact. It does not publish
a public website. After extracting the artifact, open `index.html`.

Add chapters to `docs/src/SUMMARY.md`. Keep user instructions consistent with current
behavior and update the related reference guides when a workflow changes. External
reference URLs are not fetched by the local-link check.
