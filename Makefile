test:
	swift test

linuxtest:
	docker build -f Dockerfile -t linuxtest .
	docker run --rm -v .:/home/nonroot/src/app linuxtest

cleanlinuxtest:
	docker build -f Dockerfile -t linuxtest .
	docker run --rm linuxtest

# Print a Markdown changelog built from Conventional-Commit lines.
#
# Every Conventional-Commit line (subject *and* body lines like `feat:`, `fix:`,
# `!fix:`, `chore:` ...) in <FROM>..<TO> becomes one `- **type**: subject` row,
# verbatim — no rephrasing, nothing dropped, nothing invented. Rows are grouped
# by type in the order feat, fix, perf, refactor, tests, docs, build, ci, style,
# chore (any other type comes after, in first-seen order); within a group the
# original newest-first commit order is kept. `!`-breaking lines (e.g. `!fix:`)
# group with their base type but keep the `!` in the printed label.
# Notes go to stdout (redirect to a file as needed); status goes to stderr.
#
#   make changelog                       # range auto-detected: last tag..HEAD
#   make changelog FROM=1.3.0 TO=2.1.0   # explicit range (TO defaults to HEAD)
#   make changelog > CHANGELOG.md
changelog:
	@from="$(FROM)"; \
	if [ -z "$$from" ]; then \
		from=$$(git describe --tags --abbrev=0 2>/dev/null) || { echo "error: no tags found; pass FROM=<ref>" >&2; exit 1; }; \
	fi; \
	to="$(TO)"; [ -z "$$to" ] && to=HEAD; \
	echo "Building notes from $$from..$$to" >&2; \
	notes=$$(git log "$$from..$$to" --pretty=format:'%B' \
		| awk 'BEGIN { \
			np = split("feat fix perf refactor tests test docs build ci style chore", prio, " "); \
		} \
		/^[[:space:]]*!?[a-z]+:[[:space:]]/ { \
			sub(/^[[:space:]]+/, ""); \
			i = index($$0, ":"); \
			type = substr($$0, 1, i - 1); \
			rest = substr($$0, i + 1); \
			sub(/^[[:space:]]+/, "", rest); \
			base = type; sub(/^!/, "", base); \
			if (!(base in seen)) { seen[base] = 1; order[++oc] = base; } \
			bucket[base] = bucket[base] "- **" type "**: " rest "\n"; \
		} \
		END { \
			for (i = 1; i <= np; i++) { t = prio[i]; if (t in bucket) { printf "%s", bucket[t]; done[t] = 1; } } \
			for (j = 1; j <= oc; j++) { t = order[j]; if (!(t in done)) printf "%s", bucket[t]; } \
		}'); \
	if [ -z "$$notes" ]; then echo "error: no conventional-commit lines found in $$from..$$to" >&2; exit 1; fi; \
	printf '%s\n' "$$notes"

# Draft a GitHub release whose notes are `make changelog` output for the range.
#
#   make release VERSION=2.1.0          # range auto-detected: last tag..HEAD
#   make release VERSION=2.1.0 FROM=1.3.0
#   make release VERSION=2.1.0 DRY_RUN=1   # print notes, don't touch GitHub
release:
	@command -v gh >/dev/null || { echo "error: gh (GitHub CLI) is required"; exit 1; }
	@test -n "$(VERSION)" || { echo "error: VERSION is required, e.g. make release VERSION=2.1.0"; exit 1; }
	@notes=$$($(MAKE) -s changelog FROM="$(FROM)") || exit 1; \
	printf '%s\n' "$$notes"; \
	if [ -n "$(DRY_RUN)" ]; then echo "(dry run — GitHub not touched)"; exit 0; fi; \
	if gh release view "$(VERSION)" >/dev/null 2>&1; then \
		printf '%s\n' "$$notes" | gh release edit "$(VERSION)" --notes-file -; \
		echo "Updated draft $(VERSION)"; \
	else \
		printf '%s\n' "$$notes" | gh release create "$(VERSION)" --draft --title "JWSETKit $(VERSION)" --target "$$(git rev-parse --abbrev-ref HEAD)" --notes-file -; \
	fi

.PHONY: test linuxtest cleanlinuxtest changelog release