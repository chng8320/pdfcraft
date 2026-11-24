# This fork: PdfCraft for the Dataverse

This is the Dataverse's fork of [PdfCraft](https://github.com/storytold/pdfcraft) by the ArtCraft team
(MIT OR Apache-2.0). The Dataverse runs its command line on the main server, headless, as the `pdfcraft`
package.

## Branches

| Branch | What it is |
|---|---|
| `main` | Exactly ArtCraft's `main`. Never commit here; it is only updated from them. |
| `dataverse` | `main` plus our own commits on top. This is what the Dataverse builds. |

Each of our changes is one commit on `dataverse`, following `crates/automation/README.md` ("Adding a tool"),
so it replays cleanly on every new PdfCraft and can be offered back as a pull request. PdfCraft's rules for
contributors (`AGENTS.md`) apply to our commits too: in particular, no code read from GPL, LGPL or AGPL
programs.

## Keeping up with PdfCraft

`.github/workflows/dataverse.yml` runs every Monday (and on demand from the Actions tab): it updates `main`
from ArtCraft, replays our commits on `dataverse` (opening an issue when one no longer applies), builds the
command line, runs the automation tests and attaches the program as `dataverse-pdf-cli` (Linux x86-64).

## Our changes

| Commit | What | Offered upstream? |
|---|---|---|
| Add doc_facts | A small read-only summary of a PDF for servers and flows | Not yet |

## Name

The ArtCraft name and logos are trademarks, not covered by the code licence; modified versions must not use
them. Our build is called `dataverse-pdf-cli` and is described as "based on PdfCraft by the ArtCraft team".
