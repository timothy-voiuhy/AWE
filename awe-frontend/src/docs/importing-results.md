---
title: Importing Results
summary: How to bring external subdomain lists into AWE Results and Network Graph.
order: 30
---

# Importing Results

AWE can import external subdomain lists when you already have inventory from another source.

Supported files:

- `.txt` or `.list`: one or more hosts per line.
- `.csv`: a column named `subdomain`, `domain`, `host`, `hostname`, `url`, or `fqdn`, or any cell containing a valid hostname.
- `.xlsx`: the first worksheet, using the same column detection as CSV.

Older binary `.xls` workbooks are not parsed as spreadsheets. Export them as `.xlsx` or `.csv` first.

## Where To Import

Use either:

- **Overview > Import Subdomains**
- **Results > Import Subdomains**

Both places write to the same project results store.

## What AWE Creates

An import creates:

- a completed `Imported Subdomains` session,
- `subdomain` Results records with source `manual_import`,
- an evidence record describing the imported file,
- optional imported Network Graph entities linked to the target.

When **Attach to graph** is enabled, imported hosts can immediately be selected in Network Graph and used as transform input.
