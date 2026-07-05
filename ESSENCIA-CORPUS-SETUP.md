# Essencia-Corpus Setup

This guide configures a dedicated Corpus profile branded for Essencia.

## 1) Create the profile

```bash
hermes profile create corpus
```

## 2) Deploy the Corpus persona

```bash
cp assets/essencia-corpus-soul.md ~/.hermes/profiles/corpus/SOUL.md
```

## 3) Deploy the profile preset config

```bash
cp assets/essencia-corpus-config.yaml ~/.hermes/profiles/corpus/config.yaml
```

## 4) Activate Corpus

```bash
hermes -p corpus
```

## 5) Optional: make corpus your sticky default profile

```bash
hermes -p corpus profile use corpus
```

## 6) Set owner key

Add the owner variable in `~/.hermes/profiles/corpus/.env`:

```bash
CORPUS_OWNER_NAME=Gene
```

Replace `Gene` with your actual owner name if different.

Then set the owner placeholder in the deployed `SOUL.md`:

```bash
OWNER_NAME=Gene  # replace with your owner name
sed -i.bak 's/${CORPUS_OWNER_NAME}/'"${OWNER_NAME}"'/g' ~/.hermes/profiles/corpus/SOUL.md
```

If your environment already expands `${CORPUS_OWNER_NAME}` at runtime, prefer that and skip this manual replacement step.

## Security posture

- Keep this profile local-first and CLI/TUI-only.
- Do not enable messaging gateway platforms for the corpus profile.
- Maintain profile isolation so Corpus data stays scoped to `~/.hermes/profiles/corpus/`.

## Optional scheduled routines

To run self-study while idle, add a cron routine:

```bash
hermes -p corpus cron add "every 12h" "Run self-study review" --skills self-study
```
