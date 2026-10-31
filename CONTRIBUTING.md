# Contributing to the Cybersecurity Analyst Portfolio

Thank you for helping improve this educational cybersecurity portfolio. Contributions should make the lab clearer, more reliable, or easier to reproduce without overstating what its evidence proves.

## Before contributing

- Read [README.md](README.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Use **synthetic data** and operate only on systems you own or are authorized to test.
- Never commit passwords, tokens, private investigation records, personal data, or active customer logs.
- Avoid converting simulated findings into claims about real incidents or production detection performance.

## Suggested contributions

- Correct documentation, command examples, or broken links.
- Add focused unit tests, negative cases, or clearly labeled synthetic fixtures.
- Improve evidence traceability, detection explanations, and documented limitations.
- Suggest safe automation or research improvements.

## Proposed workflow

1. Open an issue describing the problem or intended improvement, when appropriate.
2. Create a descriptive feature branch from the repository's default branch.
3. Make focused changes, keeping existing evidence and file paths intact where possible.
4. Run the reproducibility command from the repository root with Python 3.11+:

   ```bash
   python -m lab.reproduce
   ```

5. Document the actual test results, affected files, risk considerations, and any limitations.
6. Submit a pull request with a concise summary and reproduction steps.

The optional independent PCAP verification workflow is documented in [docs/LAB_GUIDE.md](docs/LAB_GUIDE.md). Do not report tests as passing unless they have actually been run.

## Responsible security reporting

Do not file public issues containing exploit details, credentials, or sensitive vulnerability information. Follow [SECURITY.md](SECURITY.md) for private reporting.
