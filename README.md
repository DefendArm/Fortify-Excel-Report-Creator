# Fortify

`fpr2xlsx.py` converts a Fortify Project Results (`.fpr`) file into a customer-friendly Excel workbook. It provides a simpler way to review findings than a large exported PDF or the Fortify desktop tools.

## Requirements

- Python 3
- [XlsxWriter](https://xlsxwriter.readthedocs.io/)

Install the dependency:

```sh
python3 -m pip install xlsxwriter
```

Run the tests with `python3 -m unittest discover -s tests`.

## Usage

```sh
python3 fpr2xlsx.py --input report.fpr
```

The resulting `.xlsx` file is created next to the input file with the same base name. For example, `report.fpr` produces `report.xlsx`.

## Workbook contents

Each finding includes:

- Risk level
- Kingdom and category
- File path, function, and vulnerable line number
- Five-line vulnerable code snippet (target line with two lines before and after) from the source archive or FVDL snippet data embedded in the FPR
- Description
- Remediation guidance
- Abstract
- References
- Fortify instance ID and rule class ID for tracing a finding back to the FPR

The workbook begins with a `metadata` worksheet containing the project and build IDs, scan UUID and dates, engine version, scan duration, source file and line counts, finding counts by severity, and rule pack versions. Fields absent from an FPR are shown as `Not available`. Scan host, user, command-line arguments, and license details are intentionally omitted.

The other worksheets contain `all` findings and separate sheets for each severity represented in the report. Columns support filtering, long text is wrapped, and the header remains visible while scrolling.

## Contributing

Issues and pull requests are welcome. If you find a bug, have an improvement in mind, or want to add support for another Fortify FPR format, please open an issue or submit a pull request.

## License

This project is licensed under the [GNU Affero General Public License version 3](LICENSE).
