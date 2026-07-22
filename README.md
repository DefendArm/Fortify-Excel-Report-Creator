# Fortify

`fpr2xlsx.py` converts a Fortify Project Results (`.fpr`) file into a customer-friendly Excel workbook. It provides a simpler way to review findings than a large exported PDF or the Fortify desktop tools.

## Requirements

- Python 3
- [XlsxWriter](https://xlsxwriter.readthedocs.io/)

Install the dependency:

```sh
python3 -m pip install xlsxwriter
```

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
- Vulnerable code snippet from the source archive or FVDL snippet data embedded in the FPR
- Description
- Remediation guidance
- Abstract
- References

The workbook contains an `all` worksheet and separate worksheets for each severity represented in the report. Columns support filtering, long text is wrapped, and the header remains visible while scrolling.

## License

This project is licensed under the [GNU Affero General Public License version 3](LICENSE).
