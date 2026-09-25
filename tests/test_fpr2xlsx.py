import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile

from fpr2xlsx import FPR, ReportWriter


FVDL = """<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
  <CreatedTS date="2026-01-02" time="03:04:05"/>
  <WriteDate date="2026-01-02" time="03:05:00+00:00"/>
  <UUID>scan-123</UUID>
  <Build>
    <Label>Example</Label><BuildID>example-build</BuildID>
    <NumberFiles>1</NumberFiles><LOC type="Fortify">5</LOC>
    <LOC type="Line Count">5</LOC><ScanTime value="10"/>
    <SourceFiles><File encoding="utf-8"><Name>example.txt</Name></File></SourceFiles>
  </Build>
  <Vulnerabilities><Vulnerability>
    <ClassInfo><ClassID>rule-123</ClassID><Kingdom>Security</Kingdom>
      <Type>Example issue</Type></ClassInfo>
    <InstanceInfo><InstanceID>instance-123</InstanceID><Confidence>5</Confidence></InstanceInfo>
    <AnalysisInfo><Unified><Context/><Trace><Primary><Entry>
      <Node isDefault="true"><SourceLocation path="example.txt" line="3" snippet="snippet-123"/></Node>
    </Entry></Primary></Trace></Unified></AnalysisInfo>
  </Vulnerability></Vulnerabilities>
  <Description classID="rule-123">
    <Abstract>&lt;Content&gt;A test issue&lt;/Content&gt;</Abstract>
    <Explanation>&lt;Content&gt;=FORMULA(1)&lt;/Content&gt;</Explanation>
    <Recommendations>&lt;Content&gt;Fix the issue&lt;/Content&gt;</Recommendations>
  </Description>
  <Snippets><Snippet id="snippet-123"><File>example.txt</File>
    <StartLine>1</StartLine><EndLine>5</EndLine>
    <Text><![CDATA[first
second
=FORMULA(1)
fourth
fifth]]></Text>
  </Snippet></Snippets>
  <EngineData><EngineVersion>25.1</EngineVersion>
    <RulePacks><RulePack><Name>Core</Name><Version>25.1.0</Version></RulePack></RulePacks>
  </EngineData>
</FVDL>"""

NAMESPACE = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def worksheet_rows(archive, filename):
	strings_root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
	strings = ["".join(item.itertext()) for item in strings_root.findall("x:si", NAMESPACE)]
	root = ET.fromstring(archive.read(filename))
	rows = []
	for row in root.findall(".//x:row", NAMESPACE):
		values = {}
		for cell in row.findall("x:c", NAMESPACE):
			value = cell.findtext("x:v", default="", namespaces=NAMESPACE)
			if cell.get("t") == "s":
				value = strings[int(value)]
			values[cell.get("r").rstrip("0123456789")] = value
		rows.append(values)
	return rows


class ConverterTests(unittest.TestCase):
	def test_metadata_and_literal_finding_text(self):
		with tempfile.TemporaryDirectory() as directory:
			fpr_path = Path(directory) / "example.fpr"
			xlsx_path = Path(directory) / "example.xlsx"
			with ZipFile(fpr_path, "w") as archive:
				archive.writestr("audit.fvdl", FVDL)

			report = FPR(str(fpr_path))
			findings = report.process()
			self.assertEqual(len(findings), 1)
			self.assertEqual(report.metadata["Scan UUID"], "scan-123")
			self.assertEqual(report.metadata["Engine version"], "25.1")
			self.assertEqual(report.rule_packs, [("Core", "25.1.0")])
			self.assertEqual(findings[0].instance_id, "instance-123")
			self.assertEqual(findings[0].code_snippet.splitlines()[2], "3: =FORMULA(1)")
			ReportWriter().write_to_excel(findings, str(xlsx_path), report.metadata, report.rule_packs)

			with ZipFile(xlsx_path) as workbook:
				self.assertIsNone(workbook.testzip())
				metadata_rows = worksheet_rows(workbook, "xl/worksheets/sheet1.xml")
				pairs = {row["A"]: row["B"] for row in metadata_rows if "A" in row and "B" in row}
				self.assertEqual(pairs["Total findings"], "1")
				self.assertEqual(pairs["Critical"], "0")
				self.assertEqual(pairs["Engine version"], "25.1")
				self.assertEqual(pairs["Core"], "25.1.0")
				self.assertEqual(pairs["Report written"], "2026-01-02 03:05:00+00:00")
				finding_rows = worksheet_rows(workbook, "xl/worksheets/sheet2.xml")
				self.assertIn("3: =FORMULA(1)", finding_rows[1]["G"])
				self.assertEqual(finding_rows[1]["H"], "=FORMULA(1)")
				self.assertEqual(finding_rows[1]["L"], "instance-123")
				self.assertEqual(finding_rows[1]["M"], "rule-123")
				self.assertNotIn(b"<f>", workbook.read("xl/worksheets/sheet2.xml"))

	def test_source_archive_snippet_and_cache(self):
		with tempfile.TemporaryDirectory() as directory:
			fpr_path = Path(directory) / "archive.fpr"
			index = (
				'<properties><entry key="example.txt">src-archive/0</entry></properties>'
			)
			with ZipFile(fpr_path, "w") as archive:
				archive.writestr("audit.fvdl", FVDL)
				archive.writestr("src-archive/index.xml", index)
				archive.writestr("src-archive/0", "first\nsecond\narchive line\nfourth\nfifth\n")

			report = FPR(str(fpr_path))
			findings = report.process()
			self.assertEqual(findings[0].code_snippet.splitlines()[2], "3: archive line")
			self.assertEqual(report.source_lines["example.txt"][2], "archive line")


if __name__ == "__main__":
	unittest.main()
