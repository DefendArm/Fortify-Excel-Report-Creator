#!/usr/bin/env python3
import argparse
import html
import re
import xml.etree.ElementTree as ET
from enum import Enum
from os import path
from zipfile import BadZipFile, ZipFile

try:
	from xlsxwriter.workbook import Workbook
except ImportError as exc:
	raise SystemExit(
		"You should install the xlsxwriter library before using this script."
	) from exc


EXCEL_CELL_LIMIT = 32767
SNIPPET_CONTEXT_LINES = 2


class Severity(Enum):
	LOW = 1
	MEDIUM = 2
	HIGH = 3
	CRITICAL = 4


class Rule:
	def __init__(self, rule_id, probability, accuracy, impact):
		self.probability = float(probability)
		self.rule_id = rule_id
		self.accuracy = float(accuracy)
		self.impact = float(impact)

	def calculate_severity(self, confidence, probability):
		effective_probability = self.probability if probability == -1 else probability
		likelihood = (self.accuracy * effective_probability * confidence) / 25
		if self.impact >= 2.5:
			return Severity.CRITICAL if likelihood >= 2.5 else Severity.HIGH
		return Severity.MEDIUM if likelihood >= 2.5 else Severity.LOW


class Finding:
	def __init__(
		self,
		kingdom,
		category,
		filename,
		severity,
		function="",
		line=1,
		code_snippet="",
		description="",
		remediation="",
		abstract="",
		references="",
	):
		self.kingdom = kingdom
		self.category = category
		self.filename = filename
		self.severity = severity
		self.function = function
		self.line = line
		self.code_snippet = code_snippet
		self.description = description
		self.remediation = remediation
		self.abstract = abstract
		self.references = references


def _float_text(element, default=0.0):
	return float(element.text) if element is not None and element.text else default


def _clean_text(value):
	"""Make Fortify's HTML-like description content readable in a cell."""
	value = html.unescape(value or "")
	value = value.replace("\r\n", "\n").replace("\r", "\n")
	value = re.sub(r"[ \t]+", " ", value)
	value = re.sub(r" *\n *", "\n", value)
	value = re.sub(r"\n{3,}", "\n\n", value)
	return value.strip()


def render_description(value, replacements):
	"""Render escaped Fortify Content XML, including finding placeholders."""
	if not value:
		return ""

	try:
		content = ET.fromstring(value)
	except ET.ParseError:
		# Some rule packs contain imperfect markup. Preserve their useful text.
		fallback = re.sub(
			r'<Replace\s+key=["\']([^"\']+)["\']\s*/>',
			lambda match: replacements.get(match.group(1), ""),
			value,
			flags=re.IGNORECASE,
		)
		fallback = re.sub(
			r"<AltParagraph\b[^>]*>.*?</AltParagraph>",
			"",
			fallback,
			flags=re.IGNORECASE | re.DOTALL,
		)
		return _clean_text(re.sub(r"<[^>]+>", "", fallback))

	block_tags = {"Content", "Paragraph", "AltParagraph", "pre", "p", "br", "li"}

	def walk(element):
		tag = element.tag.rsplit("}", 1)[-1]
		if tag == "Replace":
			return replacements.get(element.attrib.get("key", ""), "")
		if tag == "AltParagraph":
			return ""

		parts = [element.text or ""]
		for child in element:
			child_tag = child.tag.rsplit("}", 1)[-1]
			if child_tag in block_tags and parts and not parts[-1].endswith("\n"):
				parts.append("\n")
			parts.append(walk(child))
			parts.append(child.tail or "")
			if child_tag in block_tags:
				parts.append("\n")
		return "".join(parts)

	return _clean_text(walk(content))


class FPR:
	def __init__(self, fpr_file):
		self.fpr_file = fpr_file
		self.rules = {}
		self.descriptions = {}
		self.snippets = {}
		self.snippets_by_file = {}
		self.source_entries = {}
		self.source_encodings = {}
		self.findings = []
		self.archive = None
		self.root = None

	def process(self):
		try:
			self.archive = ZipFile(self.fpr_file, "r")
			xml_bytes = self.archive.read("audit.fvdl")
		except (BadZipFile, KeyError) as exc:
			if self.archive:
				self.archive.close()
			raise ValueError("Malformed FPR file: audit.fvdl was not found") from exc

		# Removing only the default namespace keeps the XPath expressions readable.
		xml_bytes = re.sub(br'\sxmlns="[^"]+"', b"", xml_bytes, count=1)
		self.root = ET.fromstring(xml_bytes)
		self._extract_source_index()
		self._extract_rules()
		self._extract_descriptions()
		self._extract_snippets()
		self._extract_findings()
		self.archive.close()
		return self.findings

	def _extract_source_index(self):
		for source_file in self.root.findall("Build/SourceFiles/File"):
			name = source_file.findtext("Name")
			if name:
				self.source_encodings[name] = source_file.attrib.get("encoding", "utf-8")

		try:
			index = ET.fromstring(self.archive.read("src-archive/index.xml"))
		except (KeyError, ET.ParseError):
			return
		for entry in index.findall("entry"):
			if entry.text:
				self.source_entries[entry.attrib.get("key", "")] = entry.text

	def _extract_rules(self):
		for rule_element in self.root.findall("EngineData/RuleInfo/Rule"):
			values = {"Accuracy": 0.0, "Impact": 0.0, "Probability": 0.0}
			for group in rule_element.findall("MetaInfo/Group"):
				name = group.attrib.get("name")
				if name in values and group.text:
					values[name] = float(group.text)
			rule_id = rule_element.attrib.get("id")
			if rule_id:
				self.rules[rule_id] = Rule(
					rule_id,
					values["Probability"],
					values["Accuracy"],
					values["Impact"],
				)

	def _extract_descriptions(self):
		for description in self.root.findall("Description"):
			class_id = description.attrib.get("classID")
			if class_id:
				self.descriptions[class_id] = description

	def _extract_snippets(self):
		for snippet in self.root.findall("Snippets/Snippet"):
			filename = snippet.findtext("File", "")
			text = snippet.findtext("Text", "")
			try:
				start_line = int(snippet.findtext("StartLine", "1"))
			except ValueError:
				start_line = 1
			try:
				end_line = int(snippet.findtext("EndLine", str(start_line)))
			except ValueError:
				end_line = start_line

			entry = {
				"file": filename,
				"start": start_line,
				"end": end_line,
				"text": text,
			}
			snippet_id = snippet.attrib.get("id")
			if snippet_id:
				self.snippets[snippet_id] = entry
			if filename:
				self.snippets_by_file.setdefault(filename, []).append(entry)

	def _primary_location(self, vulnerability):
		primary = vulnerability.find("AnalysisInfo/Unified/Trace/Primary")
		if primary is not None:
			for node in primary.findall("Entry/Node"):
				location = node.find("SourceLocation")
				if location is not None and node.attrib.get("isDefault") == "true":
					return location
			location = primary.find("Entry/Node/SourceLocation")
			if location is not None:
				return location
		return vulnerability.find(
			"AnalysisInfo/Unified/Context/FunctionDeclarationSourceLocation"
		)

	def _snippet_bounds(self, target_line, first_available, last_available):
		if first_available > last_available:
			return None
		target = min(max(target_line, first_available), last_available)
		window_size = (SNIPPET_CONTEXT_LINES * 2) + 1
		start = max(first_available, target - SNIPPET_CONTEXT_LINES)
		end = min(last_available, start + window_size - 1)
		start = max(first_available, end - window_size + 1)
		return start, end

	def _source_snippet(self, filename, target_line):
		archive_name = self.source_entries.get(filename)
		if not archive_name:
			return ""
		try:
			source = self.archive.read(archive_name)
		except KeyError:
			return ""

		encoding = self.source_encodings.get(filename, "utf-8")
		try:
			text = source.decode(encoding)
		except (LookupError, UnicodeDecodeError):
			text = source.decode("utf-8", errors="replace")
		lines = text.splitlines()
		bounds = self._snippet_bounds(target_line, 1, len(lines))
		if bounds is None:
			return ""
		start, end = bounds
		return "\n".join(
			"{0}: {1}".format(number, lines[number - 1])
			for number in range(start, end + 1)
		)

	def _embedded_snippet(self, location, filename, target_line):
		entry = None
		if location is not None:
			entry = self.snippets.get(location.attrib.get("snippet"))

		if entry is None:
			candidates = [
				snippet
				for snippet in self.snippets_by_file.get(filename, [])
				if snippet["start"] <= target_line <= snippet["end"]
			]
			if candidates:
				entry = min(
					candidates,
					key=lambda snippet: snippet["end"] - snippet["start"],
				)

		if entry is None or not entry["text"]:
			return ""

		lines = entry["text"].splitlines()
		first_available = entry["start"]
		last_available = first_available + len(lines) - 1
		bounds = self._snippet_bounds(target_line, first_available, last_available)
		if bounds is None:
			return ""
		start, end = bounds
		return "\n".join(
			"{0}: {1}".format(number, lines[number - first_available])
			for number in range(start, end + 1)
		)

	def _references(self, description):
		if description is None:
			return ""
		formatted = []
		for reference in description.findall("References/Reference"):
			title = (reference.findtext("Title") or "").strip()
			author = (reference.findtext("Author") or "").strip()
			source = (reference.findtext("Source") or "").strip()
			line = title
			if author:
				line += (" — " if line else "") + author
			if source:
				line += (" — " if line else "") + source
			if line:
				formatted.append(line)
		return "\n".join(formatted)

	def _extract_findings(self):
		for vulnerability in self.root.findall("Vulnerabilities/Vulnerability"):
			class_info = vulnerability.find("ClassInfo")
			class_id = class_info.findtext("ClassID")
			kingdom = class_info.findtext("Kingdom", "")
			category = class_info.findtext("Type", "")
			subtype = class_info.findtext("Subtype")
			if subtype:
				category += ": " + subtype

			context = vulnerability.find("AnalysisInfo/Unified/Context")
			function_element = context.find("Function") if context is not None else None
			function = function_element.attrib.get("name", "") if function_element is not None else ""
			location = self._primary_location(vulnerability)
			filename = location.attrib.get("path", "") if location is not None else ""
			line = int(location.attrib.get("line", 1)) if location is not None else 1
			instance_info = vulnerability.find("InstanceInfo")
			confidence = _float_text(instance_info.find("Confidence"))
			probability = -1
			probability_group = instance_info.find("MetaInfo/Group")
			if probability_group is not None and probability_group.text:
				probability = float(probability_group.text)
			severity = Severity.LOW
			rule = self.rules.get(class_id)
			if rule:
				severity = rule.calculate_severity(confidence, probability)

			replacements = {}
			for definition in vulnerability.findall(
				"AnalysisInfo/Unified/ReplacementDefinitions/Def"
			):
				replacements[definition.attrib.get("key", "")] = definition.attrib.get("value", "")
			description = self.descriptions.get(class_id)
			abstract_text = description.findtext("Abstract") if description is not None else ""
			explanation_text = description.findtext("Explanation") if description is not None else ""
			remediation_text = description.findtext("Recommendations") if description is not None else ""

			self.findings.append(
				Finding(
					kingdom,
					category,
					filename,
					severity,
					function,
					line,
					self._source_snippet(filename, line)
					or self._embedded_snippet(location, filename, line),
					render_description(explanation_text, replacements),
					render_description(remediation_text, replacements),
					render_description(abstract_text, replacements),
					self._references(description),
				)
			)


class ReportWriter:
	columns = [
		("Risk Level", "severity", 12),
		("Kingdom", "kingdom", 20),
		("Category", "category", 38),
		("File Path", "filename", 45),
		("Function", "function", 24),
		("Line Number", "line", 12),
		("Code Snippet", "code_snippet", 60),
		("Description", "description", 60),
		("Remediation", "remediation", 60),
		("Abstract", "abstract", 50),
		("Reference", "references", 60),
	]

	def write_worksheet(self, workbook, name):
		findings = self.order_findings(name)
		if not findings:
			return

		worksheet = workbook.add_worksheet(name)
		header_format = workbook.add_format(
			{"border": 1, "bold": True, "font_color": "white", "bg_color": "blue"}
		)
		text_format = workbook.add_format(
			{"border": 1, "text_wrap": True, "valign": "top"}
		)
		severity_formats = [
			workbook.add_format({"border": 1, "bold": True, "font_color": "white", "bg_color": color})
			for color in ("#A4A4A4", "orange", "#FF0000", "#8A0808")
		]

		for column, (heading, _, width) in enumerate(self.columns):
			worksheet.write(0, column, heading, header_format)
			worksheet.set_column(column, column, width)

		for row, finding in enumerate(findings, start=1):
			worksheet.write(
				row,
				0,
				finding.severity.name,
				severity_formats[finding.severity.value - 1],
			)
			for column, (_, attribute, _) in enumerate(self.columns[1:], start=1):
				value = getattr(finding, attribute)
				if isinstance(value, str) and len(value) > EXCEL_CELL_LIMIT:
					value = value[: EXCEL_CELL_LIMIT - 14] + "\n[truncated]"
				worksheet.write(row, column, value, text_format)

		last_column = len(self.columns) - 1
		worksheet.autofilter(0, 0, len(findings), last_column)
		worksheet.freeze_panes(1, 0)

	def write_to_excel(self, findings, filename):
		self.findings = findings
		workbook = Workbook(filename)
		for sheet_name in ("all", "critical", "high", "medium", "low"):
			self.write_worksheet(workbook, sheet_name)
		workbook.close()

	def order_findings(self, severity):
		if severity == "all":
			return sorted(
				self.findings,
				key=lambda finding: (-finding.severity.value, finding.category),
			)
		severity_value = Severity[severity.upper()].value
		return sorted(
			(finding for finding in self.findings if finding.severity.value == severity_value),
			key=lambda finding: finding.category,
		)


def main(args):
	fpr = FPR(args.input)
	findings = fpr.process()
	output_file = path.splitext(args.input)[0] + ".xlsx"
	ReportWriter().write_to_excel(findings, output_file)
	print("Created {0} with {1} findings.".format(output_file, len(findings)))


if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		description="Convert a Fortify FPR report to an Excel workbook."
	)
	parser.add_argument(
		"--input",
		"-i",
		help="input Fortify .fpr report",
		dest="input",
		required=True,
	)
	arguments = parser.parse_args()
	if path.isfile(arguments.input):
		try:
			main(arguments)
		except (ET.ParseError, ValueError) as error:
			parser.error(str(error))
	else:
		parser.error("Could not find the FPR file: {0}".format(arguments.input))
