#!/usr/bin/env python3
import argparse
import html
import re
import xml.etree.ElementTree as ET
from collections import Counter
from enum import Enum
from pathlib import Path
from zipfile import BadZipFile, ZipFile

try:
	from xlsxwriter.workbook import Workbook
except ImportError as exc:
	raise SystemExit(
		"You should install the xlsxwriter library before using this script."
	) from exc


EXCEL_CELL_LIMIT = 32767
SNIPPET_CONTEXT_LINES = 2


def _text(element, query, default=""):
	if element is None:
		return default
	return element.findtext(query, default) or default


def _timestamp(element):
	if element is None:
		return ""
	return " ".join(
		part for part in (element.get("date", ""), element.get("time", "")) if part
	)


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
		instance_id="",
		class_id="",
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
		self.instance_id = instance_id
		self.class_id = class_id


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
		self.source_lines = {}
		self.findings = []
		self.archive = None
		self.root = None
		self.metadata = {}
		self.rule_packs = []

	def process(self):
		try:
			with ZipFile(self.fpr_file) as archive:
				self.archive = archive
				xml_bytes = archive.read("audit.fvdl")
				# Removing only the default namespace keeps the XPath expressions readable.
				xml_bytes = re.sub(br'\sxmlns="[^"]+"', b"", xml_bytes, count=1)
				self.root = ET.fromstring(xml_bytes)
				self._extract_metadata()
				self._extract_source_index()
				self._extract_rules()
				self._extract_descriptions()
				self._extract_snippets()
				self._extract_findings()
		except (BadZipFile, KeyError) as exc:
			raise ValueError("Malformed FPR file: audit.fvdl was not found") from exc
		finally:
			self.archive = None
		return self.findings

	def _extract_metadata(self):
		build = self.root.find("Build")
		scan_time = build.find("ScanTime") if build is not None else None
		self.metadata = {
			"Input FPR": Path(self.fpr_file).name,
			"Project label": _text(build, "Label"),
			"Build ID": _text(build, "BuildID"),
			"Scan UUID": _text(self.root, "UUID"),
			"Scan created": _timestamp(self.root.find("CreatedTS")),
			"Report written": _timestamp(self.root.find("WriteDate")),
			"Engine version": _text(self.root, "EngineData/EngineVersion"),
			"FVDL version": self.root.get("version", ""),
			"Scan duration (seconds)": scan_time.get("value", "") if scan_time is not None else "",
			"Source files": _text(build, "NumberFiles"),
		}
		if build is not None:
			for loc in build.findall("LOC"):
				if loc.get("type") in ("Fortify", "Line Count"):
					self.metadata["Lines of code ({})".format(loc.get("type"))] = loc.text or ""
		self.rule_packs = [
			(_text(rule_pack, "Name"), _text(rule_pack, "Version"))
			for rule_pack in self.root.findall("EngineData/RulePacks/RulePack")
		]

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
		if filename not in self.source_lines:
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
			self.source_lines[filename] = text.splitlines()
		lines = self.source_lines[filename]
		if not 1 <= target_line <= len(lines):
			return ""
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
		if not first_available <= target_line <= last_available:
			return ""
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
			if class_info is None:
				continue
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
			confidence = _float_text(instance_info.find("Confidence") if instance_info is not None else None)
			probability = -1
			probability_group = instance_info.find("MetaInfo/Group") if instance_info is not None else None
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
					_text(instance_info, "InstanceID"),
					class_id or "",
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
		("Instance ID", "instance_id", 40),
		("Class ID", "class_id", 40),
	]

	def write_metadata(self, workbook, metadata, rule_packs, findings):
		worksheet = workbook.add_worksheet("metadata")
		worksheet.set_column("A:A", 30)
		worksheet.set_column("B:B", 80)
		worksheet.freeze_panes(1, 0)
		section_format = workbook.add_format(
			{"bold": True, "font_color": "white", "bg_color": "blue"}
		)
		label_format = workbook.add_format({"bold": True, "valign": "top"})
		value_format = workbook.add_format({"text_wrap": True, "valign": "top"})
		worksheet.merge_range(0, 0, 0, 1, "Scan metadata", section_format)
		row = 1

		def write_pair(label, value):
			nonlocal row
			worksheet.write_string(row, 0, label, label_format)
			worksheet.write_string(row, 1, str(value) if value is not None and value != "" else "Not available", value_format)
			row += 1

		for label, value in metadata.items():
			write_pair(label, value)

		row += 1
		worksheet.merge_range(row, 0, row, 1, "Finding summary", section_format)
		row += 1
		write_pair("Total findings", len(findings))
		counts = Counter(finding.severity for finding in findings)
		for severity in reversed(Severity):
			write_pair(severity.name.title(), counts[severity])

		if rule_packs:
			row += 1
			worksheet.merge_range(row, 0, row, 1, "Rule packs", section_format)
			row += 1
			for name, version in rule_packs:
				write_pair(name or "Unnamed rule pack", version)

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
			worksheet.write_string(
				row,
				0,
				finding.severity.name,
				severity_formats[finding.severity.value - 1],
			)
			for column, (_, attribute, _) in enumerate(self.columns[1:], start=1):
				value = getattr(finding, attribute)
				if isinstance(value, str) and len(value) > EXCEL_CELL_LIMIT:
					value = value[: EXCEL_CELL_LIMIT - 14] + "\n[truncated]"
				if isinstance(value, str):
					worksheet.write_string(row, column, value, text_format)
				else:
					worksheet.write_number(row, column, value, text_format)

		last_column = len(self.columns) - 1
		worksheet.autofilter(0, 0, len(findings), last_column)
		worksheet.freeze_panes(1, 0)

	def write_to_excel(self, findings, filename, metadata=None, rule_packs=None):
		self.findings = findings
		workbook = Workbook(filename)
		self.write_metadata(workbook, metadata or {}, rule_packs or [], findings)
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
	output_file = str(Path(args.input).with_suffix(".xlsx"))
	ReportWriter().write_to_excel(findings, output_file, fpr.metadata, fpr.rule_packs)
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
	if Path(arguments.input).is_file():
		try:
			main(arguments)
		except (ET.ParseError, ValueError) as error:
			parser.error(str(error))
	else:
		parser.error("Could not find the FPR file: {0}".format(arguments.input))
