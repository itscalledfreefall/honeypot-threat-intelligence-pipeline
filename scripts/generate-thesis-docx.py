#!/usr/bin/env python3
"""Generate the formatted COMP498 report DOCX from the reviewed Markdown source."""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import uno
from com.sun.star.awt.FontWeight import BOLD, NORMAL
from com.sun.star.beans import PropertyValue
from com.sun.star.style.BreakType import NONE, PAGE_BEFORE
from com.sun.star.style.NumberingType import ARABIC, ROMAN_LOWER
from com.sun.star.style.ParagraphAdjust import BLOCK, CENTER, LEFT
from com.sun.star.text.ControlCharacter import PARAGRAPH_BREAK
from com.sun.star.text.HoriOrientation import FULL
from com.sun.star.text.TextContentAnchorType import AS_CHARACTER


PROJECT_TITLE = (
    "DEVOPS-ORIENTED DISTRIBUTED HONEYPOT SYSTEM FOR DETECTING "
    "AND ANALYZING CYBER ATTACKS"
)
SUPERVISOR = "Dr. Öğr. Üyesi Ali Cihan Keleş"


def property_value(name: str, value: Any) -> PropertyValue:
    prop = PropertyValue()
    prop.Name = name
    prop.Value = value
    return prop


def strip_markdown(value: str) -> str:
    value = re.sub(r"\*\*(.+?)\*\*", r"\1", value)
    value = re.sub(r"(?<!\*)\*(.+?)\*(?!\*)", r"\1", value)
    value = re.sub(r"`([^`]+)`", r"\1", value)
    return value.replace("  ", " ").strip()


def is_table_separator(line: str) -> bool:
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def parse_markdown(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: list[dict[str, Any]] = []
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if not stripped:
            index += 1
            continue

        if stripped.startswith("```"):
            language = stripped[3:].strip()
            code: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code.append(lines[index])
                index += 1
            index += 1
            blocks.append({"type": "code", "language": language, "lines": code})
            continue

        image = re.fullmatch(r"!\[(.+)]\((.+)\)", stripped)
        if image:
            image_path = Path(image.group(2))
            if not image_path.is_absolute():
                image_path = path.parent / image_path
            blocks.append(
                {
                    "type": "image",
                    "caption": strip_markdown(image.group(1)),
                    "path": image_path,
                }
            )
            index += 1
            continue

        heading = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if heading:
            blocks.append(
                {
                    "type": "heading",
                    "level": len(heading.group(1)),
                    "text": strip_markdown(heading.group(2)),
                }
            )
            index += 1
            continue

        if stripped == "---":
            blocks.append({"type": "separator"})
            index += 1
            continue

        if (
            stripped.startswith("|")
            and index + 1 < len(lines)
            and is_table_separator(lines[index + 1])
        ):
            rows: list[list[str]] = []
            rows.append(
                [strip_markdown(cell) for cell in stripped.strip("|").split("|")]
            )
            index += 2
            while index < len(lines) and lines[index].strip().startswith("|"):
                rows.append(
                    [
                        strip_markdown(cell)
                        for cell in lines[index].strip().strip("|").split("|")
                    ]
                )
                index += 1
            blocks.append({"type": "table", "rows": rows})
            continue

        bullet = re.match(r"^[-*]\s+(.+)$", stripped)
        numbered = re.match(r"^(\d+)\.\s+(.+)$", stripped)
        if bullet or numbered:
            items: list[str] = []
            ordered = numbered is not None
            while index < len(lines):
                raw_candidate = lines[index]
                candidate = raw_candidate.strip()
                match = (
                    re.match(r"^(\d+)\.\s+(.+)$", candidate)
                    if ordered
                    else re.match(r"^[-*]\s+(.+)$", candidate)
                )
                if match:
                    item_text = match.group(2) if ordered else match.group(1)
                    items.append(strip_markdown(item_text))
                    index += 1
                    continue
                if items and raw_candidate.startswith(("  ", "\t")) and candidate:
                    items[-1] = f"{items[-1]} {strip_markdown(candidate)}"
                    index += 1
                    continue
                if not match:
                    break
            blocks.append({"type": "list", "ordered": ordered, "items": items})
            continue

        paragraph = [stripped]
        index += 1
        while index < len(lines):
            candidate = lines[index].strip()
            if not candidate:
                break
            if (
                candidate.startswith("#")
                or candidate == "---"
                or candidate.startswith("```")
                or candidate.startswith("|")
                or re.match(r"^[-*]\s+", candidate)
                or re.match(r"^\d+\.\s+", candidate)
            ):
                break
            paragraph.append(candidate)
            index += 1
        blocks.append({"type": "paragraph", "text": strip_markdown(" ".join(paragraph))})

    return blocks


class ThesisWriter:
    def __init__(self, document: Any):
        self.document = document
        self.text = document.Text
        self.current_section = ""
        self.pending_separator = False
        self.main_body_started = False
        self.toc: Any | None = None
        self._configure_page_styles()

    def _line_spacing(self, percent: int) -> Any:
        spacing = uno.createUnoStruct("com.sun.star.style.LineSpacing")
        spacing.Mode = 0
        spacing.Height = percent
        return spacing

    def _configure_page_styles(self) -> None:
        families = self.document.StyleFamilies
        page_styles = families.getByName("PageStyles")

        for name in ("Thesis Title", "Thesis Preliminary", "Thesis Main"):
            if page_styles.hasByName(name):
                page_styles.removeByName(name)
            page_styles.insertByName(
                name,
                self.document.createInstance("com.sun.star.style.PageStyle"),
            )

        title = page_styles.getByName("Thesis Title")
        preliminary = page_styles.getByName("Thesis Preliminary")
        main = page_styles.getByName("Thesis Main")

        for style in (title, preliminary, main):
            style.Width = 21000
            style.Height = 29700
            style.IsLandscape = False
            style.LeftMargin = 3500
            style.RightMargin = 2000
            style.TopMargin = 3500
            style.BottomMargin = 2000
            style.HeaderIsOn = False

        title.FooterIsOn = False
        preliminary.NumberingType = ROMAN_LOWER
        main.NumberingType = ARABIC
        self._add_page_number_footer(preliminary, ROMAN_LOWER)
        self._add_page_number_footer(main, ARABIC)
        # Writer adds footer height and body distance to the OOXML bottom
        # margin. These values export as a 20 mm bottom margin with the page
        # number positioned approximately 12.5 mm from the page edge.
        preliminary.BottomMargin = 1250
        main.BottomMargin = 1250

    def _add_page_number_footer(self, page_style: Any, numbering_type: int) -> None:
        page_style.FooterIsOn = True
        page_style.FooterHeight = 240
        page_style.FooterBodyDistance = 0
        footer = page_style.FooterText
        footer.String = ""
        cursor = footer.createTextCursor()
        cursor.ParaAdjust = CENTER
        cursor.CharFontName = "Times New Roman"
        cursor.CharHeight = 10.0
        field = self.document.createInstance("com.sun.star.text.TextField.PageNumber")
        field.NumberingType = numbering_type
        footer.insertTextContent(cursor, field, False)

    def _end_cursor(self) -> Any:
        return self.text.createTextCursorByRange(self.text.End)

    def insert_paragraph(
        self,
        value: str,
        *,
        font_size: float = 12.0,
        bold: bool = False,
        font_name: str = "Times New Roman",
        align: Any = BLOCK,
        first_indent: int = 1000,
        left_indent: int = 0,
        line_percent: int = 150,
        before: int = 0,
        after: int = 0,
        outline_level: int = 0,
        page_style: str | None = None,
        page_offset: int = 0,
        page_break: bool = False,
    ) -> None:
        cursor = self._end_cursor()
        cursor.CharFontName = font_name
        cursor.CharHeight = font_size
        cursor.CharWeight = BOLD if bold else NORMAL
        cursor.ParaAdjust = align
        cursor.ParaFirstLineIndent = first_indent
        cursor.ParaLeftMargin = left_indent
        cursor.ParaRightMargin = 0
        cursor.ParaTopMargin = before
        cursor.ParaBottomMargin = after
        cursor.ParaLineSpacing = self._line_spacing(line_percent)
        if outline_level:
            cursor.ParaStyleName = f"Heading {min(outline_level, 3)}"
            cursor.NumberingStyleName = ""
        cursor.BreakType = PAGE_BEFORE if page_break else NONE
        if page_style:
            cursor.PageDescName = page_style
        if page_offset:
            cursor.PageNumberOffset = page_offset
        self.text.insertString(cursor, value, False)
        self.text.insertControlCharacter(cursor, PARAGRAPH_BREAK, False)

    def insert_table(self, rows: list[list[str]]) -> None:
        if not rows:
            return
        column_count = max(len(row) for row in rows)
        table = self.document.createInstance("com.sun.star.text.TextTable")
        table.initialize(len(rows), column_count)
        self.text.insertTextContent(self._end_cursor(), table, False)
        table.HoriOrient = FULL
        self._set_table_widths(table, rows[0])

        for row_index, row in enumerate(rows):
            for column_index in range(column_count):
                name = f"{chr(ord('A') + column_index)}{row_index + 1}"
                cell = table.getCellByName(name)
                cell.String = row[column_index] if column_index < len(row) else ""
                cell_cursor = cell.createTextCursor()
                cell_cursor.gotoEnd(True)
                cell_cursor.CharFontName = "Times New Roman"
                cell_cursor.CharHeight = 10.0
                cell_cursor.CharWeight = BOLD if row_index == 0 else NORMAL
                cell_cursor.ParaAdjust = LEFT
                cell_cursor.ParaFirstLineIndent = 0
                cell_cursor.ParaLineSpacing = self._line_spacing(100)
                if row_index == 0:
                    cell.BackColor = 0xD9E2F3

        self.text.insertControlCharacter(self._end_cursor(), PARAGRAPH_BREAK, False)

    def _set_table_widths(self, table: Any, headers: list[str]) -> None:
        column_count = len(headers)
        if column_count < 2:
            return

        first_header = headers[0]
        if first_header == "Variable":
            widths = [38, 45, 17]
        elif first_header == "ID":
            widths = [12, 58, 30]
        elif first_header == "Test Module":
            widths = [30, 15, 55]
        elif first_header == "Field":
            widths = [25, 22, 53]
        elif first_header == "Service":
            widths = [25, 50, 25]
        elif first_header == "Approved Objective":
            widths = [32, 28, 40]
        elif first_header in {"Abbreviation", "Status"}:
            widths = [30, 70]
        elif first_header == "Measurement":
            widths = [65, 35]
        else:
            widths = [100 / column_count] * column_count

        separators = list(table.TableColumnSeparators)
        cumulative = 0.0
        for separator, width in zip(separators, widths[:-1], strict=False):
            cumulative += width
            separator.Position = int(cumulative * 100)
            separator.IsVisible = True
        table.TableColumnSeparators = tuple(separators)

    def insert_code(self, lines: list[str]) -> None:
        for line in lines or [""]:
            self.insert_paragraph(
                line,
                font_size=9.5,
                font_name="Consolas",
                align=LEFT,
                first_indent=0,
                left_indent=500,
                line_percent=100,
            )

    def insert_image(self, path: Path, caption: str) -> None:
        if not path.is_file():
            raise FileNotFoundError(f"Image not found: {path}")

        cursor = self._end_cursor()
        cursor.ParaAdjust = CENTER
        cursor.ParaFirstLineIndent = 0
        graphic = self.document.createInstance(
            "com.sun.star.text.TextGraphicObject"
        )
        graphic.GraphicURL = path.resolve().as_uri()
        graphic.AnchorType = AS_CHARACTER
        graphic.Width = 15500
        graphic.Height = 8625
        self.text.insertTextContent(cursor, graphic, False)
        self.text.insertControlCharacter(cursor, PARAGRAPH_BREAK, False)
        self.insert_paragraph(
            caption,
            font_size=12.0,
            align=CENTER,
            first_indent=0,
            line_percent=100,
            after=500,
        )

    def insert_toc(self) -> None:
        index = self.document.createInstance("com.sun.star.text.ContentIndex")
        index.Title = ""
        index.CreateFromOutline = True
        self.text.insertTextContent(self._end_cursor(), index, False)
        self.text.insertControlCharacter(self._end_cursor(), PARAGRAPH_BREAK, False)
        self.toc = index

    def insert_heading(self, level: int, value: str, first_heading: bool) -> None:
        if first_heading:
            self.current_section = "TITLE PAGE"
            self.insert_paragraph(
                value,
                font_size=22.0,
                bold=True,
                align=CENTER,
                first_indent=0,
                before=0,
                after=1600,
                page_style="Thesis Title",
            )
            return

        self.current_section = value
        is_main = bool(re.match(r"^[1-6]\.\s", value)) or value == "BIBLIOGRAPHY" or value.startswith("APPENDIX ")

        if is_main:
            starting_main = not self.main_body_started and value.startswith("1. ")
            self.main_body_started = True
            self.insert_paragraph(
                value.upper(),
                font_size=14.0,
                bold=True,
                align=LEFT,
                first_indent=0,
                before=0,
                after=700,
                outline_level=1,
                page_style="Thesis Main" if starting_main else None,
                page_offset=1 if starting_main else 0,
                page_break=True,
            )
            return

        if level == 1:
            page_style = "Thesis Preliminary" if value == "APPROVED BY" else None
            page_offset = 2 if value == "APPROVED BY" else 0

            if value == "APPROVED BY":
                self.insert_paragraph(
                    PROJECT_TITLE,
                    font_size=22.0,
                    bold=True,
                    align=CENTER,
                    first_indent=0,
                    after=1800,
                    page_style=page_style,
                    page_offset=page_offset,
                    page_break=True,
                )
                self.insert_paragraph(
                    value,
                    font_size=18.0,
                    align=LEFT,
                    first_indent=0,
                    after=1200,
                )
                return

            abstract_heading = value in {"ABSTRACT", "ÖZET"}
            self.insert_paragraph(
                value,
                font_size=22.0 if abstract_heading else 14.0,
                bold=not abstract_heading,
                align=CENTER if abstract_heading else LEFT,
                first_indent=0,
                after=700,
                page_break=True,
            )
            if value == "TABLE OF CONTENTS":
                self.insert_toc()
            return

        self.insert_paragraph(
            value,
            font_size=12.0,
            bold=True,
            align=LEFT,
            first_indent=0,
            before=600,
            after=600,
            outline_level=level,
        )

    def insert_front_paragraph(self, value: str) -> bool:
        if self.current_section == "TITLE PAGE":
            if value == "by":
                self.insert_paragraph(value, font_size=18, bold=True, align=CENTER, first_indent=0, before=700, after=400)
            elif value == "Ata Demir Alcinar":
                self.insert_paragraph(value, font_size=18, bold=True, align=CENTER, first_indent=0, after=1400)
            elif value == "Graduation Project Report":
                self.insert_paragraph(value, font_size=18, bold=True, align=CENTER, first_indent=0, after=1800)
            else:
                self.insert_paragraph(value, font_size=16, bold=True, align=CENTER, first_indent=0, after=250)
            return True

        if self.current_section == "APPROVED BY":
            if value == PROJECT_TITLE:
                return True
            if value == SUPERVISOR:
                self.insert_paragraph(value, font_size=14, align=LEFT, first_indent=0, before=700)
            elif value == "Supervisor":
                self.insert_paragraph("(Supervisor)", font_size=14, align=LEFT, first_indent=0, after=500)
            elif value.startswith("[Committee member"):
                self.insert_paragraph("________________________________", font_size=14, align=LEFT, first_indent=0, after=500)
            elif value.startswith("Date of Approval:"):
                self.insert_paragraph("DATE OF APPROVAL: ____/____/2026", font_size=14, align=LEFT, first_indent=0, before=1000)
            else:
                self.insert_paragraph(value, font_size=14, align=LEFT, first_indent=0)
            return True

        if self.current_section in {"ABSTRACT", "ÖZET"} and value == PROJECT_TITLE:
            self.insert_paragraph(value, font_size=18, align=CENTER, first_indent=0, after=900)
            return True

        if self.current_section == "TABLE OF CONTENTS" and value.startswith("The table of contents"):
            return True

        return False

    def write(self, blocks: list[dict[str, Any]]) -> None:
        first_heading = True
        for block in blocks:
            block_type = block["type"]
            if block_type == "separator":
                self.pending_separator = True
                continue
            if block_type == "heading":
                self.insert_heading(block["level"], block["text"], first_heading)
                first_heading = False
                self.pending_separator = False
                continue
            if block_type == "paragraph":
                value = block["text"]
                if self.insert_front_paragraph(value):
                    continue
                self.insert_paragraph(value)
                continue
            if block_type == "table":
                self.insert_table(block["rows"])
                continue
            if block_type == "code":
                self.insert_code(block["lines"])
                continue
            if block_type == "image":
                self.insert_image(block["path"], block["caption"])
                continue
            if block_type == "list":
                for number, item in enumerate(block["items"], start=1):
                    marker = f"{number}." if block["ordered"] else "•"
                    self.insert_paragraph(
                        f"{marker}  {item}",
                        align=LEFT,
                        first_indent=-500,
                        left_indent=1000,
                    )

        if self.toc is not None:
            self.toc.update()


def connect_to_libreoffice(profile: Path) -> tuple[subprocess.Popen[bytes], Any]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    command = [
        "libreoffice",
        f"-env:UserInstallation={profile.as_uri()}",
        "--headless",
        "--nologo",
        "--nodefault",
        "--nofirststartwizard",
        f"--accept=socket,host=127.0.0.1,port={port};urp;StarOffice.ServiceManager",
    ]
    environment = os.environ.copy()
    environment["HOME"] = str(profile.parent)
    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=environment,
    )

    local_context = uno.getComponentContext()
    resolver = local_context.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local_context
    )
    connection = (
        f"uno:socket,host=127.0.0.1,port={port};urp;"
        "StarOffice.ComponentContext"
    )
    deadline = time.monotonic() + 20
    while True:
        try:
            context = resolver.resolve(connection)
            return process, context
        except Exception:
            if time.monotonic() >= deadline or process.poll() is not None:
                if process.poll() is None:
                    process.terminate()
                stderr = process.communicate(timeout=5)[1].decode(
                    "utf-8", errors="replace"
                )
                raise RuntimeError(
                    f"Could not connect to the LibreOffice process: {stderr.strip()}"
                )
            time.sleep(0.2)


def generate(source: Path, template: Path, output: Path) -> None:
    blocks = parse_markdown(source)
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="thesis-lo-") as temp_directory:
        profile = Path(temp_directory) / "profile"
        profile.mkdir()
        process, context = connect_to_libreoffice(profile)
        document = None
        try:
            service_manager = context.ServiceManager
            desktop = service_manager.createInstanceWithContext(
                "com.sun.star.frame.Desktop", context
            )
            hidden = (property_value("Hidden", True),)
            document = desktop.loadComponentFromURL(
                template.resolve().as_uri(), "_blank", 0, hidden
            )
            document.Text.String = ""
            document.DocumentProperties.Title = PROJECT_TITLE
            document.DocumentProperties.Author = "Ata Demir Alcinar"
            document.DocumentProperties.Subject = "COMP498 Graduation Project Report"

            writer = ThesisWriter(document)
            writer.write(blocks)

            save_properties = (
                property_value("FilterName", "Office Open XML Text"),
                property_value("Overwrite", True),
            )
            document.storeAsURL(output.resolve().as_uri(), save_properties)
        finally:
            if document is not None:
                document.close(True)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("docs/thesis/final-report-draft.md"),
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=Path("/home/fe/Documents/gradProject/ReportFormat.docx"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "docs/thesis/DevOps-Oriented_Distributed_Honeypot_System_Report.docx"
        ),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.source.is_file():
        raise SystemExit(f"Source not found: {args.source}")
    if not args.template.is_file():
        raise SystemExit(f"Template not found: {args.template}")
    generate(args.source, args.template, args.output)
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
