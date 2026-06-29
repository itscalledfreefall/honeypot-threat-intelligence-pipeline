#!/usr/bin/env python3
"""Apply the final dashboard, bulk-demo, and environment notes to the thesis DOCX."""

from __future__ import annotations

import argparse
import copy
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "wp": "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "pic": "http://schemas.openxmlformats.org/drawingml/2006/picture",
}
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
MC_NS = "http://schemas.openxmlformats.org/markup-compatibility/2006"

for prefix, uri in NS.items():
    ET.register_namespace(prefix, uri)
ET.register_namespace("", REL_NS)


def qn(prefix: str, name: str) -> str:
    return f"{{{NS[prefix]}}}{name}"


def w_attr(name: str) -> str:
    return qn("w", name)


def paragraph_text(paragraph: ET.Element) -> str:
    return "".join(node.text or "" for node in paragraph.iter(qn("w", "t")))


def run_properties(size_half_points: int, font: str = "Times New Roman") -> ET.Element:
    properties = ET.Element(qn("w", "rPr"))
    ET.SubElement(
        properties,
        qn("w", "rFonts"),
        {
            w_attr("ascii"): font,
            w_attr("hAnsi"): font,
            w_attr("cs"): font,
        },
    )
    ET.SubElement(properties, qn("w", "sz"), {w_attr("val"): str(size_half_points)})
    ET.SubElement(properties, qn("w", "szCs"), {w_attr("val"): str(size_half_points)})
    return properties


def set_paragraph_text(paragraph: ET.Element, text: str) -> None:
    paragraph_properties = paragraph.find(qn("w", "pPr"))
    run_properties_node = paragraph.find(f"{qn('w', 'r')}/{qn('w', 'rPr')}")
    for child in list(paragraph):
        if child is not paragraph_properties:
            paragraph.remove(child)
    run = ET.SubElement(paragraph, qn("w", "r"))
    if run_properties_node is not None:
        run.append(copy.deepcopy(run_properties_node))
    text_node = ET.SubElement(run, qn("w", "t"))
    text_node.text = text


def body_paragraph(text: str) -> ET.Element:
    paragraph = ET.Element(qn("w", "p"))
    properties = ET.SubElement(paragraph, qn("w", "pPr"))
    ET.SubElement(
        properties,
        qn("w", "spacing"),
        {
            w_attr("lineRule"): "auto",
            w_attr("line"): "360",
            w_attr("before"): "0",
            w_attr("after"): "0",
        },
    )
    ET.SubElement(
        properties,
        qn("w", "ind"),
        {
            w_attr("firstLine"): "567",
            w_attr("start"): "0",
            w_attr("end"): "0",
        },
    )
    ET.SubElement(properties, qn("w", "jc"), {w_attr("val"): "both"})
    run = ET.SubElement(paragraph, qn("w", "r"))
    run.append(run_properties(24))
    text_node = ET.SubElement(run, qn("w", "t"))
    text_node.text = text
    return paragraph


def code_paragraph(text: str) -> ET.Element:
    paragraph = ET.Element(qn("w", "p"))
    properties = ET.SubElement(paragraph, qn("w", "pPr"))
    ET.SubElement(
        properties,
        qn("w", "spacing"),
        {
            w_attr("lineRule"): "auto",
            w_attr("line"): "240",
            w_attr("before"): "0",
            w_attr("after"): "0",
        },
    )
    ET.SubElement(
        properties,
        qn("w", "ind"),
        {w_attr("firstLine"): "0", w_attr("start"): "283"},
    )
    ET.SubElement(properties, qn("w", "jc"), {w_attr("val"): "left"})
    run = ET.SubElement(paragraph, qn("w", "r"))
    run.append(run_properties(20, "Consolas"))
    text_node = ET.SubElement(run, qn("w", "t"))
    text_node.text = text
    return paragraph


def caption_paragraph(text: str) -> ET.Element:
    paragraph = ET.Element(qn("w", "p"))
    properties = ET.SubElement(paragraph, qn("w", "pPr"))
    ET.SubElement(
        properties,
        qn("w", "spacing"),
        {
            w_attr("lineRule"): "auto",
            w_attr("line"): "240",
            w_attr("before"): "0",
            w_attr("after"): "283",
        },
    )
    ET.SubElement(properties, qn("w", "ind"), {w_attr("firstLine"): "0"})
    ET.SubElement(properties, qn("w", "jc"), {w_attr("val"): "center"})
    run = ET.SubElement(paragraph, qn("w", "r"))
    run.append(run_properties(24))
    text_node = ET.SubElement(run, qn("w", "t"))
    text_node.text = text
    return paragraph


def image_paragraph(relationship_id: str, drawing_id: int) -> ET.Element:
    width = 5_580_000
    height = 3_105_000
    paragraph = ET.Element(qn("w", "p"))
    properties = ET.SubElement(paragraph, qn("w", "pPr"))
    ET.SubElement(properties, qn("w", "jc"), {w_attr("val"): "center"})
    ET.SubElement(properties, qn("w", "ind"), {w_attr("firstLine"): "0"})
    run = ET.SubElement(paragraph, qn("w", "r"))
    drawing = ET.SubElement(run, qn("w", "drawing"))
    inline = ET.SubElement(
        drawing,
        qn("wp", "inline"),
        {"distT": "0", "distB": "0", "distL": "0", "distR": "0"},
    )
    ET.SubElement(inline, qn("wp", "extent"), {"cx": str(width), "cy": str(height)})
    ET.SubElement(
        inline,
        qn("wp", "effectExtent"),
        {"l": "0", "t": "0", "r": "0", "b": "0"},
    )
    ET.SubElement(
        inline,
        qn("wp", "docPr"),
        {"id": str(drawing_id), "name": "React dashboard overview"},
    )
    frame_properties = ET.SubElement(inline, qn("wp", "cNvGraphicFramePr"))
    ET.SubElement(frame_properties, qn("a", "graphicFrameLocks"), {"noChangeAspect": "1"})
    graphic = ET.SubElement(inline, qn("a", "graphic"))
    graphic_data = ET.SubElement(
        graphic,
        qn("a", "graphicData"),
        {"uri": "http://schemas.openxmlformats.org/drawingml/2006/picture"},
    )
    picture = ET.SubElement(graphic_data, qn("pic", "pic"))
    non_visual = ET.SubElement(picture, qn("pic", "nvPicPr"))
    ET.SubElement(
        non_visual,
        qn("pic", "cNvPr"),
        {"id": str(drawing_id), "name": "dashboard-overview.png"},
    )
    ET.SubElement(non_visual, qn("pic", "cNvPicPr"))
    fill = ET.SubElement(picture, qn("pic", "blipFill"))
    ET.SubElement(fill, qn("a", "blip"), {qn("r", "embed"): relationship_id})
    stretch = ET.SubElement(fill, qn("a", "stretch"))
    ET.SubElement(stretch, qn("a", "fillRect"))
    shape = ET.SubElement(picture, qn("pic", "spPr"))
    transform = ET.SubElement(shape, qn("a", "xfrm"))
    ET.SubElement(transform, qn("a", "off"), {"x": "0", "y": "0"})
    ET.SubElement(transform, qn("a", "ext"), {"cx": str(width), "cy": str(height)})
    geometry = ET.SubElement(shape, qn("a", "prstGeom"), {"prst": "rect"})
    ET.SubElement(geometry, qn("a", "avLst"))
    return paragraph


def find_paragraph(body: ET.Element, prefix: str) -> ET.Element:
    for paragraph in body.findall(qn("w", "p")):
        if paragraph_text(paragraph).startswith(prefix):
            return paragraph
    raise ValueError(f"Paragraph not found: {prefix}")


def insert_after(parent: ET.Element, anchor: ET.Element, elements: list[ET.Element]) -> None:
    position = list(parent).index(anchor) + 1
    for element in elements:
        parent.insert(position, element)
        position += 1


def add_image_relationship(relationships: ET.Element) -> str:
    ids = []
    for relationship in relationships:
        value = relationship.get("Id", "")
        if value.startswith("rId") and value[3:].isdigit():
            ids.append(int(value[3:]))
    relationship_id = f"rId{max(ids, default=0) + 1}"
    ET.SubElement(
        relationships,
        f"{{{REL_NS}}}Relationship",
        {
            "Id": relationship_id,
            "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
            "Target": "media/dashboard-overview.png",
        },
    )
    return relationship_id


def ensure_png_content_type(content_types: ET.Element) -> None:
    for item in content_types:
        if item.get("Extension", "").lower() == "png":
            return
    ET.SubElement(
        content_types,
        f"{{{CT_NS}}}Default",
        {"Extension": "png", "ContentType": "image/png"},
    )


def request_field_update(settings: ET.Element) -> None:
    update_fields = settings.find(qn("w", "updateFields"))
    if update_fields is None:
        update_fields = ET.SubElement(settings, qn("w", "updateFields"))
    update_fields.set(w_attr("val"), "true")


def enforce_page_layout(document: ET.Element) -> None:
    for section in document.iter(qn("w", "sectPr")):
        page_size = section.find(qn("w", "pgSz"))
        if page_size is None:
            page_size = ET.SubElement(section, qn("w", "pgSz"))
        page_size.set(w_attr("w"), "11906")
        page_size.set(w_attr("h"), "16838")

        margins = section.find(qn("w", "pgMar"))
        if margins is None:
            margins = ET.SubElement(section, qn("w", "pgMar"))
        margins.set(w_attr("left"), "1984")
        margins.set(w_attr("top"), "1984")
        margins.set(w_attr("right"), "1134")
        margins.set(w_attr("bottom"), "1134")
        if margins.get(w_attr("footer"), "0") != "0":
            margins.set(w_attr("footer"), "567")


def remove_dangling_compatibility_prefixes(document: ET.Element) -> None:
    # ElementTree drops unused namespace declarations. Keeping mc:Ignorable
    # would then leave QName prefixes such as w14 and wp14 unresolved.
    document.attrib.pop(f"{{{MC_NS}}}Ignorable", None)


def patch_document(source: Path, output: Path, screenshot: Path) -> None:
    with zipfile.ZipFile(source) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}

    document = ET.fromstring(contents["word/document.xml"])
    relationships = ET.fromstring(contents["word/_rels/document.xml.rels"])
    content_types = ET.fromstring(contents["[Content_Types].xml"])
    settings = ET.fromstring(contents["word/settings.xml"])
    body = document.find(qn("w", "body"))
    if body is None:
        raise ValueError("The DOCX has no document body")
    if any("Figure 4.4. React dashboard overview showing" in paragraph_text(p) for p in body):
        raise ValueError("The requested thesis additions are already present")

    relationship_id = add_image_relationship(relationships)
    ensure_png_content_type(content_types)
    drawing_ids = [
        int(node.get("id", "0"))
        for node in document.iter(qn("wp", "docPr"))
        if node.get("id", "0").isdigit()
    ]
    drawing_id = max(drawing_ids, default=0) + 1

    dashboard = find_paragraph(body, "The React application provides login and registration")
    set_paragraph_text(
        dashboard,
        "The React application provides login and registration, followed by a dashboard "
        "with Overview, Events, Sessions, Intelligence, Devices, and Monitoring views. "
        "The Overview view summarizes event volume, malicious activity, source addresses, "
        "categories, protocols, and risk levels. Event and session views preserve the "
        "relationship between individual records and session behavior, and a session can "
        "be opened as a chronological timeline. Export controls provide reports and "
        "blocklists without requiring direct database access.",
    )
    insert_after(
        body,
        dashboard,
        [
            body_paragraph(
                "The Intelligence view brings the processed analysis into one screen. It "
                "shows the distribution of risk levels, attack categories, protocol counts, "
                "and the source IP addresses with the largest event totals. These panels use "
                "the same summary and threat data returned by the authenticated backend API. "
                "Individual event details retain provider enrichment from AbuseIPDB and "
                "VirusTotal when those services are enabled."
            ),
            image_paragraph(relationship_id, drawing_id),
            caption_paragraph(
                "Figure 4.4. React dashboard overview showing the Intelligence navigation "
                "entry and generated laboratory telemetry."
            ),
        ],
    )

    old_54 = find_paragraph(body, "5.4. Objective Completion Status")
    old_55 = find_paragraph(body, "5.5. Deployment Verification Required for Final Report")
    old_56 = find_paragraph(body, "5.6. Limitations and Validity")
    set_paragraph_text(old_54, "5.5. Objective Completion Status")
    set_paragraph_text(old_55, "5.6. Deployment Verification Required for Final Report")
    set_paragraph_text(old_56, "5.7. Limitations and Validity")
    bulk_heading = copy.deepcopy(old_54)
    set_paragraph_text(bulk_heading, "5.4. Bulk Attack-Data Demonstration")
    position = list(body).index(old_54)
    bulk_elements = [
        bulk_heading,
        body_paragraph(
            "The repository includes scripts/honeypot-attack.py for generating larger "
            "Cowrie-compatible JSONL datasets without contacting an SSH service or any "
            "external host. The generator uses the documentation address ranges defined by "
            "RFC 5737 and reserved .example domains. Its full-chain mode models five stages: "
            "credential attempts, reconnaissance, malware download, cryptomining, and "
            "persistence with log removal. Captured commands remain strings in the generated "
            "JSONL file and are never executed."
        ),
        body_paragraph("The following controlled run was performed on 21 June 2026:"),
        code_paragraph(
            "python3 scripts/honeypot-attack.py --output "
            "/tmp/thesis-attack-25.json --sessions 25"
        ),
        body_paragraph(
            "The command produced 3,056 Cowrie JSON events across 25 sessions. Every session "
            "contained connection and authentication events, all 117 command patterns from "
            "the five stages, and a closing event. The exact total can vary slightly because "
            "the generator adds between one and four failed logins before each successful "
            "login. This dataset was used to exercise ingestion, session correlation, "
            "classification, risk scoring, storage, and the dashboard under a larger event "
            "load. It is synthetic test traffic and does not measure attack prevalence or "
            "classification accuracy against real-world ground truth."
        ),
    ]
    for element in bulk_elements:
        body.insert(position, element)
        position += 1

    appendix_c = find_paragraph(body, "APPENDIX C: CONFIGURATION VARIABLES")
    insert_after(
        body,
        appendix_c,
        [
            body_paragraph(
                "The repository root contains .env.example as the non-secret configuration "
                "template. A new laboratory deployment copies this file to .env, replaces "
                "the placeholder credentials, and keeps the resulting local file outside "
                "version control. The template documents the baseline settings for "
                "enrichment, SQLite, and Grafana. Deployment-only image coordinates are "
                "supplied by the CI/CD workflow."
            )
        ],
    )

    request_field_update(settings)
    enforce_page_layout(document)
    remove_dangling_compatibility_prefixes(document)
    contents["word/document.xml"] = ET.tostring(document, encoding="utf-8", xml_declaration=True)
    contents["word/_rels/document.xml.rels"] = ET.tostring(
        relationships, encoding="utf-8", xml_declaration=True
    )
    contents["[Content_Types].xml"] = ET.tostring(
        content_types, encoding="utf-8", xml_declaration=True
    )
    contents["word/settings.xml"] = ET.tostring(
        settings, encoding="utf-8", xml_declaration=True
    )
    contents["word/media/dashboard-overview.png"] = screenshot.read_bytes()

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, suffix=".docx", delete=False) as temp:
        temporary_output = Path(temp.name)
    try:
        with zipfile.ZipFile(temporary_output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in contents.items():
                archive.writestr(name, data)
        temporary_output.replace(output)
    finally:
        temporary_output.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("screenshot", type=Path)
    args = parser.parse_args()
    patch_document(args.source, args.output, args.screenshot)
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
