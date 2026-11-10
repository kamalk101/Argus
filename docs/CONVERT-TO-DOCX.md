# Prompt: convert `PROJECT-REPORT.html` to a DOCX

Paste the block below into an AI that can run Python (or use it yourself), with
`docs/PROJECT-REPORT.html` attached or available on disk.

---

I have a single self-contained HTML report at `docs/PROJECT-REPORT.html`. Convert it into a
well-formatted Microsoft Word document saved as `docs/PROJECT-REPORT.docx`.

## Context you need

- The HTML is **self-contained**: one `<style>` block at the top, then `<h1>`, 19 `<h2>` sections
  (`id="s1"` … `id="s19"`), `<h3>`, `<h4>`, `<p>`, `<ol>`/`<ul>`, 16 `<table>`s, `<pre>` code blocks,
  and styled `<div class="card …">` / `<div class="qa">` callouts. No images, no external CSS, no JS.
- It is a study/viva document. Structure and readability matter more than fidelity to the dark theme.

## Requirements

1. **Use Python**, `pip install beautifulsoup4 python-docx` if needed. Do not hand-convert.
2. **Page setup:** A4, 2 cm margins, body text 10.5–11 pt (Calibri or Segoe UI), line spacing 1.15.
3. **Headings:** map `<h1>` → Word "Title" style, `<h2>` → "Heading 1", `<h3>` → "Heading 2",
   `<h4>` → "Heading 3". Keep the numbering that is already in the text (e.g. "7. Scope tracking").
4. **Tables:** convert every `<table>` into a real Word table with:
   - the header row in **bold** with a light grey shaded background and `repeat table header row` enabled;
   - autofit to the page width, borders on all cells, 8.5–9 pt text so wide tables do not overflow.
5. **Code:** `<pre>` blocks → a paragraph in a monospace font (Consolas 8.5 pt) with a light grey
   background and no spell-check marks; preserve line breaks and indentation exactly.
6. **Callouts:** `div.card` → a single-cell bordered table or an indented paragraph with a grey
   background. `div.qa` (28 of them) contain a question line (`.q`, bold) and an answer line (`.say`)
   plus an optional `.why` note in italics. Render each as:
   - **Q:** the question, bold, preceded by a bold label "Q:";
   - **A:** the answer, normal weight;
   - **Note:** the `.why` text, italic, 9 pt, only when present.
   Put a thin bottom border or 6 pt space after each Q&A block so they are visually separated.
7. **Table of contents:** after the title, insert a real Word TOC field
   (`TOC \o "1-2" \h \z \u`) so Word can regenerate page numbers on update. Do **not** copy the
   HTML's `<ol>` list of links.
8. **Cross-references:** convert internal `href="#s7"` style links to bookmarks + Word hyperlinks if
   easy; otherwise leave the link text as plain text. Do not produce broken links.
9. **Colours and inline styling:** drop the dark background. Keep semantic emphasis only:
   `<strong>`/`<b>` → bold, `<em>`/`<i>` → italic, `<code>` → Consolas 9 pt (optionally light grey
   shading). Ignore the CSS colour classes (`g`, `a`, `r`, `c`, `v`, `d`, `tag`), `<div class="kpi">`
   boxes and `.flow` chips — but keep their **text content**, converting KPI boxes into one small
   table (Number | Label) and the flow diagram into a single line of text with `→` separators.
10. **Header/footer:** add a footer with the document title and page numbers (`Page X of Y`).
    Add a document title on the first page: "Argus — project report and viva guide".
11. **Encoding:** write the file as DOCX with UTF-8 content; keep `—`, `→`, `×`, `≥`, `≤`, `π`, `Σ`
    intact. If a character is missing in the chosen font, keep the character (Word substitutes).
12. **Do not summarise, shorten or rewrite any sentence.** This is a document for study; every
    paragraph and every table row must appear. Do not invent content.

## Deliverable

- `docs/PROJECT-REPORT.docx`.
- After writing it, open the DOCX with `python-docx` again and **verify**:
  - the number of `Heading 1` paragraphs is exactly 19;
  - there are at least 16 tables;
  - at least 25 paragraphs containing "Q:" exist;
  - the document has no empty table cells in the first column of the rule table (section 8);
  - print the first 500 characters and the paragraph count so I can sanity-check it.
- Report anything you had to skip, and why.

---

## If you prefer a manual route (no AI)

```bash
# LibreOffice is the most reliable one-shot converter
soffice --headless --convert-to docx:"MS Word 2007 XML" --outdir docs docs/PROJECT-REPORT.html
```

Then in Word: update the table of contents (right-click → Update Field) and check that the wide
tables in sections 5 and 8 fit — set them to Landscape or reduce font to 8 pt if they overflow.
