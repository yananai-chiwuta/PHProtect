"""Generate a local, dependency-free privacy page from PRIVACY.md."""
import html
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def render():
    lines = (ROOT / "PRIVACY.md").read_text(encoding="utf-8").splitlines()
    blocks, paragraph, in_list = [], [], False
    def flush():
        if paragraph:
            blocks.append("<p>" + html.escape(" ".join(paragraph)) + "</p>")
            paragraph.clear()
    for line in lines:
        if line.startswith("# "):
            flush()
            blocks.append("<h1>" + html.escape(line[2:]) + "</h1>")
        elif line.startswith("## "):
            flush()
            if in_list:
                blocks.append("</ul>")
                in_list = False
            blocks.append("<h2>" + html.escape(line[3:]) + "</h2>")
        elif line.startswith("- "):
            flush()
            if not in_list:
                blocks.append("<ul>")
                in_list = True
            blocks.append("<li>" + html.escape(line[2:]) + "</li>")
        elif not line.strip():
            flush()
            if in_list:
                blocks.append("</ul>")
                in_list = False
        else:
            paragraph.append(line)
    flush()
    if in_list:
        blocks.append("</ul>")
    page = '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PHProtect Privacy Policy</title><link rel="stylesheet" href="theme.css"><link rel="stylesheet" href="help.css"></head><body><div class="shell policy"><header><a class="brand" href="help.html">PHProtect</a><a href="help.html">Help</a></header><main>' + "\n".join(blocks) + '</main></div></body></html>\n'
    (ROOT / "src" / "privacy.html").write_text(page, encoding="utf-8", newline="\n")

if __name__ == "__main__":
    render()
