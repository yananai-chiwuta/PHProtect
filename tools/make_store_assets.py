"""Compose store assets from actual extension UI captures, not invented mockups."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / ".test-output"
OUT = ROOT / "store" / "assets"

def font(size, bold=False):
    names = [Path("C:/Windows/Fonts") / ("arialbd.ttf" if bold else "arial.ttf"),
             Path("/usr/share/fonts/truetype/liberation2") / ("LiberationSans-Bold.ttf" if bold else "LiberationSans-Regular.ttf")]
    for name in names:
        if name.exists():
            return ImageFont.truetype(str(name), size)
    return ImageFont.load_default(size=size)

def wrapped(draw, text, position, width, face, fill="#303134", gap=8):
    x, y = position
    words, line = text.split(), ""
    lines = []
    for word in words:
        candidate = (line + " " + word).strip()
        if line and draw.textlength(candidate, font=face) > width:
            lines.append(line)
            line = word
        else:
            line = candidate
    if line:
        lines.append(line)
    for line in lines:
        draw.text((x, y), line, font=face, fill=fill)
        y += face.size + gap
    return y

def screenshot(name, title, paragraphs, capture):
    image = Image.new("RGB", (1280, 800), "white")
    draw = ImageDraw.Draw(image)
    draw.text((60, 60), "PHProtect", font=font(22, True), fill="#202124")
    y = wrapped(draw, title, (60, 170), 510, font(34, True), gap=10) + 28
    for paragraph in paragraphs:
        y = wrapped(draw, paragraph, (60, y), 500, font(20), gap=9) + 23
    draw.text((60, 728), "Local test fixture. No real account or attack.", font=font(15), fill="#5f6368")
    shot = Image.open(CAPTURES / capture).convert("RGB")
    if shot.width > 500 or shot.height > 700:
        raise ValueError("Capture must use the actual popup/decision viewport")
    x, y = 1280 - 60 - shot.width, (800 - shot.height) // 2
    image.paste(shot, (x, y))
    draw.rectangle((x - 1, y - 1, x + shot.width, y + shot.height), outline="#dadce0")
    image.save(OUT / name)

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # The store listing has its own 96px artwork area on a 128px canvas.
    # Do not apply this padding to browser toolbar or extension-manager icons.
    icon = Image.open(ROOT / "src/icons/icon-128.png").convert("RGBA")
    store_icon = Image.new("RGBA", (128, 128), (0, 0, 0, 0))
    store_icon.alpha_composite(icon.resize((96, 96), Image.LANCZOS), (16, 16))
    store_icon.save(OUT / "icon-128.png", optimize=True)
    promo = Image.new("RGB", (440, 280), "#282b30")
    icon = Image.open(ROOT / "src/icons/icon-128.png").convert("RGBA")
    promo.paste(icon, (156, 45), icon)
    draw = ImageDraw.Draw(promo)
    text, face = "PHProtect", font(30, True)
    draw.text(((440 - draw.textlength(text, font=face)) / 2, 192), text, font=face, fill="white")
    promo.save(OUT / "promo-440x280.png")
    screenshot("screenshot-01.png", "Check the advertised PHP version.", [
        "Compare response-header evidence with the bundled PHP2Shell advisory.",
        "Headers can be hidden, stale or affected by vendor backports. This is a hint, not proof of compromise."
    ], "popup.png")
    screenshot("screenshot-02.png", "Review a supported wallet request.", [
        "Cancel a request before the wrapped provider receives it. High-risk continuation requires acknowledgement.",
        "Website hooks are best effort. PHProtect does not simulate transactions or verify the recipient."
    ], "warning.png")
    screenshot("screenshot-03.png", "Unknown stays unknown.", [
        "A missing version cannot establish whether a server is patched.",
        "Page signals are listed separately. No signals reported does not establish safety."
    ], "popup-unknown.png")
    screenshot("screenshot-04.png", "A cutoff is limited evidence.", [
        "The advertised version meets the published PHP2Shell cutoff.",
        "That does not verify the server, rule out compromise or make a website safe."
    ], "popup-cutoff.png")
    print("Store assets written to store/assets/")

if __name__ == "__main__":
    main()
