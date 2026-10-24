"""Render the geometric app.svg design to PNG and multi-resolution Windows ICO."""
from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parents[1] / "assets"
scale = 4
im = Image.new("RGBA", (256 * scale, 256 * scale))
d = ImageDraw.Draw(im)
def points(values):
    return [(x * scale, y * scale) for x, y in values]
d.rounded_rectangle((32, 32, 992, 992), radius=224, fill="#101c30")
d.polygon(points([(128,34),(210,65),(210,129),(200,159),(174,190),(128,225),(82,190),(56,159),(46,129),(46,65)]), fill="#39c7ac")
d.polygon(points([(128,52),(194,77),(194,129),(184,153),(162,178),(128,207),(94,178),(72,153),(66,129),(66,77)]), fill="#162840")
d.line(points([(83,154),(83,96),(128,134),(173,96),(173,154)]), fill="#e8f3ff", width=64, joint="curve")
d.ellipse((156*scale,157*scale,230*scale,231*scale), fill="#f5ac5c")
d.line(points([(175,194),(187,206),(211,180)]), fill="#101c30", width=36, joint="curve")
im = im.resize((256,256), Image.Resampling.LANCZOS)
im.save(root / "app.png")
im.save(root / "app.ico", sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
