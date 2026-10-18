"""Export the Cannabis campaign layouts with local Chromium. No network requests.

Requires Python Playwright and its Chromium browser. Run from any directory:
python scripts/render-campaign.py
"""
import argparse
import hashlib
import html
import json
import zipfile
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'web/assets/campaign'
BUILD = ROOT / 'media/build/campaign'
FORMATS = {'landscape': (1200, 630), 'square': (1080, 1080), 'portrait': (1080, 1920)}
CAMPAIGNS = {
    'purpose': {
        'art': 'prestige', 'label': 'CURIOSITY IS A GOOD START.',
        'title': 'Grow like<br>nature. Power<br><em>what’s next.</em>',
        'copy': 'A currency for useful computing.<br>A community for people who make things happen.',
        'action': 'Be part of what’s next',
    },
    'compute': {
        'art': 'prism', 'label': 'PUT YOUR ENERGY INTO POSSIBILITY.',
        'title': 'Grow<br>something<br><em>useful.</em>',
        'copy': 'Open code. Useful work.<br>Help build a wider network for your ideas.',
        'action': 'Explore the network',
    },
    'community': {
        'art': 'aurora', 'label': 'GOOD IDEAS NEED GOOD COMPANY.',
        'title': 'Bring your<br>curiosity.<br><em>Leave a mark.</em>',
        'copy': 'Builders. Creators. Curious minds.<br>There’s room for you in Cannabis.',
        'action': 'Find your place',
    },
}
CSS = '''
*{box-sizing:border-box}body{margin:0;background:#07130f;color:#f1f3e9;font-family:'Segoe UI',Arial,sans-serif}
.canvas{width:100vw;height:100vh;position:relative;overflow:hidden;padding:48px 55px;background:radial-gradient(ellipse at 90% 80%,#244b2b88,transparent 65%),#07130f}
.brand{font-size:33px;letter-spacing:-1.4px;font-weight:600;position:relative;z-index:2}.brand span{color:#d3f891}.brand b{font-size:39px;margin-right:6px;vertical-align:middle;font-weight:400}
.copy{position:absolute;left:55px;top:136px;width:56%;z-index:2}.label{font-size:9px;letter-spacing:2px;color:#b9cbb3;font-weight:600}
h1{font-weight:500;font-size:76px;letter-spacing:-4.5px;line-height:.99;margin:22px 0}h1 em{font-style:normal;color:#d3f891}
.description{font-size:15px;line-height:1.7;color:#bdcdb9;margin:0}.action{display:inline-flex;align-items:center;gap:32px;background:#d3f891;color:#142514;border-radius:40px;font-size:12px;font-weight:600;padding:16px 22px;margin-top:25px}.action span{font-size:19px;line-height:1}
.art{position:absolute;right:48px;top:45px;width:43%;height:528px;overflow:hidden;border:1px solid #3a5b42;border-radius:160px 160px 26px 26px;box-shadow:0 0 90px #98df5220}.art img{width:100%;height:100%;object-fit:cover;object-position:center 53%}.art:after{content:'';position:absolute;inset:0;background:linear-gradient(transparent 68%,#061b12c0)}
.caption{position:absolute;bottom:26px;left:26px;color:#f1f3e9;font-size:10px;letter-spacing:2px;z-index:1}
.footer{position:absolute;bottom:22px;left:55px;right:55px;display:flex;justify-content:space-between;align-items:center;gap:20px;font-size:10px;letter-spacing:.2px;color:#b2c5af}.footer .status{display:flex;gap:8px;align-items:center}.dot{width:5px;height:5px;border-radius:50%;background:#d3f891}
.square .canvas{padding:55px}.square .copy{top:140px;width:70%}.square h1{font-size:106px;letter-spacing:-6px;margin:26px 0}.square .description{font-size:20px}.square .label{font-size:12px}.square .action{font-size:16px;padding:19px 28px;margin-top:30px}.square .art{top:390px;right:-105px;width:600px;height:665px;transform:rotate(-8deg);border-radius:180px 180px 28px 28px}.square .art img{transform:rotate(8deg) scale(1.14)}.square .copy{filter:drop-shadow(0 4px 20px #07130f)}.square .art:after{background:linear-gradient(90deg,#07130fbd,transparent 45%),linear-gradient(transparent 75%,#07130f)}.square .caption{display:none}.square .footer{font-size:13px;bottom:30px}.square .brand{font-size:41px}.square .brand b{font-size:47px}
.portrait .canvas{padding:85px 70px}.portrait .brand{font-size:50px}.portrait .brand b{font-size:57px}.portrait .copy{left:70px;top:225px;width:90%}.portrait .label{font-size:15px}.portrait h1{font-size:124px;letter-spacing:-7px;margin:38px 0}.portrait .description{font-size:25px}.portrait .action{font-size:21px;padding:24px 34px;margin-top:35px;gap:55px}.portrait .action span{font-size:27px}.portrait .art{top:850px;left:70px;right:70px;width:auto;height:900px;border-radius:280px 280px 35px 35px}.portrait .art img{object-position:center 53%}.portrait .caption{font-size:16px;left:35px;bottom:35px}.portrait .footer{left:70px;right:70px;bottom:85px;font-size:15px}.portrait .dot{height:7px;width:7px}
.community.square h1{font-size:98px}.community.portrait h1{font-size:116px}.compute .art img{object-position:56% center}
'''

def layout(name, format_name):
    item = CAMPAIGNS[name]
    image = (ROOT / f'web/assets/crystal-{item["art"]}.png').as_uri()
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Cannabis campaign</title><style>{CSS}</style></head><body class="{name} {format_name}"><main class="canvas"><div class="brand"><b>✳</b> Cannabis<span>.</span></div><div class="art"><img src="{html.escape(image, quote=True)}" alt="Emerald crystal artwork"><div class="caption">CANNABIS / BRILLIANT BY NATURE</div></div><div class="copy"><div class="label">{item['label']}</div><h1>{item['title']}</h1><p class="description">{item['copy']}</p><div class="action">{item['action']} <span>↗</span></div></div><div class="footer"><span class="status"><span class="dot"></span> Preparing mainnet launch</span><span>cannabis-coin.online</span></div></main></body></html>'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--only', choices=list(CAMPAIGNS))
    parser.add_argument('--format', choices=list(FORMATS))
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    records = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            for name in CAMPAIGNS:
                if args.only and name != args.only:
                    continue
                for format_name, (width, height) in FORMATS.items():
                    if args.format and format_name != args.format:
                        continue
                    source = BUILD / f'{name}-{format_name}.html'
                    source.write_text(layout(name, format_name), encoding='utf-8')
                    page = browser.new_page(viewport={'width': width, 'height': height}, device_scale_factor=1)
                    page.route('http://**', lambda route: route.abort())
                    page.route('https://**', lambda route: route.abort())
                    page.goto(source.as_uri(), wait_until='networkidle')
                    page.evaluate('document.fonts.ready')
                    assert page.locator('img').evaluate('(img) => img.complete && img.naturalWidth > 0')
                    target = OUT / f'{name}-{format_name}.png'
                    page.screenshot(path=str(target), animations='disabled')
                    if format_name == 'square':
                        page.screenshot(path=str(OUT / f'{name}-preview.jpg'), type='jpeg', quality=85, animations='disabled')
                    page.close()
                    records.append({'file': target.relative_to(ROOT).as_posix(), 'width': width, 'height': height,
                                    'sha256': hashlib.sha256(target.read_bytes()).hexdigest()})
                    print(target.name, flush=True)
        finally:
            browser.close()
    (BUILD/'exports.json').write_text(json.dumps(records, indent=2)+'\n', encoding='utf-8')
    files = [OUT / f'{name}-{format_name}.png' for name in CAMPAIGNS for format_name in FORMATS]
    if all(file.exists() for file in files):
        with zipfile.ZipFile(OUT / 'cannabis-graphics.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for file in files:
                info = zipfile.ZipInfo(file.name, (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                archive.writestr(info, file.read_bytes())

if __name__ == '__main__':
    main()
