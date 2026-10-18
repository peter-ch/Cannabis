"""Check the built site's local links, fragments and documentation routes."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.ids, self.links = set(), []
        self.feed(text)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if 'id' in attrs:
            if attrs['id'] in self.ids:
                raise ValueError('Duplicate element id: ' + attrs['id'])
            self.ids.add(attrs['id'])
        for attr in ('href', 'src', 'poster'):
            if attrs.get(attr):
                self.links.append(attrs[attr])


def check(root):
    root = root.resolve()
    pages = {file: Page(file.read_text(encoding='utf-8')) for file in root.rglob('*.html')}
    errors, checked = [], 0
    for file, page in pages.items():
        for href in page.links:
            url = urlsplit(href)
            if url.scheme or url.netloc:
                continue
            checked += 1
            if url.path.startswith('/'):
                errors.append(f'{file.name}: root-relative link breaks project-site hosting: {href}')
                continue
            target = (file.parent / unquote(url.path)).resolve() if url.path else file
            if target.is_dir():
                target /= 'index.html'
            if not target.is_relative_to(root) or not target.is_file():
                errors.append(f'{file.relative_to(root)}: missing target {href}')
            elif target.suffix == '.md':
                errors.append(f'{file.relative_to(root)}: raw Markdown navigation {href}')
            elif url.fragment and target in pages and unquote(url.fragment) not in pages[target].ids:
                errors.append(f'{file.relative_to(root)}: missing section {href}')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'Checked {len(pages)} HTML pages and {checked} local links: no missing targets, broken sections or raw Markdown navigation.')


if __name__ == '__main__':
    check(Path(__file__).resolve().parents[1] / 'dist-site')
