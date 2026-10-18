"""Render landscape and portrait project teasers with FFmpeg; no hosted generation."""
import argparse
import json
import math
from pathlib import Path
import subprocess
import textwrap
import hashlib
from narration_policy import display_text, validate_narration

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'media/build'

def ass_time(seconds):
    cs = round(seconds * 100)
    return f'{cs // 360000}:{cs // 6000 % 60:02}:{cs // 100 % 60:02}.{cs % 100:02}'

def srt_time(seconds):
    ms = round(seconds * 1000)
    return f'{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02},{ms % 1000:03}'

def render(portrait, duration, segments, silent):
    name = 'portrait' if portrait else 'landscape'
    w, h = (1080, 1920) if portrait else (1920, 1080)
    out = ROOT / 'media' / f'cannabis-{name}{"-silent" if silent else ""}.mp4'
    font = 68 if portrait else 72
    caption_size = 44 if portrait else 38
    margin_v = 250 if portrait else 95
    header = f'''[Script Info]
ScriptType: v4.00+
PlayResX: {w}
PlayResY: {h}
WrapStyle: 0
[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Title,Arial,{font},&H00D7F4C3,&H000000FF,&H00102211,&H00000000,-1,0,0,0,100,100,0,0,1,3,1,8,70,70,{190 if portrait else 100},1
Style: Caption,Arial,{caption_size},&H00FFFFFF,&H000000FF,&H00121C13,&HAA000000,0,0,0,0,100,100,0,0,3,2,0,2,80,80,{margin_v},1
Style: Label,Arial,{24 if portrait else 22},&H00DCE9D8,&H000000FF,&H00121C13,&H00000000,0,0,0,0,100,100,1,0,1,2,0,8,50,50,{85 if portrait else 40},1
Style: Footer,Arial,{23 if portrait else 22},&H00E1E8DB,&H000000FF,&H00121C13,&H00000000,0,0,0,0,100,100,0,0,1,2,0,2,50,50,{95 if portrait else 35},1
[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
'''
    def event(start, end, style, text):
        return f'Dialogue: 0,{ass_time(start)},{ass_time(end)},{style},,0,0,0,,{{\\fad(180,180)}}{text}\n'
    text = header + event(0, duration, 'Label', 'CANNABIS / GROW SOMETHING WILD')
    text += event(0, duration, 'Footer', 'Public launch ahead.\\NOpen code. Visible rules.' if not silent else 'Public launch ahead.\\NOpen code. Visible rules.')
    titles = ['Cannabis.', 'Efficient by design.', '99% community.\\N1% founder vesting.', 'Privacy. Community.\\NBuild it together.']
    for i, title in enumerate(titles):
        text += event(duration * i / 4, duration * (i + 1) / 4, 'Title', title)
    for segment in segments:
        words = textwrap.wrap(display_text(segment['text']), width=34 if portrait else 75)
        text += event(segment['start'], segment['end'], 'Caption', '\\N'.join(words))
    ass = BUILD / f'{name}.ass'
    ass.write_text(text, encoding='utf-8-sig', newline='\n')
    args = ['ffmpeg', '-y', '-hide_banner', '-loglevel', 'warning']
    scene_frames = math.ceil(duration * 30 / 4)
    scene_duration = scene_frames / 30
    assets = ['hero.png', 'network.png', 'network.png', 'hero.png']
    for image in assets:
        args += ['-loop', '1', '-framerate', '30', '-t', str(scene_duration), '-i', str(ROOT / 'web/assets' / image)]
    if not silent:
        args += ['-i', str(ROOT / 'media/narration.wav')]
    chains = []
    for i in range(4):
        chains.append(f'[{i}:v]scale={w * 2}:{h * 2}:force_original_aspect_ratio=increase,crop={w * 2}:{h * 2},'
            f"zoompan=z='1.02+on*0.0001':x='iw/2-iw/zoom/2':y='ih/2-ih/zoom/2':d=1:s={w}x{h}:fps=30,"
            f'setsar=1,format=yuv420p,fade=t=in:st=0:d=0.22,fade=t=out:st={scene_duration - .22}:d=0.22,setpts=PTS-STARTPTS[v{i}]')
    chains.append('[v0][v1][v2][v3]concat=n=4:v=1:a=0,'
        f'drawbox=x=0:y=0:w=iw:h={350 if portrait else 260}:color=black@0.30:t=fill,'
        f'drawbox=x=0:y=ih-{520 if portrait else 270}:w=iw:h={520 if portrait else 270}:color=black@0.55:t=fill,'
        f"subtitles=media/build/{name}.ass[v]")
    args += ['-filter_complex', ';'.join(chains), '-map', '[v]']
    if not silent:
        args += ['-map', '4:a:0', '-af', 'loudnorm=I=-16:TP=-1.5:LRA=9', '-c:a', 'aac', '-b:a', '192k']
    pending = BUILD / (out.stem + '.pending.mp4')
    args += ['-t', str(duration), '-c:v', 'libx264', '-preset', 'fast', '-crf', '21', '-threads', '6',
        '-pix_fmt', 'yuv420p', '-movflags', '+faststart', str(pending)]
    print(f'Rendering {name}: {duration:.1f}s', flush=True)
    subprocess.run(args, cwd=ROOT, check=True)
    probe = json.loads(subprocess.check_output(['ffprobe', '-v', 'error', '-show_streams', '-show_format', '-of', 'json', str(pending)]))
    videos = [s for s in probe['streams'] if s['codec_type'] == 'video']
    audios = [s for s in probe['streams'] if s['codec_type'] == 'audio']
    if len(videos) != 1 or len(audios) != (0 if silent else 1) or (videos[0]['width'], videos[0]['height'], videos[0]['codec_name']) != (w, h, 'h264') or abs(float(probe['format']['duration']) - duration) > .15:
        raise RuntimeError('Unexpected video export')
    if not silent and (audios[0]['codec_name'] != 'aac' or abs(float(audios[0]['duration']) - duration) > .15):
        raise RuntimeError('Narration does not cover the complete film')
    pending.replace(out)
    if not silent:
        text = (ROOT / 'media/narration.txt').read_text(encoding='utf-8').strip()
        report = {'scriptSHA256': hashlib.sha256(text.encode()).hexdigest(), 'voiceSHA256': hashlib.sha256((ROOT / 'media/narration.wav').read_bytes()).hexdigest(), 'sha256': hashlib.sha256(out.read_bytes()).hexdigest(), 'bytes': out.stat().st_size, 'seconds': float(probe['format']['duration']), 'width': w, 'height': h, 'audio': 'English narration only'}
        report['captionsSHA256'] = hashlib.sha256((ROOT / 'media/captions.srt').read_bytes()).hexdigest()
        out.with_suffix('.render.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(out, flush=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--silent', action='store_true')
    parser.add_argument('--format', choices=['both', 'landscape', 'portrait'], default='both')
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    if args.silent:
        duration = 30
        sentences = ['Meet Cannabis. A bold idea. A community ready to grow.',
            'Open code. Big character. Bring your ideas.',
            '99% for community claims. 1% founder allocation vested over 24 months.',
            'The public launch is ahead. Help shape the next chapter.']
        segments = [{'start': i * 7.5, 'end': (i + 1) * 7.5, 'text': t} for i, t in enumerate(sentences)]
    else:
        data = json.loads((ROOT / 'media/narration.json').read_text(encoding='utf-8'))
        validate_narration((ROOT / 'media/narration.txt').read_text(encoding='utf-8'), data, ROOT / 'media/narration.wav')
        duration = data['seconds']
        segments = data.get('segments')
        if not segments:
            raise RuntimeError('Narration must include segment timings for accurate captions')
        srt = '\n\n'.join(f'{i + 1}\n{srt_time(s["start"])} --> {srt_time(s["end"])}\n{display_text(s["text"])}' for i, s in enumerate(segments))
        (ROOT / 'media/captions.srt').write_text(srt + '\n', encoding='utf-8', newline='\n')
    for portrait in ([False, True] if args.format == 'both' else [args.format == 'portrait']):
        render(portrait, duration, segments, args.silent)

if __name__ == '__main__':
    main()
