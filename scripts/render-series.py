"""Assemble silent Animation footage, stable diagrams and local narration into captioned films."""
import argparse,hashlib,json,subprocess,textwrap
from fractions import Fraction
from pathlib import Path
from narration_policy import display_text, validate_narration

ROOT=Path(__file__).resolve().parents[1]
SERIES=ROOT/'media/series'
BUILD=SERIES/'build'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def ass_time(t):
    n=round(t*100);return f'{n//360000}:{n//6000%60:02}:{n//100%60:02}.{n%100:02}'
def srt_time(t):
    n=round(t*1000);return f'{n//3600000:02}:{n//60000%60:02}:{n//1000%60:02},{n%1000:03}'

def clip_motion_filters(i,count,flowing,source_index=None,head_index=None):
    source_index=i if source_index is None else source_index
    if flowing:
        # Keep water flowing forward. Blend the last half-second into the first,
        # then repeat the middle plus the blend; both loop boundaries match.
        # Independent demux inputs avoid a split/trim framesync deadlock.
        if head_index is None:raise ValueError('Flowing scenes require an independent head input')
        n=12
        filters=[f'[{head_index}:v]fps=24,format=yuv444p,trim=end_frame={n},setpts=PTS-STARTPTS[h{i}]',
                 f'[{source_index}:v]fps=24,format=yuv444p,trim=start_frame={n},setpts=PTS-STARTPTS[b{i}]',
                 f'[b{i}][h{i}]xfade=transition=fade:duration={n/24}:offset={(count-2*n)/24:.9f},format=yuv420p,loop=loop=-1:size={count-n}:start=0,setpts=N/(24*TB)[motion{i}]']
        return filters,'forward motion with half-second seam crossfade'
    return [f'[{source_index}:v]fps=24,split=2[forward{i}][backward{i}]',
            f'[backward{i}]reverse[reversed{i}]',
            f'[forward{i}][reversed{i}]concat=n=2:v=1:a=0,loop=loop=-1:size={2*count}:start=0,setpts=N/(24*TB)[motion{i}]'], 'forward/reverse with matched endpoints'

def verify_film(path,w,h,duration):
    probe=json.loads(subprocess.check_output(['ffprobe','-v','error','-show_streams','-show_format','-of','json',str(path)]))
    videos=[s for s in probe['streams'] if s['codec_type']=='video']
    audios=[s for s in probe['streams'] if s['codec_type']=='audio']
    if len(probe['streams'])!=2 or len(videos)!=1 or len(audios)!=1:
        raise RuntimeError('Expected one video and one local narration stream')
    video,audio=videos[0],audios[0]
    if (video['width'],video['height'],video['codec_name'],video['pix_fmt'])!=(w,h,'h264','yuv420p'):
        raise RuntimeError('Unexpected video dimensions or encoding')
    if Fraction(video['avg_frame_rate'])!=24 or audio['codec_name']!='aac':
        raise RuntimeError('Unexpected frame rate or narration encoding')
    seconds=float(probe['format']['duration'])
    if abs(seconds-duration)>.15 or abs(float(video['duration'])-duration)>.15 or abs(float(audio['duration'])-duration)>.15:
        raise RuntimeError('Video and narration must cover the complete film')
    return {'seconds':seconds,'width':w,'height':h,'fps':24,'videoCodec':'h264','audioCodec':'aac','audioStreams':1}

def captions(meta):
    result=[]
    for s in meta['segments']:
        words=display_text(s['text']).split();chunks=[words[i:i+11] for i in range(0,len(words),11)];offset=0
        for chunk in chunks:
            start=s['start']+(s['end']-s['start'])*offset/len(words);offset+=len(chunk)
            end=s['start']+(s['end']-s['start'])*offset/len(words)
            result.append({'start':start,'end':end,'text':' '.join(chunk)})
    return result

def render(film,meta,portrait,allow_stills=False):
    script_digest=validate_narration('\n'.join(film['lines']),meta,SERIES/(film['id']+'.wav'))
    fmt='portrait' if portrait else 'landscape';w,h=(1080,1920) if portrait else (1920,1080)
    target=SERIES/f"{film['id']}-{fmt}.mp4";report=SERIES/f"{film['id']}-{fmt}.render.json"
    pending=BUILD/f"{film['id']}-{fmt}.pending.mp4"
    duration=meta['seconds']+.35;inputs=[];kinds=[]
    for art in film['art']:
        if portrait:
            art={'crystal-dawn':'crystal-aurora','crystal-prism':'crystal-monolith','crystal-crown':'crystal-aurora',
                 'crystal-tide':'crystal-waterfall','crystal-dew':'crystal-waterfall','crystal-facets':'crystal-monolith'}.get(art,art)
        if art.startswith('compute-'):
            inputs.append(ROOT/f'web/assets/diagrams/{art}.png');kinds.append('diagram')
        else:
            clip=SERIES/f'broll/{art}.mp4'
            if clip.exists():inputs.append(clip);kinds.append('animation')
            elif allow_stills:inputs.append(ROOT/f'web/assets/{art}.png');kinds.append('still')
            else:raise FileNotFoundError('Animation footage is not ready: '+str(clip))
    signature=hashlib.sha256(json.dumps({'script':sha(__file__),'captionPolicy':sha(Path(__file__).with_name('narration_policy.py')),'film':film,'meta':meta,'sources':[sha(p) for p in inputs],'voice':sha(SERIES/(film['id']+'.wav')),'format':fmt},sort_keys=True).encode()).hexdigest()
    if target.exists() and report.exists():
        previous=json.loads(report.read_text())
        if previous.get('signature')==signature and previous.get('sha256')==sha(target):
            print('Already assembled',target.name,flush=True);return
    chunks=captions(meta)
    (SERIES/(film['id']+'.srt')).write_text('\n\n'.join(f'{i+1}\n{srt_time(s["start"])} --> {srt_time(s["end"])}\n{s["text"]}' for i,s in enumerate(chunks))+'\n',encoding='utf-8', newline='\n')
    (SERIES/(film['id']+'.vtt')).write_text('WEBVTT\n\n'+'\n\n'.join(f'{srt_time(s["start"]).replace(",", ".")} --> {srt_time(s["end"]).replace(",", ".")}\n{s["text"]}' for s in chunks)+'\n',encoding='utf-8', newline='\n')
    heading=70 if portrait else 64;caption=48 if portrait else 43
    ass=f'''[Script Info]
ScriptType: v4.00+
PlayResX: {w}
PlayResY: {h}
WrapStyle: 0
[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Title,Segoe UI,{heading},&H00E9F3F1,&H000000FF,&H00152312,&H00000000,-1,0,0,0,100,100,0,0,1,2,0,8,65,65,{170 if portrait else 90},1
Style: Label,Segoe UI,{26 if portrait else 25},&H0091F8D3,&H000000FF,&H00152312,&H00000000,0,0,0,0,100,100,2,0,1,2,0,8,55,55,{90 if portrait else 40},1
Style: Caption,Segoe UI,{caption},&H00FFFFFF,&H000000FF,&H00152312,&HAA000000,0,0,0,0,100,100,0,0,3,2,0,2,65,65,{290 if portrait else 125},1
Style: Footer,Segoe UI,{24 if portrait else 23},&H0091F8D3,&H000000FF,&H00152312,&H00000000,0,0,0,0,100,100,0,0,1,2,0,2,50,50,{110 if portrait else 40},1
[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
'''
    def event(a,b,style,text):return f'Dialogue: 0,{ass_time(a)},{ass_time(b)},{style},,0,0,0,,{text}\n'
    ass+=event(0,duration,'Label','CANNABIS / '+film['id'][:2])
    ass+=event(0,duration,'Title','\\N'.join(textwrap.wrap(display_text(film['title']),width=24 if portrait else 46)))
    ass+=event(0,duration,'Footer','cannabis-coin.online\\NPreparing mainnet launch · Grow like nature. Power what’s next.')
    for s in chunks:ass+=event(s['start'],s['end'],'Caption','\\N'.join(textwrap.wrap(s['text'],width=34 if portrait else 76)))
    subtitle=BUILD/f"{film['id']}-{fmt}.ass";subtitle.write_text(ass,encoding='utf-8-sig', newline='\n')
    args=['ffmpeg','-y','-hide_banner','-loglevel','warning','-filter_complex_threads','2']
    spans=[];source_indices=[];input_count=0
    for i,(p,kind) in enumerate(zip(inputs,kinds)):
        start=meta['segments'][i]['start'];end=meta['segments'][i+1]['start'] if i+1<len(inputs) else duration
        seconds=end-start;spans.append(seconds)
        # Animation inputs must be finite: reverse needs their end. Loop matched endpoints
        # in the filter graph, avoiding a camera jump from the last frame to the first.
        args+=([] if kind=='animation' else ['-loop','1','-framerate','24'])+['-i',str(p)]
        main_index=input_count;input_count+=1;head_index=None
        if kind=='animation' and p.stem in {'crystal-waterfall','crystal-tide','crystal-dew'}:
            head_index=input_count;input_count+=1;args+=['-i',str(p)]
        source_indices.append((main_index,head_index))
    args+=['-i',str(SERIES/(film['id']+'.wav'))]
    filters=[];loop_modes=[]
    for i,(kind,seconds) in enumerate(zip(kinds,spans)):
        if kind=='diagram':
            # Keep text in diagrams undistorted and clear of titles/captions.
            area_w,area_h=(w-50,800) if portrait else (w-100,650)
            fit=f'scale={area_w}:{area_h}:force_original_aspect_ratio=decrease,pad={w}:{h}:(ow-iw)/2:(oh-ih)/2:color=0x092116'
        else:
            fit=f'scale={w}:{h}:force_original_aspect_ratio=increase,crop={w}:{h}'
        if kind=='animation':
            source=json.loads(subprocess.check_output(['ffprobe','-v','error','-count_frames','-select_streams','v:0','-show_entries','stream=avg_frame_rate,nb_read_frames','-of','json',str(inputs[i])]))['streams'][0]
            count=int(source['nb_read_frames'])
            if Fraction(source['avg_frame_rate'])!=24 or count!=121:raise RuntimeError('Expected the reviewed 121-frame animation at 24 fps')
            # Buffer at the native shot resolution, before upscaling, to limit memory.
            main_index,head_index=source_indices[i]
            motion,mode=clip_motion_filters(i,count,head_index is not None,main_index,head_index)
            filters.extend(motion);loop_modes.append(mode)
            start_filter=f'[motion{i}]'
        else:start_filter=f'[{source_indices[i][0]}:v]fps=24,';loop_modes.append('static')
        filters.append(f'{start_filter}{fit},setsar=1,format=yuv420p,trim=duration={seconds:.4f},setpts=PTS-STARTPTS,fade=t=in:st=0:d=0.2,fade=t=out:st={max(0,seconds-.2):.4f}:d=0.2[v{i}]')
    filters.append(''.join(f'[v{i}]' for i in range(len(inputs)))+f'concat=n={len(inputs)}:v=1:a=0[joined]')
    top,bottom=(400,570) if portrait else (200,205)
    alpha=f'if(lt(Y,{top}),110*(1-Y/{top}),if(gt(Y,H-{bottom}),165*(Y-(H-{bottom}))/{bottom},0))'
    # A narrow gradient expanded horizontally avoids processing a full-size alpha expression.
    filters.append(f"color=c=black:s=2x{h}:r=24:d={duration},format=rgba,geq=r=0:g=0:b=0:a='{alpha}',scale={w}:{h}[shade]")
    filters.append(f'[joined][shade]overlay=shortest=1,subtitles=media/series/build/{subtitle.name}[v]')
    args+=['-filter_complex',';'.join(filters),'-map','[v]','-map',f'{input_count}:a:0','-af','apad,loudnorm=I=-16:TP=-1.5:LRA=9','-t',str(duration),'-c:v','libx264','-preset','fast','-crf','22','-threads','4','-pix_fmt','yuv420p','-c:a','aac','-b:a','160k','-movflags','+faststart',str(pending)]
    print('Assembling',target.name,flush=True);subprocess.run(args,cwd=ROOT,check=True)
    verified=verify_film(pending,w,h,duration)
    result={'signature':signature,'scriptSHA256':script_digest,'voiceSHA256':sha(SERIES/(film['id']+'.wav')),'sources':[str(p.relative_to(ROOT)).replace('\\','/') for p in inputs],'sourceKinds':kinds,'motionLoops':loop_modes,'audio':'English narration only',**verified,'bytes':pending.stat().st_size,'sha256':sha(pending),'captionTiming':'proportional within narration segments'}
    result['captionsSHA256']={extension:sha(SERIES/(film['id']+'.'+extension)) for extension in ['srt','vtt']}
    pending_report=BUILD/(report.name+'.pending')
    pending_report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8', newline='\n')
    pending.replace(target);pending_report.replace(report)

def main():
    p=argparse.ArgumentParser();p.add_argument('--only');p.add_argument('--format',choices=['both','landscape','portrait'],default='both');p.add_argument('--allow-stills',action='store_true',help='Explicitly permit static artwork where Animation footage is unavailable');p.add_argument('--skip-unready',action='store_true');args=p.parse_args()
    BUILD.mkdir(exist_ok=True,parents=True)
    for film in json.loads((SERIES/'scripts.json').read_text())['films']:
        if args.only and args.only!=film['id']:continue
        try:
            meta=json.loads((SERIES/(film['id']+'.json')).read_text())
            for portrait in ([False,True] if args.format=='both' else [args.format=='portrait']):render(film,meta,portrait,args.allow_stills)
        except FileNotFoundError:
            if not args.skip_unready:raise
            print('Not ready',film['id'],flush=True)

if __name__=='__main__':main()
