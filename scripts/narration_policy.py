"""Shared spoken-name and narration/source consistency checks."""
import hashlib
import re
from pathlib import Path


def display_text(text):
    """Use the official name in visible copy while preserving spoken scripts."""
    return re.sub(r'\bCannabis coin\b', 'Cannabis', text, flags=re.IGNORECASE)


def validate_spoken_name(text):
    if re.search(r'\bCannabis\b(?! coin\b)', text, re.IGNORECASE):
        raise ValueError('Every spoken project reference must say "Cannabis coin"')
    return text


def validate_narration(text, metadata, wav=None):
    text = validate_spoken_name(text.strip())
    if metadata.get('text') != text:
        raise ValueError('Narration is outdated; regenerate the audio before rendering')
    digest = hashlib.sha256(text.encode()).hexdigest()
    if metadata.get('scriptSHA256') != digest:
        raise ValueError('Narration script hash does not match the current script')
    if '\n'.join(segment['text'] for segment in metadata['segments']) != text:
        raise ValueError('Narration segments do not match the current script')
    if wav is not None and hashlib.sha256(Path(wav).read_bytes()).hexdigest() != metadata.get('wavSHA256'):
        raise ValueError('Narration audio hash does not match its metadata')
    return digest
