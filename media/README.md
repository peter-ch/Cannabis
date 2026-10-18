# Cannabis media

Original brand artwork, English narrated films and technical illustrations for the Cannabis community.

- [Landscape introduction](https://peter-ch.github.io/Cannabis/media/series/00-crystal-introduction-landscape.mp4)
- [Portrait introduction](https://peter-ch.github.io/Cannabis/media/series/00-crystal-introduction-portrait.mp4)
- [Introduction transcript](series/00-crystal-introduction.txt) and [captions](series/00-crystal-introduction.srt)
- [Shareable campaign graphics](https://peter-ch.github.io/Cannabis/share.html)
- [Crystal collection](https://peter-ch.github.io/Cannabis/collection.html)
- [Computing architecture](https://peter-ch.github.io/Cannabis/network.html)
- [Documentation films](https://peter-ch.github.io/Cannabis/learn.html)

The twelve-image crystal collection includes landscape, square and portrait compositions. Download full-resolution artwork from the collection page. Crystal, metal and light are brand motifs.

The diagrams explain encrypted packaging, task dependencies, protected execution, client-side result assembly and payment settlement. Allocation and payment illustrations are collected in the [terms library](https://peter-ch.github.io/Cannabis/terms.html), with complete disclosures and illustrative pricing.

Films use H.264 video and AAC English narration, with readable captions. The documentation series includes downloadable SRT captions and browser WebVTT tracks. Render reports record dimensions, duration and file hashes. Publication checks validate available films against those reports.

Promotional films focus on community, useful computing and confidentiality. Allocation and payment explainers are available through the terms library. [distribution.json](distribution.json) records the intended placement of each film and financial diagram. Further editions appear after completion and review. Technical claims reflect the documented implementation and current launch status.

Internal creative briefs and production records are maintained separately from this public repository. The project name is Cannabis.

## Visual identity

Deep emerald, luminous crystal, warm white and a sharp lime accent connect the website, films and campaign graphics. Lead with a useful idea and a clear invitation. Keep the name Cannabis in visible copy, launch status legible, and participation terms linked.

Nine composed graphics cover three messages in landscape (1200 × 630), square (1080 × 1080) and portrait (1080 × 1920). The editable layout and local browser exporter are in [render-campaign.py](../scripts/render-campaign.py). Rebuild with `python scripts/render-campaign.py` using Python Playwright and Chromium. Exported files live in `web/assets/campaign/`. Original crystal PNGs remain downloadable; the site uses smaller WebP versions.
