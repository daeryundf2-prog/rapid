# RapidTriage Community Feedback Intake

This note captures public practitioner feedback from Reddit, Forensic Focus, and Stack Overflow-style performance discussions and turns it into product requirements for RapidTriage.

## Feedback Themes

- Fast first pass matters. Practitioners repeatedly warn that enabling every parser/module up front can waste hours or days, especially on large images, Outlook/PST/OST, volume shadows, carving, and indexing-heavy work.
- Easy UI is valuable, but opaque processing is dangerous. Users like quick triage views, but they distrust tools that report success while hiding parser failures, missing evidence, or ambiguous source names.
- Reports must be selective. A report that dumps every column, every attachment, or tens of thousands of irrelevant rows is not usable for attorneys, detectives, reviewers, or court.
- Portable/review cases are useful when they preserve integrity boundaries. Reviewers should tag and comment without needing to handle the original image, while the examiner keeps the authoritative evidence and hash trail.
- Search must be indexed and scoped. Large-case keyword search should avoid repeated full scans and must allow source, path, type, and status filters.

## Sources Reviewed

- Reddit r/computerforensics: AXIOM discussion on triage value, memory-analysis limits, source validation, and hidden failures. Source: https://www.reddit.com/r/computerforensics/comments/126ot8k/axiom/
- Reddit r/computerforensics: Autopsy/large image processing discussion where users recommend not enabling every module for first pass. Source: https://www.reddit.com/r/computerforensics/comments/1ogp9sy/is_this_normal/
- Reddit r/computerforensics: AXIOM reporting discussion where legal users struggle with noisy, unprintable exports. Source: https://www.reddit.com/r/computerforensics/comments/kaed02/magnet_axiom_producing_a_report/
- Reddit r/computerforensics: portable case discussions around artifact-only review, tagging, and original-image boundaries. Sources: https://www.reddit.com/r/computerforensics/comments/wxpper/asking_for_advice_on_sharing_axiom_portable_cases/ and https://www.reddit.com/r/computerforensics/comments/v7rnj8/should_i_be_able_to_create_an_axiom_portable_case/
- Forensic Focus: AXIOM review highlighting source hyperlinks, artifact filters, tagging, report-by-tag, portable cases, and conversation/media views. Source: https://www.forensicfocus.com/reviews/axiom-2-5-from-magnet-forensics/
- Forensic Focus forums: processing bottlenecks around uninitialized areas, Outlook/PST/OST, volume shadows, and long-running single-threaded work. Source: https://www.forensicfocus.com/forums/general/whats-with-magnet-axiom-and-being-stuck-during-processing/
- Stack Overflow: FTS/search discussions reinforcing that `%LIKE%` scans do not scale once data grows into hundreds of thousands or millions of rows. Source: https://stackoverflow.com/questions/79468456/sqlite-search-optimization-across-multiple-tables-with-fts5

## Product Changes Already Applied

- Added `Check evidence support` before running a case so users know whether an image can be handled directly or must be mounted/exported first.
- Added whole-case search filters for source, extension, and path fragments.
- Added on-demand source metadata/hash computation in the viewer instead of hashing every large file automatically.
- Added bounded table pagination, compare tray, review board, selected report candidates, and submission hash manifest in earlier work.
- Added web run processing profiles: `Fast first pass`, `Standard`, and `Deep`, with visible extraction caps.

## Next Backlog From Feedback

- Add parser warning badges in the UI: no silent success when a provider found zero rows, errored, or was skipped.
- Add a processing profile summary to every run report: what was included, skipped, capped, and intentionally deferred.
- Add saved searches and reusable keyword packs per case.
- Add report templates that hide noisy metadata by default and expose full technical metadata in an appendix.
- Add portable reviewer bundle: static HTML/JSON review package with selected artifacts, thumbnails/previews, hashes, and no original image.
- Add a high-risk source-name warning when evidence display names are ambiguous or point at a host drive instead of the intended exhibit.
