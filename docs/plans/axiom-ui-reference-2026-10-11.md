# Magnet AXIOM Examine 9.11 (Korean UI) - UI Reference from Screenshots

Date: 2026-10-11. Source: `axiom-10.png` to `axiom-55.png` (46 frames, 1920x1080) in the agent scratchpad. Read-only; nothing was run, clicked or captured.

Scope note: the scratchpad also holds `axiom-1.png` to `axiom-3.png`. They are outside the requested range and are not covered here.

Mapping caveat: the Read tool returned images without filenames, and several frames came back with their image removed and had to be re-read. Only frames whose content was unambiguous are attributed below. The file-to-view column is therefore marked "verified" (content unambiguous) or "unverified" (view identified from content, but the file number could not be confirmed).

## 1. File to view table

Views are identified from the visible content. "dup" marks a frame showing the same view as another frame.

| File | Shows | Mapping |
|---|---|---|
| axiom-10 | Claude desktop app "Artifacts" home (not AXIOM) | verified |
| axiom-11 | Claude desktop chat "Lumos" (not AXIOM) | verified |
| axiom-12 | Claude usage settings page (not AXIOM) | verified |
| axiom-13 | AXIOM case dashboard (케이스 대시보드) | verified |
| axiom-14 | Artifacts tree (아티팩트), 14,007 documents, agentlog.txt, preview "찾기" | unverified |
| axiom-15 | Artifacts view, agentlog.txt with the same detail pane | unverified (dup of 14) |
| axiom-16 | RapidForensic web UI on 127.0.0.1:8791 overlaid on AXIOM (not AXIOM view) | unverified |
| axiom-17 | 파일 시스템 view, evidence "260807_ssd.E01" loading | unverified |
| axiom-18 | 파일 시스템 view, 5 partitions listed | unverified |
| axiom-19 | 레지스트리 view, loading registry details (0 items) | unverified |
| axiom-20 | 레지스트리 view, hives COMPONENTS/DEFAULT/SAM/SECURITY/SOFTWARE/SYSTEM | unverified |
| axiom-21 | 타임라인 view, "타임라인 구축" build dialog | unverified |
| axiom-22 | 미디어 탐색기 view, 1,762,839 results, thumbnails, 열 보기 menu | unverified |
| axiom-23 | 미디어 탐색기 view, thumbnail grid with preview | unverified |
| axiom-24 | Artifacts (아티팩트) view, 운영 체제 category, B0EE6193 volume info | unverified |
| axiom-25 | Artifacts view, LNK 파일 list with 연결된 경로 column | unverified |
| axiom-26 | Artifacts view, agentlog.txt with 세부 정보 | verified |
| axiom-27 | Artifacts view, 운영 체제 category, B0EE6193 detail | verified |
| axiom-28 | Artifacts view, LNK 파일 list loading (filter applying) | verified |
| axiom-29 | Artifacts view, LNK entry detail "1628-03-03" | verified |
| axiom-30 | Artifacts view, 연결된 경로 folder detail C:\Users\admin\Desktop\주간업무보고 | unverified |
| axiom-31 | Artifacts view, 열 보기 with date columns | unverified |
| axiom-32 | Artifacts view, 태그 및 주석 pane open | unverified |
| axiom-33 | Artifacts view, folder detail with Net Bios / MAC fields | unverified (dup of 30) |
| axiom-34 | 열 보기 dropdown (경로 보기 / 대화 보기 / 세계지도 보기 / 열 보기 / 축소판 그림 보기 / 클래식 보기 / 행 보기 / 히스토그램 보기) | unverified |
| axiom-35 | 미디어 탐색기 thumbnail grid with sort menu | unverified |
| axiom-36 | 미디어 탐색기 preview of pagefile.sys entry | unverified |
| axiom-37 | 히스토그램 view, LNK 파일 1,543 | unverified |
| axiom-38 | 히스토그램 view, LNK 파일 1,543 (dup of 37) | unverified |
| axiom-39 | Artifacts view with 아티팩트 category dropdown (Alt+1 to Alt+7 views) | verified |
| axiom-40 | Artifacts view, 파일 시스템 menu list | verified |
| axiom-41 | 레지스트리 dropdown menu open | unverified |
| axiom-42 | 타임라인 view, build dialog | unverified (dup of 21) |
| axiom-43 | 파일 시스템 view, evidence loading | unverified (dup of 17) |
| axiom-44 | 파일 시스템 view, evidence list | unverified (dup of 16/17) |
| axiom-45 | 파일 시스템 view, partition list | unverified (dup of 18) |
| axiom-46 | 레지스트리 view, hive tree | unverified |
| axiom-47 | 히스토그램 view, 아티팩트 category dropdown open | verified |
| axiom-48 | 파일 시스템 view, evidence list | unverified (dup) |
| axiom-49 | 파일 시스템 view, 5 partitions | unverified (dup) |
| axiom-50 | 히스토그램 view, LNK 파일 1,543 with category list | unverified (dup) |
| axiom-51 | 레지스트리 view, empty loading state | verified |
| axiom-52 | 레지스트리 view, hive tree with 증거 1 | verified |
| axiom-53 | 타임라인 view, build dialog | verified |
| axiom-54 | 파일 시스템 view, evidence list | verified |
| axiom-55 | 파일 시스템 view, 5 partitions | verified |

## 2. Distinct views and their layout

Window: about 1600x950 at the top-left of the screen. Title bar reads "Magnet Axiom Examine v9.11.0.47760 - 260807_ssd [라이선스: Axiom Essentials (증굴)]". The screen footer shows timezone "시간대 UTC+9:00" at bottom-right.

Common chrome (all views):
- Menu bar: 파일(F), 도구, 프로세스, 도움말(H).
- Toolbar: 필터, 증거, 아티팩트, 콘텐츠 유형, 날짜 및 시간, 태그 및 주석, 비슷한 사진, 더 많은 내용. Search box top-right with 이동 button and 고급 link.
- Left navigation: collapse arrows at top-left; a home icon (집) plus a view-switcher dropdown.
- Three-column body: left nav approx 100-493 px, center list approx 519-1127 px, right details pane approx 1150-1630 px. Left nav takes about 20% of the window, the center list about 35%, the details pane about 30%.
- Status bar: 시간대 UTC+9:00 at bottom-right.

### 2a. Case dashboard (케이스 대시보드)
- Layout: four columns (케이스 개요 / 증거 개요 / 시작할 곳), with a left vertical section list.
- Left list: 케이스 개요 (selected), 이벤트 스냅샷 (0), 증거 소스 (1), 인사이트, 잠재적인 클라우드 증거 리드 (0).
- 케이스 개요 cards: 케이스 요약 노트, 케이스 처리 세부 내용 (scan date, examiner), 케이스 내보내기/보고서 (table of export name, type, date, status), MAGNET REVIEW promo.
- 증거 개요: evidence card "260807_SSD.E01 (1,762,839)" with 증거 번호, 설명, 위치, 플랫폼, 프로세싱 방식.
- 시작할 곳: 아티팩트 범주 bar list (운영 체제 1,084,239; 맞춤형 289,374; 미디어 226,698; 웹 관련 120,304; ...); 태그 및 주석 table (증거 red, 북마크 green, 예외 orange); 키워드 일치 table.

### 2b. Artifacts explorer (아티팩트)
- Left nav: category tree grouped by 아티팩트 category. Groups seen: 웹 관련 (120,304), 커뮤니케이션 (34), 미디어 (226,698) expanded to AMR 파일 4, 오디오 671, Carved Audio 1,064, Photoshop Files 327, 사진 223,508, 잠재 Facebook 사진 11, 동영상 1,112, 웹 비디오 조각 1; 이메일 및 캘린더 (16,315); 문서 (14,007) expanded to CSV 281, 한글 워드 프로세서 5, Excel 442, Office Backstage 164, PowerPoint 34, Sticky Notes 11, Word 157, OpenOffice 4, PDF 5,073, RTF 3,110, 텍스트 문서 4,724, WordPerfect 2; 추가 소스 4; 클라우드 저장소 1; 애플리케이션 사용량 451; 운영 체제 1,084,239 expanded to $LogFile 분석 10,587, AmCache group, 자동 실행 항목 443, LNK 파일 1,543, MRU group, MUICache 463, 네트워크 group, NTFS 타임스탬프 불일치 903; 암호화 & 로그인 정보 209; 연결된 디바이스 273.
- Each category shows a right-aligned count in bold; parent counts are bold and children are regular weight. Selected category row is highlighted blue; checked categories show a blue background across the group.
- Center list (artifact table): columns 아티팩트 (icon + 문서 / 텍스트 문서), 주요 세부 정보 (파일 이름 / 연결된 경로), 원본 세부 정보 (크기 바이트 etc.), with more date/time columns available (생성한 날짜/시간, 마지막 수정 날짜/시간, 액세스한 날짜/시간, 대상 파일 생성 날짜). Two-line rows: the top line is the artifact type, the second the value. Row density is about 50 px. Selection is light blue.
- Red flag chip at left of row = 증거 tag; green bar = 북마크; orange = 예외 (not visible in the rows shown).
- View switcher above the list: 열 보기 dropdown with 경로 보기 (Alt+Shift+1), 대화 보기 (Alt+Shift+2), 세계지도 보기 (Alt+Shift+3), 열 보기 (Alt+Shift+4), 축소판 그림 보기 (Alt+Shift+5), 클래식 보기 (Alt+Shift+6), 행 보기 (Alt+Shift+7), 히스토그램 보기 (Alt+Shift+8).
- Right details pane: header is the artifact name (e.g. agentlog.txt); a yellow info bar says "이 항목에 대한 일부 정보를 표시할 수 없습니다. 소스 찾기" when the source is unavailable. Sections in order: 증거 source (260807_ssd.E01), 미리 보기 (preview with "찾기" link; text preview with timestamp log line), 세부 정보 (아티팩트 정보: 파일 이름, 크기, 수정/액세스/생성 날짜/시간 with clock icons, MD5 해시, SHA1 해시, 유형 with icon). For LNK items: 대상 파일 정보 (대상 특성, 명령 표시, 대상 파일 크기, 유형, 항목 ID), 증거 정보 (소스 link, 복구 방법 "카빙" or "파싱됨", 삭제된 출처, 위치 "File Offset ...", 증거 번호).
- Source link in 증거 정보 is blue underlined text.
- Right-pane pinned/collapse controls at top-right; a vertical side tab labeled "관심 항목 / 태그" appears in the far right edge.

### 2c. Registry (레지스트리)
- Left nav: tree 모든 증거 > 260807_ssd.E01 > hives COMPONENTS, DEFAULT, SAM, SECURITY, SOFTWARE, SYSTEM; then folder groups 사용자 하이브 and 기타 하이브.
- Center list: 이름 / 유형 table with one row (260807_ssd.E01, 증거). Details pane: 레지스트리 키 정보 (이름, 유형).
- Loading state: "레지스트리 세부 정보 로드 중" with spinner at bottom-left.

### 2d. File system (파일 시스템)
- Left nav: 모든 증거 > 260807_ssd.E01 tree.
- Center list: 이름 / 유형 / 파일 / 크기 / 생성함 / 액세스 / 수정됨 columns. Evidence row shows 260807_ssd.E01 with type "Image", ext ".E01".
- Partition list (after expansion): Partition 1 (Microsoft FAT32, 100 MB) NO NAME, Partition 2 (16 MB), Partition 3 (Microsoft NTFS, 930.87 GB), Partition 4 (Microsoft NTFS, 536 MB), Unpartitioned Space.
- Details pane shows the selected partition name in the header and a "텍스트 및 16진수" section: "다음 위치에서 소스를 사용할 수 없습니다" followed by the source path and 소스 찾기 link.
- Loading overlay: centred white card with spinner, "파일 시스템 형성 중..." and 취소 link.

### 2e. Timeline (타임라인)
- Empty state text: "플롯할 타임 라인 데이터가 없습니다. 기간 또는 시간을 조정합니다."
- Build dialog: "타임라인 구축" with body text asking to build the timeline for the case, a 취소 link and a primary blue button "타임 라인 구축".
- Table below with columns 날짜, 타임 라인 범주, 아티팩트, 주요 세부 정보, 지원 세부.

### 2f. Media explorer (미디어 탐색기)
- Header bar: 미디어 범주화 진행률, 미디어 흐리게 dropdown, 음향 켜기 toggle, 리마인더 설정.
- Left nav: 일치하는 결과 (235,297, selected), 웹 관련 3,887, 미디어 215,526, 이메일 및 캘린더 11,333, 연결된 디바이스 3, 맞춤형 4,548. Counts right-aligned.
- Center: thumbnail grid with sort control 정렬 기준 and 작음 (size) dropdown; grid icon at right; numbered thumbnails (0, 1, 2, ...) with labels under each. Grid is about 4-5 thumbnails per row.
- View switcher dropdown shows the same eight modes as 열 보기, with 축소판 그림 보기 highlighted.
- Right pane: large preview (TALK icon), 미리보기 확장 and 유사한 사진 찾기 links, zoom level "확대/축소 100%", related media artifacts (4), 세부 정보 with 크기, 스킨톤 분석 비율 (%), 원본 너비/높이.

### 2g. Histogram / connections (히스토그램 보기 on the 아티팩트 list)
- Center: "증거 (1,543)" header with a "히스토그램 보기" dropdown at top-right.
- Chart: horizontal bar for "LNK 파일" with 현재 (blue) series count 1543 and total 214403, plus 기준선 로드 and 기준선으로 저장 buttons (baseline save/load) and a fit-to-view icon.
- Right pane is collapsed when the histogram is open.

## 3. Colours and conventions observed

- Tag colours (태그 및 주석 pane): 증거 red, 북마크 green, 예외 orange, 관심 항목 yellow.
- Row tag chips: a small coloured bar at the far left of the row (red = 증거, green = 북마크).
- Selected row: light blue background; multi-selected category groups: blue tint.
- Links: blue text, underlined on hover (소스 찾기, 파일 시스템에서 보기 pattern).
- Warning info bar: pale yellow strip with an info icon at the top of the details pane.
- Counts: bold, right-aligned, thousands separator.
- Keyboard hints: view-switch shortcuts Alt+1..Alt+7 (view), Alt+Shift+1..8 (list mode).
- Status: footer shows timezone (UTC+9:00).

Not visible in these frames: the "파일 시스템에서 보기" and "헥스" links, a hex-view preview, a SQLite preview, a chat (대화) preview with bubbles, the filter bar date/time range control, and keyword/tag filter chips. Do not assume these appear in this build from this set alone.

## 4. Twenty implementable patterns for an open-source React console

1. Three-column workbench (left category tree, centre list, right details) with fixed proportions near 20/35/30 (see 2b). Helps examiners keep context while moving between categories and items.
2. Category tree with bold right-aligned counts and parent/child grouping (2b). Shows volume at a glance and avoids opening empty categories.
3. Selected-category tint and grouped blue highlight (2b, section 3). Makes multi-select scope obvious before a bulk action.
4. Tag colour legend next to the case tag table (2a): red 증거, green 북마크, orange 예외, yellow 관심. Standardises triage vocabulary across users.
5. Coloured edge bar on each row for tag state (2b). Scans tagged rows without a dedicated column.
6. Two-line row layout (type over value) with a fixed row height of about 50 px (2b). Dense yet legible for long lists.
7. View-mode switcher with eight named modes (2b, 2f): 경로 / 대화 / 세계지도 / 열 / 축소판 그림 / 클래식 / 행 / 히스토그램. Lets one dataset be read as list, grid, chat or chart without reloading.
8. Keyboard shortcut per view (Alt+1..7 for view, Alt+Shift+1..8 for list mode) shown inline in the menu (2b, 2c). Teaches shortcuts where people look.
9. Right details pane with stacked collapsible sections in fixed order: source, preview, details, hashes (2b). Repeatable layout for every artifact type.
10. Yellow inline notice when source media is unavailable, with a "소스 찾기" (locate source) action (2b, 2d). Turns a dead end into a next step.
11. Hash and timestamp block with MD5 and SHA1 values and clock icons on time fields (2b). Makes integrity values and time provenance readable.
12. Source/offset provenance section: evidence link, recovery method (파싱됨 / 카빙), deleted source, File Offset link (2b). Lets an examiner trace each item to its byte location.
13. Loading overlay with spinner and cancel link for long operations (2d, 2e). Shows that work is in progress and lets the user stop it.
14. Build-confirmation dialog before a costly index such as the timeline (2e). Warns about cost before a long computation.
15. Empty-state message that tells the user what to adjust (2e: "기간 또는 시간을 조정합니다"). Gives an actionable next step.
16. Thumbnail grid with numbered tiles, sort control and size control (2f). Fast visual triage of images without leaving the list.
17. Large preview with zoom readout and "유사한 사진 찾기" (find similar) action (2f). Supports visual comparison directly from the preview.
18. Histogram with baseline load/save controls (2g). Lets examiners compare current counts against a saved baseline over time.
19. Case dashboard with four columns and a notes card that feeds the report (2a). Puts case status, notes, exports and tag totals in one place.
20. Export/report table with name, type, date and status columns (2a). Makes exports auditable and re-downloadable.

## 5. Open items

- Confirm the file-number mapping by re-reading individual files one per call and recording the filename with each result, or by renaming the frames to their view names.
- The filter bar (date/time range, keyword, tags, artifact type, match mode) and the toolbar groups were not clearly captured in these frames; a dedicated capture would be needed to describe them precisely.
