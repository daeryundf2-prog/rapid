import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type RefObject, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { saveSearch } from "../../api/caseDb";
import { listKeywordPacks, SEARCH_SOURCES } from "../../api/keywordPacks";
import { lazyView } from "../../components/LazyView";
import { Popover } from "../../components/Popover";
import { Icon } from "../../icons";
import { ensureRunCaseDb } from "../grid/reviewActions";
import { ErrorText } from "./ErrorText";
import { ReasonButton } from "./ReasonButton";
import { invalidateSavedSearches } from "./savedSearches";
import { useSearchState } from "./searchState";
import "./case.css";
import { useWriteBlock } from "../../shell/readOnly";

// T-116: 개체 패널 is a lazy chunk, fetched the first time it opens.
const EntityPanel = lazyView("개체 패널", () => import("./EntityPanel").then((m) => m.EntityPanel));

function toggle(list: string[], value: string, on: boolean): string[] {
  return on ? [...list.filter((v) => v !== value), value] : list.filter((v) => v !== value);
}

/**
 * Compact search-options popover for S1's top-bar search. Mount it next to the
 * search input: `<SearchOptionsButton runId={runId} />`. Options live in
 * `useSearchState` and are turned into a request with `searchPath()`.
 */
export function SearchOptionsButton({ runId }: { runId: string | null }) {
  const open = useSearchState((s) => s.popoverOpen);
  const setOpen = useSearchState((s) => s.setPopoverOpen);
  const entityOpen = useSearchState((s) => s.entityPanelOpen);
  const closeEntityPanel = useSearchState((s) => s.closeEntityPanel);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverId = useId();
  return (
    <span className="search-options-anchor">
      {/* Folded into the search field (visual-polish S7): an icon button at the input's end. */}
      <ReasonButton
        ref={triggerRef}
        className="search-options-trigger"
        aria-label="검색 옵션"
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-controls={open && runId ? popoverId : undefined}
        reason={runId ? undefined : "열린 케이스가 없습니다"}
        onClick={() => setOpen(!open)}
      >
        <Icon name="filter" />
      </ReasonButton>
      {open && runId && (
        <SearchOptionsPopover
          id={popoverId}
          runId={runId}
          triggerRef={triggerRef}
          onClose={() => {
            setOpen(false);
            triggerRef.current?.focus();
          }}
        />
      )}
      {/* Portaled: the top bar is a containing block for fixed children (the dialog would sit in it). */}
      {entityOpen &&
        runId &&
        createPortal(<EntityPanel runId={runId} onClose={closeEntityPanel} />, document.body)}
    </span>
  );
}

/**
 * Entity / language / hash-set chips of the options popover (R7 lane B): each opens the
 * 개체·언어 검색 panel with its query (the panel shows the counts, masked values and the syntax).
 */
export const ENTITY_CHIPS: ReadonlyArray<{ q: string; label: string; title: string }> = [
  { q: "rrn:*", label: "주민등록번호", title: "주민등록번호가 있는 행(값은 가려서)" },
  { q: "card:*", label: "카드번호", title: "Luhn 검증을 통과한 카드번호" },
  { q: "phone:*", label: "전화번호", title: "휴대전화·유선 전화번호" },
  { q: "account:*", label: "계좌번호", title: "은행별 자릿수로 찾은 계좌번호 후보(신뢰도 낮음)" },
  { q: "email:*", label: "이메일", title: "이메일 주소(앞부분은 가려서)" },
  { q: "ip:*", label: "IP 주소", title: "IPv4·IPv6 주소" },
  { q: "lang:ko", label: "한국어 문서", title: "한글이 대부분인 문서·메일" },
  { q: "lang:ja", label: "일본어 문서", title: "가나·한자가 대부분인 문서·메일" },
  { q: "hashset:known-bad", label: "알려진 악성 해시", title: "알려진 악성 해시 집합에 든 파일" },
];

/**
 * The options panel sits on the shared Popover (review B2-9): first option focused on open,
 * Tab / Shift+Tab stay inside, Esc returns to the trigger, a press outside — including on
 * another popover's trigger — closes it.
 */
/**
 * Korean names of the built-in keyword packs (core keyword packs; C-G15). The pack id and its first
 * keywords are the tooltip; a pack the console does not know keeps the server label, else its id.
 */
export const KEYWORD_PACK_LABELS: Readonly<Record<string, string>> = {
  "browser-ai": "생성형 AI 서비스",
  // R7 AI 사용 (갈래 A pack): product names, service domains, API key prefixes (never values).
  "ai-tools": "AI 도구(제품·도메인·키 접두사)",
  credentials: "자격 증명·비밀",
  execution: "명령 실행 도구",
  exfiltration: "외부 반출·클라우드 전송",
  network: "네트워크·다운로드",
  "windows-ir": "Windows 침해 대응 이벤트",
};

export function keywordPackLabel(name: string, label?: string | null): string {
  return KEYWORD_PACK_LABELS[name] ?? (label || name);
}

export function SearchOptionsPopover({
  runId,
  onClose,
  id,
  triggerRef,
}: {
  runId: string;
  onClose: () => void;
  id: string;
  triggerRef: RefObject<HTMLElement | null>;
}) {
  const queryClient = useQueryClient();
  const options = useSearchState((s) => s.options);
  const keywords = useSearchState((s) => s.keywords);
  const patch = useSearchState((s) => s.patchOptions);
  const reset = useSearchState((s) => s.resetOptions);
  const [saveName, setSaveName] = useState("");
  const packs = useQuery({ queryKey: ["keyword-packs"], queryFn: listKeywordPacks, retry: false });

  const openEntityPanel = useSearchState((s) => s.openEntityPanel);

  const save = useMutation({
    mutationFn: async () => {
      // Same handle as the review marks (R7 S2 #13): a run that reports `case_db_ready` needs no
      // `/case-db/ensure` POST; otherwise ensure once per run.
      const db = await ensureRunCaseDb(runId);
      if (!db) throw new Error("이 런은 케이스 DB를 만들 수 없어 검색을 저장할 수 없습니다.");
      return saveSearch({
        database: db.database,
        case_id: db.case_id,
        name: saveName.trim(),
        keywords,
        limit: options.limit,
        sources: options.sources,
        created_by: "web-ui",
      });
    },
    onSuccess: () => {
      setSaveName("");
      void invalidateSavedSearches(queryClient, runId);
      void queryClient.invalidateQueries({ queryKey: ["review-counts", runId] });
    },
  });

  // T-348: a read-only result / server says why instead of answering with a 409.
  const writeBlock = useWriteBlock("run");
  const saveReasonOwn = !keywords.length
    ? "저장할 검색어가 없습니다. 먼저 검색어를 입력하세요."
    : !saveName.trim()
      ? "검색 이름을 입력하세요."
      : undefined;
  const saveReason = writeBlock ?? saveReasonOwn;

  return (
    <Popover
      id={id}
      open
      onClose={onClose}
      triggerRef={triggerRef}
      label="검색 옵션"
      align="end"
      className="search-options-popover"
    >
      <div className="case-field">
        <label htmlFor="so-mode">검색 방식</label>
        <select
          id="so-mode"
          value={options.mode}
          onChange={(e) => patch({ mode: e.target.value as "exact" | "fuzzy" | "regex" })}
        >
          <option value="exact">정확히 일치</option>
          <option value="fuzzy">유사 일치</option>
          <option value="regex">정규식</option>
        </select>
      </div>
      {options.mode === "fuzzy" && (
        <div className="case-field">
          <label htmlFor="so-fuzzy">허용 편집 거리 (0-2)</label>
          <input
            id="so-fuzzy"
            type="number"
            min={0}
            max={2}
            value={options.fuzzyDistance}
            onChange={(e) => patch({ fuzzyDistance: Math.min(2, Math.max(0, Number(e.target.value) || 0)) })}
          />
        </div>
      )}
      <fieldset className="case-field">
        <legend>검색 범위</legend>
        {SEARCH_SOURCES.map((source) => (
          <label key={source.id}>
            <input
              type="checkbox"
              checked={options.sources.includes(source.id)}
              onChange={(e) => patch({ sources: toggle(options.sources, source.id, e.target.checked) })}
            />{" "}
            {source.label}
          </label>
        ))}
      </fieldset>
      <div className="case-field">
        <label htmlFor="so-ext">확장자 (쉼표로 구분)</label>
        <input
          id="so-ext"
          type="text"
          value={options.extensions.join(",")}
          onChange={(e) =>
            patch({
              extensions: e.target.value
                .split(",")
                .map((v) => v.trim())
                .filter(Boolean),
            })
          }
        />
      </div>
      <div className="case-field">
        <label htmlFor="so-path">경로 포함 문자열</label>
        <input
          id="so-path"
          type="text"
          value={options.pathContains}
          onChange={(e) => patch({ pathContains: e.target.value })}
        />
      </div>
      <div className="case-field">
        <label htmlFor="so-prox">근접 검색 창 (0 = 사용 안 함)</label>
        <input
          id="so-prox"
          type="number"
          min={0}
          max={100}
          value={options.proximityWindow}
          onChange={(e) =>
            patch({ proximityWindow: Math.min(100, Math.max(0, Number(e.target.value) || 0)) })
          }
        />
      </div>
      <label>
        <input type="checkbox" checked={options.ocr} onChange={(e) => patch({ ocr: e.target.checked })} /> OCR
        텍스트 포함
      </label>
      <label>
        <input
          type="checkbox"
          checked={options.hideKnownGood}
          onChange={(e) => patch({ hideKnownGood: e.target.checked })}
        />{" "}
        <span title="알려진 정상 파일(known-good 해시 목록에 있는 파일)을 결과에서 뺍니다">
          알려진 정상 파일 숨기기
        </span>
      </label>
      <fieldset className="case-field">
        <legend>개체·언어 검색</legend>
        <div className="entity-chips">
          {ENTITY_CHIPS.map((chip) => (
            <button
              key={chip.q}
              type="button"
              className="chip"
              title={chip.title}
              onClick={() => openEntityPanel(chip.q)}
            >
              {chip.label}
            </button>
          ))}
          <button type="button" className="chip" onClick={() => openEntityPanel("")}>
            개체 요약·문법…
          </button>
        </div>
      </fieldset>
      <fieldset className="case-field">
        <legend>키워드 팩</legend>
        {packs.isPending && <span aria-busy="true">불러오는 중…</span>}
        {packs.isError && <span className="case-error">키워드 팩을 불러오지 못했습니다.</span>}
        {packs.data?.length === 0 && <span className="case-reason">사용 가능한 키워드 팩이 없습니다.</span>}
        {packs.data?.map((pack) => (
          <label key={pack.name}>
            <input
              type="checkbox"
              checked={options.keywordPacks.includes(pack.name)}
              onChange={(e) =>
                patch({ keywordPacks: toggle(options.keywordPacks, pack.name, e.target.checked) })
              }
            />{" "}
            <span
              title={`${pack.name}${Array.isArray(pack.keywords) ? `: ${pack.keywords.slice(0, 8).join(", ")}` : ""}`}
            >
              {keywordPackLabel(pack.name, pack.label)}
            </span>
          </label>
        ))}
      </fieldset>
      <div className="case-field">
        <label htmlFor="so-save-name">현재 검색 저장</label>
        <input
          id="so-save-name"
          type="text"
          value={saveName}
          placeholder="검색 이름"
          onChange={(e) => setSaveName(e.target.value)}
        />
        {save.error && (
          <ErrorText>{save.error instanceof Error ? save.error.message : "저장하지 못했습니다."}</ErrorText>
        )}
        {save.isSuccess && <p>검색을 저장했습니다.</p>}
      </div>
      <div className="case-actions">
        <button type="button" className="button" onClick={reset}>
          기본값
        </button>
        <ReasonButton reason={saveReason} onClick={() => save.mutate()}>
          저장
        </ReasonButton>
        <button type="button" className="button primary" onClick={onClose}>
          닫기
        </button>
      </div>
    </Popover>
  );
}
