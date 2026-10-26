import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type RefObject, useId, useRef, useState } from "react";
import { ensureCaseDb, saveSearch } from "../../api/caseDb";
import { listKeywordPacks, SEARCH_SOURCES } from "../../api/keywordPacks";
import { Popover } from "../../components/Popover";
import { Icon } from "../../icons";
import { ErrorText } from "./ErrorText";
import { ReasonButton } from "./ReasonButton";
import { invalidateSavedSearches } from "./savedSearches";
import { useSearchState } from "./searchState";
import "./case.css";

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
    </span>
  );
}

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

  const save = useMutation({
    mutationFn: async () => {
      const db = await ensureCaseDb(runId);
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

  const saveReason = !keywords.length
    ? "저장할 검색어가 없습니다. 먼저 검색어를 입력하세요."
    : !saveName.trim()
      ? "검색 이름을 입력하세요."
      : undefined;

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
