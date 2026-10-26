import { type KeyboardEvent, useEffect, useId, useMemo, useRef, useState } from "react";
import { Popover } from "../components/Popover";
import { Icon } from "../icons";
import { useRoute, useRuns, useTimezone } from "../state/hooks";
import { type CaseOption, casePickerOptions, caseStatusLabel, moveActiveIndex } from "./casePicker";

/**
 * Top-bar run picker (review #5, R7 C-G5): "런: 이름 · 모드" opens a 420px popover with a search
 * field on top (role=combobox) and the runs as a listbox — two lines per run (name; the run chip
 * `모드 · 시작 시각 · 소요 · id8`) with a status dot on the right, newest start first. ↓/↑ move, Enter opens, Esc
 * closes and returns to the trigger; typing a character on the closed trigger opens the
 * picker with that character as the search (typeahead).
 */
export function CasePickerCombobox() {
  const { runs } = useRuns();
  const { route, navigate } = useRoute();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(-1);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverId = useId();
  const listId = useId();
  const optionPrefix = useId();

  const { timezone } = useTimezone();
  const options = useMemo(() => casePickerOptions(runs, query, timezone), [runs, query, timezone]);
  const current = runs.find((run) => run.run_id === route.runId);
  const currentOption = current ? casePickerOptions([current], "", timezone)[0] : undefined;
  const activeIndex = active >= options.length ? options.length - 1 : active;
  const activeOption = activeIndex >= 0 ? options[activeIndex] : undefined;

  // Each opening starts on the current case (or the first row).
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset once per opening
  useEffect(() => {
    if (!open) return;
    const index = options.findIndex((o) => o.runId === route.runId);
    setActive(index >= 0 && !query ? index : options.length ? 0 : -1);
  }, [open]);

  const close = () => {
    setOpen(false);
    setQuery("");
  };
  const choose = (option: CaseOption) => {
    navigate({ runId: option.runId, collection: "intake" });
    close();
    triggerRef.current?.focus();
  };

  const onInputKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      setActive(moveActiveIndex(activeIndex, event.key === "ArrowDown" ? 1 : -1, options.length));
    } else if (event.key === "Home" && options.length) {
      event.preventDefault();
      setActive(0);
    } else if (event.key === "End" && options.length) {
      event.preventDefault();
      setActive(options.length - 1);
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (activeOption) choose(activeOption);
    }
  };

  const label = currentOption
    ? `${currentOption.name} · ${currentOption.mode}`
    : runs.length
      ? "런 선택…"
      : "런 없음";

  return (
    <div className="case-picker popover-anchor">
      <button
        ref={triggerRef}
        type="button"
        className="case-picker-trigger"
        data-testid="case-picker"
        aria-label={`런: ${label}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? popoverId : undefined}
        title={label}
        onClick={() => {
          if (open) close();
          else setOpen(true);
        }}
        onKeyDown={(event) => {
          if (open) return;
          if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            setOpen(true);
          } else if (
            event.key.length === 1 &&
            event.key !== " " &&
            !event.ctrlKey &&
            !event.metaKey &&
            !event.altKey
          ) {
            // Typeahead: the first character starts the search.
            event.preventDefault();
            setQuery(event.key);
            setOpen(true);
          }
        }}
      >
        <span className="case-picker-name">{label}</span>
        <Icon name="chevron-down" className="case-picker-chevron" />
      </button>
      <Popover
        id={popoverId}
        open={open}
        onClose={close}
        triggerRef={triggerRef}
        label="런 선택"
        className="case-picker-popover"
      >
        <input
          type="search"
          role="combobox"
          className="case-picker-search"
          aria-label="런 검색"
          aria-expanded="true"
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={activeOption ? `${optionPrefix}-${activeOption.runId}` : undefined}
          placeholder="증거 이름·모드·런 ID"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActive(0);
          }}
          onKeyDown={onInputKeyDown}
        />
        <div id={listId} role="listbox" aria-label="런" className="case-picker-list">
          {options.length === 0 ? (
            <p className="case-picker-empty">{runs.length ? "일치하는 런이 없습니다." : "런 없음"}</p>
          ) : (
            options.map((option, index) => (
              // biome-ignore lint/a11y/useKeyWithClickEvents: keyboard is handled by the search combobox (aria-activedescendant)
              <div
                key={option.runId}
                id={`${optionPrefix}-${option.runId}`}
                role="option"
                tabIndex={-1}
                aria-selected={index === activeIndex}
                aria-current={option.runId === route.runId ? "true" : undefined}
                className={`case-picker-option${index === activeIndex ? " active" : ""}${option.runId === route.runId ? " is-current" : ""}`}
                onMouseMove={() => setActive(index)}
                onClick={() => choose(option)}
              >
                <span className="case-picker-option-text">
                  <span className="case-picker-option-name">{option.name}</span>
                  <span className="case-picker-option-meta">{option.chip}</span>
                </span>
                <span
                  className={`status-dot${option.tone ? ` ${option.tone}` : ""}`}
                  role="img"
                  aria-label={caseStatusLabel(option.status)}
                  title={caseStatusLabel(option.status)}
                />
              </div>
            ))
          )}
        </div>
      </Popover>
    </div>
  );
}
