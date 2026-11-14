/**
 * Left panel of the 접수 stage (r7 L4, console review C-I3): the whole 탐색 tree was here, although
 * 접수 is the case summary. Now shortcuts to what the analyst checks on intake — the evidence, the
 * runs, the processing problems — each jumping to its dashboard card (or the stage that holds it),
 * and one way on into 탐색.
 */

import { announce } from "../../a11y";
import { Icon, type IconName } from "../../icons";
import { useRoute } from "../../state/hooks";
import { openStage } from "./stages";
import "./stages.css";

/** Move to a dashboard card: scroll it in and focus its heading (the card's own h2). */
export function focusIntakeCard(cardId: string, label: string): boolean {
  const card = document.querySelector<HTMLElement>(`[data-card="${cardId}"]`);
  if (!card) {
    announce(`${label} 카드가 숨겨져 있습니다. 접수 화면의 "숨긴 카드 다시 표시"로 되살리세요`);
    return false;
  }
  card.scrollIntoView?.({ block: "start" });
  const heading = card.querySelector<HTMLElement>("h2") ?? card;
  if (!heading.hasAttribute("tabindex")) heading.setAttribute("tabindex", "-1");
  heading.focus();
  return true;
}

interface Shortcut {
  id: string;
  label: string;
  hint: string;
  icon: IconName;
  run: () => void;
}

export function IntakePanel() {
  const { route, openCollection } = useRoute();
  if (!route.runId) return <p className="pane-empty">케이스를 먼저 선택하세요.</p>;
  const shortcuts: Shortcut[] = [
    {
      id: "evidence",
      label: "증거",
      hint: "증거 번호·해시 검증·연결된 런",
      icon: "hard-drive",
      run: () => focusIntakeCard("evidence", "증거"),
    },
    {
      id: "status",
      label: "처리 상태",
      hint: "이 런의 단계·소요·출력 폴더",
      icon: "clock",
      run: () => focusIntakeCard("status", "처리 상태"),
    },
    {
      id: "warnings",
      label: "처리 문제",
      hint: "파서 오류·건너뛴 처리·제한 사항",
      icon: "alert",
      run: () => focusIntakeCard("warnings", "처리 경고·제한 사항"),
    },
    {
      id: "runs",
      label: "런 목록",
      hint: "처리 단계: 이 케이스의 런과 분석",
      icon: "cpu",
      run: () => openStage("process"),
    },
  ];
  return (
    <div className="stage-panel intake-panel" data-testid="intake-panel">
      <h2 id="intake-shortcuts-title">바로가기</h2>
      <ul aria-labelledby="intake-shortcuts-title">
        {shortcuts.map((item) => (
          <li key={item.id}>
            <button
              type="button"
              className="stage-link intake-link"
              data-testid={`intake-link-${item.id}`}
              title={item.hint}
              onClick={item.run}
            >
              <Icon name={item.icon} />
              <span>
                {item.label}
                <small className="intake-link-hint">{item.hint}</small>
              </span>
            </button>
          </li>
        ))}
      </ul>
      <h2 id="intake-next-title">다음</h2>
      <ul aria-labelledby="intake-next-title">
        <li>
          <button
            type="button"
            className="stage-link intake-link"
            data-testid="intake-link-files"
            onClick={() => openCollection("files")}
          >
            <Icon name="search" />
            <span>탐색: 파일 목록 열기</span>
          </button>
        </li>
      </ul>
    </div>
  );
}
