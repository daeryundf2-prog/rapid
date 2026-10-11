// biome-ignore-all lint/a11y/useSemanticElements: virtualized ARIA list/listbox; items are positioned divs
/**
 * 대화 보기 (S9, plan X6): messenger message rows (KakaoTalk / mobile export)
 * as conversations. Left: conversation list (listbox, roving arrows). Right:
 * virtualized bubbles (sender, time, text with the route keyword highlighted,
 * attachments). Up/Down/Home/End/PageUp/PageDown move between bubbles, Enter
 * opens the bubble's row in the viewer, ←/→ switch between list and bubbles.
 * The viewer target follows bubble focus, so R/X/I/B/1–5 mark the message.
 */

import { useVirtualizer } from "@tanstack/react-virtual";
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { useRovingTabindex } from "../../a11y";
import type { GridRow } from "../../contracts/collection";
import { encodeRowRef } from "../../contracts/rowRef";
import { useViewerTarget } from "../grid/adapter";
import { REVIEW_LABELS } from "../grid/columns/common";
import { buildViewerTarget } from "../grid/gridCommands";
import { errorText } from "../viewer/useAsync";
import {
  type ChatMessage,
  type Conversation,
  groupConversations,
  highlightParts,
  highlightTerms,
  isMessageRow,
  messageMatches,
} from "./chat";
import { useAutoLoad, useViewRows } from "./useViewRows";
import { EmptyState, ErrorState, LoadingCard } from "./ViewState";

/** Rows loaded automatically for the conversation list (then "더 불러오기"). */
export const CHAT_AUTOLOAD_ROWS = 10_000;

function Highlighted({ text, terms }: { text: string; terms: readonly string[] }) {
  return (
    <>
      {highlightParts(text, terms).map((part, i) =>
        part.hit ? (
          // biome-ignore lint/suspicious/noArrayIndexKey: parts are positional and never reordered
          <mark key={i} className="chat-hit">
            {part.text}
          </mark>
        ) : (
          // biome-ignore lint/suspicious/noArrayIndexKey: parts are positional and never reordered
          <span key={i}>{part.text}</span>
        ),
      )}
    </>
  );
}

function bubbleLabel(message: ChatMessage): string {
  const parts = [message.sender || "발신자 미상", message.timestamp ?? "시각 없음", message.text];
  if (message.attachments.length) parts.push(`첨부 ${message.attachments.length}개`);
  if (message.row.reviewStatus) parts.push(REVIEW_LABELS[message.row.reviewStatus]);
  return parts.join(", ");
}

function ConversationList({
  conversations,
  selectedId,
  onSelect,
  onEnterMessages,
}: {
  conversations: Conversation[];
  selectedId: string;
  onSelect: (id: string) => void;
  onEnterMessages: () => void;
}) {
  const listRef = useRef<HTMLDivElement | null>(null);
  const selectedIndex = Math.max(
    0,
    conversations.findIndex((c) => c.id === selectedId),
  );
  const roving = useRovingTabindex(listRef, {
    orientation: "vertical",
    itemSelector: '[role="option"]',
    initialIndex: selectedIndex,
    typeAhead: true,
  });
  return (
    <div
      ref={listRef}
      className="chat-list"
      role="listbox"
      aria-label={`대화 목록, ${conversations.length}개`}
      onKeyDown={(event) => {
        if (event.key === "ArrowRight") {
          event.preventDefault();
          onEnterMessages();
          return;
        }
        roving.containerProps.onKeyDown(event);
      }}
    >
      {conversations.map((conversation, index) => (
        <div
          key={conversation.id}
          role="option"
          className="chat-list-item"
          aria-selected={conversation.id === selectedId}
          tabIndex={roving.getItemProps(index).tabIndex}
          data-roving-index={index}
          onFocus={roving.getItemProps(index).onFocus}
          onClick={() => onSelect(conversation.id)}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              onSelect(conversation.id);
              if (event.key === "Enter") onEnterMessages();
            }
          }}
        >
          <span className="chat-list-title">{conversation.label}</span>
          <span className="chat-list-meta">
            {[conversation.service, `메시지 ${conversation.messages.length.toLocaleString("ko-KR")}개`]
              .filter(Boolean)
              .join(" · ")}
          </span>
          {conversation.lastTimestamp ? (
            <span className="chat-list-meta">{conversation.lastTimestamp}</span>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function MessageList({
  conversation,
  terms,
  runId,
  focusRequest,
  onLeave,
}: {
  conversation: Conversation;
  terms: readonly string[];
  runId: string | null;
  focusRequest: number;
  onLeave: () => void;
}) {
  const { target, publishFocusedRow, requestFocus } = useViewerTarget();
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const messages = conversation.messages;
  const [active, setActive] = useState(0);
  const activeIndex = Math.min(active, Math.max(messages.length - 1, 0));
  const pendingFocus = useRef<number | null>(null);
  const virtualizer = useVirtualizer({
    count: messages.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 76,
    overscan: 6,
    initialRect: { width: 600, height: 600 },
  });
  const items = virtualizer.getVirtualItems();
  const hits = useMemo(
    () => messages.flatMap((m, i) => (messageMatches(m, terms) ? [i] : [])),
    [messages, terms],
  );

  // biome-ignore lint/correctness/useExhaustiveDependencies: reset on conversation change only
  useEffect(() => {
    setActive(0);
    virtualizer.scrollToIndex(0);
  }, [conversation.id]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: a new request moves focus into the list
  useEffect(() => {
    if (focusRequest > 0) focusMessage(activeIndex);
  }, [focusRequest]);

  useEffect(() => {
    if (pendingFocus.current === null) return;
    const el = scrollRef.current?.querySelector<HTMLElement>(`[data-chat-index="${pendingFocus.current}"]`);
    if (el) {
      pendingFocus.current = null;
      el.focus();
    }
  });

  const publish = (row: GridRow | undefined) => {
    if (!row || !runId) return;
    if (target?.runId === runId && encodeRowRef(target.ref) === encodeRowRef(row.ref)) return;
    publishFocusedRow(row, buildViewerTarget(runId, row));
  };

  function focusMessage(index: number) {
    if (messages.length === 0) return;
    const next = Math.min(Math.max(index, 0), messages.length - 1);
    setActive(next);
    pendingFocus.current = next;
    virtualizer.scrollToIndex(next, { align: "auto" });
  }

  const jumpHit = (direction: 1 | -1) => {
    if (hits.length === 0) return;
    const next =
      direction === 1
        ? (hits.find((i) => i > activeIndex) ?? hits[0])
        : ([...hits].reverse().find((i) => i < activeIndex) ?? hits[hits.length - 1]);
    if (next !== undefined) focusMessage(next);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = Number(event.currentTarget.dataset.chatIndex ?? activeIndex);
    const page = Math.max(1, items.length - 2);
    const moves: Record<string, number> = {
      ArrowDown: index + 1,
      ArrowUp: index - 1,
      Home: 0,
      End: messages.length - 1,
      PageDown: index + page,
      PageUp: index - page,
    };
    const next = moves[event.key];
    if (next !== undefined) {
      event.preventDefault();
      focusMessage(next);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      onLeave();
    } else if (event.key === "Enter") {
      event.preventDefault();
      publish(messages[index]?.row);
      requestFocus();
    }
  };

  return (
    <section className="chat-thread" aria-label={`${conversation.label} 대화`}>
      <header className="chat-thread-head">
        <span className="chat-thread-title">{conversation.label}</span>
        <span className="chat-list-meta">
          {[
            conversation.service,
            conversation.participants.length ? `참여자 ${conversation.participants.join(", ")}` : "",
            `메시지 ${messages.length.toLocaleString("ko-KR")}개`,
          ]
            .filter(Boolean)
            .join(" · ")}
        </span>
        {terms.length ? (
          <span className="chat-hits">
            검색어 일치 {hits.length.toLocaleString("ko-KR")}건
            <button type="button" className="view-link" disabled={!hits.length} onClick={() => jumpHit(-1)}>
              이전 일치
            </button>
            <button type="button" className="view-link" disabled={!hits.length} onClick={() => jumpHit(1)}>
              다음 일치
            </button>
          </span>
        ) : null}
      </header>
      <div
        ref={scrollRef}
        className="chat-scroll"
        role="list"
        aria-label={`${conversation.label} 메시지 ${messages.length}개`}
      >
        <div className="chat-body" style={{ height: virtualizer.getTotalSize() }}>
          {items.map((item) => {
            const message = messages[item.index] as ChatMessage;
            const previous = messages[item.index - 1];
            const showSender = !previous || previous.sender !== message.sender;
            return (
              <div
                key={message.row.rowKey}
                ref={virtualizer.measureElement}
                data-index={item.index}
                data-chat-index={item.index}
                role="listitem"
                tabIndex={item.index === activeIndex ? 0 : -1}
                aria-label={bubbleLabel(message)}
                className={`chat-row${message.outgoing ? " is-out" : ""}${messageMatches(message, terms) ? " has-hit" : ""}`}
                data-review={message.row.reviewStatus ?? undefined}
                style={{ transform: `translateY(${item.start}px)` }}
                onKeyDown={onKeyDown}
                onFocus={() => {
                  setActive(item.index);
                  publish(message.row);
                }}
                onClick={() => publish(message.row)}
                onDoubleClick={() => {
                  publish(message.row);
                  requestFocus();
                }}
              >
                {showSender ? <span className="chat-sender">{message.sender || "발신자 미상"}</span> : null}
                <div className="chat-bubble">
                  <p className="chat-text">
                    <Highlighted text={message.text} terms={terms} />
                  </p>
                  {message.attachments.length ? (
                    <ul className="chat-attachments" aria-label="첨부">
                      {message.attachments.map((name) => (
                        <li key={name}>
                          첨부: <Highlighted text={name} terms={terms} />
                        </li>
                      ))}
                    </ul>
                  ) : null}
                  <time className="chat-time">{message.timestamp ?? "시각 없음"}</time>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

export function ChatView() {
  const { cq, rows, runId, q } = useViewRows({ predicate: isMessageRow, textFilter: false });
  const capped = useAutoLoad(cq, true, CHAT_AUTOLOAD_ROWS);
  const conversations = useMemo(() => groupConversations(rows), [rows]);
  const terms = useMemo(() => highlightTerms(q), [q]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [focusRequest, setFocusRequest] = useState(0);
  const layoutRef = useRef<HTMLDivElement | null>(null);
  const conversation = conversations.find((c) => c.id === selectedId) ?? conversations[0];

  if (cq.error && cq.loadedCount === 0) {
    return <ErrorState message={`대화를 불러오지 못했습니다. ${errorText(cq.error)}`} onRetry={cq.refetch} />;
  }
  if (cq.isLoading) return <LoadingCard label="대화를 불러오는 중…" />;
  if (!conversation) {
    if (cq.isFetching || (cq.canLoadMore && !capped)) {
      return (
        <LoadingCard label={`메시지를 찾는 중… (행 ${cq.loadedCount.toLocaleString("ko-KR")}개 확인)`} />
      );
    }
    return (
      <EmptyState
        title="이 노드에는 대화 메시지가 없습니다."
        hint="메신저 파서가 메시지 행을 만든 노드에서 대화 보기를 사용할 수 있습니다. 열 보기에서 원본 후보 행을 확인하세요."
      />
    );
  }

  return (
    <div className="view-pane chat-view" ref={layoutRef}>
      <div className="view-toolbar">
        <span className="view-count">
          대화 {conversations.length.toLocaleString("ko-KR")}개 · 메시지 {rows.length.toLocaleString("ko-KR")}
          개{cq.isFetching ? " · 불러오는 중…" : ""}
        </span>
        {capped ? (
          <button type="button" className="view-link" onClick={cq.loadMore}>
            더 불러오기
          </button>
        ) : null}
      </div>
      <div className="chat-layout">
        <ConversationList
          conversations={conversations}
          selectedId={conversation.id}
          onSelect={setSelectedId}
          onEnterMessages={() => setFocusRequest((n) => n + 1)}
        />
        <MessageList
          conversation={conversation}
          terms={terms}
          runId={runId}
          focusRequest={focusRequest}
          onLeave={() =>
            layoutRef.current
              ?.querySelector<HTMLElement>('.chat-list [role="option"][aria-selected="true"]')
              ?.focus()
          }
        />
      </div>
    </div>
  );
}
