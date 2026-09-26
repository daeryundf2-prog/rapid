// Behavioral tests for app_kakao.js message normalization + bubble rendering.
// Run: node tests/js/test_app_kakao.mjs

import {
  collectKakaoMessages,
  isKakaoPayload,
  renderKakaoArtifactChatCard,
  renderKakaoChat,
} from "../../rapidtriage/web/static/app_kakao.js";

let failures = 0;
function check(name, cond) {
  if (cond) console.log(`ok - ${name}`);
  else { failures += 1; console.log(`FAIL - ${name}`); }
}

// --- normalization: decrypt-entry shape ---------------------------------------
const decryptPayload = {
  command: "kakaotalk-decrypt",
  summary: { message_row_count: 3, commercial_grade_ready: false },
  entries: [
    {
      chat_id: "42",
      path: "chat_data/chatlogs_42.edb",
      message_previews: [
        { message_text: "안녕", fields: { authorId: "100", sendAt: "1700000000" }, rowid: 1 },
        { message_text: "잘 지내?", fields: { authorId: "200", sendAt: "1700000060" }, rowid: 2 },
      ],
    },
  ],
};

const { messages, notes } = collectKakaoMessages(decryptPayload);
check("decrypt entries normalize to messages", messages.length === 2);
check("messages sorted by timestamp", messages[0].text === "안녕" && messages[1].text === "잘 지내?");
check("validation note emitted for ungraded payload", notes.some((n) => n.includes("검증 미완료")));
check("chat id carried from entry", messages[0].chatId === "42");

// --- normalization: raw chatlog rows + attachments ----------------------------
const chatlogPayload = {
  details: {
    user_id: "me-1",
    chat_messages: [
      { logId: 9, authorId: "me-1", sendAt: 1700000000, message: "보낸 메시지" },
      {
        logId: 10,
        authorId: "other",
        sendAt: 1700000100,
        message: "",
        media_class: "image",
        display_name: "photo.jpg",
        declared_size: 204800,
        local_matches: [{ path: "kakao/media/photo.jpg" }],
      },
    ],
  },
};
const { messages: chatMessages, meId } = collectKakaoMessages(chatlogPayload);
check("chat_messages normalize", chatMessages.length === 2);
check("meId detected", meId === "me-1");
check("attachment row becomes attachment bubble", chatMessages[1].attachments.length === 1);
check("attachment keeps local path", chatMessages[1].attachments[0].localPath === "kakao/media/photo.jpg");

// --- rendering ----------------------------------------------------------------
const html = renderKakaoChat({
  title: "테스트 대화방",
  messages: chatMessages,
  meId,
  notes: ["검증 메모"],
});
check("outgoing bubble aligned right", html.includes("kakao-row-out"));
check("incoming bubble aligned left", html.includes("kakao-row-in"));
check("attachment icon rendered", html.includes("kakao-attachment"));
check("status notes rendered", html.includes("검증 메모"));
check("provenance/aria label present", html.includes('role="log"'));
check("message count in header", html.includes("2개 메시지"));

// --- XSS safety ----------------------------------------------------------------
const xss = renderKakaoChat({
  messages: [{ id: "1", chatId: "1", authorId: "x", author: "<img>", timestamp: "", text: '<script>alert(1)</script>', attachments: [] }],
});
check("message text escaped", !xss.includes("<script>") && xss.includes("&lt;script&gt;"));

// --- empty + locked states -----------------------------------------------------
const emptyHtml = renderKakaoChat({ title: "빈방", messages: [], emptyText: "메시지 없음" });
check("empty state rendered", emptyHtml.includes("메시지 없음"));

const locked = renderKakaoArtifactChatCard({
  artifact_type: "kakaotalk-db",
  details: { message_content_status: "not-decrypted-inventory-only" },
});
check("locked inventory shows status note", locked.includes("not-decrypted-inventory-only"));

// --- detection -----------------------------------------------------------------
check("isKakaoPayload detects kakao artifact", isKakaoPayload({ kind: "kakao", artifact_type: "kakaotalk", details: { message_content_status: "x" } }));
check("isKakaoPayload rejects non-kakao", !isKakaoPayload({ kind: "browser", details: {} }));
check("isKakaoPayload rejects null", !isKakaoPayload(null));

// --- day separators -------------------------------------------------------------
const multi = renderKakaoChat({
  messages: [
    { id: "1", chatId: "1", authorId: "a", timestamp: "2024-01-01T10:00:00Z", text: "one", attachments: [] },
    { id: "2", chatId: "1", authorId: "b", timestamp: "2024-01-02T09:00:00Z", text: "two", attachments: [] },
  ],
});
check("day separator rendered per day", (multi.match(/kakao-day-separator/g) || []).length === 2);

if (failures) {
  console.log(`${failures} failure(s)`);
  process.exit(1);
}
console.log("all kakao-viewer tests passed");
