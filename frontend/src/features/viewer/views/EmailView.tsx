import { useState } from "react";
import { type EmailAttachmentPackage, fetchEmailAttachment, type SourcePreview } from "../../../api/viewer";
import { errorText } from "../useAsync";
import { highlight, keywordPattern } from "./Highlight";

function formatBytes(value: number | undefined): string {
  const size = value ?? 0;
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

interface EmailViewProps {
  runId: string;
  preview: SourcePreview;
  terms: string[];
  onCopy: (text: string, sentence: string) => void;
}

export function EmailView({ runId, preview, terms, onCopy }: EmailViewProps) {
  const email = preview.email || {};
  const messages = email.messages || [];
  const diagnostics = email.parse_diagnostics || {};
  const pattern = keywordPattern(terms);
  const partial = Boolean(
    diagnostics.source_truncated ||
      diagnostics.message_limit_reached ||
      Number(diagnostics.message_size_truncated_count || 0) > 0,
  );
  const [packages, setPackages] = useState<Record<string, EmailAttachmentPackage | string>>({});

  const loadPackage = async (messageIndex: number, attachmentIndex: number) => {
    const key = `${messageIndex}:${attachmentIndex}`;
    try {
      const pkg = await fetchEmailAttachment(runId, preview.path, messageIndex, attachmentIndex);
      setPackages((current) => ({ ...current, [key]: pkg }));
      const citation = pkg.copy_safe_citation?.text;
      if (citation) onCopy(citation, "첨부 인용을 복사했습니다.");
    } catch (error) {
      setPackages((current) => ({ ...current, [key]: errorText(error) }));
    }
  };

  if (!messages.length) {
    return <p className="viewer-empty">{email.error || "메일 메시지를 찾지 못했습니다."}</p>;
  }

  return (
    <div className="email-view">
      {partial ? (
        <p className="viewer-warning" role="note">
          메일함 일부만 해석했습니다(크기·개수 한도). 전체 메일함으로 단정하지 마세요.
        </p>
      ) : null}
      <p className="viewer-note">메시지 {email.message_count ?? messages.length}개</p>
      {messages.map((message) => (
        <article key={message.index} className="email-message" aria-label={message.subject || "(제목 없음)"}>
          <h3 className="viewer-subtitle">{highlight(message.subject || "(제목 없음)", pattern)}</h3>
          <dl className="viewer-dl">
            <dt>보낸 사람</dt>
            <dd>{message.from || "—"}</dd>
            <dt>받는 사람</dt>
            <dd>{message.to || "—"}</dd>
            {message.cc ? (
              <>
                <dt>참조</dt>
                <dd>{message.cc}</dd>
              </>
            ) : null}
            <dt>날짜</dt>
            <dd>{message.date || "—"}</dd>
            {message.message_id ? (
              <>
                <dt>Message-ID</dt>
                <dd className="mono">{message.message_id}</dd>
              </>
            ) : null}
          </dl>
          <pre className="viewer-pre email-body">
            {highlight(message.body_preview || "(본문 없음)", pattern)}
          </pre>
          {message.body_truncated ? <p className="viewer-note">본문 앞부분만 표시했습니다.</p> : null}
          {(message.attachments || []).length ? (
            <section aria-label="첨부 파일">
              <h4>첨부 {message.attachment_count ?? message.attachments?.length}개</h4>
              <ul className="email-attachments">
                {(message.attachments || []).map((attachment) => {
                  const key = `${message.index}:${attachment.index}`;
                  const pkg = packages[key];
                  return (
                    <li key={key}>
                      <span>
                        {attachment.filename || attachment.content_type || `첨부 ${attachment.index}`}
                      </span>
                      <small>
                        {attachment.content_type} · {formatBytes(attachment.size)}
                        {attachment.sha256 ? ` · sha256 ${attachment.sha256.slice(0, 16)}…` : ""}
                      </small>
                      <button
                        type="button"
                        className="viewer-button"
                        onClick={() => loadPackage(message.index, attachment.index)}
                      >
                        첨부 인용 복사
                      </button>
                      {typeof pkg === "string" ? <small className="viewer-error">실패: {pkg}</small> : null}
                      {pkg && typeof pkg !== "string" && pkg.hashes?.sha256 ? (
                        <small className="mono">sha256 {pkg.hashes.sha256}</small>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            </section>
          ) : null}
        </article>
      ))}
    </div>
  );
}
