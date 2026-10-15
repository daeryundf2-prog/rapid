/**
 * "원본 레코드" (viewer redesign §6): an EVTX record rebuilt as Event XML from the decoded row —
 * System fields + EventData — because the backend ships the decoded values, not the raw XML.
 * The text says so ("디코딩된 레코드(재구성)"): element order and names follow the Windows event
 * schema, values are the parser's, and nothing absent from the row is invented.
 */

import { flatValue } from "../../utils/flatValue";
import { eventDataOf } from "./fieldSheets";

export const RECONSTRUCTED_LABEL = "디코딩된 레코드(재구성)";

function esc(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function text(value: unknown): string {
  return flatValue(value).trim();
}

/** True when the row is an EVTX event (or a detection carrying the event's fields). */
export function hasEventRecord(
  artifactType: string | null | undefined,
  fields: Record<string, unknown>,
): boolean {
  const type = artifactType ?? "";
  if (!/^eventlog-(event|detection|record-candidate)$/.test(type)) return false;
  return text(fields.event_id) !== "" || eventDataOf(fields) !== null;
}

/** Event XML of the decoded record; lines are indented two spaces. */
export function eventRecordXml(fields: Record<string, unknown>): string {
  const lines: string[] = [
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
    "  <System>",
  ];
  const provider = text(fields.provider_name ?? fields.provider);
  const guid = text(fields.provider_guid);
  if (provider || guid) {
    const attrs = [provider ? `Name="${esc(provider)}"` : "", guid ? `Guid="${esc(guid)}"` : ""].filter(
      Boolean,
    );
    lines.push(`    <Provider ${attrs.join(" ")} />`);
  }
  const element = (name: string, value: unknown) => {
    const v = text(value);
    if (v) lines.push(`    <${name}>${esc(v)}</${name}>`);
  };
  element("EventID", fields.event_id);
  element("Version", fields.version ?? fields.event_version);
  element("Level", fields.level);
  element("Task", fields.task);
  element("Opcode", fields.opcode);
  element("Keywords", fields.keywords);
  const created = text(fields.timestamp ?? fields.time_created);
  if (created) lines.push(`    <TimeCreated SystemTime="${esc(created)}" />`);
  element("EventRecordID", fields.record_id ?? fields.event_record_id);
  const activity = text(fields.activity_id);
  if (activity) lines.push(`    <Correlation ActivityID="${esc(activity)}" />`);
  const pid = text(fields.process_id);
  const tid = text(fields.thread_id);
  if (pid || tid) {
    const attrs = [pid ? `ProcessID="${esc(pid)}"` : "", tid ? `ThreadID="${esc(tid)}"` : ""].filter(Boolean);
    lines.push(`    <Execution ${attrs.join(" ")} />`);
  }
  element("Channel", fields.channel);
  element("Computer", fields.computer);
  const sid = text(fields.user_sid ?? fields.security_user_id);
  if (sid) lines.push(`    <Security UserID="${esc(sid)}" />`);
  lines.push("  </System>");
  const data = eventDataOf(fields);
  if (data) {
    const userData = fields.user_data !== undefined && fields.event_data === undefined;
    lines.push(userData ? "  <UserData>" : "  <EventData>");
    for (const [name, value] of Object.entries(data)) {
      const v = typeof value === "object" && value !== null ? JSON.stringify(value) : text(value);
      lines.push(v ? `    <Data Name="${esc(name)}">${esc(v)}</Data>` : `    <Data Name="${esc(name)}" />`);
    }
    lines.push(userData ? "  </UserData>" : "  </EventData>");
  }
  const message = text(fields.rendered_message ?? fields.message);
  if (message) {
    lines.push("  <RenderingInfo>", `    <Message>${esc(message)}</Message>`, "  </RenderingInfo>");
  }
  lines.push("</Event>");
  return lines.join("\n");
}
