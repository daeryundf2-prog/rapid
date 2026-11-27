import { headerZoneParts } from "../utils/time";

/**
 * A time reading under a column header that names its zone ("시각 (KST)"): the eye reads
 * "2026-10-18 08:02:48", while a text selection, copy and screen readers still get
 * "2026-10-18 08:02:48 KST" (the zone part has no width, it is not removed). Text whose zone is
 * not the header's (a daylight-saving half, 현지(미확정)) shows whole.
 */
export function ZoneTime({ text, zone }: { text: string; zone: string }) {
  const parts = headerZoneParts(text, zone);
  if (parts.length === 1) return <>{text}</>;
  return (
    <>
      {parts.map((part, index) =>
        part.zone ? (
          // biome-ignore lint/suspicious/noArrayIndexKey: parts of one fixed string, never reordered
          <span key={index} className="zone-time-hidden">
            {part.text}
          </span>
        ) : (
          part.text
        ),
      )}
    </>
  );
}
