import type { ReactNode } from "react";
import { MiddlePath } from "../../../components/MiddlePath";
import { ToneChip } from "../../../components/ToneChip";
import { evidenceFolderOf, evidencePathOf } from "../../../utils/pathDisplay";

/** Marker of a recovered (deleted / carved / orphan) item in the 경로 cell (r8 C.9.1). */
export const RECOVERED_MARK = "복구";
/** What a recovered item with no known original location shows instead of a pseudo folder. */
export const LOCATION_UNKNOWN_TEXT = "원래 위치 알 수 없음";

export interface PathCellOptions {
  /** Show the parent folder only (files: the 이름 column already names the file). */
  folderOnly?: boolean;
  /** The row is a recovered item: a `복구` marker precedes the path. */
  recovered?: boolean;
  /** The row's original location is unknown (carved / orphan) even when its path looks normal. */
  locationUnknown?: boolean;
  /** Volume letter of the row's file system, when the server names it. */
  volume?: string | null;
}

/** The in-evidence text a 경로 cell shows (and filters / copies on); null when unknown. */
export function pathCellText(path: string | null, options: PathCellOptions = {}): string | null {
  const evidence = evidencePathOf(path, options.volume);
  if (options.locationUnknown || evidence.locationUnknown) return null;
  return options.folderOnly ? evidenceFolderOf(path, options.volume) : evidence.path;
}

/** Tooltip of a 경로 cell: the whole in-evidence path, or the recovered / unknown wording. */
export function pathCellTooltip(path: string | null, options: PathCellOptions = {}): string {
  const evidence = evidencePathOf(path, options.volume);
  const unknown = options.locationUnknown || evidence.locationUnknown;
  if (unknown) return `${RECOVERED_MARK} — ${LOCATION_UNKNOWN_TEXT}`;
  const text = evidence.path ?? "";
  return options.recovered && text ? `${RECOVERED_MARK} — ${text}` : text;
}

/**
 * 경로 cell (review #9; r8 C.9.1 / IS-128): the path INSIDE the evidence — the result-folder
 * prefix (`…\_e01\fs\`) never shows — tail first under one front ellipsis. With `folderOnly` the
 * parent folder only. A recovered item gets a `복구` marker; one from a recovery pseudo folder
 * (`_deleted_mft`, `$OrphanFiles`) or with no known location reads "원래 위치 알 수 없음".
 */
export function pathCell(path: string | null, options: PathCellOptions = {}): ReactNode {
  if (!path) return null;
  const evidence = evidencePathOf(path, options.volume);
  const unknown = Boolean(options.locationUnknown || evidence.locationUnknown);
  const shown = pathCellText(path, options);
  const tooltip = pathCellTooltip(path, options);
  if (!unknown && !options.recovered) {
    return shown ? <MiddlePath path={shown} title={evidence.path ?? shown} /> : null;
  }
  return (
    <span className="grid-path-cell" data-testid="path-cell-recovered" title={tooltip}>
      <ToneChip tone="warn">{RECOVERED_MARK}</ToneChip>
      {unknown || !shown ? (
        <span className="grid-cell-empty">{LOCATION_UNKNOWN_TEXT}</span>
      ) : (
        <MiddlePath path={shown} title={tooltip} />
      )}
    </span>
  );
}

/**
 * 이름 cell of a files row (T-171, r8 C.9.1): a recovered item carries the same `복구` marker as
 * its 경로 cell, so the marker shows in the default column set even when 경로 is hidden (a narrow
 * grid or a large image run). The tooltip names the in-evidence location.
 */
export function recoveredNameCell(
  name: string,
  options: PathCellOptions & { path?: string | null },
): ReactNode {
  if (!options.recovered && !options.locationUnknown) return <span className="grid-cell-text">{name}</span>;
  return (
    <span
      className="grid-path-cell"
      data-testid="name-cell-recovered"
      title={pathCellTooltip(options.path ?? null, options) || RECOVERED_MARK}
    >
      <ToneChip tone="warn">{RECOVERED_MARK}</ToneChip>
      <span className="grid-cell-text">{name}</span>
    </span>
  );
}
