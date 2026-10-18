/**
 * 레지스트리 탐색기 (plan r4 §2.2 V2): hive → key tree | key details + value table.
 *
 * Route `#/case/{run}/explore/registry/{hive}?key={key path}`. The tree lists the run's hives
 * (`GET /registry-tree`) and loads child keys lazily (`?hive=&key=`); Enter / click selects a key.
 * The right side shows the key (path, last written, value count), its values decoded from the hive
 * file (`GET /registry-values`; collected names only when the hive file is not readable, with the
 * reason), 키 경로 복사 / 인용 복사, and the artifact rows produced from the key (jump = open the row
 * in its grid and viewer).
 */

import { useQuery } from "@tanstack/react-query";
import { type ReactNode, useCallback, useMemo, useState } from "react";
import { announce, DisabledReason } from "../../a11y";
import {
  fetchRegistryHives,
  fetchRegistryLevel,
  fetchRegistryValues,
  type RegistryHive,
  type RegistryKey,
  type RegistryLinkedRow,
  type RegistryValue,
  type RegistryValues,
} from "../../api/explorers";
import { Icon } from "../../icons";
import { useRoute } from "../../state/hooks";
import { writeClipboard } from "../viewer/commands";
import { errorText } from "../viewer/useAsync";
import { type ExplorerChildPage, ExplorerTree, type ExplorerTreeItem } from "./ExplorerTree";
import "./explorers.css";

export const REGISTRY_TREE_PAGE = 200;
const SEP = "\u0000";
const n = (value: number) => value.toLocaleString("ko-KR");

/** Tree id of a key: `<hive id>\0<key path>` (`""` = the hive root). */
export function keyId(hive: string, key: string): string {
  return `${hive}${SEP}${key}`;
}

function splitId(id: string): { hive: string; key: string } {
  const at = id.indexOf(SEP);
  return at < 0 ? { hive: id, key: "" } : { hive: id.slice(0, at), key: id.slice(at + 1) };
}

export function keyItem(hive: string, key: RegistryKey): ExplorerTreeItem {
  const values = key.value_count ?? 0;
  return {
    id: keyId(hive, key.key_path),
    label: key.name,
    badge: key.child_count ? n(key.child_count) : undefined,
    description: `하위 키 ${n(key.child_count)}개, 값 ${n(values)}개${key.last_written_at ? `, 마지막 기록 ${key.last_written_at}` : ""}`,
    hasChildren: key.has_children,
    icon: "key",
    title: key.key_path,
  };
}

/** Ancestor key paths of `key` inside `hive` (the hive root first), the key itself excluded. */
export function keyAncestorIds(hive: RegistryHive | undefined, key: string): string[] {
  if (!hive) return [];
  const out = [keyId(hive.id, "")];
  const mount = hive.mount;
  if (!key || key.toLowerCase() === mount.toLowerCase()) return out;
  if (!key.toLowerCase().startsWith(`${mount.toLowerCase()}\\`)) return out;
  const parts = key
    .slice(mount.length + 1)
    .split("\\")
    .filter(Boolean);
  for (let i = 1; i < parts.length; i += 1)
    out.push(keyId(hive.id, `${mount}\\${parts.slice(0, i).join("\\")}`));
  return out;
}

function decodedText(value: RegistryValue): ReactNode {
  switch (value.decoded_kind) {
    case "number":
      return `${value.decoded} (${value.decoded_hex ?? ""})`;
    case "list":
      return Array.isArray(value.decoded) ? value.decoded.join(" · ") : "";
    case "text":
      return String(value.decoded ?? "") + (value.decoded_truncated ? " …" : "");
    case "binary":
      return <span className="explorer-muted">이진 데이터</span>;
    case "empty":
      return <span className="explorer-muted">(비어 있음)</span>;
    case "too-large":
      return <span className="explorer-muted">데이터가 커서 읽지 않음</span>;
    default:
      return <span className="explorer-muted">값을 읽지 못함</span>;
  }
}

function ValueTable({ data }: { data: RegistryValues }) {
  if (data.values.length === 0) {
    return <p className="explorer-note">이 키에는 값이 없습니다.</p>;
  }
  return (
    <div className="explorer-table-wrap">
      <table className="explorer-table" aria-label={`${data.key.name} 값 ${n(data.value_total)}개`}>
        <colgroup>
          <col className="col-name" />
          <col className="col-type" />
          <col className="col-data" />
          <col />
        </colgroup>
        <thead>
          <tr>
            <th scope="col">이름</th>
            <th scope="col">형식</th>
            <th scope="col">데이터(앞 64바이트)</th>
            <th scope="col">디코딩 값</th>
          </tr>
        </thead>
        <tbody>
          {data.values.map((value) => (
            // Value names are unique within a key (regf).
            <tr key={value.name}>
              <th scope="row">{value.display_name}</th>
              <td>{value.type ?? "—"}</td>
              <td className="explorer-mono explorer-hex">
                {value.data_hex ?? "—"}
                {value.data_truncated ? " …" : ""}
                {value.data_size !== null ? (
                  <span className="explorer-muted"> ({n(value.data_size)} B)</span>
                ) : null}
              </td>
              <td className="explorer-decoded">{decodedText(value)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {data.value_total > data.values.length ? (
        <p className="explorer-note">
          값 {n(data.value_total)}개 중 {n(data.values.length)}개를 표시합니다.
        </p>
      ) : null}
    </div>
  );
}

function LinkedRows({ data, onJump }: { data: RegistryValues; onJump: (row: RegistryLinkedRow) => void }) {
  if (data.artifact_row_total === 0) {
    return <p className="explorer-note">이 키에서 나온 아티팩트 행이 없습니다(키 트리 행 제외).</p>;
  }
  return (
    <section aria-label="이 키에서 나온 아티팩트 행" className="explorer-linked">
      <h4>
        이 키에서 나온 아티팩트 행 {n(data.artifact_row_total)}건
        {data.artifact_row_total > data.artifact_rows.length
          ? ` (앞 ${n(data.artifact_rows.length)}건 표시)`
          : ""}
      </h4>
      <ul>
        {data.artifact_rows.map((row) => (
          <li key={`${row.kind}|${row.record_index}`}>
            <button
              type="button"
              className="view-link"
              onClick={() => onJump(row)}
              aria-label={`${row.label} 행 열기 (${row.artifact_type})`}
            >
              {row.label}
            </button>
            <span className="explorer-muted"> {row.artifact_type}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function KeyDetails({ runId, hive, keyPath }: { runId: string; hive: RegistryHive; keyPath: string }) {
  const { navigate } = useRoute();
  const [copied, setCopied] = useState("");
  const values = useQuery({
    queryKey: ["registry-values", runId, hive.id, keyPath],
    queryFn: ({ signal }) => fetchRegistryValues(runId, hive.id, keyPath, signal),
    staleTime: 60_000,
    retry: false,
  });
  // The kind's grid jumps to the row's page (its record index) and the viewer opens it; an
  // `artifact_type=` filter would make the server scan the whole kind first.
  const jump = (row: RegistryLinkedRow) => {
    navigate({
      runId,
      collection: "artifacts",
      kind: row.kind,
      row: { collection: "artifacts", kind: row.kind, locator: row.locator },
    });
    announce(`${row.label} 행을 엽니다`);
  };
  const copy = async (text: string, what: string) => {
    try {
      await writeClipboard(text);
      setCopied(`${what}을(를) 복사했습니다`);
      announce(`${what}을(를) 복사했습니다`);
    } catch (error) {
      setCopied(`복사하지 못했습니다: ${errorText(error)}`);
    }
  };
  if (values.isLoading) return <p className="explorer-note">값을 불러오는 중…</p>;
  if (values.error || !values.data) {
    return (
      <p className="explorer-note is-error" role="alert">
        값을 불러오지 못했습니다: {errorText(values.error)}
      </p>
    );
  }
  const data = values.data;
  const treeRow = data.citation.locator;
  return (
    <div className="registry-key-details" data-testid="registry-key-details">
      <h3 className="explorer-key-path explorer-mono">{data.key.key_path}</h3>
      <dl className="explorer-facts">
        <div>
          <dt>하이브</dt>
          <dd title={hive.path}>{hive.label}</dd>
        </div>
        <div>
          <dt>마지막 기록</dt>
          <dd>{data.key.last_written_at ?? "알 수 없음"}</dd>
        </div>
        <div>
          <dt>값</dt>
          <dd>{n(data.value_total)}개</dd>
        </div>
        <div>
          <dt>하위 키</dt>
          <dd>{n(data.key.child_count)}개</dd>
        </div>
      </dl>
      <div className="explorer-actions">
        <button type="button" className="button" onClick={() => copy(data.key.key_path, "키 경로")}>
          <Icon name="copy" /> 키 경로 복사
        </button>
        <button type="button" className="button" onClick={() => copy(data.citation.text, "인용")}>
          <Icon name="quote" /> 인용 복사
        </button>
        <DisabledReason
          reason={treeRow ? undefined : "수집기가 이 키의 트리 행을 남기지 않았습니다(상위 경로만 있음)"}
        >
          <button
            type="button"
            className="button"
            onClick={() => {
              if (!treeRow) return;
              navigate({
                runId,
                collection: "artifacts",
                kind: data.citation.kind,
                row: { collection: "artifacts", kind: data.citation.kind, locator: treeRow },
              });
            }}
          >
            <Icon name="external" /> 키 트리 행 열기
          </button>
        </DisabledReason>
        {copied ? <span className="explorer-muted">{copied}</span> : null}
      </div>
      <p className="explorer-citation explorer-mono" title="인용">
        {data.citation.text}
      </p>
      {data.values_status === "names-only" ? <p className="explorer-note">{data.reason}</p> : null}
      <ValueTable data={data} />
      <LinkedRows data={data} onJump={jump} />
    </div>
  );
}

export function RegistryExplorer() {
  const { route, patchRoute } = useRoute();
  const runId = route.runId;
  const hives = useQuery({
    queryKey: ["registry-hives", runId],
    queryFn: ({ signal }) => fetchRegistryHives(runId as string, signal),
    enabled: Boolean(runId),
    staleTime: 5 * 60_000,
    retry: false,
  });
  const hiveList = hives.data?.hives ?? [];
  const hive = hiveList.find((item) => item.id === route.kind);
  const keyPath = route.key ?? (hive ? hive.mount : "");

  const loadChildren = useCallback(
    async (id: string, after: string | null, signal: AbortSignal): Promise<ExplorerChildPage> => {
      const { hive: hiveId, key } = splitId(id);
      const page = await fetchRegistryLevel(
        runId as string,
        { hive: hiveId, key, limit: REGISTRY_TREE_PAGE, after },
        signal,
      );
      return {
        items: page.children.map((child) => keyItem(hiveId, child)),
        nextAfter: page.next_after,
        total: page.child_total,
      };
    },
    [runId],
  );

  const roots = useMemo<ExplorerTreeItem[]>(
    () =>
      hiveList.map((item) => ({
        id: keyId(item.id, ""),
        label: item.label,
        badge: n(item.key_count),
        description: `키 ${n(item.key_count)}개, ${item.path}`,
        hasChildren: true,
        icon: "database",
        title: item.path,
      })),
    [hiveList],
  );
  const selectedId = hive
    ? route.key && route.key.toLowerCase() !== hive.mount.toLowerCase()
      ? keyId(hive.id, route.key)
      : keyId(hive.id, "")
    : null;
  const expandIds = useMemo(() => keyAncestorIds(hive, route.key ?? ""), [hive, route.key]);

  const onOpen = (item: ExplorerTreeItem) => {
    const { hive: hiveId, key } = splitId(item.id);
    const target = hiveList.find((entry) => entry.id === hiveId);
    patchRoute({ kind: hiveId, key: key || undefined });
    announce(`${key || target?.mount || item.label} 키를 엽니다`);
  };

  let tree: ReactNode;
  if (hives.isLoading) {
    tree = (
      <p className="explorer-note">레지스트리 색인을 만드는 중… (처음 한 번은 수 초 걸릴 수 있습니다)</p>
    );
  } else if (hives.error) {
    tree = (
      <p className="explorer-note is-error" role="alert">
        레지스트리 트리를 불러오지 못했습니다: {errorText(hives.error)}
      </p>
    );
  } else if (hiveList.length === 0) {
    tree = (
      <p className="explorer-note">{hives.data?.reason ?? "이 런에는 레지스트리 키 트리 행이 없습니다"}</p>
    );
  } else {
    tree = (
      <ExplorerTree
        label="레지스트리 키 트리"
        roots={roots}
        loadChildren={loadChildren}
        selectedId={selectedId}
        onOpen={onOpen}
        expandIds={expandIds}
        resetKey={runId ?? ""}
        testId="registry-explorer-tree"
      />
    );
  }

  return (
    <div className="explorer-layout" data-testid="registry-explorer">
      <section className="explorer-pane" aria-label="레지스트리 하이브와 키">
        <div className="explorer-pane-head">
          <h2 className="explorer-title">
            <Icon name="database" /> 레지스트리 탐색기
          </h2>
        </div>
        {tree}
        {hives.data?.index?.truncated ? <p className="explorer-note">{hives.data.index.reason}</p> : null}
      </section>
      <div className="explorer-main explorer-scroll">
        {runId && hive ? (
          <KeyDetails runId={runId} hive={hive} keyPath={keyPath} />
        ) : route.kind && hives.data && !hive ? (
          <p className="explorer-note">이 런에 없는 하이브입니다. 왼쪽 트리에서 하이브를 고르세요.</p>
        ) : (
          <p className="explorer-note explorer-empty">
            왼쪽 트리에서 하이브와 키를 고르면 값 표와 이 키에서 나온 아티팩트 행이 여기에 표시됩니다.
            {hives.data?.index
              ? ` (하이브 ${n(hives.data.index.hives)}개 · 키 ${n(hives.data.index.keys)}개)`
              : ""}
          </p>
        )}
      </div>
    </div>
  );
}
