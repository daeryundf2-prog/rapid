/**
 * Expert viewer modes loaded on demand (T-116): 헥스, SQLite and 이미지 are their own JS chunks,
 * fetched the first time a row opens in that mode ("… 불러오는 중", role=status; a failed chunk
 * shows a Korean 다시 시도 message — `lazyView`).
 */

import { lazyView } from "../../components/LazyView";

export const HexView = lazyView("헥스 보기", () => import("./views/HexView").then((m) => m.HexView));
export const SqliteView = lazyView("SQLite 보기", () =>
  import("./views/SqliteView").then((m) => m.SqliteView),
);
export const ImageView = lazyView("이미지 보기", () => import("./views/ImageView").then((m) => m.ImageView));
