import { Landing } from "../features/case/Landing";

/** No API token yet: the landing card asks for it (visual-polish S10; the token field lives in the card). */
export function TokenGate({ onSaved }: { onSaved: () => void }) {
  return (
    <main id="main" tabIndex={-1} className="landing-frame" aria-label="연결">
      <Landing tokenRequired onTokenSaved={onSaved} />
    </main>
  );
}
