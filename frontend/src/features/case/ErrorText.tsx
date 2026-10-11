import { type ReactNode, useEffect, useRef } from "react";
import { announce } from "../../a11y";

/** Visible error line; screen readers are told via announce() (the only live-region owner). */
export function ErrorText({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    const text = ref.current?.textContent;
    if (text) announce(text, { politeness: "assertive" });
  }, []);
  return (
    <p ref={ref} className="case-error">
      {children}
    </p>
  );
}
