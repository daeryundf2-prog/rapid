/** Over text whose secrets the server masked (`redacted` on source-preview / source-text). */
export function RedactionNote() {
  return (
    <p className="viewer-note" data-testid="source-redacted-note">
      BitLocker 복구 키·저장된 비밀번호·개인 키 같은 비밀 값은 가려서 표시합니다. 가리지 않은 원본은 원본
      열기로 내려받아 확인하세요.
    </p>
  );
}
