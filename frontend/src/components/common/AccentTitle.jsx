// Renders a heading with its last word in italic (styled by soc-redesign.css).
export default function AccentTitle({ text }) {
  const t = String(text ?? '').trimEnd();
  const i = t.lastIndexOf(' ');
  if (i < 0) return <>{t}</>;
  return (
    <>
      {t.slice(0, i + 1)}
      <em>{t.slice(i + 1)}</em>
    </>
  );
}
