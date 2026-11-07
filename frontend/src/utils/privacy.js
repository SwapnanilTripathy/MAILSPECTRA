// Redact the presentation copy recursively so evidence kept for saving stays intact.
export function maskAnalysis(analysis) {
  if (!analysis) return analysis;
  const metadata = analysis.metadata || analysis.email_metadata || {};
  const people = [
    metadata.from_sender,
    ...(metadata.to_recipients || []),
    ...(metadata.cc_recipients || []),
    ...(metadata.bcc_recipients || []),
    ...(metadata.reply_to || []),
  ];
  const names = people
    .map((person) => person?.display_name)
    .filter((name) => typeof name === 'string' && name.length > 1);
  const maskName = (name) =>
    name
      .split(/(\s+)/)
      .map((word) =>
        /^\s+$/.test(word)
          ? word
          : word.length <= 2
            ? `${word[0]}*`
            : `${word[0]}${'*'.repeat(word.length - 2)}${word[word.length - 1]}`,
      )
      .join('');
  const maskString = (value) => {
    let result = value;
    for (const name of names) result = result.split(name).join(maskName(name));
    result = result.replace(
      /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
      (email) => {
        const [local, domain] = email.split('@');
        return `${local.length <= 2 ? `${local[0]}*` : `${local[0]}${'*'.repeat(local.length - 2)}${local[local.length - 1]}`}@${domain}`;
      },
    );
    result = result.replace(
      /\b(\d{1,3})(\.|\[\.\])(\d{1,3})(\.|\[\.\])\d{1,3}(\.|\[\.\])\d{1,3}\b/g,
      '$1$2$3$4***$5***',
    );
    return result.replace(
      /(?<![a-z0-9:])(?:[a-f0-9]{0,4}:){2,}[a-f0-9]{0,4}(?![a-z0-9:])/gi,
      (ip) =>
        ip.includes('::') || (ip.match(/:/g) || []).length >= 7
          ? '[masked IPv6]'
          : ip,
    );
  };
  const visit = (value) =>
    typeof value === 'string'
      ? maskString(value)
      : Array.isArray(value)
        ? value.map(visit)
        : value && typeof value === 'object'
          ? Object.fromEntries(
              Object.entries(value).map(([key, item]) => [
                maskString(key),
                visit(item),
              ]),
            )
          : value;
  return visit(analysis);
}
