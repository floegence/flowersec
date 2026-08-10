const selectorPattern = /<!-- readme-locales:start -->[\s\S]*?<!-- readme-locales:end -->/g;
const fencedBlockPattern = /```[\s\S]*?```/g;

function withoutSelector(content) {
  return content.replace(selectorPattern, "");
}

export function extractInlineCodeLiterals(content) {
  const text = withoutSelector(content).replace(fencedBlockPattern, "");
  return [...text.matchAll(/`([^`\n]+)`/g)].map((match) => match[1]).sort();
}

export function extractMarkdownShape(content) {
  const shape = [];
  let paragraph = false;
  let fenced = false;
  const flushParagraph = () => {
    if (paragraph) {
      shape.push("paragraph");
      paragraph = false;
    }
  };

  for (const rawLine of withoutSelector(content).replace(/\r\n/g, "\n").split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("```")) {
      flushParagraph();
      if (!fenced) shape.push(`code:${line.slice(3).trim()}`);
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    if (line === "" || /^<!--.*-->$/.test(line) || /^<a id="[^"]+"><\/a>$/.test(line)) {
      flushParagraph();
      continue;
    }
    if (/^#{1,6}\s/.test(line)) {
      flushParagraph();
      shape.push(`heading:${line.match(/^#+/)[0].length}`);
      continue;
    }
    if (/^[-*+]\s/.test(line)) {
      flushParagraph();
      shape.push("list-item");
      continue;
    }
    if (/^\|.*\|$/.test(line)) {
      flushParagraph();
      shape.push(`table-row:${line.split("|").length - 2}`);
      continue;
    }
    paragraph = true;
  }
  flushParagraph();
  return shape;
}

export function extractProductVersion(content) {
  return /\bFlowersec\s+(\d+\.\d+\.\d+)\b/u.exec(content)?.[1] ?? null;
}
