const fencedBlockPattern = /```[\s\S]*?```/g;
const selectorStart = "<!-- readme-locales:start -->";
const selectorEnd = "<!-- readme-locales:end -->";

function withoutSelector(content) {
  let result = "";
  let offset = 0;

  while (offset < content.length) {
    const start = content.indexOf(selectorStart, offset);
    if (start === -1) return result + content.slice(offset);

    result += content.slice(offset, start);
    const end = content.indexOf(selectorEnd, start + selectorStart.length);
    if (end === -1) return result;
    offset = end + selectorEnd.length;
  }

  return result;
}

function withoutHtmlComments(content) {
  let result = "";
  let offset = 0;

  while (offset < content.length) {
    const start = content.indexOf("<!--", offset);
    if (start === -1) return result + content.slice(offset);

    result += content.slice(offset, start);
    const end = content.indexOf("-->", start + 4);
    const commentEnd = end === -1 ? content.length : end + 3;
    for (let index = start; index < commentEnd; index += 1) {
      if (content[index] === "\n") result += "\n";
    }
    offset = commentEnd;
  }

  return result;
}

function visibleMarkdown(content) {
  return withoutHtmlComments(withoutSelector(content));
}

function isAnchorOnlyLine(line) {
  const prefix = "<a id=\"";
  const suffix = "\"></a>";
  if (!line.startsWith(prefix) || !line.endsWith(suffix)) return false;

  const id = line.slice(prefix.length, -suffix.length);
  return id.length > 0 && !id.includes("\"");
}

export function extractInlineCodeLiterals(content) {
  const text = visibleMarkdown(content).replace(fencedBlockPattern, "");
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

  for (const rawLine of visibleMarkdown(content).replace(/\r\n/g, "\n").split("\n")) {
    const line = rawLine.trim();
    if (line.startsWith("```")) {
      flushParagraph();
      if (!fenced) shape.push(`code:${line.slice(3).trim()}`);
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    if (line === "" || isAnchorOnlyLine(line)) {
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
