import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

/** @param {unknown} value @returns {value is number[]} */
function validIDs(value) {
  return Array.isArray(value) && value.every(id => Number.isInteger(id) && id > 0 && id <= 0xffffffff);
}

/** The host may revoke access by atomically replacing its policy file.
 * @param {string | undefined} path @param {'execute' | 'disclose'} action @param {number} id
 */
export function policyAllows(path, action, id) {
  if (path === undefined) return true;
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > 4096) return false;
    const bytes = Buffer.alloc(stat.size + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, null);
      if (count === 0) break;
      used += count;
    }
    if (used !== stat.size) return false;
    const grants = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, used)));
    return grants !== null && typeof grants === "object" && Object.keys(grants).length === 2 &&
      validIDs(grants.execute) && validIDs(grants.disclose) && grants[action].includes(id);
  } catch { return false; }
  finally { if (fd !== undefined) closeSync(fd); }
}
