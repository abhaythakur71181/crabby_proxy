// Strong password generator for admin-set credentials. Guarantees at least one
// letter and one digit so it always satisfies the backend's validate_password
// rule, and draws from a safe symbol set (no quotes/backslash/space).
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I/O to avoid confusion
const LOWER = "abcdefghijkmnpqrstuvwxyz"; // no l/o
const DIGIT = "23456789"; // no 0/1
const SYMBOL = "!@#$%^&*-_=+?";
const ALL = UPPER + LOWER + DIGIT + SYMBOL;

function pick(set: string): string {
  const idx = crypto.getRandomValues(new Uint32Array(1))[0] % set.length;
  return set[idx];
}

export function generatePassword(len = 20): string {
  const chars: string[] = [
    pick(UPPER),
    pick(LOWER),
    pick(DIGIT),
    pick(SYMBOL),
  ];
  while (chars.length < len) chars.push(pick(ALL));
  // Fisher-Yates shuffle so the guaranteed classes aren't always in front.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
