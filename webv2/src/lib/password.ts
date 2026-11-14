// Strong password generator for admin-set credentials. Guarantees at least one
// letter and one digit so it always satisfies the backend's validate_password
// rule, and draws from a safe symbol set (no quotes/backslash/space).
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I/O to avoid confusion
const LOWER = "abcdefghijkmnpqrstuvwxyz"; // no l/o
const DIGIT = "23456789"; // no 0/1
const SYMBOL = "!@#$%^&*-_=+?";
const ALL = UPPER + LOWER + DIGIT + SYMBOL;

const U32_RANGE = 0x1_0000_0000; // 2^32

/** Uniform random integer in [0, n) from the CSPRNG. Uses rejection sampling:
 * a plain `u32 % n` over-weights small results whenever n does not divide 2^32,
 * so draws at or above the largest multiple of n are discarded and redrawn. */
export function randomIndex(n: number): number {
  if (!Number.isInteger(n) || n <= 0 || n > U32_RANGE) {
    throw new RangeError(`randomIndex: n must be an integer in [1, 2^32], got ${n}`);
  }
  const limit = U32_RANGE - (U32_RANGE % n); // largest multiple of n ≤ 2^32
  const buf = new Uint32Array(1);
  for (;;) {
    const v = crypto.getRandomValues(buf)[0];
    if (v < limit) return v % n;
  }
}

function pick(set: string): string {
  return set[randomIndex(set.length)];
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
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
