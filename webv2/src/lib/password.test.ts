import { expect, spyOn, test } from "bun:test";
import { generatePassword, randomIndex } from "./password";

test("generatePassword satisfies the backend rule across many iterations", () => {
  for (let i = 0; i < 500; i++) {
    const p = generatePassword();
    expect(p.length).toBe(20);
    expect(/[A-Za-z]/.test(p)).toBe(true); // at least one letter
    expect(/[0-9]/.test(p)).toBe(true); // at least one digit
  }
});

test("generatePassword honors a custom length", () => {
  expect(generatePassword(32).length).toBe(32);
});

test("randomIndex stays in range", () => {
  for (const n of [1, 2, 3, 7, 24, 66]) {
    for (let i = 0; i < 200; i++) {
      const v = randomIndex(n);
      expect(Number.isInteger(v)).toBe(true);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(n);
    }
  }
});

test("randomIndex redraws values in the biased tail instead of wrapping them", () => {
  // n = 3: 2^32 % 3 === 1, so the single draw 2^32 - 1 lies in the biased
  // tail and must be discarded. The second draw (5) maps to 5 % 3 = 2.
  const draws = [0xffff_ffff, 5];
  const spy = spyOn(crypto, "getRandomValues").mockImplementation(((arr: Uint32Array) => {
    arr[0] = draws.shift()!;
    return arr;
  }) as typeof crypto.getRandomValues);
  try {
    expect(randomIndex(3)).toBe(2);
    expect(spy).toHaveBeenCalledTimes(2);
  } finally {
    spy.mockRestore();
  }
});

test("randomIndex rejects invalid bounds", () => {
  expect(() => randomIndex(0)).toThrow(RangeError);
  expect(() => randomIndex(1.5)).toThrow(RangeError);
});
