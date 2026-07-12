import { expect, test } from "bun:test";
import { generatePassword } from "./password";

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
