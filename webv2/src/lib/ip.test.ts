import { expect, test } from "bun:test";
import { isIpv4 } from "./ip";

test("isIpv4 accepts dotted-quad IPv4", () => {
  expect(isIpv4("1.2.3.4")).toBe(true);
  expect(isIpv4("140.11.11.5")).toBe(true);
  expect(isIpv4("255.255.255.255")).toBe(true);
});

test("isIpv4 rejects non-IPv4", () => {
  expect(isIpv4("not-an-ip")).toBe(false);
  expect(isIpv4("256.1.1.1")).toBe(false);
  expect(isIpv4("1.2.3")).toBe(false);
  expect(isIpv4("2401:4900::1")).toBe(false);
  expect(isIpv4("140.11.11.*")).toBe(false);
});
