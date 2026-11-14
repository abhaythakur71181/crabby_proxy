import { expect, test } from "bun:test";
import { isIpv4, tunnelTargetError } from "./ip";

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

test("tunnelTargetError accepts IP:port targets", () => {
  expect(tunnelTargetError("203.0.113.10:5432")).toBeNull();
  expect(tunnelTargetError(" 127.0.0.1:80 ")).toBeNull();
  expect(tunnelTargetError("[2001:db8::1]:443")).toBeNull();
  expect(tunnelTargetError("[::1]:65535")).toBeNull();
});

test("tunnelTargetError rejects missing or malformed targets", () => {
  expect(tunnelTargetError("")).not.toBeNull();
  expect(tunnelTargetError("   ")).not.toBeNull();
  expect(tunnelTargetError("10.0.0.1")).not.toBeNull();
  expect(tunnelTargetError("db.internal:5432")).not.toBeNull();
  expect(tunnelTargetError("10.0.0.1:0")).not.toBeNull();
  expect(tunnelTargetError("10.0.0.1:65536")).not.toBeNull();
  expect(tunnelTargetError("10.0.0.1:080")).not.toBeNull();
  expect(tunnelTargetError("2001:db8::1:443")).not.toBeNull();
  expect(tunnelTargetError("[not:an:ip:zz]:443")).not.toBeNull();
  expect(tunnelTargetError("[2001:db8::1]")).not.toBeNull();
});
