import { expect, test } from "bun:test";
import { toCsv } from "./utils";

test("toCsv writes the header row then the data rows", () => {
  expect(toCsv(["username", "password"], [["alice", "s3cret"], ["bob", 42]])).toBe(
    "username,password\nalice,s3cret\nbob,42",
  );
});

test("toCsv quotes cells with commas, quotes and line breaks", () => {
  expect(toCsv(["a"], [["x,y"], ['say "hi"'], ["l1\nl2"], ["cr\r"]])).toBe(
    'a\n"x,y"\n"say ""hi"""\n"l1\nl2"\n"cr\r"',
  );
});

test("toCsv leaves generated-password symbols untouched", () => {
  expect(toCsv(["p"], [["!@#$%^&*-_=+?"]])).toBe("p\n!@#$%^&*-_=+?");
});
