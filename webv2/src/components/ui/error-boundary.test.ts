// Logic-level tests (bun:test has no DOM here): the boundary captures errors,
// renders the fallback, and resets on retry or when resetKey changes.
import { expect, test } from "bun:test";
import { ErrorBoundary } from "./error-boundary";

function make(resetKey: unknown, onReset?: () => void) {
  const fallback = ({ error }: { error: Error }) => `fallback:${error.message}`;
  const b = new ErrorBoundary({ children: "ok", fallback, resetKey, onReset });
  // Stand in for React's state machinery.
  b.setState = ((s: object) => Object.assign(b.state, s)) as typeof b.setState;
  return b;
}

test("getDerivedStateFromError normalises thrown values to Error", () => {
  expect(ErrorBoundary.getDerivedStateFromError(new Error("boom")).error?.message).toBe("boom");
  expect(ErrorBoundary.getDerivedStateFromError("str").error).toBeInstanceOf(Error);
});

test("renders children normally and the fallback after an error", () => {
  const b = make("/a");
  expect(b.render()).toBe("ok");
  Object.assign(b.state, ErrorBoundary.getDerivedStateFromError(new Error("boom")));
  expect(b.render()).toBe("fallback:boom");
});

test("reset clears the error and calls onReset", () => {
  let resets = 0;
  const b = make("/a", () => resets++);
  Object.assign(b.state, ErrorBoundary.getDerivedStateFromError(new Error("boom")));
  b.reset();
  expect(b.state.error).toBeNull();
  expect(resets).toBe(1);
});

test("a changed resetKey recovers from the error; an unchanged one does not", () => {
  const b = make("/b");
  Object.assign(b.state, ErrorBoundary.getDerivedStateFromError(new Error("boom")));
  b.componentDidUpdate({ ...b.props, resetKey: "/b" });
  expect(b.state.error).not.toBeNull();
  b.componentDidUpdate({ ...b.props, resetKey: "/a" });
  expect(b.state.error).toBeNull();
});
