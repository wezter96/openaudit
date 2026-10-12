// Test files are skipped by code.security.
test("eval", () => {
	expect(eval("1 + 1")).toBe(2);
});
