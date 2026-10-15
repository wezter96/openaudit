import type * as TS from "typescript";

import { codeLineMask, directivesBefore } from "./lines";
import type { Bump, FileMetrics, FunctionMetrics, Param } from "./metrics";

type Ts = typeof TS;

/**
 * Code Health metrics for JavaScript and TypeScript, measured the way
 * CodeScene measures them so the two tools agree on what a smell is.
 *
 * A unit is a named function: a declaration, a method, or a function
 * assigned to a variable or property. Anonymous callbacks fold into the unit
 * that contains them, except one passed to a call that starts with a string
 * (`test("name", () => {})`), which is a unit named after that string. An
 * arrow function whose body is a single expression wrapping another function
 * (`run: (ctx) => Effect.gen(function* () {})`) hands its name to that
 * function. Named inner functions are units of their own (`outer.inner`).
 */
interface Unit {
	readonly name: string;
	readonly node: TS.FunctionLikeDeclaration;
	readonly start: number;
	readonly expressionBody: boolean;
}

interface Named {
	readonly name: string;
	readonly start: TS.Node;
	/** Already qualified (a class or object member, or a call label). */
	readonly complete: boolean;
}

/** Everything the measuring functions share for one file. */
interface Context {
	readonly ts: Ts;
	readonly sf: TS.SourceFile;
	readonly unitOf: ReadonlyMap<TS.Node, Unit>;
	readonly lineOf: (pos: number) => number;
}

const FUNCTION_KINDS = (ts: Ts) =>
	new Set([
		ts.SyntaxKind.FunctionDeclaration,
		ts.SyntaxKind.FunctionExpression,
		ts.SyntaxKind.ArrowFunction,
		ts.SyntaxKind.MethodDeclaration,
		ts.SyntaxKind.Constructor,
		ts.SyntaxKind.GetAccessor,
		ts.SyntaxKind.SetAccessor,
	]);

const DECISION_KINDS = (ts: Ts) =>
	new Set([
		ts.SyntaxKind.IfStatement,
		ts.SyntaxKind.ConditionalExpression,
		ts.SyntaxKind.ForStatement,
		ts.SyntaxKind.ForInStatement,
		ts.SyntaxKind.ForOfStatement,
		ts.SyntaxKind.WhileStatement,
		ts.SyntaxKind.DoStatement,
		ts.SyntaxKind.CatchClause,
		ts.SyntaxKind.CaseClause,
	]);

/** Statements that open a level of conditional nesting. */
const NESTING_KINDS = (ts: Ts) =>
	new Set([
		ts.SyntaxKind.IfStatement,
		ts.SyntaxKind.ForStatement,
		ts.SyntaxKind.ForInStatement,
		ts.SyntaxKind.ForOfStatement,
		ts.SyntaxKind.WhileStatement,
		ts.SyntaxKind.DoStatement,
		ts.SyntaxKind.SwitchStatement,
	]);

const PRIMITIVE_TYPES = (ts: Ts) =>
	new Set([
		ts.SyntaxKind.StringKeyword,
		ts.SyntaxKind.NumberKeyword,
		ts.SyntaxKind.BooleanKeyword,
		ts.SyntaxKind.BigIntKeyword,
		ts.SyntaxKind.SymbolKeyword,
	]);

/** Kind sets are built once per TypeScript module. */
const kindsCache = new WeakMap<Ts, ReturnType<typeof buildKinds>>();
const buildKinds = (ts: Ts) => ({
	functions: FUNCTION_KINDS(ts),
	decisions: DECISION_KINDS(ts),
	nesting: NESTING_KINDS(ts),
	primitives: PRIMITIVE_TYPES(ts),
});
const kinds = (ts: Ts) => {
	let k = kindsCache.get(ts);
	if (!k) {
		k = buildKinds(ts);
		kindsCache.set(ts, k);
	}
	return k;
};

const isFunctionWithBody = (
	ts: Ts,
	node: TS.Node,
): node is TS.FunctionLikeDeclaration =>
	kinds(ts).functions.has(node.kind) &&
	(node as TS.FunctionLikeDeclaration).body !== undefined;

const isLogical = (ts: Ts, node: TS.Node) => {
	if (!ts.isBinaryExpression(node)) return false;
	const op = node.operatorToken.kind;
	return (
		op === ts.SyntaxKind.AmpersandAmpersandToken ||
		op === ts.SyntaxKind.BarBarToken
	);
};

/** Optional chaining (`a?.b`) is a branch too. */
const isOptionalChain = (node: TS.Node) =>
	(node as { questionDotToken?: unknown }).questionDotToken !== undefined;

const isDecision = (ts: Ts, node: TS.Node) =>
	kinds(ts).decisions.has(node.kind) ||
	isLogical(ts, node) ||
	isOptionalChain(node);

/** `else if` continues its `if` chain instead of nesting inside it. */
const isElseIf = (ts: Ts, node: TS.Node) =>
	ts.isIfStatement(node.parent) && node.parent.elseStatement === node;

const opensNesting = (ts: Ts, node: TS.Node) =>
	kinds(ts).nesting.has(node.kind) && !isElseIf(ts, node);

const propertyName = (ts: Ts, name: TS.PropertyName): string =>
	ts.isIdentifier(name) || ts.isStringLiteral(name)
		? name.text
		: name.getText();

/** The name of the class or object literal a member belongs to. */
const containerName = (ts: Ts, member: TS.Node): string | undefined => {
	const parent = member.parent;
	if (ts.isClassLike(parent)) return parent.name?.text;
	if (!ts.isObjectLiteralExpression(parent)) return undefined;
	const holder = parent.parent;
	if (ts.isPropertyAssignment(holder)) return propertyName(ts, holder.name);
	return ts.isVariableDeclaration(holder) && ts.isIdentifier(holder.name)
		? holder.name.text
		: undefined;
};

const qualify = (owner: string | undefined, name: string) =>
	owner ? `${owner}.${name}` : name;

const memberName = (ts: Ts, member: TS.Node, name: TS.PropertyName): Named => {
	const container = containerName(ts, member);
	return {
		name: qualify(container, propertyName(ts, name)),
		start: member,
		complete: container !== undefined,
	};
};

/** The statement a variable declaration sits in, where its unit begins. */
const declarationStart = (ts: Ts, decl: TS.VariableDeclaration): TS.Node => {
	const statement = decl.parent?.parent;
	return statement && ts.isVariableStatement(statement) ? statement : decl;
};

/** A string literal that starts the call a callback is passed to. */
const callLabel = (ts: Ts, fn: TS.Node): Named | undefined => {
	const call = fn.parent;
	if (!ts.isCallExpression(call)) return undefined;
	const first = call.arguments[0];
	if (!first || first === fn) return undefined;
	if (!ts.isStringLiteralLike(first)) return undefined;
	return { name: `"${first.text}"`, start: call, complete: true };
};

const isMember = (ts: Ts, node: TS.Node) =>
	ts.isMethodDeclaration(node) ||
	ts.isGetAccessorDeclaration(node) ||
	ts.isSetAccessorDeclaration(node);

/** How the function itself, or the place it is assigned to, names it. */
const ownName = (
	ts: Ts,
	node: TS.FunctionLikeDeclaration,
): Named | undefined => {
	if (ts.isConstructorDeclaration(node))
		return {
			name: qualify(containerName(ts, node), "constructor"),
			start: node,
			complete: true,
		};
	if (isMember(ts, node))
		return memberName(ts, node, node.name as TS.PropertyName);
	const name = (node as { name?: TS.Identifier }).name;
	return name ? { name: name.text, start: node, complete: false } : undefined;
};

const assignedName = (ts: Ts, node: TS.Node): Named | undefined => {
	const parent = node.parent;
	if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name))
		return {
			name: parent.name.text,
			start: declarationStart(ts, parent),
			complete: false,
		};
	if (ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent))
		return memberName(ts, parent, parent.name);
	if (!ts.isBinaryExpression(parent) || parent.right !== node) return undefined;
	return parent.operatorToken.kind === ts.SyntaxKind.EqualsToken
		? { name: parent.left.getText(), start: parent, complete: false }
		: undefined;
};

const nameOf = (ts: Ts, node: TS.FunctionLikeDeclaration): Named | undefined =>
	ownName(ts, node) ?? assignedName(ts, node) ?? callLabel(ts, node);

/**
 * A top-level anonymous function takes the name of the declaration holding
 * it: `export const quality = defineAuditor({ run: ... })` is `quality`.
 */
const enclosingName = (ts: Ts, node: TS.Node): Named => {
	for (let p: TS.Node | undefined = node.parent; p; p = p.parent) {
		if (ts.isVariableDeclaration(p) && ts.isIdentifier(p.name))
			return {
				name: p.name.text,
				start: declarationStart(ts, p),
				complete: true,
			};
		if (ts.isExportAssignment(p))
			return { name: "default", start: p, complete: true };
	}
	return { name: "(anonymous)", start: node, complete: true };
};

const containsFunction = (ts: Ts, node: TS.Node): boolean =>
	ts.isFunctionLike(node) ||
	(ts.forEachChild(node, (child) => containsFunction(ts, child) || undefined) ??
		false);

/** An expression-bodied arrow that only wraps another function is not a unit. */
const isUnitCandidate = (
	ts: Ts,
	node: TS.Node,
): node is TS.FunctionLikeDeclaration => {
	if (!isFunctionWithBody(ts, node)) return false;
	const body = node.body as TS.ConciseBody;
	return ts.isBlock(body) || !containsFunction(ts, body);
};

const collectUnits = (ts: Ts, sf: TS.SourceFile): Unit[] => {
	const units: Unit[] = [];
	const visit = (node: TS.Node, owner: Unit | undefined) => {
		const unit = isUnitCandidate(ts, node)
			? toUnit(ts, sf, node, owner)
			: undefined;
		if (unit) units.push(unit);
		ts.forEachChild(node, (child) => visit(child, unit ?? owner));
	};
	visit(sf, undefined);
	return units;
};

const toUnit = (
	ts: Ts,
	sf: TS.SourceFile,
	node: TS.FunctionLikeDeclaration,
	owner: Unit | undefined,
): Unit | undefined => {
	const named =
		nameOf(ts, node) ?? (owner ? undefined : enclosingName(ts, node));
	if (!named) return undefined;
	const qualified = owner !== undefined && !named.complete;
	return {
		name: qualified ? qualify(owner.name, named.name) : named.name,
		node,
		start: named.start.getStart(sf),
		expressionBody: !ts.isBlock(node.body as TS.ConciseBody),
	};
};

/**
 * Walks a unit's own code: folded callbacks yes, other units no. Code inside
 * `${}` of a template literal is text being built, not control flow.
 */
const walkOwn = (c: Context, unit: Unit, visit: (node: TS.Node) => void) => {
	const go = (node: TS.Node) => {
		const owner = c.unitOf.get(node);
		if (owner !== undefined && owner !== unit) return;
		if (c.ts.isTemplateSpan(node)) return;
		visit(node);
		c.ts.forEachChild(node, go);
	};
	c.ts.forEachChild(unit.node, go);
};

/** Logical operators in a condition, not counting functions inside it. */
const countLogical = (ts: Ts, expr: TS.Node): number => {
	if (ts.isFunctionLike(expr)) return 0;
	let n = isLogical(ts, expr) ? 1 : 0;
	ts.forEachChild(expr, (child) => {
		n += countLogical(ts, child);
	});
	return n;
};

/** The condition whose logical operators can make a complex conditional. */
const conditionOf = (ts: Ts, node: TS.Node): TS.Expression | undefined => {
	if (ts.isIfStatement(node) || ts.isWhileStatement(node))
		return node.expression;
	if (ts.isDoStatement(node)) return node.expression;
	if (ts.isForStatement(node)) return node.condition;
	return ts.isConditionalExpression(node) ? node.condition : undefined;
};

/** Deepest nesting of conditionals and loops below `root`, in the unit's own code. */
const maxNesting = (c: Context, root: TS.Node, unit: Unit): number => {
	let max = 0;
	const go = (node: TS.Node, depth: number) => {
		const owner = c.unitOf.get(node);
		if (owner !== undefined && owner !== unit) return;
		const d = opensNesting(c.ts, node) ? depth + 1 : depth;
		max = Math.max(max, d);
		c.ts.forEachChild(node, (child) => go(child, d));
	};
	c.ts.forEachChild(root, (child) => go(child, 0));
	return max;
};

const blockStatements = (
	ts: Ts,
	s: TS.Statement,
): ReadonlyArray<TS.Statement> => (ts.isBlock(s) ? s.statements : [s]);

const ifChildren = (ts: Ts, s: TS.IfStatement): ReadonlyArray<TS.Statement> => {
	const otherwise = s.elseStatement;
	const rest = !otherwise
		? []
		: ts.isIfStatement(otherwise)
			? ifChildren(ts, otherwise)
			: blockStatements(ts, otherwise);
	return [...blockStatements(ts, s.thenStatement), ...rest];
};

const tryChildren = (s: TS.TryStatement): ReadonlyArray<TS.Statement> => [
	...s.tryBlock.statements,
	...(s.catchClause?.block.statements ?? []),
	...(s.finallyBlock?.statements ?? []),
];

/** Statements directly inside a statement's blocks; `else if` chains flatten. */
const childStatements = (
	ts: Ts,
	s: TS.Statement,
): ReadonlyArray<TS.Statement> => {
	if (ts.isIfStatement(s)) return ifChildren(ts, s);
	if (ts.isIterationStatement(s, false) || ts.isLabeledStatement(s))
		return blockStatements(ts, s.statement);
	if (ts.isSwitchStatement(s))
		return s.caseBlock.clauses.flatMap((clause) => [...clause.statements]);
	if (ts.isTryStatement(s)) return tryChildren(s);
	return ts.isBlock(s) ? s.statements : [];
};

/**
 * Chunks of nested conditional logic. A statement that reaches a nesting
 * depth of two is a bump, unless two or more of its own statements are
 * bumps, in which case those count instead.
 */
const bumpsOf = (c: Context, body: TS.Block, unit: Unit): Bump[] => {
	const depthOf = (s: TS.Statement) =>
		(opensNesting(c.ts, s) ? 1 : 0) + maxNesting(c, s, unit);
	const bumps = (s: TS.Statement): Bump[] => {
		if (depthOf(s) < 2) return [];
		const inner = childStatements(c.ts, s).flatMap(bumps);
		if (inner.length >= 2) return inner;
		return [{ lines: c.lineOf(s.getEnd()) - c.lineOf(s.getStart(c.sf)) + 1 }];
	};
	return body.statements.flatMap(bumps);
};

const literalParam = (ts: Ts, init: TS.Expression | undefined): Param => {
	if (init === undefined) return { primitive: false, string: false };
	if (ts.isStringLiteralLike(init)) return { primitive: true, string: true };
	const primitive =
		ts.isNumericLiteral(init) ||
		init.kind === ts.SyntaxKind.TrueKeyword ||
		init.kind === ts.SyntaxKind.FalseKeyword;
	return { primitive, string: false };
};

/** A parameter's declared type, or the type of its default value. */
const paramOf = (ts: Ts, p: TS.ParameterDeclaration): Param => {
	const type = p.type;
	if (!type) return literalParam(ts, p.initializer);
	const string = type.kind === ts.SyntaxKind.StringKeyword;
	const primitive =
		kinds(ts).primitives.has(type.kind) || ts.isLiteralTypeNode(type);
	return { primitive, string };
};

const isThisParam = (ts: Ts, p: TS.ParameterDeclaration) =>
	ts.isIdentifier(p.name) && p.name.text === "this";

/** Tokens of the unit's own code, with string contents left out. */
const tokensOf = (c: Context, unit: Unit): string[] => {
	const out: string[] = [];
	walkOwn(c, unit, (node) => {
		if (node.getChildCount(c.sf) > 0) return;
		out.push(c.ts.isStringLiteralLike(node) ? '""' : node.getText(c.sf));
	});
	return out;
};

const ownCodeLines = (
	c: Context,
	unit: Unit,
	units: ReadonlyArray<Unit>,
	codeLines: Uint8Array,
): number => {
	const start = c.lineOf(unit.start);
	const own = codeLines.slice(start, c.lineOf(unit.node.getEnd()) + 1);
	for (const inner of units) {
		if (inner === unit || !within(unit.node, inner.node)) continue;
		own.fill(
			0,
			c.lineOf(inner.start) - start,
			c.lineOf(inner.node.getEnd()) + 1 - start,
		);
	}
	return own.reduce((n, v) => n + v, 0);
};

const within = (outer: TS.Node, inner: TS.Node) =>
	inner.pos >= outer.pos && inner.end <= outer.end;

const branchesOf = (c: Context, unit: Unit) => {
	let cc = 1;
	const conditionals: FunctionMetrics["conditionals"][number][] = [];
	walkOwn(c, unit, (node) => {
		if (isDecision(c.ts, node)) cc++;
		const condition = conditionOf(c.ts, node);
		const branches = condition ? countLogical(c.ts, condition) : 0;
		if (branches > 0)
			conditionals.push({
				line: c.lineOf(node.getStart(c.sf)),
				endLine: c.lineOf((condition as TS.Node).getEnd()),
				branches,
			});
	});
	return { cc, conditionals };
};

const measure = (
	c: Context,
	unit: Unit,
	units: ReadonlyArray<Unit>,
	codeLines: Uint8Array,
): FunctionMetrics => {
	const body = unit.node.body as TS.ConciseBody;
	const startLine = c.lineOf(unit.start);
	return {
		name: unit.name,
		startLine,
		endLine: c.lineOf(unit.node.getEnd()),
		loc: ownCodeLines(c, unit, units, codeLines),
		...branchesOf(c, unit),
		params: unit.node.parameters
			.filter((p) => !isThisParam(c.ts, p))
			.map((p) => paramOf(c.ts, p)),
		isConstructor: c.ts.isConstructorDeclaration(unit.node),
		expressionBody: unit.expressionBody,
		nesting: maxNesting(c, body, unit),
		bumps: c.ts.isBlock(body) ? bumpsOf(c, body, unit) : [],
		tokens: tokensOf(c, unit),
		disabled: directivesBefore(c.sf.text, unit.start),
	};
};

export const scriptKindOf = (ts: Ts, path: string): TS.ScriptKind => {
	if (/\.tsx$/i.test(path)) return ts.ScriptKind.TSX;
	if (/\.jsx$/i.test(path)) return ts.ScriptKind.JSX;
	return /\.[cm]?js$/i.test(path) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
};

/** Code Health metrics for one JavaScript or TypeScript file. */
export const analyzeJs = (ts: Ts, path: string, text: string): FileMetrics => {
	const sf = ts.createSourceFile(
		path,
		text,
		ts.ScriptTarget.Latest,
		true,
		scriptKindOf(ts, path),
	);
	const units = collectUnits(ts, sf);
	const c: Context = {
		ts,
		sf,
		unitOf: new Map(units.map((u) => [u.node, u])),
		lineOf: (pos) => sf.getLineAndCharacterOfPosition(pos).line + 1,
	};
	const codeLines = codeLineMask(text);
	return {
		lines: text.split("\n").length,
		codeLines: codeLines.reduce((n, v) => n + v, 0),
		functions: units.map((unit) => measure(c, unit, units, codeLines)),
	};
};
