import { describe, expect, test } from "bun:test";

import {
	decodeAxml,
	decodeProtoXml,
	parseAndroidXml,
	parseXmlText,
} from "../src/mobile/axml";
import { type El, encodeAxml, encodeProtoXml } from "./mobile-encoders";
import { must } from "./must";

const manifest: El = {
	name: "manifest",
	attrs: { package: "com.example.app" },
	children: [
		{ name: "uses-sdk", attrs: { minSdkVersion: 21, targetSdkVersion: 33 } },
		{
			name: "application",
			attrs: { debuggable: true, allowBackup: false, label: "Ünïcode ✓" },
			children: [
				{ name: "activity", attrs: { name: ".Main", exported: true } },
			],
		},
	],
};

type XmlNode = NonNullable<ReturnType<typeof decodeAxml>>;

/** The node at `path` (child indexes) below `root`, failing the test if absent. */
const nodeAt = (root: XmlNode | undefined, ...path: number[]): XmlNode =>
	path.reduce(
		(node, i) => must(node.children[i], `child ${i} of <${node.name}>`),
		must(root, "a root element"),
	);

/** The manifest round-trips through AXML with either string pool encoding. */
const expectDecodedManifest = (utf8: boolean) => {
	const root = nodeAt(decodeAxml(encodeAxml(manifest, { utf8 })));
	expect(root.name).toBe("manifest");
	expect(root.attrs.package).toBe("com.example.app");
	expect(nodeAt(root, 0).attrs).toEqual({
		minSdkVersion: "21",
		targetSdkVersion: "33",
	});
	const app = nodeAt(root, 1);
	expect(app.attrs).toEqual({
		debuggable: "true",
		allowBackup: "false",
		label: "Ünïcode ✓",
	});
	expect(nodeAt(app, 0).attrs).toEqual({
		name: ".Main",
		exported: "true",
	});
	expect(app.line).toBe(3);
};

describe("mobile axml", () => {
	for (const utf8 of [false, true]) {
		test(`decodes AXML with a ${utf8 ? "UTF-8" : "UTF-16"} string pool`, () =>
			expectDecodedManifest(utf8));
	}

	test("falls back to the resource map for stripped attribute names", () => {
		const root = decodeAxml(encodeAxml(manifest, { stripAttrNames: true }));
		const app = nodeAt(root, 1);
		expect(app.attrs.debuggable).toBe("true");
		expect(nodeAt(app, 0).attrs.exported).toBe("true");
		expect(nodeAt(root, 0).attrs.targetSdkVersion).toBe("33");
	});

	test("decodes element text (CDATA chunks)", () => {
		const root = decodeAxml(
			encodeAxml({
				name: "network-security-config",
				children: [
					{
						name: "domain-config",
						children: [{ name: "domain", text: "example.com" }],
					},
				],
			}),
		);
		expect(nodeAt(root, 0, 0).text).toBe("example.com");
	});

	test("rejects malformed input without throwing", () => {
		const good = encodeAxml(manifest);
		expect(decodeAxml(new Uint8Array([3, 0, 8, 0, 255, 255, 0, 0]))).toBe(
			undefined,
		);
		expect(() => decodeAxml(good.subarray(0, 60))).not.toThrow();
		expect(decodeAxml(new TextEncoder().encode("<manifest/>"))).toBe(undefined);
	});

	test("decodes aapt2 protobuf XML (AAB manifests)", () => {
		const root = decodeProtoXml(
			encodeProtoXml({
				...manifest,
				children: [
					...(manifest.children ?? []),
					{ name: "domain", text: "example.org" },
				],
			}),
		);
		expect(nodeAt(root).name).toBe("manifest");
		expect(nodeAt(root, 0).attrs.minSdkVersion).toBe("21");
		expect(nodeAt(root, 1).attrs.debuggable).toBe("true");
		expect(nodeAt(root, 1).attrs.allowBackup).toBe("false");
		expect(nodeAt(root, 1, 0).attrs.name).toBe(".Main");
		expect(nodeAt(root, 2).text).toBe("example.org");
		expect(decodeProtoXml(new Uint8Array([0x0a, 0xff]))).toBe(undefined);
	});

	test("parses text XML, stripping the android: prefix", () => {
		const root = parseXmlText(
			[
				'<?xml version="1.0" encoding="utf-8"?>',
				'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">',
				'  <application android:allowBackup="true" tools:replace="label">',
				'    <activity android:name=".Main" android:exported="true"/>',
				"  </application>",
				"</manifest>",
			].join("\n"),
		);
		const app = nodeAt(root, 0);
		expect(app.attrs).toEqual({
			allowBackup: "true",
			"tools:replace": "label",
		});
		expect(app.line).toBe(3);
		expect(nodeAt(app, 0).line).toBe(4);
		expect(nodeAt(app, 0).attrs.exported).toBe("true");
	});

	test("parseAndroidXml detects the encoding", () => {
		expect(nodeAt(parseAndroidXml(encodeAxml(manifest))).name).toBe("manifest");
		expect(nodeAt(parseAndroidXml(encodeProtoXml(manifest))).name).toBe(
			"manifest",
		);
		const text = new TextEncoder().encode("  <manifest package='x'/>");
		expect(nodeAt(parseAndroidXml(text)).attrs.package).toBe("x");
	});
});
