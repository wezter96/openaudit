import Head from "next/head";
import { Html, Main, NextScript } from "next/document";

export default function Document() {
	return (
		<Html lang="en">
			<Head />
			<body>
				<script src="https://example.com/analytics.js" />
				<Main />
				<NextScript />
			</body>
		</Html>
	);
}
