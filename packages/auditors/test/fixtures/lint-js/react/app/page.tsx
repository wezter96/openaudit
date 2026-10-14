export default function Page() {
	return (
		<main>
			<img src="/hero.png" />
			<div onClick={() => console.log("clicked")}>Open</div>
			<span tabIndex={2}>Focus me</span>
			<a>Nowhere</a>
		</main>
	);
}
