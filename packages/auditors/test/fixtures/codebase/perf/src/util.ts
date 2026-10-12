import _ from "lodash";
import { debounce } from "lodash";

export const run = debounce(() => {
	console.log("step 1", _.now());
	console.log("step 2", _.now());
	console.log("step 3", _.now());
	console.log("step 4", _.now());
	console.log("step 5", _.now());
	console.log("step 6", _.now());
	console.log("step 7", _.now());
	console.log("step 8", _.now());
	console.log("step 9", _.now());
	console.log("step 10", _.now());
	// console.log("commented out");
}, 100);
