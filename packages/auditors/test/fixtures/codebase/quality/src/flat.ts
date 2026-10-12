// @ts-ignore legacy typing
import legacy from "legacy";

// HACK: works around an upstream bug
export const flat = (x: number) => (x > 0 ? legacy(x) : 0);
