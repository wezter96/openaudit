export type Context = {
	/** Client address used for rate limiting; undefined when unknown. */
	clientIp?: string;
	/** Self-hosting escape hatch: let `audit.url` reach private networks. */
	allowPrivateTargets?: boolean;
};
