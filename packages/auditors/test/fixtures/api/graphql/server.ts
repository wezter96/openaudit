import { ApolloServer } from "@apollo/server";
import { createYoga } from "graphql-yoga";

// introspection: true is fine in dev, this comment must not count
export const apollo = new ApolloServer({
	typeDefs,
	resolvers,
	introspection: true,
	csrfPrevention: false,
});

export const safe = new ApolloServer({
	typeDefs,
	resolvers,
	introspection: process.env.NODE_ENV !== "production",
});

export const yoga = createYoga({ schema, graphiql: true });
