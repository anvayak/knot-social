import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import { connectDB } from './config/db.js';
import typeDefs from './graphql/typeDefs.js';
import resolvers from './graphql/resolvers.js';
import { getUserFromReq } from './utils/auth.js';
import { securityPipeline } from './security/pipeline.js';

if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET missing in .env');

const isProd = process.env.NODE_ENV === 'production';
const app = express();

// Security headers. CSP is relaxed in dev so the Apollo Sandbox page loads.
app.use(helmet({ contentSecurityPolicy: isProd ? undefined : false }));
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(express.json({ limit: '100kb' })); // body size limit (basic DoS protection)

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: !isProd, // hide the schema in production
  includeStacktraceInErrorResponses: !isProd, // never leak stack traces in production
});

await server.start();
await connectDB();

app.use(
  '/graphql',
  securityPipeline, // <-- all Day 2/3 security checks plug in here
  expressMiddleware(server, {
    context: async ({ req }) => ({ user: await getUserFromReq(req), ip: req.ip }),
  })
);

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`GraphQL ready at http://localhost:${port}/graphql`));
