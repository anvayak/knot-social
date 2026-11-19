# Knot Social

Knot Social is a social-network API that combines ordinary posts and interactions with a GraphQL request-security layer. The project is currently implemented as a Node.js and MongoDB backend. It supports user registration and login, posts, replies, likes, profile queries, and an administrator-only security console.

The backend is designed to inspect requests before they reach Apollo GraphQL. It can measure query depth and complexity, detect suspicious payload patterns, apply IP and authentication rate limits, record security decisions, and temporarily block abusive IP addresses.

## Table of contents

- [Project overview](#project-overview)
- [Features](#features)
- [Technology stack](#technology-stack)
- [Project structure](#project-structure)
- [Architecture](#architecture)
- [Request workflow](#request-workflow)
- [Authentication and authorization](#authentication-and-authorization)
- [GraphQL API](#graphql-api)
- [MongoDB data model](#mongodb-data-model)
- [Security system](#security-system)
- [Configuration](#configuration)
- [Local setup](#local-setup)
- [Available scripts](#available-scripts)
- [Development methodology](#development-methodology)
- [Current limitations](#current-limitations)
- [Operational considerations](#operational-considerations)

## Project overview

The application follows a layered architecture:

```text
Client / Apollo Sandbox
        |
        | HTTP POST or GET /graphql
        v
Express and middleware
        |
        | 1. Security pipeline
        v
Apollo GraphQL Server
        |
        | Query or mutation resolvers
        v
Mongoose
        |
        v
MongoDB
```

The security pipeline and GraphQL server are separate concerns. Express middleware rejects dangerous or excessive traffic before GraphQL executes it, while resolvers implement application behavior and authorization.

## Features

### Social features

- Create a user account with username, email, and password.
- Log in and receive a JSON Web Token (JWT).
- Identify the current authenticated user.
- Retrieve the latest feed.
- Retrieve a post or user by ID.
- Create, view, and delete posts.
- Reply to a post.
- Add or remove the current user's like.
- Read nested author and reply relationships.

### Security features

- Helmet HTTP security headers.
- Restricted CORS configuration.
- Maximum JSON request size of 100 KB.
- GraphQL query length limits.
- Query depth, field count, alias, complexity, and fragment analysis.
- Detection of SQL, NoSQL, XSS, SSRF, and command-injection patterns.
- Global and authentication-specific rate limiting.
- Risk scoring and allow, flag, or block decisions.
- Temporary IP blocking with persistent MongoDB records.
- Administrator-only security statistics and event logs.
- Development-only sandbox introspection and state-reset behavior.

## Technology stack

| Area | Technology |
|---|---|
| Runtime | Node.js |
| Module system | ECMAScript modules (`type: module`) |
| HTTP server | Express |
| GraphQL server | Apollo Server 4 |
| API contract | GraphQL schema and resolvers |
| Database | MongoDB |
| Database ODM | Mongoose |
| Authentication | JSON Web Tokens and bcrypt password hashes |
| Security headers | Helmet |
| Cross-origin requests | CORS |
| Environment variables | dotenv |
| Development runner | Node.js watch mode |

Key dependencies are declared in [backend/package.json](backend/package.json):

- `@apollo/server`
- `express`
- `graphql`
- `mongoose`
- `jsonwebtoken`
- `bcryptjs`
- `helmet`
- `cors`
- `dotenv`

## Project structure

```text
Knot Social/
|-- backend/
|   |-- package.json
|   |-- package-lock.json
|   |-- src/
|   |   |-- index.js                 # Server startup and middleware wiring
|   |   |-- config/
|   |   |   `-- db.js                # MongoDB connection
|   |   |-- graphql/
|   |   |   |-- typeDefs.js          # GraphQL schema
|   |   |   `-- resolvers.js         # GraphQL queries and mutations
|   |   |-- models/
|   |   |   |-- User.js
|   |   |   |-- Post.js
|   |   |   |-- Reply.js
|   |   |   |-- SecurityEvent.js
|   |   |   `-- BlockedIp.js
|   |   |-- security/
|   |   |   |-- pipeline.js          # Ordered request checks
|   |   |   |-- config.js            # Security thresholds and limits
|   |   |   |-- queryAnalyzer.js     # GraphQL AST analysis
|   |   |   |-- payloadScanner.js    # Pattern-based input detection
|   |   |   |-- riskEngine.js        # Risk score and decision
|   |   |   |-- rateLimiter.js       # In-memory sliding windows
|   |   |   |-- blocklist.js         # Strike and temporary block logic
|   |   |   |-- logger.js            # Security-event persistence
|   |   |   `-- stats.js             # Security console aggregation
|   |   `-- utils/
|   |       |-- auth.js              # JWT signing and request authentication
|   |       `-- sanitize.js          # User-text normalization and HTML removal
|   `-- .env                         # Local-only environment configuration
`-- README.md
```

## Architecture

### Server entry point

[backend/src/index.js](backend/src/index.js) is the application bootstrap:

1. Loads environment variables.
2. Requires `JWT_SECRET`.
3. Creates the Express application.
4. Adds Helmet, CORS, and the JSON parser.
5. Creates Apollo Server with the GraphQL schema and resolvers.
6. Starts Apollo Server.
7. Connects to MongoDB.
8. Loads existing IP blocks from MongoDB.
9. Mounts `securityPipeline` before `expressMiddleware`.
10. Starts listening on `PORT`, which defaults to `4000`.

Apollo is mounted at `/graphql`.

### GraphQL layer

[backend/src/graphql/typeDefs.js](backend/src/graphql/typeDefs.js) declares the public schema. [backend/src/graphql/resolvers.js](backend/src/graphql/resolvers.js) connects GraphQL fields to Mongoose operations and contains authorization rules.

Field resolvers provide nested relationships:

- `User.posts` resolves posts authored by the user.
- `Post.author` resolves the author.
- `Post.replies` resolves replies to the post.
- `Post.likesCount` derives the number of likes.
- `Post.likedByMe` derives whether the authenticated user liked the post.
- `Reply.author` resolves the reply author.

User passwords are never selected for normal user lookups or returned by GraphQL. The `User.email` field is only returned to the account owner or an administrator; all other clients receive `"hidden"`.

### Persistence layer

Mongoose models define both the application entities and security state:

- `User`
- `Post`
- `Reply`
- `SecurityEvent`
- `BlockedIp`

The use of Mongoose ObjectIds establishes relationships between users, posts, and replies.

## Request workflow

### Social request

An authenticated mutation such as `createPost` follows this path:

1. The client sends an HTTP request to `/graphql` with an `Authorization: Bearer <token>` header.
2. Express normalizes the client IP and applies body parsing.
3. The security pipeline checks the IP blocklist and rate limits.
4. The pipeline parses and analyzes the GraphQL query and variables.
5. Payload patterns and GraphQL resource limits contribute to a risk score.
6. An allowed request is passed to Apollo.
7. `getUserFromReq` validates the JWT and loads the user.
8. The mutation resolver authenticates the operation.
9. Input text is sanitized.
10. Mongoose creates or updates the MongoDB document.
11. The result is resolved by the appropriate field resolvers and returned as GraphQL JSON.

### Security-console request

An administrator requesting `securityStats` follows a similar path, but the GraphQL resolver additionally calls `requireAdmin`. A JWT with a non-administrator role is rejected with a `FORBIDDEN` GraphQL error.

## Authentication and authorization

### Password handling

Registration validates the username, email, and password before creating a user. Passwords are hashed with bcrypt using a cost factor of 12. Plaintext passwords are never inserted into Mongoose user documents.

### Login and JWT

Login searches by normalized email and compares the supplied password with the stored bcrypt hash. A successful login returns a JWT signed with `JWT_SECRET`. The token expires after two hours and contains the user ID and role.

The client sends the token with the following header:

```http
Authorization: Bearer <jwt>
```

The server validates the token and loads the current user for every request. Invalid or missing tokens result in no authenticated user, rather than a server error.

### Authorization rules

- `me` returns the authenticated user or `null`.
- Social mutations require authentication.
- `deletePost` allows the post owner or an administrator to delete it.
- Deleting a post also deletes all replies associated with that post.
- Security queries and `unblockIp` require the `admin` role.
- Email visibility is limited to the account owner or an administrator.

## GraphQL API

### Queries

| Query | Access | Purpose |
|---|---|---|
| `me` | Optional auth | Return the current user |
| `feed(limit)` | Public | Return posts in descending creation order |
| `post(id)` | Public | Return one post |
| `user(id)` | Public | Return one user |
| `securityStats` | Admin | Return aggregate security metrics |
| `securityEvents(limit, decision)` | Admin | Return recent security events |
| `blockedIps` | Admin | Return active IP blocks |

### Mutations

| Mutation | Access | Purpose |
|---|---|---|
| `signup` | Public | Register a user |
| `login` | Public | Authenticate and return a JWT |
| `createPost` | Authenticated | Create a post |
| `deletePost` | Owner or admin | Delete a post and its replies |
| `toggleLike` | Authenticated | Add or remove a like |
| `addReply` | Authenticated | Reply to a post |
| `unblockIp` | Admin | Remove an IP block |

### Example signup

```graphql
mutation {
  signup(
    username: "alex"
    email: "alex@example.com"
    password: "strong-password"
  ) {
    token
    user {
      id
      username
      role
    }
  }
}
```

### Example create post

```graphql
mutation {
  createPost(content: "Building Knot Social") {
    id
    content
    likesCount
  }
}
```

Send this mutation with the Bearer token in the request header.

### Example feed

```graphql
query {
  feed(limit: 20) {
    id
    content
    createdAt
    likesCount
    likedByMe
    author {
      id
      username
    }
  }
}
```

GraphQL errors use Apollo `GraphQLError` extension codes such as:

- `UNAUTHENTICATED`
- `FORBIDDEN`
- `BAD_USER_INPUT`
- `NOT_FOUND`
- `IP_BLOCKED`
- `SECURITY_BLOCKED`

## MongoDB data model

### User

| Field | Rule |
|---|---|
| `username` | Required, unique, 3-20 characters |
| `email` | Required, unique, lowercased |
| `password` | Required bcrypt hash |
| `role` | `user` or `admin`; defaults to `user` |

Mongoose timestamps add `createdAt` and `updatedAt`.

### Post

| Field | Rule |
|---|---|
| `author` | Required User ObjectId |
| `content` | Required text, maximum 280 characters |
| `likes` | Array of unique User ObjectIds |

### Reply

| Field | Rule |
|---|---|
| `post` | Required Post ObjectId |
| `author` | Required User ObjectId |
| `content` | Required text, maximum 280 characters |

### SecurityEvent

Records an IP, attack type, risk score, decision, optional query snippet, and timestamp. Password text is redacted before it is stored.

### BlockedIp

Records the normalized IP, reason, strike count field, and block expiration time. Expired records may remain in MongoDB but are excluded from active-block checks.

## Security system

All configurable values are in [backend/src/security/config.js](backend/src/security/config.js).

### 1. IP block check

Before doing further analysis, the pipeline checks whether the client IP is currently blocked. A blocked request receives HTTP `403` and the remaining block duration.

### 2. Global rate limit

The global sliding-window limit is 100 requests per IP per minute by default. The auth limit is 10 login or signup operations per IP per minute.

Rate limiting is currently held in process memory and is therefore local to one server instance. It is cleared on restart unless the IP block persisted in MongoDB has already blocked the IP.

### 3. GraphQL structural analysis

The pipeline parses the GraphQL document and traverses fields, fragments, and inline fragments. It measures:

- Maximum selection depth.
- Weighted estimated cost.
- Number of fields.
- Number of aliases.
- Number of login/signup operations.
- Budget overflow from excessive traversal.
- Introspection attempts.
- String values passed through GraphQL arguments.

Default limits are:

| Limit | Default |
|---|---|
| Maximum query length | 5,000 characters |
| Maximum depth | 6 |
| Maximum cost | 2,000 |
| Maximum fields | 50 |
| Maximum aliases | 5 |
| Maximum feed page size | 50 |

### 4. Payload scanning

The payload scanner checks GraphQL argument strings and variables for:

- SQL injection
- MongoDB/NoSQL operators
- Cross-site scripting
- Server-side request forgery
- Command injection

It also checks URL-decoded input so encoded payloads are considered. Password variables are skipped during scanning and password literals are not stored in security logs.

### 5. Risk scoring

The risk engine combines findings and sums their points, capped at 100:

| Score | Decision |
|---|---|
| 0-30 | `ALLOW` |
| 31-70 | `FLAG` |
| 71-100 | `BLOCK` |

Some structural and attack findings worth 75 points block immediately. Hard limits are intentionally blocking rather than only flagging.

### 6. Strike and block behavior

Five blocked security requests within ten minutes produce a temporary IP block. The default block duration is five minutes. An administrator can remove a block through the `unblockIp` mutation.

Development state can be reset through `POST /dev/security/reset`. This endpoint is not registered outside `NODE_ENV=development`.

## Configuration

Create or update `backend/.env` with:

```dotenv
PORT=4000
MONGO_URI=mongodb+srv://<user>:<password>@<cluster>/<database>
JWT_SECRET=<long-random-secret>
CLIENT_URL=http://localhost:3000
NODE_ENV=development
BLOCK_MINUTES=5
```

| Variable | Required | Purpose |
|---|---|---|
| `PORT` | No | HTTP port; defaults to `4000` |
| `MONGO_URI` | Yes | MongoDB connection string |
| `JWT_SECRET` | Yes | JWT signing and verification secret |
| `CLIENT_URL` | No | CORS allowed origin |
| `NODE_ENV` | No | Development or production behavior |
| `BLOCK_MINUTES` | No | Temporary block duration; defaults to `5` |

Do not commit `.env`. The repository ignore files exclude environment files and `node_modules`.

Never reuse a real database password or JWT secret in source control or documentation. The JWT secret and database credential should be rotated if they have been exposed.

## Local setup

### Requirements

- Node.js 18 or newer is recommended.
- npm.
- A reachable MongoDB database.

### Steps

1. Install dependencies:

```powershell
cd backend
npm install
```

2. Create `backend/.env` with the configuration shown above.

3. Start the server in development watch mode:

```powershell
npm run dev
```

4. Open the GraphQL endpoint:

```text
http://localhost:4000/graphql
```

Development mode exposes Apollo Sandbox. Production mode disables schema introspection and stack traces in GraphQL responses.

### First administrator

The model permits `role: "admin"`, but the public signup mutation does not accept a role. An initial administrator should be created through controlled database administration or a separate verified bootstrap process. Do not expose unrestricted role assignment to clients.

## Available scripts

Run these from [backend/](backend/):

| Command | Purpose |
|---|---|
| `npm run dev` | Start with Node watch mode |
| `npm start` | Start the server normally |

There is currently no test script, lint script, build step, or frontend package in the repository.

## Development methodology

The repository history indicates an incremental, milestone-based development process:

1. **Day 1 - Core backend:** GraphQL, MongoDB, user authentication, posts, likes, and replies.
2. **Day 2 - GraphQL security:** Request analysis, depth and complexity protection, and security configuration.
3. **Day 3 - Detection and response:** Payload scanning, risk scoring, logging, rate limits, and temporary IP blocks.

This is a practical defensive implementation workflow: build the application first, then add security boundaries and an operational security console.

The code follows a modular separation of concerns:

- Server setup belongs in `index.js`.
- GraphQL contracts belong in `typeDefs.js`.
- GraphQL application behavior belongs in `resolvers.js`.
- Database connection and schemas belong in `config/` and `models/`.
- Authentication and text sanitization belong in `utils/`.
- Security policy and enforcement belong in `security/`.

Security values are centralized in `security/config.js` to make limits easier to tune and explain. Behavior is split into small modules so that parsing, scoring, blocking, logging, and presentation can be maintained independently.

## Current limitations

- There is no frontend application in the repository.
- There are no automated tests or test scripts.
- There is no CI/CD configuration.
- Rate limiter state exists only in process memory.
- The batch request check is based on an array request body and is not a complete distributed batching policy.
- Security payload detection uses regular expressions and should be treated as defense-in-depth, not perfect detection.
- The blocklist has in-memory state and asynchronously persists blocks.
- The security event model contains `userId`, but the current logger does not populate it.
- Apollo introspection is enabled in development and disabled in production.
- No Redis or external session store is used.
- The project does not use subscriptions or real-time delivery.

## Operational considerations

### Production

For deployment, use environment-provided secrets rather than a checked-in `.env` file. Set `NODE_ENV=production`, configure `CLIENT_URL` for the deployed frontend, and replace development-only reset behavior.

In production:

- Introspection is disabled.
- Stack traces are hidden.
- Security findings in the API response are not detailed.
- CORS is restricted to `CLIENT_URL`.

For multiple application instances, move rate limiting and block state to a shared store such as Redis. Otherwise, each server process maintains an independent view of request counts and strikes.

### Monitoring

Use the administrator security console or inspect MongoDB collections for:

- `SecurityEvent` volume and decisions.
- Attack types.
- Active `BlockedIp` records.
- Event trends over time.
- Repeated abuse by IP.

### Maintenance

Before changing security limits, review the defaults and update [backend/src/security/config.js](backend/src/security/config.js). After changing GraphQL fields or relationships, update both [backend/src/graphql/typeDefs.js](backend/src/graphql/typeDefs.js) and [backend/src/graphql/resolvers.js](backend/src/graphql/resolvers.js).
