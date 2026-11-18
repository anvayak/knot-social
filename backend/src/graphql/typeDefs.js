export default `#graphql
  type User {
    id: ID!
    username: String!
    email: String!
    role: String!
    createdAt: String
    posts: [Post!]!
  }

  type Reply {
    id: ID!
    content: String!
    author: User!
    createdAt: String
  }

  type Post {
    id: ID!
    content: String!
    author: User!
    likesCount: Int!
    likedByMe: Boolean!
    replies: [Reply!]!
    createdAt: String
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type SecurityEvent {
    id: ID!
    ip: String!
    attackType: String!
    riskScore: Int!
    decision: String!
    snippet: String
    createdAt: String!
  }

  type BlockedIp {
    ip: String!
    reason: String
    blockedUntil: String!
  }

  type AttackTypeCount {
    attackType: String!
    count: Int!
  }

  type TimelinePoint {
    hour: String!
    allowed: Int!
    flagged: Int!
    blocked: Int!
  }

  type SecurityStats {
    total: Int!
    allowed: Int!
    flagged: Int!
    blocked: Int!
    activeBlockedIps: Int!
    byAttackType: [AttackTypeCount!]!
    timeline: [TimelinePoint!]!
  }

  type Query {
    me: User
    feed(limit: Int = 20): [Post!]!
    post(id: ID!): Post
    user(id: ID!): User
    securityStats: SecurityStats!
    securityEvents(limit: Int = 50, decision: String): [SecurityEvent!]!
    blockedIps: [BlockedIp!]!
  }

  type Mutation {
    signup(username: String!, email: String!, password: String!): AuthPayload!
    login(email: String!, password: String!): AuthPayload!
    createPost(content: String!): Post!
    deletePost(id: ID!): Boolean!
    toggleLike(postId: ID!): Post!
    addReply(postId: ID!, content: String!): Reply!
    unblockIp(ip: String!): Boolean!
  }
`;