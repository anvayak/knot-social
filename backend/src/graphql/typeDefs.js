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

  type Query {
    me: User
    feed(limit: Int = 20): [Post!]!
    post(id: ID!): Post
    user(id: ID!): User
  }

  type Mutation {
    signup(username: String!, email: String!, password: String!): AuthPayload!
    login(email: String!, password: String!): AuthPayload!
    createPost(content: String!): Post!
    deletePost(id: ID!): Boolean!
    toggleLike(postId: ID!): Post!
    addReply(postId: ID!, content: String!): Reply!
  }
`;
