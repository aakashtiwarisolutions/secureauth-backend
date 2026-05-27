// In-memory user store — swap with PostgreSQL/MongoDB in production
const { v4: uuidv4 } = require('uuid');

const users = [];

const UserStore = {
  findByEmail: (email) => users.find(u => u.email === email.toLowerCase()),

  findById: (id) => users.find(u => u.id === id),

  create: ({ name, email, password }) => {
    const user = {
      id: uuidv4(),
      name,
      email: email.toLowerCase(),
      password,
      createdAt: new Date().toISOString(),
      loginHistory: [],
    };
    users.push(user);
    return user;
  },

  recordLogin: (id, ip) => {
    const user = users.find(u => u.id === id);
    if (user) {
      user.loginHistory.push({ timestamp: new Date().toISOString(), ip });
      if (user.loginHistory.length > 10) user.loginHistory.shift();
    }
  },

  safeUser: (user) => ({
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt,
    loginHistory: user.loginHistory,
  }),
};

module.exports = UserStore;
