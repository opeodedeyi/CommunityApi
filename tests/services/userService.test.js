const userService = require('../src/services/userService');
const User = require('../src/models/user');

// To handle async errors
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

// Initialize in-memory MongoDB server
let mongoServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  await mongoose.connect(mongoServer.getUri(), {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

// Clean up the database after each test
afterEach(async () => {
  await User.deleteMany({});
});

describe('userService', () => {
  test('createUser should create a new user', async () => {
    const userData = {
      email: 'test@example.com',
      password: 'password123',
      fullname: 'John Doe',
    };

    const newUser = await userService.createUser(userData);

    expect(newUser.email).toBe(userData.email);
    expect(newUser.fullname).toBe(userData.fullname);
    expect(newUser.password).not.toBe(userData.password); // Password should be hashed
  });

  test('createUser should throw an error if user already exists', async () => {
    const userData = {
      email: 'test@example.com',
      password: 'password123',
      fullname: 'John Doe',
    };

    await userService.createUser(userData);

    await expect(userService.createUser(userData)).rejects.toThrow('User already exists');
  });

  test('findUserByEmail should return a user with the given email', async () => {
    const userData = {
      email: 'test@example.com',
      password: 'password123',
      fullname: 'John Doe',
    };

    const newUser = await userService.createUser(userData);
    const foundUser = await userService.findUserByEmail(userData.email);

    expect(foundUser.email).toBe(newUser.email);
    expect(foundUser.fullname).toBe(newUser.fullname);
  });

  test('findUserById should return a user with the given ID', async () => {
    const userData = {
      email: 'test@example.com',
      password: 'password123',
      fullname: 'John Doe',
    };

    const newUser = await userService.createUser(userData);
    const foundUser = await userService.findUserById(newUser._id);

    expect(foundUser.email).toBe(newUser.email);
    expect(foundUser.fullname).toBe(newUser.fullname);
  });

  test('updateUser should update the user with the given updates', async () => {
    const userData = {
      email: 'test@example.com',
      password: 'password123',
      fullname: 'John Doe',
    };

    const updates = {
      email: 'new@example.com',
      fullname: 'Jane Doe',
    };

    const newUser = await userService.createUser(userData);
    await userService.updateUser(newUser, updates);

    const updatedUser = await userService.findUserById(newUser._id);

    expect(updatedUser.email).toBe(updates.email);
    expect(updatedUser.fullname).toBe(updates.fullname);
  });
});
