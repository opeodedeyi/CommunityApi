const sinon = require('sinon');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const User = require('../src/models/user');
const { auth, isVerified } = require('./path/to/your/middleware');
const app = require('./path/to/your/express/app');

describe('auth middleware', () => {
  afterEach(() => {
    sinon.restore();
  });

  it('should authenticate a valid user with a valid token', async () => {
    const user = new User({ _id: '123', email: 'user@example.com' });
    const token = 'validToken';

    sinon.stub(jwt, 'verify').returns({ _id: user._id });
    sinon.stub(User, 'findOne').resolves(user);

    const req = { header: () => `Bearer ${token}` };
    const res = { status: sinon.stub().returnsThis(), send: sinon.spy() };
    const next = sinon.spy();

    await auth(req, res, next);

    expect(next.calledOnce).toBe(true);
    expect(req.user).toEqual(user);
    expect(req.token).toEqual(token);
  });

  // Add more test cases for different scenarios (e.g., invalid token, user not found, etc.)
});

app.get('/protected', auth, isVerified, (req, res) => {
  res.send({ message: 'Protected data' });
});

describe('GET /protected', () => {
  it('should return 401 if the token is not provided', async () => {
    const response = await request(app).get('/protected');
    expect(response.status).toEqual(401);
  });

  it('should return 401 if the token is invalid', async () => {
    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer invalidToken');
    expect(response.status).toEqual(401);
  });

  // Add more test cases for different scenarios (e.g., email not verified, etc.)
});
