const { expect } = require('chai');
const sinon = require('sinon');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { auth, isVerified } = require('./path/to/your/middleware');
const app = require('./path/to/your/express/app');

describe('auth middleware', () => {
    afterEach(() => {
      sinon.restore();
    });
  
    it('should authenticate a valid user with a valid token', async () => {
      // Mock user data and token
      const user = new User({ _id: '123', email: 'user@example.com' });
      const token = 'validToken';
  
      // Stub the verifyToken and findUserByToken functions to return the mocked data
      sinon.stub(jwt, 'verify').returns({ _id: user._id });
      sinon.stub(User, 'findOne').resolves(user);
  
      // Mock the request and response objects
      const req = { header: () => `Bearer ${token}` };
      const res = { status: sinon.stub().returnsThis(), send: sinon.spy() };
      const next = sinon.spy();
  
      // Call the auth middleware
      await auth(req, res, next);
  
      // Assert that the next middleware was called and the user and token were attached to the request
      expect(next.calledOnce).to.be.true;
      expect(req.user).to.deep.equal(user);
      expect(req.token).to.equal(token);
    });
  
    // Add more test cases for different scenarios (e.g., invalid token, user not found, etc.)
});


app.get('/protected', auth, isVerified, (req, res) => {
    res.send({ message: 'Protected data' });
});

describe('GET /protected', () => {
    it('should return 401 if the token is not provided', async () => {
      const response = await request(app).get('/protected');
      expect(response.status).to.equal(401);
    });
  
    it('should return 401 if the token is invalid', async () => {
      const response = await request(app)
        .get('/protected')
        .set('Authorization', 'Bearer invalidToken');
      expect(response.status).to.equal(401);
    });
  
    // Add more test cases for different scenarios (e.g., email not verified, etc.)
});
  
