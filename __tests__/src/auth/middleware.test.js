'use strict';

process.env.SECRET = 'test';

const supergoose = require('../../supergoose.js');
const auth = require('../../../src/auth/middleware.js');
const Users = require('../../../src/auth/users-model.js');

let users = {
  admin: { username: 'admin', password: 'password', role: 'admin' },
  editor: { username: 'editor', password: 'password', role: 'editor' },
  user: { username: 'user', password: 'password', role: 'user' },
};

beforeAll(async done => {
  await supergoose.startDB();
  // eslint-disable-next-line
  const adminUser = await new Users(users.admin).save();
  // eslint-disable-next-line
  const editorUser = await new Users(users.editor).save();
  // eslint-disable-next-line
  const userUser = await new Users(users.user).save();
  done();
});

afterAll(supergoose.stopDB);

describe('Auth Middleware', () => {
  // admin:password: YWRtaW46cGFzc3dvcmQ=
  // admin:foo: YWRtaW46Zm9v

  let errorObject = 'Invalid User ID/Password';

  describe('user authentication', () => {
    // eslint-disable-next-line
    let cachedToken;

    it('fails a login for a user (admin) with the incorrect basic credentials', () => {
      let req = {
        headers: {
          authorization: 'Basic YWRtaW46Zm9v',
        },
      };
      let res = {};
      let next = jest.fn();
      let middleware = auth;

      return middleware(req, res, next).then(() => {
        expect(next).toHaveBeenCalledWith(errorObject);
      });
    }); // it()

    it('logs in an admin user with the right credentials', () => {
      let req = {
        headers: {
          authorization: 'Basic YWRtaW46cGFzc3dvcmQ=',
        },
      };
      let res = {};
      let next = jest.fn();
      let middleware = auth;

      return middleware(req, res, next).then(() => {
        cachedToken = req.token;
        expect(next).toHaveBeenCalledWith();
      });
    }); // it()
  });
});
