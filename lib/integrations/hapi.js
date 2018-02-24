'use strict';

var _errors = require('../errors');

var _JwksClient = require('../JwksClient');

var handleSigningKeyError = function handleSigningKeyError(err, cb) {
  // If we didn't find a match, can't provide a key.
  if (err && err.name === 'SigningKeyNotFoundError') {
    return cb(null, null, null);
  }

  // If an error occured like rate limiting or HTTP issue, we'll bubble up the error.
  if (err) {
    return cb(err, null, null);
  }
};

module.exports.hapiJwt2Key = function (options) {
  if (options === null || options === undefined) {
    throw new _errors.ArgumentError('An options object must be provided when initializing expressJwtSecret');
  }

  var client = new _JwksClient.JwksClient(options);
  var onError = options.handleSigningKeyError || handleSigningKeyError;

  return function secretProvider(decoded, cb) {
    // We cannot find a signing certificate if there is no header (no kid).
    if (!decoded || !decoded.header) {
      if (cb) {
        return cb(null, null, null);
      }
      return Promise.resolve();
    }

    // Only RS256 is supported.
    if (decoded.header.alg !== 'RS256') {
      if (cb) {
        return cb(null, null, null);
      }
      return Promise.resolve();
    }

    if (cb) {
      return client.getSigningKey(decoded.header.kid, function (err, key) {
        if (err) {
          return onError(err, function (newError) {
            return cb(newError, null, null);
          });
        }

        // Provide the key.
        return cb(null, key.publicKey || key.rsaPublicKey, key);
      });
    }

    return new Promise(function (resolve, reject) {
      client.getSigningKey(decoded.header.kid, function (err, key) {
        if (err) {
          return onError(err, reject);
        }

        // Provide the key.
        return resolve({ key: key.publicKey || key.rsaPublicKey });
      });
    });
  };
};