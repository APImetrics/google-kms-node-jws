/*global module*/
var Buffer = require('safe-buffer').Buffer;
var DataStream = require('./data-stream');
var jwa = require('jwa');
var Stream = require('stream');
var toString = require('./tostring');
var util = require('util');

function base64url(string, encoding) {
  return Buffer
    .from(string, encoding)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

// Normally, we concatenate the base64url encoded header and payload with a period ('.') in between.
// However, if the header.b64 property is set to false, we do not base64url encode the payload.
// See: https://directory.openbanking.org.uk/obieservicedesk/s/article/Can-you-explain-what-are-the-supported-values-of-b64-claim-for-different-versions-of-specifications
function jwsSecuredInput(header, payload, encoding) {
  encoding = encoding || 'utf8';
  var encodedHeader = base64url(toString(header), 'binary');
  var encodedPayload = header.b64 !== false ? base64url(toString(payload), encoding) : toString(payload);
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

async function jwsSign(opts) {
  var header = opts.header;
  var payload = opts.payload;
  var secretOrKey = opts.secret || opts.privateKey;
  var encoding = opts.encoding;
  var algo = jwa(header.alg);
  var securedInput = jwsSecuredInput(header, payload, encoding);
  var signature = await algo.sign(securedInput, secretOrKey);
  return util.format('%s.%s', securedInput, signature);
}

function SignStream(opts) {
  var secret = opts.secret||opts.privateKey||opts.key;
  var secretStream = new DataStream(secret);
  this.readable = true;
  this.header = opts.header;
  this.encoding = opts.encoding;
  this.secret = this.privateKey = this.key = secretStream;
  this.payload = new DataStream(opts.payload);
  this.secret.once('close', function () {
    if (!this.payload.writable && this.readable)
      this.sign();
  }.bind(this));

  this.payload.once('close', function () {
    if (!this.secret.writable && this.readable)
      this.sign();
  }.bind(this));
}
util.inherits(SignStream, Stream);

SignStream.prototype.sign = async function sign() {
  try {
    var signature = await jwsSign({
      header: this.header,
      payload: this.payload.buffer,
      secret: this.secret.buffer,
      encoding: this.encoding
    });
    this.emit('done', signature);
    this.emit('data', signature);
    this.emit('end');
    this.readable = false;
    return signature;
  } catch (e) {
    if (this.readable) {
      this.readable = false;
      this.emit('error', e);
      this.emit('close');
    }
  }
};

SignStream.sign = jwsSign;

module.exports = SignStream;
