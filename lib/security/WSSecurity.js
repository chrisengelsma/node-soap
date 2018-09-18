"use strict";

var crypto = require('crypto');
var passwordDigest = require('../utils').passwordDigest;
var validPasswordTypes = ['PasswordDigest', 'PasswordText'];

function WSSecurity(username, password, options) {
  options = options || {};
  this._username = username;
  this._password = password;
  //must account for backward compatibility for passwordType String param as well as object options defaults: passwordType = 'PasswordText', hasTimeStamp = true   
  if (typeof options === 'string') {
    this._passwordType = options ? options : 'PasswordText';
    options = {};
  } else {
    this._passwordType = options.passwordType ? options.passwordType : 'PasswordText';
  }

  if (validPasswordTypes.indexOf(this._passwordType) === -1) {
    this._passwordType = 'PasswordText';
  }

  this._hasTimeStamp = options.hasTimeStamp || typeof options.hasTimeStamp === 'boolean' ? !!options.hasTimeStamp : true;
  /*jshint eqnull:true */
  if (options.hasNonce != null) {
    this._hasNonce = !!options.hasNonce;
  }
  this._hasTokenCreated = options.hasTokenCreated || typeof options.hasTokenCreated === 'boolean' ? !!options.hasTokenCreated : true;
  if (options.actor != null) {
    this._actor = options.actor;
  }
  if (options.mustUnderstand != null) {
    this._mustUnderstand = !!options.mustUnderstand;
  }
}

WSSecurity.prototype.toXML = function() {
  // avoid dependency on date formatting libraries
  function getDate(d) {
    function pad(n) {
      return n < 10 ? '0' + n : n;
    }
    return d.getUTCFullYear() + '-'
      + pad(d.getUTCMonth() + 1) + '-'
      + pad(d.getUTCDate()) + 'T'
      + pad(d.getUTCHours()) + ':'
      + pad(d.getUTCMinutes()) + ':'
      + pad(d.getUTCSeconds()) + 'Z';
  }
  var now = new Date();
  var created = getDate(now);
  var timeStampXml = '';
  if (this._hasTimeStamp) {
    var expires = getDate( new Date(now.getTime() + (1000 * 600)) );
    timeStampXml = "<u:Timestamp u:Id=\"Timestamp-"+created+"\">" +
      "<u:Created>"+created+"</u:Created>" +
      "<u:Expires>"+expires+"</u:Expires>" +
      "</u:Timestamp>";
  }

  var password, nonce;
  if (this._hasNonce || this._passwordType !== 'PasswordText') {
    // nonce = base64 ( sha1 ( created + random ) )
    var nHash = crypto.createHash('sha1');
    nHash.update(created + Math.random());
    nonce = nHash.digest('base64');
  }
  if (this._passwordType === 'PasswordText') {
    password = "<o:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">" + this._password + "</o:Password>";
    if (nonce) {
      password += "<o:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + nonce + "</o:Nonce>";
    }
  } else {
    password = "<o:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + passwordDigest(nonce, created, this._password) + "</o:Password>" +
      "<o:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + nonce + "</o:Nonce>";
  }

  return "<o:Security " + (this._actor ? "soap:actor=\"" + this._actor + "\" " : "") +
    (this._mustUnderstand ? "s:mustUnderstand=\"1\" " : "") +
    "xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" +
    timeStampXml +
    "<o:UsernameToken xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"SecurityToken-" + created + "\">" +
    "<o:Username>" + this._username + "</o:Username>" +
    password +
    (this._hasTokenCreated ? "<u:Created>" + created + "</u:Created>" : "") +
    "</o:UsernameToken>" +
    "</o:Security>";
};

module.exports = WSSecurity;
