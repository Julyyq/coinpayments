'use strict';

var qs = require('querystring'),
    crypto = require('crypto');

module.exports = function () {

  function IPN(_ref,ctx,next) {
    var _this = this;

    var merchantId = _ref.merchantId,
        merchantSecret = _ref.merchantSecret;

    if (!merchantId || !merchantSecret) {
      throw "Merchant ID and Merchant Secret are needed";
    }
    var hmac = void 0;

    var getPrivateHeadersIPN = function getPrivateHeadersIPN(parameters) {
      var signature = void 0,
          paramString = void 0;

      paramString = qs.stringify(parameters).replace(/%20/g, '+');

      signature = crypto.createHmac('sha512', merchantSecret).update(paramString).digest('hex');

      return signature;
    };

    const req = ctx.request;
    const res = ctx.response;
    if (!req.get('HMAC') || !req.body || !req.body.ipn_mode || req.body.ipn_mode != 'hmac' || merchantId != req.body.merchant) {
      return next("COINPAYMENTS_INVALID_REQUEST");
    }
    hmac = getPrivateHeadersIPN(req.body);
    if (hmac != req.get('HMAC')) {
      return next("COINPAYMENTS_INVALID_REQUEST");
    }
    ctx.res.end();
    if (req.body.status < 0) {
      _this.emit('ipn_fail', req.body);
      return next();
    }
    if (req.body.status < 100) {
      _this.emit('ipn_pending', req.body);
      return next();
    }
    if (req.body.status == 100) {
      _this.emit('ipn_complete', req.body);
      return next();
    }
  }

  return IPN;
}();