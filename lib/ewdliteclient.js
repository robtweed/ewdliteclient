var crypto = require('crypto');
var https = require('https');
var http = require('http');

var utils = {
  escape: function(string, encode) {
    if (encode === "escape") {
      var unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~';
      var escString = '';
      var c;
      var hex;
      for (var i=0; i< string.length; i++) {
        c = string.charAt(i);
        if (unreserved.indexOf(c) !== -1) {
          escString = escString + c;
        }
        else {
          hex = string.charCodeAt(i).toString(16).toUpperCase();
          //console.log(string + "; c=" + c + "; hex = " + hex);
          if (hex.length === 1) hex = '0' + hex;
          escString = escString + '%' + hex;
        }
      }
      return escString;
    }
    else {
      var enc = encodeURIComponent(string);
      return enc.replace(/\*/g, "%2A").replace(/\'/g, "%27").replace(/\!/g, "%21").replace(/\(/g, "%28").replace(/\)/g, "%29");
    }
  },
  createStringToSign: function(action, includePort, encodeType) {
    var stringToSign;
    var name;
    var amp = '';
    var value;
    var keys = [];
    var index = 0;
    var pieces;
    var host = action.host;
    if (!includePort) { 
      if (host.indexOf(":") !== -1) {
        pieces = host.split(":");
        host = pieces[0];
      }
    }
    var url = action.uri;
    var method = 'GET'
    stringToSign = method + '\n' + host + '\n' + url + '\n';
    for (name in action.query) {
      if (name !== 'signature') {
        keys[index] = name;
        index++;
      }
    }
    keys.sort();
    for (var i=0; i < keys.length; i++) {
      name = keys[i];
      value = action.query[name];
      //console.log("name = " + name + "; value = " + value);
      stringToSign = stringToSign + amp + utils.escape(name, encodeType) + '=' + utils.escape(value, encodeType);
      amp = '&';
    }
    return stringToSign;
  },
  digest: function(string, key, type) {
    // type = sha1|sha256|sha512
    var hmac = crypto.createHmac(type, key.toString());
    hmac.update(string);
    return hmac.digest('base64');
  }

};

module.exports = {

  run: function(obj, callback) {

    var params = obj.params;
    var secretKey = obj.secretKey;
    var appName = obj.appName;
    var serviceName = obj.serviceName;

    var options = {
      hostname: obj.host,
      port: obj.port,
      path: '/json/' + appName + '/' + serviceName,
      agent: false,
      rejectUnauthorized: false // set this to true if remote site uses proper SSL certs
    };
    var uri = options.path;

    params.timestamp = new Date().toUTCString();

    var amp = '?';
    for (name in params) {
      options.path = options.path + amp + utils.escape(name, 'uri') + '=' + utils.escape(params[name], 'uri');
      amp = '&';
    } 

    var action = {
      host: options.hostname,
      query: params,
      uri: uri
    };
    var stringToSign = utils.createStringToSign(action, false, "uri");
    var hash = utils.digest(stringToSign, secretKey, 'sha256');
    options.path = options.path + '&signature=' + utils.escape(hash, 'uri');
    var req;

    if (obj.ssl) {
      req = https.get(options, function(response) {
        var data = '';
        response.on('data', function(chunk) {
          data += chunk;
        });
        response.on('end', function() {
          if (callback) callback(false, JSON.parse(data));
          return;
        });
      });
    }
    else {
      req = http.get(options, function(response) {
        var data = '';
        response.on('data', function(chunk) {
          data += chunk;
        });
        response.on('end', function() {
          if (callback) callback(false, JSON.parse(data));
          return;
        });
      });
    }

    req.on('error', function(error) {
      if (callback) callback(JSON.parse(error));
    });

    req.end();
    return;
  },

  example: function() {

    // modify the values below as appropriate for the
    // remote EWD Lite system you wish to access

    var args = {
      host: '192.168.1.98',
      port: 8080,
      ssl: true,
      appName: 'demo',
      serviceName: 'webServiceExample',
      params: {
        // query string name/value pairs
        accessId: 'rob',  // required by EWD Lite's security
        id: 1233          // patient id (required by demo/webServiceExample)
      },
      secretKey: 'a1234567'  // %zewd("EWDLiteServiceAccessId", accessId) = secretKey 
                             //  must exist on the remote system and match the values here.
                             //  Used to sign the outgoing request
    };

   this.run(args, function(error, data) {
     // do whatever you need to do with the returned JSON data, eg:
     if (typeof results === 'undefined') results = {};
     if (error) {
       // note: use of console.log will upset testing in REPL
       //console.log('An error occurred: ' + JSON.stringify(error));
       results.error = error;
     }
     else {
       //console.log('Data returned by web service: ' + JSON.stringify(data));
       results.data = data;
     }
   });

  }

};
