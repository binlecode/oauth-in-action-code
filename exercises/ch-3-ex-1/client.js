var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information


/*
 * Add the client information in here
 */
var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"]
};

var protectedResource = 'http://localhost:9002/resource';

/*
 * To prevent man-in-middle attach that any one could invoke '/callback' other than the intended
 * redirect, using an optional OAuth parameter called state, which is assigned a random string 
 * for every redirect request.
 * It is important to keep the 'state' variable at application scope so that it is available
 * everytime when the call to the 'redirect_url' comes back.
 */
var state = null;

/*
 * The kind of OAuth access token defined here is known as a bearer token, which
 * means that whoever holds the token can present it to the protected resource.
 */
var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/authorize', function(req, res) {

	/*
	 * redirect the user to the authorization server - "front channel"
	 */

	access_token = null;


	// @see state checking logic in '/callback' handler function
	state = randomstring.generate();
	
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	});

	console.log("redirect", authorizeUrl);
	res.redirect(authorizeUrl);
});


/**
 * This request is coming in as a redirect from the authorization server, not as an HTTP 
 * response to resource owner direct request.
 */
app.get('/callback', function(req, res){

	/*
	 * Parse the response from the authorization server and get a token
	 */

	if (req.query.error) {
		res.render('error', {error: req.query.error});
		return;
	}

	// If the state value doesn’t match what we’re expecting, that’s a very good indication
    // that something untoward is happening, such as a session fixation attack.
	if (req.query.state != state) {
		console.log('State does not match: expected %s, got %s', state, req.query.state);
		res.render('error', {error: 'State value did not match'});
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0]
	});

	// add headers to mark this as form encoded request as well as HTTP basic authentication
	// HTTP basic auth is base64 encoded string combining client id and secret
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + encodeClientCredentials(client.client_id, client.client_secret) 
	};
	
	var tokRes = request('POST', authServer.tokenEndpoint, {
		body: form_data,
		headers: headers
	});

	console.log('Requesting access token for code %s', code);

	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
		access_token = body.access_token;
		console.log('Got access token: %s', access_token);

		res.render('index', {access_token: access_token, scope: scope});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode});
	}
});

app.get('/fetch_resource', function(req, res) {
	
	/*
	 * Use the access token to call the resource server
	 */
	
	if (!access_token) {
		res.render('error', {error: 'Missing access token'});
		return;
	}

	console.log('Making request with access token %s', access_token);

	var headers = {
		'Authorization': 'Bearer ' + access_token
	};

	var resource = request('POST', protectedResource, {
		headers: headers
	});

	if (resource.statusCode >=200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('data', {resource: body});
		return;
	} else {
		res.render('error', {error: 'Server returned response code: ' + resource.statusCode});
		return;
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var encodeClientCredentials = function(clientId, clientSecret) {
	return new Buffer(querystring.escape(clientId) + ':' + querystring.escape(clientSecret)).toString('base64');
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
