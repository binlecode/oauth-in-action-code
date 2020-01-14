var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

var getAccessToken = function(req, res, next) {
	/*
	 * Scan for an access token on the incoming request.
	 */

	var inToken = null;
	var auth = req.headers['authorization']; // express auto-lower-cases header key
	// Note that the token value itself is case sensitive, so we slice the original string and 
	// not a transformed version.
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {  // in form encoded format, less preferred
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {  // as query string parameter, least preferred
		inToken = req.query.access_token;
	}

	nosql.one(function(token) {
		if (token.access_token == inToken) {
			return token;
		}
	}, function(err, token) { // called when either a match is found or not (token value is null in this case)
		if (token) {
			console.log('We found a matching token: %s', inToken);
		} else {
			console.log('No matching token was found.');
		}

		req.access_token = token;  // attach the matching token record to request
		next();  // pass to next handling stage
		return;
	});
	
};

app.options('/resource', cors());


/*
 * Add the getAccessToken function to this handler
 */
// app.post("/resource", cors(), function(req, res) {
app.post("/resource", cors(), getAccessToken, function(req, res) {

	/*
	 * Check to see if the access token was found or not
	 */

	if (req.access_token) {
		res.json(resource);
	} else {
		res.status(401).end();
	}
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
