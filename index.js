const dotenv 		= require('dotenv').config();
const express 		= require('express');
const app 			= express();
const crypto		= require('crypto');
const cookie		= require('cookie');
const nonce			= require('nonce')();
const querystring	= require('querystring');
const request		= require('request-promise');

const apiKey 		= process.env.SHOPIFY_API_KEY;
const apiSecret 	= process.env.SHOPIFY_API_SECRET;
const scopes		= 'write_products';
const forwardingAddress = 'https://2238ec44.ngrok.io';
const port 			= process.env.PORT_NUMBER;

app.get('/shopify', (req, res) => {
	const shop = req.query.shop;
	if (shop) {
		const state 		= nonce();
		const redirectUri 	= forwardingAddress + '/shopify/callback';
		const installUri 	= 'https://' + shop + '/admin/oauth/authorize?client_id=' + apiKey + 
		'&scope=' + scopes +
		'&state=' + state +
		'&redirect_uri=' + redirectUri;

		res.cookie('state', state);
		res.redirect(installUri);
	}else{
		res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
	}
});

app.get('/shopify/callback', (req, res) => {
	const { shop, hmac, code, state} = req.query;
	const stateCookie = cookie.parse(req.headers.cookie).state;

	if ( state !== stateCookie) {
		return res.status(403).send('Request origin cannot be verified');
	}

	if (shop && hmac && code) {
		const map = Object.assign({}, req.query);
		delete map['hmac'];
		const message = querystring.stringify(map);
		const generatedHash = crypto
			.createHmac('sha256', apiSecret)
			.update(message)
			.digest('hex');

		if (generatedHash !== hmac){
			return res.status(400).send('HMAC validation failed');
		}

		// request for access token
		const accessTokenUrl 		= 'https://' +  shop + '/admin/oauth/access_token';
		const accessTokenPayload 	= {
			client_id		: apiKey,
			client_secret	: apiSecret,
			code
		}

		request.post(accessTokenUrl, {json: accessTokenPayload})
		.then( (accessTokenResponse) => {
			const accessToken = accessTokenResponse.access_token;

			res.status(200).send('api token: ' + accessToken);
		})
		.catch( (error) => {
			console.log(error)
			res.status(error.statusCode).send(error.error.error_description);
		});
	
	}else {
		return res.status(400).send('Required parameters missing');
	}

});

app.listen(port, () => {
	console.log("App running on port:" + port);
});
//  https://2238ec44.ngrok.io/shopify?shop=iwdbundletest.myshopify.com