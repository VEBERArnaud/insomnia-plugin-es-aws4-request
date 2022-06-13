const { SignatureV4 } = require('@aws-sdk/signature-v4');
const { HttpRequest } = require('@aws-sdk/protocol-http');
const { defaultProvider } = require('@aws-sdk/credential-provider-node');
const { Sha256 } = require('@aws-crypto/sha256-js');
const { parse: parseQuery } = require('query-string');

module.exports.requestHooks = [
  async ({ request }) => {
    // bypass plugin if USE_ES_AWS4_REQUEST_PLUGIN header not set
    if (!request.hasHeader('USE_ES_AWS4_REQUEST_PLUGIN')) {
      return;
    }

    // export AWS credentials
    process.env.AWS_ACCESS_KEY_ID = request.getEnvironmentVariable('AWS_ACCESS_KEY_ID');
    process.env.AWS_SECRET_ACCESS_KEY = request.getEnvironmentVariable('AWS_SECRET_ACCESS_KEY');
    process.env.AWS_REGION = request.getEnvironmentVariable('AWS_REGION')
      || request.getEnvironmentVariable('AWS_DEFAULT_REGION');

    // remove USE_ES_AWS4_REQUEST_PLUGIN header
    request.removeHeader('USE_ES_AWS4_REQUEST_PLUGIN');

    // remove AUTHORIZATION header if set
    if (request.hasHeader('AUTHORIZATION')) {
      request.removeHeader('AUTHORIZATION');
    }

    // retrieve request components
    const method = request.getMethod();
    const {
      hostname, pathname: path, port, protocol, search,
    } = new URL(request.getUrl());
    const query = parseQuery(search);
    const body = request.getBody().text;
    const headers = request.getHeaders()
      .map(header => ({ [header.name]: header.value }))
      .shift();

    // add Host header
    headers.Host = hostname;

    // create http request for signature
    const httpRequest = new HttpRequest({
      body, headers, hostname, method, path, port, protocol, query,
    });

    // bypass plugin  if request is invalid
    if (!HttpRequest.isInstance(httpRequest)) {
      console.error('[insomnia-plugin-es-aws4-request] Unabble to sign request');

      return;
    }

    // sign http request
    const signer = new SignatureV4({
      credentials: defaultProvider(),
      service: 'es',
      region: process.env.AWS_REGION,
      sha256: Sha256,
    });
    const signedHttpRequest = await signer.sign(httpRequest);

    // set signed headers in insomnia request
    Object.keys(signedHttpRequest.headers).forEach(name => request.setHeader(name, signedHttpRequest.headers[name]));
  },
];
