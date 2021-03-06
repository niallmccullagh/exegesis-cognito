# exegesis-cognito

[![NPM version](https://badge.fury.io/js/exegesis-cognito.svg)](https://www.npmjs.com/package/exegesis-cognito)
[![Build Status](https://travis-ci.org/niallmccullagh/exegesis-cognito.svg)](https://travis-ci.org/niallmccullagh/exegesis-cognito)
[![Coverage Status](https://coveralls.io/repos/github/niallmccullagh/exegesis-cognito/badge.svg?branch=master)](https://coveralls.io/github/niallmccullagh/exegesis-cognito?branch=master)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release) [![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fniallmccullagh%2Fexegesis-cognito.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fniallmccullagh%2Fexegesis-cognito?ref=badge_shield)

[![Greenkeeper badge](https://badges.greenkeeper.io/niallmccullagh/exegesis-cognito.svg)](https://greenkeeper.io/)

This package provides authentication of AWS cognito tokens in Exegesis requests.

**Configure server**
```js
import * as exegesisExpress from 'exegesis-express';
import exegesisCognito from 'exegesis-cognito';


async function createServer() {
    const app = express();

    const jwks = fs.readFileSync('config/jwks.json', 'utf8')

    app.use(await exegesisExpress.middleware(
        path.resolve(__dirname, './openapi.yaml'),
        {
            // Other options go here...
            authenticators: {
                bearerAuth: exegesisCognito( { jwks })
            }
        }
    ));

    const server = http.createServer(app);
    server.listen(3000);
}
```

**Open API spec**

```yaml
...
paths:
  '/things':
    get:
      operationId: getThings
      x-exegesis-controller: thingController
      security:
        - bearerAuth: []
...
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
```
## API

### exegesisCognito(options)

Returns an Exegesis authenticator that will authenticate a request with an AWS bearer token.

#### Configuration

The authenticator can be configured by passing in an options object.

##### Mandatory

`jwks` is a JSON object that represents a set of JWKs. The JSON object MUST have a keys member, which is an
array of [JWKs](https://tools.ietf.org/html/rfc7517). The JWKS for a AWS cognito pool can be found at this well known

`https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json`

See [AWS cognito](https://aws.amazon.com/cognito/) site for more details.

##### Optional

* `algorithms`: List of strings with the names of the allowed algorithms. For instance, `["HS256", "HS384"]`.
* `audience`: if you want to check audience (`aud`), provide a value here. The audience can be checked against a string, a regular expression or a list of strings and/or regular expressions. Eg: `"urn:foo"`, `/urn:f[o]{2}/`, `[/urn:f[o]{2}/, "urn:bar"]`
* `issuer` (optional): string or array of strings of valid values for the `iss` field.
* `ignoreExpiration`: if `true` do not validate the expiration of the token.
* `ignoreNotBefore`...
* `subject`: if you want to check subject (`sub`), provide a value here
* `clockTolerance`: number of seconds to tolerate when checking the `nbf` and `exp` claims, to deal with small clock differences among different servers
* `maxAge`: the maximum allowed age for tokens to still be valid. It is expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms). Eg: `1000`, `"2 days"`, `"10h"`, `"7d"`. A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default (`"120"` is equal to `"120ms"`).
* `clockTimestamp`: the time in seconds that should be used as the current time for all necessary comparisons.


## Exegesis context

The authenticator will store the verified decoded token in the `context.security` object.
 

It will also poupulate the `context.user` object. The details extracted will deped on whether the bearer token is an id 
or access token.    

### Id token
```json
{
    "user": {
        "id": "ba5bcf72-4b20-4c06-bc6b-ffc710adb244",
        "username": "jane",
        "email_verified": false,
        "email": "janeh@d.oe",
        "roles": [
            "mygroup"
        ]
    }
}
```

### Access token

```json
{
  "user": {
    "id": "ba5bcf72-4b20-4c06-bc6b-ffc710adb244",
    "username": "niall"
  }
}
```

## Sending a request

The client must send the access/id token in the Authorization header when making requests to protected resources.
For example,

```bash
curl -X GET \
  'http://localhost:3000/things' \
  -H 'Authorization: Bearer eyJraWQiOiJpaGZYSVQ4Uk4yeFwvQW15UVo0Z2FUdEw5T3ZqQVpQa3RUcHY4SUpTbWttaz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiYTViY2Y3Mi00YjIwLTRjMDYtYmM2Yi1mZmM3MTBhZGIyNDQiLCJhdWQiOiIyNzh2b2EwY3UzM2Mxa3VlODJyYTYycTY1cSIsImNvZ25pdG86Z3JvdXBzIjpbIm15Z3JvdXAiXSwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV2ZW50X2lkIjoiMzI4NDRkNDgtYjFkZC0xMWU4LWE0NzQtMDVhN2YwNzQzYmE3IiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE1MzYyNDI0MjIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX1RFU1QiLCJjb2duaXRvOnVzZXJuYW1lIjoiamFuZSIsImV4cCI6MTUzNjI0NjAyMiwiaWF0IjoxNTM2MjQyNDIyLCJlbWFpbCI6ImphbmVAZC5vZSJ9.IdZV1F0MxEU0eC_6Qe_98EjgMSgYEGhP-mwqZtzQb4L8U1jOw-hnK4J1REChsaOatffE-aOJ4uoLV4oPYedRqnX4ABJ9XueN3lWfcZHc_DE2RTvDuEAV7hHoNTZwwn_mgaaYwLNMMOJeciXu3iM7PeT7xJAjdCxcdczZi1hPpqBc9Yx9wM7EMHyEo5klov3zRPJyvFPEpQPgpG1TjNkuvFwcl848YaXQDdlS9rXtTOySBVQu913e3i25VBnxZGxeHpFO3mmUomefOprDEvZpBSPg3-Di4F2-vKDzIl1OT98J8GayrJnD39O1TMUdiW-ApZKBFydtJtqvydQoVmEo_g'
```


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fniallmccullagh%2Fexegesis-cognito.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fniallmccullagh%2Fexegesis-cognito?ref=badge_large)