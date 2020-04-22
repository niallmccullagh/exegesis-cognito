import { default as exegesisCognito, Options } from '../src';
import { jwks, keys } from './jwks';
import pb from 'promise-breaker';
import {AuthenticationSuccess, CallbackAuthenticator} from 'exegesis';
import { sign } from 'jsonwebtoken';
import { expect } from 'chai';
import 'mocha';

const idToken = {
    'sub': 'b3bc1aca-8f26-4sa7-9060-5d01d170cc5e',
    'aud': 'myapplication',
    'email_verified': true,
    'event_id': '8c734a86-a551-11e8-b3e4-db56b0c39024',
    'token_use': 'id',
    'iss': 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TEST',
    'cognito:username': 'jane.@d.oe',
    'cognito:groups': [
        'administrator',
        'user'
    ],
    'email': 'jane.@d.oe',
    "phone_number_verified": true,
    "phone_number": "+441000000000",
};

const accessToken = {
    "sub": "ba5bcf72-4b20-4c06-bc6b-ffc710adb244",
    "event_id": "5969c740-b1c8-11e8-9075-59819eb4d6a9",
    "token_use": "access",
    "scope": "write read",
    'iss': 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TEST',
    "jti": "8703cdf8-978f-46f2-bf17-e343eaae9377",
    "client_id": "278voa0cu33c1kue82ra62q65q",
    "username": "jane"
};

describe('exegesisCognito when given', () => {
    describe('no token', () => {
        it('should return missing result if there is no authentication header', async () => {
            const options: Options = {
                jwks
            };
            const authenticator : CallbackAuthenticator = exegesisCognito(options);

            const pluginContext : any = {req: {
                headers: {apikey: 'secret'}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {}, done));

            expect(result).to.eql({
                type: 'missing',
                status: 401
            });
        });

        it('should return missing result if the authentication header is not a Bearer token', async () => {
            const options: Options = {
                jwks
            };
            const authenticator : CallbackAuthenticator = exegesisCognito(options);

            const pluginContext : any = {req: {
                headers: {authorization: 'api-key asdad'}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {}, done));

            expect(result).to.eql({
                type: 'missing',
                status: 401
            });
        });
    });
    describe('a valid id token', () => {
        let result: AuthenticationSuccess;

        before(async () => {
            const options: Options = {
                jwks
            };

            const token = sign(idToken, keys[0].privateKey, { keyid: keys[0].kid, algorithm: 'RS256' });

            const authenticator: CallbackAuthenticator = exegesisCognito(options);

            const pluginContext: any = {
                req: {
                    headers: {authorization: `Bearer ${token}`}
                }
            };

            result = await pb.call((done: any) => authenticator(pluginContext, {}, done));
        });

        it('result should be success', async () => {
            expect(result.type).to.eql('success');
        });

        it('should set user object', async () => {
            expect(result.user).to.eql({
                id: 'b3bc1aca-8f26-4sa7-9060-5d01d170cc5e',
                email: 'jane.@d.oe',
                email_verified: true,
                phone_number_verified: true,
                phone_number: "+441000000000",
                username: 'jane.@d.oe',
                "roles": [
                    "administrator",
                    "user"
                ]

            });
        });

        it('should set roles from the cognito groups', async () => {
            expect(result.roles).to.eql(['administrator', 'user']);
        });
    });
    describe('a valid access token', () => {
        let result: AuthenticationSuccess;

        before(async () => {
            const options: Options = {
                jwks
            };

            const token = sign(accessToken, keys[0].privateKey, { keyid: keys[0].kid, algorithm: 'RS256' });

            const authenticator: CallbackAuthenticator = exegesisCognito(options);

            const pluginContext: any = {
                req: {
                    headers: {authorization: `Bearer ${token}`}
                }
            };

            result = await pb.call((done: any) => authenticator(pluginContext, {}, done));
        });

        it('result should be success', async () => {
            expect(result.type).to.eql('success');
        });

        it('should set user object', async () => {
            expect(result.user).to.eql({
                id: 'ba5bcf72-4b20-4c06-bc6b-ffc710adb244',
                username: 'jane'
            });
        });

        it('should set scopes', async () => {
            expect(result.scopes).to.eql(['write','read']);
        });
    });

    describe('a valid access token with no scope', () => {
        let result: AuthenticationSuccess;

        before(async () => {
            const options: Options = {
                jwks
            };

            const customToken = Object.assign({}, accessToken);
            delete customToken.scope;
            const token = sign(customToken, keys[0].privateKey, { keyid: keys[0].kid, algorithm: 'RS256' });

            const authenticator: CallbackAuthenticator = exegesisCognito(options);

            const pluginContext: any = {
                req: {
                    headers: {authorization: `Bearer ${token}`}
                }
            };

            result = await pb.call((done: any) => authenticator(pluginContext, {}, done));
        });

        it('result should be success', async () => {
            expect(result.type).to.eql('success');
        });

        it('should set user object', async () => {
            expect(result.user).to.eql({
                id: 'ba5bcf72-4b20-4c06-bc6b-ffc710adb244',
                username: 'jane'
            });
        });

        it('should set scopes', async () => {
            expect(result.scopes).to.eql(undefined);
        });
    });

    describe('an invalid token', () => {
        it('should return an invalid result if JWK not recognised', async () => {
            const options: Options = {
                jwks
            };

            const token = sign(idToken, keys[0].privateKey, { keyid: 'unknown', algorithm: 'RS256' });

            const authenticator : CallbackAuthenticator = exegesisCognito(options);

            const pluginContext : any = {req: {
                headers: {authorization: `Bearer ${token}`}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {}, done));

            expect(result).to.eql({
                type: 'invalid',
                status: 401,
                message: 'invalid signature'
            });
        });

        it('should return an invalid result if signature is invalid', async () => {
            const options: Options = {
                jwks
            };

            const token = sign(idToken, keys[0].privateKey, { keyid: keys[1].kid, algorithm: 'RS256' });

            const authenticator : CallbackAuthenticator = exegesisCognito(options);

            const pluginContext : any = {req: {
                headers: {authorization: `Bearer ${token}`}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {}, done));

            expect(result).to.eql({
                type: 'invalid',
                status: 401,
                message: 'invalid signature'
            });
        });

        it('should strip the expected value from in the result error message as it leaks information', async () => {
            const options: Options = {
                issuer: 'asd',
                jwks
            };

            const token = sign(idToken, keys[0].privateKey, { keyid: keys[0].kid, algorithm: 'RS256' });

            const authenticator : CallbackAuthenticator = exegesisCognito(options);

            const pluginContext : any = {req: {
                headers: {authorization: `Bearer ${token}`}
            }};

            const result = await pb.call((done: any) => authenticator(pluginContext, {}, done));

            expect(result).to.eql({
                message: 'jwt issuer invalid.',
                status: 401,
                type: 'invalid'
            });
        });
    });
});