import { verify, decode, VerifyOptions, JsonWebTokenError } from 'jsonwebtoken';
import {
    AuthenticationSuccess,
    ExegesisPluginContext,
    Authenticator,
    AuthenticationFailure,
    AuthenticatorInfo
} from 'exegesis';
import debug from 'debug';
import jwkToPem = require('jwk-to-pem');

const log = debug('exegesis-cognito');

export interface Options {
    jwks: Jwks;
    algorithms?: string[];
    audience?: string | string[];
    clockTolerance?: number;
    issuer?: string | string[];
    ignoreExpiration?: boolean;
    ignoreNotBefore?: boolean;
    jwtid?: string;
    subject?: string;
}

interface Key {
    alg?: string;
    e: string;
    kid: string;
    kty: string;
    n: string;
    use?: string;
}

export interface Jwks {
    keys: Key[];
}

function convert(options: Options): VerifyOptions {
    return {
        algorithms: options.algorithms,
        audience: options.audience,
        clockTolerance: options.clockTolerance,
        issuer: options.issuer,
        ignoreExpiration: options.ignoreExpiration,
        ignoreNotBefore: options.ignoreNotBefore,
        jwtid: options.jwtid,
        subject: options.subject,
    };
}

function mapAccessToken(token: any): any {
    return {
        id: token.sub,
        username: token["cognito:username"],
        email_verified: token.email_verified,
        email: token.email,
        roles: token["cognito:groups"],
    };
}

function mapIdToken(token: any): any {
    return {
        id: token.sub,
        username: token.username,
    };
}

function formatScopes(scope :string) {
    if(scope) {
        return scope.split(' ');
    }
    return scope;
}

function generateSuccessResult(
    token: any
):AuthenticationSuccess {
    log('Decoded token', token);
    if(token.token_use === 'id') {
        return Object.assign(
            { type: 'success' } as { type: 'success' },
            { user: mapAccessToken(token) },
            { roles: token["cognito:groups"] },
            { token });
    }
    return Object.assign(
        { type: 'success' } as { type: 'success' },
        { user: mapIdToken(token) },
        { scopes: formatScopes(token.scope) },
        { token });
}

function generateMissingResult(): AuthenticationFailure {
    return {type: 'missing', status: 401};
}

function generateErrorResult(message: string): AuthenticationFailure {
    let userMessage: string = message;
    if (message.indexOf(' expected') > 0) {
        userMessage = message.substr(0, message.indexOf(' expected'));
    }
    const result: AuthenticationFailure = {type: 'invalid', status: 401, message: userMessage};
    return result;
}

function getToken(pluginContext: ExegesisPluginContext) {
    const header = pluginContext.req.headers.authorization;
    if (header) {
        const [ type, token ] = header.split(' ');
        if (type === 'Bearer') {
            return token;
        }
    }
    return undefined;
}

function jwkstoPems(jwks: Jwks): any {
    const pems: any = {};

    for (const key of jwks.keys) {
        pems[key.kid] = jwkToPem(key);
    }

    return pems;
}

function getPem(token: string, pems: any) {
    const decodedToken: any = decode(token, { complete: true, json: true });
    const kid: string = decodedToken.header.kid;

    log(`kid: [${kid}]`);

    const pem = pems[kid];
    return pem;
}

function createAuthenticator(options: Options) : Authenticator {

    const verifyOptions = convert(options);
    const pems = jwkstoPems(options.jwks);

    return function cognitoAuthenticator(
        pluginContext: ExegesisPluginContext,
        info: AuthenticatorInfo,
        done
    ) {
        log(info);
        const token = getToken(pluginContext);

        if(token) {

            const pem = getPem(token, pems);

            if(pem) {
                verify(token,
                    pem,
                    verifyOptions,
                    (err: JsonWebTokenError, decoded: string | object) => {
                        if (err) {
                            log('Failed to verify', err);
                            done(null, generateErrorResult(err.message));
                        } else {
                            log('verified', decoded);
                            done(null, generateSuccessResult(decoded));
                        }
                    });
            } else {
                log('token has unknown key id');
                done(null, generateErrorResult('invalid signature'));
            }
        } else {
            log('Failed to verify. No token found');
            done(null, generateMissingResult());
        }
    };
}

export function exegesisCognito(options: Options) : Authenticator {
    return createAuthenticator(options);
}

export default exegesisCognito;