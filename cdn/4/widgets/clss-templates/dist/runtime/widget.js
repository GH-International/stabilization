System.register(["jimu-core","jimu-ui","jimu-core/react","jimu-arcgis"], function(__WEBPACK_DYNAMIC_EXPORT__, __system_context__) {
	var __WEBPACK_EXTERNAL_MODULE_jimu_core__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_ui__ = {};
	var __WEBPACK_EXTERNAL_MODULE_react__ = {};
	var __WEBPACK_EXTERNAL_MODULE_jimu_arcgis__ = {};
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_core__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_ui__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_react__, "__esModule", { value: true });
	Object.defineProperty(__WEBPACK_EXTERNAL_MODULE_jimu_arcgis__, "__esModule", { value: true });
	return {
		setters: [
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_core__[key] = module[key];
				});
			},
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_ui__[key] = module[key];
				});
			},
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_react__[key] = module[key];
				});
			},
			function(module) {
				Object.keys(module).forEach(function(key) {
					__WEBPACK_EXTERNAL_MODULE_jimu_arcgis__[key] = module[key];
				});
			}
		],
		execute: function() {
			__WEBPACK_DYNAMIC_EXPORT__(
/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/UserSession.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/UserSession.js ***!
  \*********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "UserSession": () => (/* binding */ UserSession)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-auth/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/decode-query-string.js");
/* harmony import */ var _generate_token__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./generate-token */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/generate-token.js");
/* harmony import */ var _fetch_token__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./fetch-token */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/fetch-token.js");
/* harmony import */ var _federation_utils__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./federation-utils */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/federation-utils.js");
/* harmony import */ var _validate_app_access__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./validate-app-access */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/validate-app-access.js");
/* Copyright (c) 2017-2019 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */






function defer() {
    var deferred = {
        promise: null,
        resolve: null,
        reject: null,
    };
    deferred.promise = new Promise(function (resolve, reject) {
        deferred.resolve = resolve;
        deferred.reject = reject;
    });
    return deferred;
}
/**
 * ```js
 * import { UserSession } from '@esri/arcgis-rest-auth';
 * UserSession.beginOAuth2({
 *   // register an app of your own to create a unique clientId
 *   clientId: "abc123",
 *   redirectUri: 'https://yourapp.com/authenticate.html'
 * })
 *   .then(session)
 * // or
 * new UserSession({
 *   username: "jsmith",
 *   password: "123456"
 * })
 * // or
 * UserSession.deserialize(cache)
 * ```
 * Used to authenticate both ArcGIS Online and ArcGIS Enterprise users. `UserSession` includes helper methods for [OAuth 2.0](/arcgis-rest-js/guides/browser-authentication/) in both browser and server applications.
 */
var UserSession = /** @class */ (function () {
    function UserSession(options) {
        this.clientId = options.clientId;
        this._refreshToken = options.refreshToken;
        this._refreshTokenExpires = options.refreshTokenExpires;
        this.username = options.username;
        this.password = options.password;
        this._token = options.token;
        this._tokenExpires = options.tokenExpires;
        this.portal = options.portal
            ? (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(options.portal)
            : "https://www.arcgis.com/sharing/rest";
        this.ssl = options.ssl;
        this.provider = options.provider || "arcgis";
        this.tokenDuration = options.tokenDuration || 20160;
        this.redirectUri = options.redirectUri;
        this.refreshTokenTTL = options.refreshTokenTTL || 20160;
        this.server = options.server;
        this.federatedServers = {};
        this.trustedDomains = [];
        // if a non-federated server was passed explicitly, it should be trusted.
        if (options.server) {
            // if the url includes more than '/arcgis/', trim the rest
            var root = this.getServerRootUrl(options.server);
            this.federatedServers[root] = {
                token: options.token,
                expires: options.tokenExpires,
            };
        }
        this._pendingTokenRequests = {};
    }
    Object.defineProperty(UserSession.prototype, "token", {
        /**
         * The current ArcGIS Online or ArcGIS Enterprise `token`.
         */
        get: function () {
            return this._token;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(UserSession.prototype, "tokenExpires", {
        /**
         * The expiration time of the current `token`.
         */
        get: function () {
            return this._tokenExpires;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(UserSession.prototype, "refreshToken", {
        /**
         * The current token to ArcGIS Online or ArcGIS Enterprise.
         */
        get: function () {
            return this._refreshToken;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(UserSession.prototype, "refreshTokenExpires", {
        /**
         * The expiration time of the current `refreshToken`.
         */
        get: function () {
            return this._refreshTokenExpires;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(UserSession.prototype, "trustedServers", {
        /**
         * Deprecated, use `federatedServers` instead.
         *
         * @deprecated
         */
        get: function () {
            console.log("DEPRECATED: use federatedServers instead");
            return this.federatedServers;
        },
        enumerable: false,
        configurable: true
    });
    /**
     * Begins a new browser-based OAuth 2.0 sign in. If `options.popup` is `true` the
     * authentication window will open in a new tab/window and the function will return
     * Promise&lt;UserSession&gt;. Otherwise, the user will be redirected to the
     * authorization page in their current tab/window and the function will return `undefined`.
     *
     * @browserOnly
     */
    /* istanbul ignore next */
    UserSession.beginOAuth2 = function (options, win) {
        if (win === void 0) { win = window; }
        if (options.duration) {
            console.log("DEPRECATED: 'duration' is deprecated - use 'expiration' instead");
        }
        var _a = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({
            portal: "https://www.arcgis.com/sharing/rest",
            provider: "arcgis",
            expiration: 20160,
            popup: true,
            popupWindowFeatures: "height=400,width=600,menubar=no,location=yes,resizable=yes,scrollbars=yes,status=yes",
            state: options.clientId,
            locale: "",
        }, options), portal = _a.portal, provider = _a.provider, clientId = _a.clientId, expiration = _a.expiration, redirectUri = _a.redirectUri, popup = _a.popup, popupWindowFeatures = _a.popupWindowFeatures, state = _a.state, locale = _a.locale, params = _a.params;
        var url;
        if (provider === "arcgis") {
            url = portal + "/oauth2/authorize?client_id=" + clientId + "&response_type=token&expiration=" + (options.duration || expiration) + "&redirect_uri=" + encodeURIComponent(redirectUri) + "&state=" + state + "&locale=" + locale;
        }
        else {
            url = portal + "/oauth2/social/authorize?client_id=" + clientId + "&socialLoginProviderName=" + provider + "&autoAccountCreateForSocial=true&response_type=token&expiration=" + (options.duration || expiration) + "&redirect_uri=" + encodeURIComponent(redirectUri) + "&state=" + state + "&locale=" + locale;
        }
        // append additional params
        if (params) {
            url = url + "&" + (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__.encodeQueryString)(params);
        }
        if (!popup) {
            win.location.href = url;
            return undefined;
        }
        var session = defer();
        win["__ESRI_REST_AUTH_HANDLER_" + clientId] = function (errorString, oauthInfoString) {
            if (errorString) {
                var error = JSON.parse(errorString);
                session.reject(new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError(error.errorMessage, error.error));
                return;
            }
            if (oauthInfoString) {
                var oauthInfo = JSON.parse(oauthInfoString);
                session.resolve(new UserSession({
                    clientId: clientId,
                    portal: portal,
                    ssl: oauthInfo.ssl,
                    token: oauthInfo.token,
                    tokenExpires: new Date(oauthInfo.expires),
                    username: oauthInfo.username,
                }));
            }
        };
        win.open(url, "oauth-window", popupWindowFeatures);
        return session.promise;
    };
    /**
     * Completes a browser-based OAuth 2.0 sign in. If `options.popup` is `true` the user
     * will be returned to the previous window. Otherwise a new `UserSession`
     * will be returned. You must pass the same values for `options.popup` and
     * `options.portal` as you used in `beginOAuth2()`.
     *
     * @browserOnly
     */
    /* istanbul ignore next */
    UserSession.completeOAuth2 = function (options, win) {
        if (win === void 0) { win = window; }
        var _a = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ portal: "https://www.arcgis.com/sharing/rest", popup: true }, options), portal = _a.portal, clientId = _a.clientId, popup = _a.popup;
        function completeSignIn(error, oauthInfo) {
            try {
                var handlerFn = void 0;
                var handlerFnName = "__ESRI_REST_AUTH_HANDLER_" + clientId;
                if (popup) {
                    // Guard b/c IE does not support window.opener
                    if (win.opener) {
                        if (win.opener.parent && win.opener.parent[handlerFnName]) {
                            handlerFn = win.opener.parent[handlerFnName];
                        }
                        else if (win.opener && win.opener[handlerFnName]) {
                            // support pop-out oauth from within an iframe
                            handlerFn = win.opener[handlerFnName];
                        }
                    }
                    else {
                        // IE
                        if (win !== win.parent && win.parent && win.parent[handlerFnName]) {
                            handlerFn = win.parent[handlerFnName];
                        }
                    }
                    // if we have a handler fn, call it and close the window
                    if (handlerFn) {
                        handlerFn(error ? JSON.stringify(error) : undefined, JSON.stringify(oauthInfo));
                        win.close();
                        return undefined;
                    }
                }
            }
            catch (e) {
                throw new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError("Unable to complete authentication. It's possible you specified popup based oAuth2 but no handler from \"beginOAuth2()\" present. This generally happens because the \"popup\" option differs between \"beginOAuth2()\" and \"completeOAuth2()\".");
            }
            if (error) {
                throw new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError(error.errorMessage, error.error);
            }
            return new UserSession({
                clientId: clientId,
                portal: portal,
                ssl: oauthInfo.ssl,
                token: oauthInfo.token,
                tokenExpires: oauthInfo.expires,
                username: oauthInfo.username,
            });
        }
        var params = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_4__.decodeQueryString)(win.location.hash);
        if (!params.access_token) {
            var error = void 0;
            var errorMessage = "Unknown error";
            if (params.error) {
                error = params.error;
                errorMessage = params.error_description;
            }
            return completeSignIn({ error: error, errorMessage: errorMessage });
        }
        var token = params.access_token;
        var expires = new Date(Date.now() + parseInt(params.expires_in, 10) * 1000 - 60 * 1000);
        var username = params.username;
        var ssl = params.ssl === "true";
        return completeSignIn(undefined, {
            token: token,
            expires: expires,
            ssl: ssl,
            username: username,
        });
    };
    /**
     * Request session information from the parent application
     *
     * When an application is embedded into another application via an IFrame, the embedded app can
     * use `window.postMessage` to request credentials from the host application. This function wraps
     * that behavior.
     *
     * The ArcGIS API for Javascript has this built into the Identity Manager as of the 4.19 release.
     *
     * Note: The parent application will not respond if the embedded app's origin is not:
     * - the same origin as the parent or *.arcgis.com (JSAPI)
     * - in the list of valid child origins (REST-JS)
     *
     *
     * @param parentOrigin origin of the parent frame. Passed into the embedded application as `parentOrigin` query param
     * @browserOnly
     */
    UserSession.fromParent = function (parentOrigin, win) {
        /* istanbul ignore next: must pass in a mockwindow for tests so we can't cover the other branch */
        if (!win && window) {
            win = window;
        }
        // Declare handler outside of promise scope so we can detach it
        var handler;
        // return a promise that will resolve when the handler receives
        // session information from the correct origin
        return new Promise(function (resolve, reject) {
            // create an event handler that just wraps the parentMessageHandler
            handler = function (event) {
                // ensure we only listen to events from the parent
                if (event.source === win.parent && event.data) {
                    try {
                        return resolve(UserSession.parentMessageHandler(event));
                    }
                    catch (err) {
                        return reject(err);
                    }
                }
            };
            // add listener
            win.addEventListener("message", handler, false);
            win.parent.postMessage({ type: "arcgis:auth:requestCredential" }, parentOrigin);
        }).then(function (session) {
            win.removeEventListener("message", handler, false);
            return session;
        });
    };
    /**
     * Begins a new server-based OAuth 2.0 sign in. This will redirect the user to
     * the ArcGIS Online or ArcGIS Enterprise authorization page.
     *
     * @nodeOnly
     */
    UserSession.authorize = function (options, response) {
        if (options.duration) {
            console.log("DEPRECATED: 'duration' is deprecated - use 'expiration' instead");
        }
        var _a = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ portal: "https://arcgis.com/sharing/rest", expiration: 20160 }, options), portal = _a.portal, clientId = _a.clientId, expiration = _a.expiration, redirectUri = _a.redirectUri;
        response.writeHead(301, {
            Location: portal + "/oauth2/authorize?client_id=" + clientId + "&expiration=" + (options.duration || expiration) + "&response_type=code&redirect_uri=" + encodeURIComponent(redirectUri),
        });
        response.end();
    };
    /**
     * Completes the server-based OAuth 2.0 sign in process by exchanging the `authorizationCode`
     * for a `access_token`.
     *
     * @nodeOnly
     */
    UserSession.exchangeAuthorizationCode = function (options, authorizationCode) {
        var _a = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({
            portal: "https://www.arcgis.com/sharing/rest",
            refreshTokenTTL: 20160,
        }, options), portal = _a.portal, clientId = _a.clientId, redirectUri = _a.redirectUri, refreshTokenTTL = _a.refreshTokenTTL;
        return (0,_fetch_token__WEBPACK_IMPORTED_MODULE_5__.fetchToken)(portal + "/oauth2/token", {
            params: {
                grant_type: "authorization_code",
                client_id: clientId,
                redirect_uri: redirectUri,
                code: authorizationCode,
            },
        }).then(function (response) {
            return new UserSession({
                clientId: clientId,
                portal: portal,
                ssl: response.ssl,
                redirectUri: redirectUri,
                refreshToken: response.refreshToken,
                refreshTokenTTL: refreshTokenTTL,
                refreshTokenExpires: new Date(Date.now() + (refreshTokenTTL - 1) * 60 * 1000),
                token: response.token,
                tokenExpires: response.expires,
                username: response.username,
            });
        });
    };
    UserSession.deserialize = function (str) {
        var options = JSON.parse(str);
        return new UserSession({
            clientId: options.clientId,
            refreshToken: options.refreshToken,
            refreshTokenExpires: new Date(options.refreshTokenExpires),
            username: options.username,
            password: options.password,
            token: options.token,
            tokenExpires: new Date(options.tokenExpires),
            portal: options.portal,
            ssl: options.ssl,
            tokenDuration: options.tokenDuration,
            redirectUri: options.redirectUri,
            refreshTokenTTL: options.refreshTokenTTL,
        });
    };
    /**
     * Translates authentication from the format used in the [ArcGIS API for JavaScript](https://developers.arcgis.com/javascript/).
     *
     * ```js
     * UserSession.fromCredential({
     *   userId: "jsmith",
     *   token: "secret"
     * });
     * ```
     *
     * @returns UserSession
     */
    UserSession.fromCredential = function (credential) {
        // At ArcGIS Online 9.1, credentials no longer include the ssl and expires properties
        // Here, we provide default values for them to cover this condition
        var ssl = typeof credential.ssl !== "undefined" ? credential.ssl : true;
        var expires = credential.expires || Date.now() + 7200000; /* 2 hours */
        return new UserSession({
            portal: credential.server.includes("sharing/rest")
                ? credential.server
                : credential.server + "/sharing/rest",
            ssl: ssl,
            token: credential.token,
            username: credential.userId,
            tokenExpires: new Date(expires),
        });
    };
    /**
     * Handle the response from the parent
     * @param event DOM Event
     */
    UserSession.parentMessageHandler = function (event) {
        if (event.data.type === "arcgis:auth:credential") {
            return UserSession.fromCredential(event.data.credential);
        }
        if (event.data.type === "arcgis:auth:error") {
            var err = new Error(event.data.error.message);
            err.name = event.data.error.name;
            throw err;
        }
        else {
            throw new Error("Unknown message type.");
        }
    };
    /**
     * Returns authentication in a format useable in the [ArcGIS API for JavaScript](https://developers.arcgis.com/javascript/).
     *
     * ```js
     * esriId.registerToken(session.toCredential());
     * ```
     *
     * @returns ICredential
     */
    UserSession.prototype.toCredential = function () {
        return {
            expires: this.tokenExpires.getTime(),
            server: this.portal,
            ssl: this.ssl,
            token: this.token,
            userId: this.username,
        };
    };
    /**
     * Returns information about the currently logged in [user](https://developers.arcgis.com/rest/users-groups-and-items/user.htm). Subsequent calls will *not* result in additional web traffic.
     *
     * ```js
     * session.getUser()
     *   .then(response => {
     *     console.log(response.role); // "org_admin"
     *   })
     * ```
     *
     * @param requestOptions - Options for the request. NOTE: `rawResponse` is not supported by this operation.
     * @returns A Promise that will resolve with the data from the response.
     */
    UserSession.prototype.getUser = function (requestOptions) {
        var _this = this;
        if (this._pendingUserRequest) {
            return this._pendingUserRequest;
        }
        else if (this._user) {
            return Promise.resolve(this._user);
        }
        else {
            var url = this.portal + "/community/self";
            var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ httpMethod: "GET", authentication: this }, requestOptions), { rawResponse: false });
            this._pendingUserRequest = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options).then(function (response) {
                _this._user = response;
                _this._pendingUserRequest = null;
                return response;
            });
            return this._pendingUserRequest;
        }
    };
    /**
     * Returns information about the currently logged in user's [portal](https://developers.arcgis.com/rest/users-groups-and-items/portal-self.htm). Subsequent calls will *not* result in additional web traffic.
     *
     * ```js
     * session.getPortal()
     *   .then(response => {
     *     console.log(portal.name); // "City of ..."
     *   })
     * ```
     *
     * @param requestOptions - Options for the request. NOTE: `rawResponse` is not supported by this operation.
     * @returns A Promise that will resolve with the data from the response.
     */
    UserSession.prototype.getPortal = function (requestOptions) {
        var _this = this;
        if (this._pendingPortalRequest) {
            return this._pendingPortalRequest;
        }
        else if (this._portalInfo) {
            return Promise.resolve(this._portalInfo);
        }
        else {
            var url = this.portal + "/portals/self";
            var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ httpMethod: "GET", authentication: this }, requestOptions), { rawResponse: false });
            this._pendingPortalRequest = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options).then(function (response) {
                _this._portalInfo = response;
                _this._pendingPortalRequest = null;
                return response;
            });
            return this._pendingPortalRequest;
        }
    };
    /**
     * Returns the username for the currently logged in [user](https://developers.arcgis.com/rest/users-groups-and-items/user.htm). Subsequent calls will *not* result in additional web traffic. This is also used internally when a username is required for some requests but is not present in the options.
     *
     *    * ```js
     * session.getUsername()
     *   .then(response => {
     *     console.log(response); // "casey_jones"
     *   })
     * ```
     */
    UserSession.prototype.getUsername = function () {
        if (this.username) {
            return Promise.resolve(this.username);
        }
        else if (this._user) {
            return Promise.resolve(this._user.username);
        }
        else {
            return this.getUser().then(function (user) {
                return user.username;
            });
        }
    };
    /**
     * Gets an appropriate token for the given URL. If `portal` is ArcGIS Online and
     * the request is to an ArcGIS Online domain `token` will be used. If the request
     * is to the current `portal` the current `token` will also be used. However if
     * the request is to an unknown server we will validate the server with a request
     * to our current `portal`.
     */
    UserSession.prototype.getToken = function (url, requestOptions) {
        if ((0,_federation_utils__WEBPACK_IMPORTED_MODULE_6__.canUseOnlineToken)(this.portal, url)) {
            return this.getFreshToken(requestOptions);
        }
        else if (new RegExp(this.portal, "i").test(url)) {
            return this.getFreshToken(requestOptions);
        }
        else {
            return this.getTokenForServer(url, requestOptions);
        }
    };
    /**
     * Get application access information for the current user
     * see `validateAppAccess` function for details
     *
     * @param clientId application client id
     */
    UserSession.prototype.validateAppAccess = function (clientId) {
        return this.getToken(this.portal).then(function (token) {
            return (0,_validate_app_access__WEBPACK_IMPORTED_MODULE_7__.validateAppAccess)(token, clientId);
        });
    };
    UserSession.prototype.toJSON = function () {
        return {
            clientId: this.clientId,
            refreshToken: this.refreshToken,
            refreshTokenExpires: this.refreshTokenExpires,
            username: this.username,
            password: this.password,
            token: this.token,
            tokenExpires: this.tokenExpires,
            portal: this.portal,
            ssl: this.ssl,
            tokenDuration: this.tokenDuration,
            redirectUri: this.redirectUri,
            refreshTokenTTL: this.refreshTokenTTL,
        };
    };
    UserSession.prototype.serialize = function () {
        return JSON.stringify(this);
    };
    /**
     * For a "Host" app that embeds other platform apps via iframes, after authenticating the user
     * and creating a UserSession, the app can then enable "post message" style authentication by calling
     * this method.
     *
     * Internally this adds an event listener on window for the `message` event
     *
     * @param validChildOrigins Array of origins that are allowed to request authentication from the host app
     */
    UserSession.prototype.enablePostMessageAuth = function (validChildOrigins, win) {
        /* istanbul ignore next: must pass in a mockwindow for tests so we can't cover the other branch */
        if (!win && window) {
            win = window;
        }
        this._hostHandler = this.createPostMessageHandler(validChildOrigins);
        win.addEventListener("message", this._hostHandler, false);
    };
    /**
     * For a "Host" app that has embedded other platform apps via iframes, when the host needs
     * to transition routes, it should call `UserSession.disablePostMessageAuth()` to remove
     * the event listener and prevent memory leaks
     */
    UserSession.prototype.disablePostMessageAuth = function (win) {
        /* istanbul ignore next: must pass in a mockwindow for tests so we can't cover the other branch */
        if (!win && window) {
            win = window;
        }
        win.removeEventListener("message", this._hostHandler, false);
    };
    /**
     * Manually refreshes the current `token` and `tokenExpires`.
     */
    UserSession.prototype.refreshSession = function (requestOptions) {
        // make sure subsequent calls to getUser() don't returned cached metadata
        this._user = null;
        if (this.username && this.password) {
            return this.refreshWithUsernameAndPassword(requestOptions);
        }
        if (this.clientId && this.refreshToken) {
            return this.refreshWithRefreshToken();
        }
        return Promise.reject(new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError("Unable to refresh token."));
    };
    /**
     * Determines the root of the ArcGIS Server or Portal for a given URL.
     *
     * @param url the URl to determine the root url for.
     */
    UserSession.prototype.getServerRootUrl = function (url) {
        var root = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(url).split(/\/rest(\/admin)?\/services(?:\/|#|\?|$)/)[0];
        var _a = root.match(/(https?:\/\/)(.+)/), match = _a[0], protocol = _a[1], domainAndPath = _a[2];
        var _b = domainAndPath.split("/"), domain = _b[0], path = _b.slice(1);
        // only the domain is lowercased because in some cases an org id might be
        // in the path which cannot be lowercased.
        return "" + protocol + domain.toLowerCase() + "/" + path.join("/");
    };
    /**
     * Returns the proper [`credentials`] option for `fetch` for a given domain.
     * See [trusted server](https://enterprise.arcgis.com/en/portal/latest/administer/windows/configure-security.htm#ESRI_SECTION1_70CC159B3540440AB325BE5D89DBE94A).
     * Used internally by underlying request methods to add support for specific security considerations.
     *
     * @param url The url of the request
     * @returns "include" or "same-origin"
     */
    UserSession.prototype.getDomainCredentials = function (url) {
        if (!this.trustedDomains || !this.trustedDomains.length) {
            return "same-origin";
        }
        return this.trustedDomains.some(function (domainWithProtocol) {
            return url.startsWith(domainWithProtocol);
        })
            ? "include"
            : "same-origin";
    };
    /**
     * Return a function that closes over the validOrigins array and
     * can be used as an event handler for the `message` event
     *
     * @param validOrigins Array of valid origins
     */
    UserSession.prototype.createPostMessageHandler = function (validOrigins) {
        var _this = this;
        // return a function that closes over the validOrigins and
        // has access to the credential
        return function (event) {
            // Verify that the origin is valid
            // Note: do not use regex's here. validOrigins is an array so we're checking that the event's origin
            // is in the array via exact match. More info about avoiding postMessage xss issues here
            // https://jlajara.gitlab.io/web/2020/07/17/Dom_XSS_PostMessage_2.html#tipsbypasses-in-postmessage-vulnerabilities
            var isValidOrigin = validOrigins.indexOf(event.origin) > -1;
            // JSAPI handles this slightly differently - instead of checking a list, it will respond if
            // event.origin === window.location.origin || event.origin.endsWith('.arcgis.com')
            // For Hub, and to enable cross domain debugging with port's in urls, we are opting to
            // use a list of valid origins
            // Ensure the message type is something we want to handle
            var isValidType = event.data.type === "arcgis:auth:requestCredential";
            var isTokenValid = _this.tokenExpires.getTime() > Date.now();
            if (isValidOrigin && isValidType) {
                var msg = {};
                if (isTokenValid) {
                    var credential = _this.toCredential();
                    // arcgis:auth:error with {name: "", message: ""}
                    // the following line allows us to conform to our spec without changing other depended-on functionality
                    // https://github.com/Esri/arcgis-rest-js/blob/master/packages/arcgis-rest-auth/post-message-auth-spec.md#arcgisauthcredential
                    credential.server = credential.server.replace("/sharing/rest", "");
                    msg = { type: "arcgis:auth:credential", credential: credential };
                }
                else {
                    // Return an error
                    msg = {
                        type: "arcgis:auth:error",
                        error: {
                            name: "tokenExpiredError",
                            message: "Session token was expired, and not returned to the child application",
                        },
                    };
                }
                event.source.postMessage(msg, event.origin);
            }
        };
    };
    /**
     * Validates that a given URL is properly federated with our current `portal`.
     * Attempts to use the internal `federatedServers` cache first.
     */
    UserSession.prototype.getTokenForServer = function (url, requestOptions) {
        var _this = this;
        // requests to /rest/services/ and /rest/admin/services/ are both valid
        // Federated servers may have inconsistent casing, so lowerCase it
        var root = this.getServerRootUrl(url);
        var existingToken = this.federatedServers[root];
        if (existingToken &&
            existingToken.expires &&
            existingToken.expires.getTime() > Date.now()) {
            return Promise.resolve(existingToken.token);
        }
        if (this._pendingTokenRequests[root]) {
            return this._pendingTokenRequests[root];
        }
        this._pendingTokenRequests[root] = this.fetchAuthorizedDomains().then(function () {
            return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(root + "/rest/info", {
                credentials: _this.getDomainCredentials(url),
            })
                .then(function (response) {
                if (response.owningSystemUrl) {
                    /**
                     * if this server is not owned by this portal
                     * bail out with an error since we know we wont
                     * be able to generate a token
                     */
                    if (!(0,_federation_utils__WEBPACK_IMPORTED_MODULE_6__.isFederated)(response.owningSystemUrl, _this.portal)) {
                        throw new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError(url + " is not federated with " + _this.portal + ".", "NOT_FEDERATED");
                    }
                    else {
                        /**
                         * if the server is federated, use the relevant token endpoint.
                         */
                        return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(response.owningSystemUrl + "/sharing/rest/info", requestOptions);
                    }
                }
                else if (response.authInfo &&
                    _this.federatedServers[root] !== undefined) {
                    /**
                     * if its a stand-alone instance of ArcGIS Server that doesn't advertise
                     * federation, but the root server url is recognized, use its built in token endpoint.
                     */
                    return Promise.resolve({
                        authInfo: response.authInfo,
                    });
                }
                else {
                    throw new _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.ArcGISAuthError(url + " is not federated with any portal and is not explicitly trusted.", "NOT_FEDERATED");
                }
            })
                .then(function (response) {
                return response.authInfo.tokenServicesUrl;
            })
                .then(function (tokenServicesUrl) {
                // an expired token cant be used to generate a new token
                if (_this.token && _this.tokenExpires.getTime() > Date.now()) {
                    return (0,_generate_token__WEBPACK_IMPORTED_MODULE_8__.generateToken)(tokenServicesUrl, {
                        params: {
                            token: _this.token,
                            serverUrl: url,
                            expiration: _this.tokenDuration,
                            client: "referer",
                        },
                    });
                    // generate an entirely fresh token if necessary
                }
                else {
                    return (0,_generate_token__WEBPACK_IMPORTED_MODULE_8__.generateToken)(tokenServicesUrl, {
                        params: {
                            username: _this.username,
                            password: _this.password,
                            expiration: _this.tokenDuration,
                            client: "referer",
                        },
                    }).then(function (response) {
                        _this._token = response.token;
                        _this._tokenExpires = new Date(response.expires);
                        return response;
                    });
                }
            })
                .then(function (response) {
                _this.federatedServers[root] = {
                    expires: new Date(response.expires),
                    token: response.token,
                };
                delete _this._pendingTokenRequests[root];
                return response.token;
            });
        });
        return this._pendingTokenRequests[root];
    };
    /**
     * Returns an unexpired token for the current `portal`.
     */
    UserSession.prototype.getFreshToken = function (requestOptions) {
        var _this = this;
        if (this.token && !this.tokenExpires) {
            return Promise.resolve(this.token);
        }
        if (this.token &&
            this.tokenExpires &&
            this.tokenExpires.getTime() > Date.now()) {
            return Promise.resolve(this.token);
        }
        if (!this._pendingTokenRequests[this.portal]) {
            this._pendingTokenRequests[this.portal] = this.refreshSession(requestOptions).then(function (session) {
                _this._pendingTokenRequests[_this.portal] = null;
                return session.token;
            });
        }
        return this._pendingTokenRequests[this.portal];
    };
    /**
     * Refreshes the current `token` and `tokenExpires` with `username` and
     * `password`.
     */
    UserSession.prototype.refreshWithUsernameAndPassword = function (requestOptions) {
        var _this = this;
        var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ params: {
                username: this.username,
                password: this.password,
                expiration: this.tokenDuration,
            } }, requestOptions);
        return (0,_generate_token__WEBPACK_IMPORTED_MODULE_8__.generateToken)(this.portal + "/generateToken", options).then(function (response) {
            _this._token = response.token;
            _this._tokenExpires = new Date(response.expires);
            return _this;
        });
    };
    /**
     * Refreshes the current `token` and `tokenExpires` with `refreshToken`.
     */
    UserSession.prototype.refreshWithRefreshToken = function (requestOptions) {
        var _this = this;
        if (this.refreshToken &&
            this.refreshTokenExpires &&
            this.refreshTokenExpires.getTime() < Date.now()) {
            return this.refreshRefreshToken(requestOptions);
        }
        var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ params: {
                client_id: this.clientId,
                refresh_token: this.refreshToken,
                grant_type: "refresh_token",
            } }, requestOptions);
        return (0,_fetch_token__WEBPACK_IMPORTED_MODULE_5__.fetchToken)(this.portal + "/oauth2/token", options).then(function (response) {
            _this._token = response.token;
            _this._tokenExpires = response.expires;
            return _this;
        });
    };
    /**
     * Exchanges an unexpired `refreshToken` for a new one, also updates `token` and
     * `tokenExpires`.
     */
    UserSession.prototype.refreshRefreshToken = function (requestOptions) {
        var _this = this;
        var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ params: {
                client_id: this.clientId,
                refresh_token: this.refreshToken,
                redirect_uri: this.redirectUri,
                grant_type: "exchange_refresh_token",
            } }, requestOptions);
        return (0,_fetch_token__WEBPACK_IMPORTED_MODULE_5__.fetchToken)(this.portal + "/oauth2/token", options).then(function (response) {
            _this._token = response.token;
            _this._tokenExpires = response.expires;
            _this._refreshToken = response.refreshToken;
            _this._refreshTokenExpires = new Date(Date.now() + (_this.refreshTokenTTL - 1) * 60 * 1000);
            return _this;
        });
    };
    /**
     * ensures that the authorizedCrossOriginDomains are obtained from the portal and cached
     * so we can check them later.
     *
     * @returns this
     */
    UserSession.prototype.fetchAuthorizedDomains = function () {
        var _this = this;
        // if this token is for a specific server or we don't have a portal
        // don't get the portal info because we cant get the authorizedCrossOriginDomains
        if (this.server || !this.portal) {
            return Promise.resolve(this);
        }
        return this.getPortal().then(function (portalInfo) {
            /**
             * Specific domains can be configured as secure.esri.com or https://secure.esri.com this
             * normalizes to https://secure.esri.com so we can use startsWith later.
             */
            if (portalInfo.authorizedCrossOriginDomains &&
                portalInfo.authorizedCrossOriginDomains.length) {
                _this.trustedDomains = portalInfo.authorizedCrossOriginDomains
                    .filter(function (d) { return !d.startsWith("http://"); })
                    .map(function (d) {
                    if (d.startsWith("https://")) {
                        return d;
                    }
                    else {
                        return "https://" + d;
                    }
                });
            }
            return _this;
        });
    };
    return UserSession;
}());

//# sourceMappingURL=UserSession.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/federation-utils.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/federation-utils.js ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "canUseOnlineToken": () => (/* binding */ canUseOnlineToken),
/* harmony export */   "getOnlineEnvironment": () => (/* binding */ getOnlineEnvironment),
/* harmony export */   "isFederated": () => (/* binding */ isFederated),
/* harmony export */   "isOnline": () => (/* binding */ isOnline),
/* harmony export */   "normalizeOnlinePortalUrl": () => (/* binding */ normalizeOnlinePortalUrl)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");

/**
 * Used to test if a URL is an ArcGIS Online URL
 */
var arcgisOnlineUrlRegex = /^https?:\/\/(\S+)\.arcgis\.com.+/;
/**
 * Used to test if a URL is production ArcGIS Online Portal
 */
var arcgisOnlinePortalRegex = /^https?:\/\/(dev|devext|qa|qaext|www)\.arcgis\.com\/sharing\/rest+/;
/**
 * Used to test if a URL is an ArcGIS Online Organization Portal
 */
var arcgisOnlineOrgPortalRegex = /^https?:\/\/(?:[a-z0-9-]+\.maps(dev|devext|qa|qaext)?)?.arcgis\.com\/sharing\/rest/;
function isOnline(url) {
    return arcgisOnlineUrlRegex.test(url);
}
function normalizeOnlinePortalUrl(portalUrl) {
    if (!arcgisOnlineUrlRegex.test(portalUrl)) {
        return portalUrl;
    }
    switch (getOnlineEnvironment(portalUrl)) {
        case "dev":
            return "https://devext.arcgis.com/sharing/rest";
        case "qa":
            return "https://qaext.arcgis.com/sharing/rest";
        default:
            return "https://www.arcgis.com/sharing/rest";
    }
}
function getOnlineEnvironment(url) {
    if (!arcgisOnlineUrlRegex.test(url)) {
        return null;
    }
    var match = url.match(arcgisOnlineUrlRegex);
    var subdomain = match[1].split(".").pop();
    if (subdomain.includes("dev")) {
        return "dev";
    }
    if (subdomain.includes("qa")) {
        return "qa";
    }
    return "production";
}
function isFederated(owningSystemUrl, portalUrl) {
    var normalizedPortalUrl = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(normalizeOnlinePortalUrl(portalUrl)).replace(/https?:\/\//, "");
    var normalizedOwningSystemUrl = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(owningSystemUrl).replace(/https?:\/\//, "");
    return new RegExp(normalizedOwningSystemUrl, "i").test(normalizedPortalUrl);
}
function canUseOnlineToken(portalUrl, requestUrl) {
    var portalIsOnline = isOnline(portalUrl);
    var requestIsOnline = isOnline(requestUrl);
    var portalEnv = getOnlineEnvironment(portalUrl);
    var requestEnv = getOnlineEnvironment(requestUrl);
    if (portalIsOnline && requestIsOnline && portalEnv === requestEnv) {
        return true;
    }
    return false;
}
//# sourceMappingURL=federation-utils.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/fetch-token.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/fetch-token.js ***!
  \*********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "fetchToken": () => (/* binding */ fetchToken)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

function fetchToken(url, requestOptions) {
    var options = requestOptions;
    // we generate a response, so we can't return the raw response
    options.rawResponse = false;
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.request)(url, options).then(function (response) {
        var r = {
            token: response.access_token,
            username: response.username,
            expires: new Date(
            // convert seconds in response to milliseconds and add the value to the current time to calculate a static expiration timestamp
            Date.now() + (response.expires_in * 1000 - 1000)),
            ssl: response.ssl === true
        };
        if (response.refresh_token) {
            r.refreshToken = response.refresh_token;
        }
        return r;
    });
}
//# sourceMappingURL=fetch-token.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/generate-token.js":
/*!************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/generate-token.js ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "generateToken": () => (/* binding */ generateToken)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

function generateToken(url, requestOptions) {
    var options = requestOptions;
    /* istanbul ignore else */
    if (typeof window !== "undefined" &&
        window.location &&
        window.location.host) {
        options.params.referer = window.location.host;
    }
    else {
        options.params.referer = _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.NODEJS_DEFAULT_REFERER_HEADER;
    }
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.request)(url, options);
}
//# sourceMappingURL=generate-token.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/dist/esm/validate-app-access.js":
/*!*****************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/dist/esm/validate-app-access.js ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "validateAppAccess": () => (/* binding */ validateAppAccess)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2018-2020 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

/**
 * Validates that the user has access to the application
 * and if they user should be presented a "View Only" mode
 *
 * This is only needed/valid for Esri applications that are "licensed"
 * and shipped in ArcGIS Online or ArcGIS Enterprise. Most custom applications
 * should not need or use this.
 *
 * ```js
 * import { validateAppAccess } from '@esri/arcgis-rest-auth';
 *
 * return validateAppAccess('your-token', 'theClientId')
 * .then((result) => {
 *    if (!result.value) {
 *      // redirect or show some other ui
 *    } else {
 *      if (result.viewOnlyUserTypeApp) {
 *        // use this to inform your app to show a "View Only" mode
 *      }
 *    }
 * })
 * .catch((err) => {
 *  // two possible errors
 *  // invalid clientId: {"error":{"code":400,"messageCode":"GWM_0007","message":"Invalid request","details":[]}}
 *  // invalid token: {"error":{"code":498,"message":"Invalid token.","details":[]}}
 * })
 * ```
 *
 * Note: This is only usable by Esri applications hosted on *arcgis.com, *esri.com or within
 * an ArcGIS Enterprise installation. Custom applications can not use this.
 *
 * @param token platform token
 * @param clientId application client id
 * @param portal Optional
 */
function validateAppAccess(token, clientId, portal) {
    if (portal === void 0) { portal = "https://www.arcgis.com/sharing/rest"; }
    var url = portal + "/oauth2/validateAppAccess";
    var ro = {
        method: "POST",
        params: {
            f: "json",
            client_id: clientId,
            token: token,
        },
    };
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.request)(url, ro);
}
//# sourceMappingURL=validate-app-access.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-auth/node_modules/tslib/tslib.es6.js":
/*!*****************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-auth/node_modules/tslib/tslib.es6.js ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "__assign": () => (/* binding */ __assign),
/* harmony export */   "__asyncDelegator": () => (/* binding */ __asyncDelegator),
/* harmony export */   "__asyncGenerator": () => (/* binding */ __asyncGenerator),
/* harmony export */   "__asyncValues": () => (/* binding */ __asyncValues),
/* harmony export */   "__await": () => (/* binding */ __await),
/* harmony export */   "__awaiter": () => (/* binding */ __awaiter),
/* harmony export */   "__classPrivateFieldGet": () => (/* binding */ __classPrivateFieldGet),
/* harmony export */   "__classPrivateFieldSet": () => (/* binding */ __classPrivateFieldSet),
/* harmony export */   "__createBinding": () => (/* binding */ __createBinding),
/* harmony export */   "__decorate": () => (/* binding */ __decorate),
/* harmony export */   "__exportStar": () => (/* binding */ __exportStar),
/* harmony export */   "__extends": () => (/* binding */ __extends),
/* harmony export */   "__generator": () => (/* binding */ __generator),
/* harmony export */   "__importDefault": () => (/* binding */ __importDefault),
/* harmony export */   "__importStar": () => (/* binding */ __importStar),
/* harmony export */   "__makeTemplateObject": () => (/* binding */ __makeTemplateObject),
/* harmony export */   "__metadata": () => (/* binding */ __metadata),
/* harmony export */   "__param": () => (/* binding */ __param),
/* harmony export */   "__read": () => (/* binding */ __read),
/* harmony export */   "__rest": () => (/* binding */ __rest),
/* harmony export */   "__spread": () => (/* binding */ __spread),
/* harmony export */   "__spreadArrays": () => (/* binding */ __spreadArrays),
/* harmony export */   "__values": () => (/* binding */ __values)
/* harmony export */ });
/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    }
    return __assign.apply(this, arguments);
}

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

function __spreadArrays() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};

function __await(v) {
    return this instanceof __await ? (this.v = v, this) : new __await(v);
}

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
};

function __importStar(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}


/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/add.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/add.js ***!
  \**********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "addFeatures": () => (/* binding */ addFeatures)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 * ```js
 * import { addFeatures } from '@esri/arcgis-rest-feature-layer';
 * //
 * addFeatures({
 *   url: "https://sampleserver6.arcgisonline.com/arcgis/rest/services/ServiceRequest/FeatureServer/0",
 *   features: [{
 *     geometry: { x: -120, y: 45, spatialReference: { wkid: 4326 } },
 *     attributes: { status: "alive" }
 *   }]
 * })
 *   .then(response)
 * ```
 * Add features request. See the [REST Documentation](https://developers.arcgis.com/rest/services-reference/add-features.htm) for more information.
 *
 * @param requestOptions - Options for the request.
 * @returns A Promise that will resolve with the addFeatures response.
 */
function addFeatures(requestOptions) {
    var url = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/addFeatures";
    // edit operations are POST only
    var options = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__.appendCustomParams)(requestOptions, ["features", "gdbVersion", "returnEditMoment", "rollbackOnFailure"], { params: (0,tslib__WEBPACK_IMPORTED_MODULE_2__.__assign)({}, requestOptions.params) });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options);
}
//# sourceMappingURL=add.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/delete.js":
/*!*************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/delete.js ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "deleteFeatures": () => (/* binding */ deleteFeatures)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 * ```js
 * import { deleteFeatures } from '@esri/arcgis-rest-feature-layer';
 * //
 * deleteFeatures({
 *   url: "https://sampleserver6.arcgisonline.com/arcgis/rest/services/ServiceRequest/FeatureServer/0",
 *   objectIds: [1,2,3]
 * });
 * ```
 * Delete features request. See the [REST Documentation](https://developers.arcgis.com/rest/services-reference/delete-features.htm) for more information.
 *
 * @param deleteFeaturesRequestOptions - Options for the request.
 * @returns A Promise that will resolve with the deleteFeatures response.
 */
function deleteFeatures(requestOptions) {
    var url = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/deleteFeatures";
    // edit operations POST only
    var options = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__.appendCustomParams)(requestOptions, [
        "where",
        "objectIds",
        "gdbVersion",
        "returnEditMoment",
        "rollbackOnFailure"
    ], { params: (0,tslib__WEBPACK_IMPORTED_MODULE_2__.__assign)({}, requestOptions.params) });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options);
}
//# sourceMappingURL=delete.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/query.js":
/*!************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/query.js ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "getFeature": () => (/* binding */ getFeature),
/* harmony export */   "queryFeatures": () => (/* binding */ queryFeatures)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 * ```js
 * import { getFeature } from '@esri/arcgis-rest-feature-layer';
 * //
 * const url = "https://services.arcgis.com/V6ZHFr6zdgNZuVG0/arcgis/rest/services/Landscape_Trees/FeatureServer/0";
 * //
 * getFeature({
 *   url,
 *   id: 42
 * }).then(feature => {
 *  console.log(feature.attributes.FID); // 42
 * });
 * ```
 * Get a feature by id.
 *
 * @param requestOptions - Options for the request
 * @returns A Promise that will resolve with the feature or the [response](https://developer.mozilla.org/en-US/docs/Web/API/Response) itself if `rawResponse: true` was passed in.
 */
function getFeature(requestOptions) {
    var url = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/" + requestOptions.id;
    // default to a GET request
    var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ httpMethod: "GET" }, requestOptions);
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__.request)(url, options).then(function (response) {
        if (options.rawResponse) {
            return response;
        }
        return response.feature;
    });
}
/**
 * ```js
 * import { queryFeatures } from '@esri/arcgis-rest-feature-layer';
 * //
 * queryFeatures({
 *   url: "http://sampleserver6.arcgisonline.com/arcgis/rest/services/Census/MapServer/3",
 *   where: "STATE_NAME = 'Alaska'"
 * })
 *   .then(result)
 * ```
 * Query a feature service. See [REST Documentation](https://developers.arcgis.com/rest/services-reference/query-feature-service-layer-.htm) for more information.
 *
 * @param requestOptions - Options for the request
 * @returns A Promise that will resolve with the query response.
 */
function queryFeatures(requestOptions) {
    var queryOptions = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.appendCustomParams)(requestOptions, [
        "where",
        "objectIds",
        "relationParam",
        "time",
        "distance",
        "units",
        "outFields",
        "geometry",
        "geometryType",
        "spatialRel",
        "returnGeometry",
        "maxAllowableOffset",
        "geometryPrecision",
        "inSR",
        "outSR",
        "gdbVersion",
        "returnDistinctValues",
        "returnIdsOnly",
        "returnCountOnly",
        "returnExtentOnly",
        "orderByFields",
        "groupByFieldsForStatistics",
        "outStatistics",
        "returnZ",
        "returnM",
        "multipatchOption",
        "resultOffset",
        "resultRecordCount",
        "quantizationParameters",
        "returnCentroid",
        "resultType",
        "historicMoment",
        "returnTrueCurves",
        "sqlFormat",
        "returnExceededLimitFeatures",
        "f"
    ], {
        httpMethod: "GET",
        params: (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ 
            // set default query parameters
            where: "1=1", outFields: "*" }, requestOptions.params)
    });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__.request)((0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/query", queryOptions);
}
//# sourceMappingURL=query.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/queryRelated.js":
/*!*******************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/queryRelated.js ***!
  \*******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "queryRelated": () => (/* binding */ queryRelated)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* Copyright (c) 2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 *
 * ```js
 * import { queryRelated } from '@esri/arcgis-rest-feature-layer'
 * //
 * queryRelated({
 *  url: "http://services.myserver/OrgID/ArcGIS/rest/services/Petroleum/KSPetro/FeatureServer/0",
 *  relationshipId: 1,
 *  params: { returnCountOnly: true }
 * })
 *  .then(response) // response.relatedRecords
 * ```
 * Query the related records for a feature service. See the [REST Documentation](https://developers.arcgis.com/rest/services-reference/query-related-records-feature-service-.htm) for more information.
 *
 * @param requestOptions
 * @returns A Promise that will resolve with the query response
 */
function queryRelated(requestOptions) {
    var options = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.appendCustomParams)(requestOptions, ["objectIds", "relationshipId", "definitionExpression", "outFields"], {
        httpMethod: "GET",
        params: (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ 
            // set default query parameters
            definitionExpression: "1=1", outFields: "*", relationshipId: 0 }, requestOptions.params)
    });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_2__.request)((0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.cleanUrl)(requestOptions.url) + "/queryRelatedRecords", options);
}
//# sourceMappingURL=queryRelated.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/update.js":
/*!*************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/update.js ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "updateFeatures": () => (/* binding */ updateFeatures)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js");
/* harmony import */ var _esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-request */ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 *
 * ```js
 * import { updateFeatures } from '@esri/arcgis-rest-feature-layer';
 * //
 * updateFeatures({
 *   url: "https://sampleserver6.arcgisonline.com/arcgis/rest/services/ServiceRequest/FeatureServer/0",
 *   features: [{
 *     geometry: { x: -120, y: 45, spatialReference: { wkid: 4326 } },
 *     attributes: { status: "alive" }
 *   }]
 * });
 * ```
 * Update features request. See the [REST Documentation](https://developers.arcgis.com/rest/services-reference/update-features.htm) for more information.
 *
 * @param requestOptions - Options for the request.
 * @returns A Promise that will resolve with the updateFeatures response.
 */
function updateFeatures(requestOptions) {
    var url = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_0__.cleanUrl)(requestOptions.url) + "/updateFeatures";
    // edit operations are POST only
    var options = (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_1__.appendCustomParams)(requestOptions, ["features", "gdbVersion", "returnEditMoment", "rollbackOnFailure", "trueCurveClient"], { params: (0,tslib__WEBPACK_IMPORTED_MODULE_2__.__assign)({}, requestOptions.params) });
    return (0,_esri_arcgis_rest_request__WEBPACK_IMPORTED_MODULE_3__.request)(url, options);
}
//# sourceMappingURL=update.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js":
/*!**************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-feature-layer/node_modules/tslib/tslib.es6.js ***!
  \**************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "__assign": () => (/* binding */ __assign),
/* harmony export */   "__asyncDelegator": () => (/* binding */ __asyncDelegator),
/* harmony export */   "__asyncGenerator": () => (/* binding */ __asyncGenerator),
/* harmony export */   "__asyncValues": () => (/* binding */ __asyncValues),
/* harmony export */   "__await": () => (/* binding */ __await),
/* harmony export */   "__awaiter": () => (/* binding */ __awaiter),
/* harmony export */   "__classPrivateFieldGet": () => (/* binding */ __classPrivateFieldGet),
/* harmony export */   "__classPrivateFieldSet": () => (/* binding */ __classPrivateFieldSet),
/* harmony export */   "__createBinding": () => (/* binding */ __createBinding),
/* harmony export */   "__decorate": () => (/* binding */ __decorate),
/* harmony export */   "__exportStar": () => (/* binding */ __exportStar),
/* harmony export */   "__extends": () => (/* binding */ __extends),
/* harmony export */   "__generator": () => (/* binding */ __generator),
/* harmony export */   "__importDefault": () => (/* binding */ __importDefault),
/* harmony export */   "__importStar": () => (/* binding */ __importStar),
/* harmony export */   "__makeTemplateObject": () => (/* binding */ __makeTemplateObject),
/* harmony export */   "__metadata": () => (/* binding */ __metadata),
/* harmony export */   "__param": () => (/* binding */ __param),
/* harmony export */   "__read": () => (/* binding */ __read),
/* harmony export */   "__rest": () => (/* binding */ __rest),
/* harmony export */   "__spread": () => (/* binding */ __spread),
/* harmony export */   "__spreadArrays": () => (/* binding */ __spreadArrays),
/* harmony export */   "__values": () => (/* binding */ __values)
/* harmony export */ });
/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    }
    return __assign.apply(this, arguments);
}

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

function __spreadArrays() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};

function __await(v) {
    return this instanceof __await ? (this.v = v, this) : new __await(v);
}

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
};

function __importStar(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}


/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/request.js":
/*!********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/request.js ***!
  \********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ArcGISAuthError": () => (/* binding */ ArcGISAuthError),
/* harmony export */   "NODEJS_DEFAULT_REFERER_HEADER": () => (/* binding */ NODEJS_DEFAULT_REFERER_HEADER),
/* harmony export */   "checkForErrors": () => (/* binding */ checkForErrors),
/* harmony export */   "request": () => (/* binding */ request),
/* harmony export */   "setDefaultRequestOptions": () => (/* binding */ setDefaultRequestOptions)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-request/node_modules/tslib/tslib.es6.js");
/* harmony import */ var _utils_encode_form_data__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./utils/encode-form-data */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-form-data.js");
/* harmony import */ var _utils_encode_query_string__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./utils/encode-query-string */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js");
/* harmony import */ var _utils_process_params__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./utils/process-params */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js");
/* harmony import */ var _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./utils/ArcGISRequestError */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/ArcGISRequestError.js");
/* harmony import */ var _utils_warn__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./utils/warn */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/warn.js");
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */






var NODEJS_DEFAULT_REFERER_HEADER = "@esri/arcgis-rest-js";
var DEFAULT_ARCGIS_REQUEST_OPTIONS = {
    httpMethod: "POST",
    params: {
        f: "json",
    },
};
/**
 * Sets the default options that will be passed in **all requests across all `@esri/arcgis-rest-js` modules**.
 *
 *
 * ```js
 * import { setDefaultRequestOptions } from "@esri/arcgis-rest-request";
 * setDefaultRequestOptions({
 *   authentication: userSession // all requests will use this session by default
 * })
 * ```
 * You should **never** set a default `authentication` when you are in a server side environment where you may be handling requests for many different authenticated users.
 *
 * @param options The default options to pass with every request. Existing default will be overwritten.
 * @param hideWarnings Silence warnings about setting default `authentication` in shared environments.
 */
function setDefaultRequestOptions(options, hideWarnings) {
    if (options.authentication && !hideWarnings) {
        (0,_utils_warn__WEBPACK_IMPORTED_MODULE_0__.warn)("You should not set `authentication` as a default in a shared environment such as a web server which will process multiple users requests. You can call `setDefaultRequestOptions` with `true` as a second argument to disable this warning.");
    }
    DEFAULT_ARCGIS_REQUEST_OPTIONS = options;
}
var ArcGISAuthError = /** @class */ (function (_super) {
    (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__extends)(ArcGISAuthError, _super);
    /**
     * Create a new `ArcGISAuthError`  object.
     *
     * @param message - The error message from the API
     * @param code - The error code from the API
     * @param response - The original response from the API that caused the error
     * @param url - The original url of the request
     * @param options - The original options of the request
     */
    function ArcGISAuthError(message, code, response, url, options) {
        if (message === void 0) { message = "AUTHENTICATION_ERROR"; }
        if (code === void 0) { code = "AUTHENTICATION_ERROR_CODE"; }
        var _this = _super.call(this, message, code, response, url, options) || this;
        _this.name = "ArcGISAuthError";
        _this.message =
            code === "AUTHENTICATION_ERROR_CODE" ? message : code + ": " + message;
        return _this;
    }
    ArcGISAuthError.prototype.retry = function (getSession, retryLimit) {
        var _this = this;
        if (retryLimit === void 0) { retryLimit = 3; }
        var tries = 0;
        var retryRequest = function (resolve, reject) {
            getSession(_this.url, _this.options)
                .then(function (session) {
                var newOptions = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({}, _this.options), { authentication: session });
                tries = tries + 1;
                return request(_this.url, newOptions);
            })
                .then(function (response) {
                resolve(response);
            })
                .catch(function (e) {
                if (e.name === "ArcGISAuthError" && tries < retryLimit) {
                    retryRequest(resolve, reject);
                }
                else if (e.name === "ArcGISAuthError" && tries >= retryLimit) {
                    reject(_this);
                }
                else {
                    reject(e);
                }
            });
        };
        return new Promise(function (resolve, reject) {
            retryRequest(resolve, reject);
        });
    };
    return ArcGISAuthError;
}(_utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError));

/**
 * Checks for errors in a JSON response from the ArcGIS REST API. If there are no errors, it will return the `data` passed in. If there is an error, it will throw an `ArcGISRequestError` or `ArcGISAuthError`.
 *
 * @param data The response JSON to check for errors.
 * @param url The url of the original request
 * @param params The parameters of the original request
 * @param options The options of the original request
 * @returns The data that was passed in the `data` parameter
 */
function checkForErrors(response, url, params, options, originalAuthError) {
    // this is an error message from billing.arcgis.com backend
    if (response.code >= 400) {
        var message = response.message, code = response.code;
        throw new _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError(message, code, response, url, options);
    }
    // error from ArcGIS Online or an ArcGIS Portal or server instance.
    if (response.error) {
        var _a = response.error, message = _a.message, code = _a.code, messageCode = _a.messageCode;
        var errorCode = messageCode || code || "UNKNOWN_ERROR_CODE";
        if (code === 498 ||
            code === 499 ||
            messageCode === "GWM_0003" ||
            (code === 400 && message === "Unable to generate token.")) {
            if (originalAuthError) {
                throw originalAuthError;
            }
            else {
                throw new ArcGISAuthError(message, errorCode, response, url, options);
            }
        }
        throw new _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError(message, errorCode, response, url, options);
    }
    // error from a status check
    if (response.status === "failed" || response.status === "failure") {
        var message = void 0;
        var code = "UNKNOWN_ERROR_CODE";
        try {
            message = JSON.parse(response.statusMessage).message;
            code = JSON.parse(response.statusMessage).code;
        }
        catch (e) {
            message = response.statusMessage || response.message;
        }
        throw new _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError(message, code, response, url, options);
    }
    return response;
}
/**
 * ```js
 * import { request } from '@esri/arcgis-rest-request';
 * //
 * request('https://www.arcgis.com/sharing/rest')
 *   .then(response) // response.currentVersion === 5.2
 * //
 * request('https://www.arcgis.com/sharing/rest', {
 *   httpMethod: "GET"
 * })
 * //
 * request('https://www.arcgis.com/sharing/rest/search', {
 *   params: { q: 'parks' }
 * })
 *   .then(response) // response.total => 78379
 * ```
 * Generic method for making HTTP requests to ArcGIS REST API endpoints.
 *
 * @param url - The URL of the ArcGIS REST API endpoint.
 * @param requestOptions - Options for the request, including parameters relevant to the endpoint.
 * @returns A Promise that will resolve with the data from the response.
 */
function request(url, requestOptions) {
    if (requestOptions === void 0) { requestOptions = { params: { f: "json" } }; }
    var options = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ httpMethod: "POST" }, DEFAULT_ARCGIS_REQUEST_OPTIONS), requestOptions), {
        params: (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({}, DEFAULT_ARCGIS_REQUEST_OPTIONS.params), requestOptions.params),
        headers: (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({}, DEFAULT_ARCGIS_REQUEST_OPTIONS.headers), requestOptions.headers),
    });
    var missingGlobals = [];
    var recommendedPackages = [];
    // don't check for a global fetch if a custom implementation was passed through
    if (!options.fetch && typeof fetch !== "undefined") {
        options.fetch = fetch.bind(Function("return this")());
    }
    else {
        missingGlobals.push("`fetch`");
        recommendedPackages.push("`node-fetch`");
    }
    if (typeof Promise === "undefined") {
        missingGlobals.push("`Promise`");
        recommendedPackages.push("`es6-promise`");
    }
    if (typeof FormData === "undefined") {
        missingGlobals.push("`FormData`");
        recommendedPackages.push("`isomorphic-form-data`");
    }
    if (!options.fetch ||
        typeof Promise === "undefined" ||
        typeof FormData === "undefined") {
        throw new Error("`arcgis-rest-request` requires a `fetch` implementation and global variables for `Promise` and `FormData` to be present in the global scope. You are missing " + missingGlobals.join(", ") + ". We recommend installing the " + recommendedPackages.join(", ") + " modules at the root of your application to add these to the global scope. See https://bit.ly/2KNwWaJ for more info.");
    }
    var httpMethod = options.httpMethod, authentication = options.authentication, rawResponse = options.rawResponse;
    var params = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({ f: "json" }, options.params);
    var originalAuthError = null;
    var fetchOptions = {
        method: httpMethod,
        /* ensures behavior mimics XMLHttpRequest.
        needed to support sending IWA cookies */
        credentials: options.credentials || "same-origin",
    };
    // the /oauth2/platformSelf route will add X-Esri-Auth-Client-Id header
    // and that request needs to send cookies cross domain
    // so we need to set the credentials to "include"
    if (options.headers &&
        options.headers["X-Esri-Auth-Client-Id"] &&
        url.indexOf("/oauth2/platformSelf") > -1) {
        fetchOptions.credentials = "include";
    }
    return (authentication
        ? authentication.getToken(url, { fetch: options.fetch }).catch(function (err) {
            /**
             * append original request url and requestOptions
             * to the error thrown by getToken()
             * to assist with retrying
             */
            err.url = url;
            err.options = options;
            /**
             * if an attempt is made to talk to an unfederated server
             * first try the request anonymously. if a 'token required'
             * error is thrown, throw the UNFEDERATED error then.
             */
            originalAuthError = err;
            return Promise.resolve("");
        })
        : Promise.resolve(""))
        .then(function (token) {
        if (token.length) {
            params.token = token;
        }
        if (authentication && authentication.getDomainCredentials) {
            fetchOptions.credentials = authentication.getDomainCredentials(url);
        }
        // Custom headers to add to request. IRequestOptions.headers with merge over requestHeaders.
        var requestHeaders = {};
        if (fetchOptions.method === "GET") {
            // Prevents token from being passed in query params when hideToken option is used.
            /* istanbul ignore if - window is always defined in a browser. Test case is covered by Jasmine in node test */
            if (params.token &&
                options.hideToken &&
                // Sharing API does not support preflight check required by modern browsers https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
                typeof window === "undefined") {
                requestHeaders["X-Esri-Authorization"] = "Bearer " + params.token;
                delete params.token;
            }
            // encode the parameters into the query string
            var queryParams = (0,_utils_encode_query_string__WEBPACK_IMPORTED_MODULE_3__.encodeQueryString)(params);
            // dont append a '?' unless parameters are actually present
            var urlWithQueryString = queryParams === "" ? url : url + "?" + (0,_utils_encode_query_string__WEBPACK_IMPORTED_MODULE_3__.encodeQueryString)(params);
            if (
            // This would exceed the maximum length for URLs specified by the consumer and requires POST
            (options.maxUrlLength &&
                urlWithQueryString.length > options.maxUrlLength) ||
                // Or if the customer requires the token to be hidden and it has not already been hidden in the header (for browsers)
                (params.token && options.hideToken)) {
                // the consumer specified a maximum length for URLs
                // and this would exceed it, so use post instead
                fetchOptions.method = "POST";
                // If the token was already added as a Auth header, add the token back to body with other params instead of header
                if (token.length && options.hideToken) {
                    params.token = token;
                    // Remove existing header that was added before url query length was checked
                    delete requestHeaders["X-Esri-Authorization"];
                }
            }
            else {
                // just use GET
                url = urlWithQueryString;
            }
        }
        /* updateResources currently requires FormData even when the input parameters dont warrant it.
    https://developers.arcgis.com/rest/users-groups-and-items/update-resources.htm
        see https://github.com/Esri/arcgis-rest-js/pull/500 for more info. */
        var forceFormData = new RegExp("/items/.+/updateResources").test(url);
        if (fetchOptions.method === "POST") {
            fetchOptions.body = (0,_utils_encode_form_data__WEBPACK_IMPORTED_MODULE_4__.encodeFormData)(params, forceFormData);
        }
        // Mixin headers from request options
        fetchOptions.headers = (0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_1__.__assign)({}, requestHeaders), options.headers);
        /* istanbul ignore next - karma reports coverage on browser tests only */
        if (typeof window === "undefined" && !fetchOptions.headers.referer) {
            fetchOptions.headers.referer = NODEJS_DEFAULT_REFERER_HEADER;
        }
        /* istanbul ignore else blob responses are difficult to make cross platform we will just have to trust the isomorphic fetch will do its job */
        if (!(0,_utils_process_params__WEBPACK_IMPORTED_MODULE_5__.requiresFormData)(params) && !forceFormData) {
            fetchOptions.headers["Content-Type"] =
                "application/x-www-form-urlencoded";
        }
        return options.fetch(url, fetchOptions);
    })
        .then(function (response) {
        if (!response.ok) {
            // server responded w/ an actual error (404, 500, etc)
            var status_1 = response.status, statusText = response.statusText;
            throw new _utils_ArcGISRequestError__WEBPACK_IMPORTED_MODULE_2__.ArcGISRequestError(statusText, "HTTP " + status_1, response, url, options);
        }
        if (rawResponse) {
            return response;
        }
        switch (params.f) {
            case "json":
                return response.json();
            case "geojson":
                return response.json();
            case "html":
                return response.text();
            case "text":
                return response.text();
            /* istanbul ignore next blob responses are difficult to make cross platform we will just have to trust that isomorphic fetch will do its job */
            default:
                return response.blob();
        }
    })
        .then(function (data) {
        if ((params.f === "json" || params.f === "geojson") && !rawResponse) {
            var response = checkForErrors(data, url, params, options, originalAuthError);
            if (originalAuthError) {
                /* If the request was made to an unfederated service that
                didn't require authentication, add the base url and a dummy token
                to the list of trusted servers to avoid another federation check
                in the event of a repeat request */
                var truncatedUrl = url
                    .toLowerCase()
                    .split(/\/rest(\/admin)?\/services\//)[0];
                options.authentication.federatedServers[truncatedUrl] = {
                    token: [],
                    // default to 24 hours
                    expires: new Date(Date.now() + 86400 * 1000),
                };
                originalAuthError = null;
            }
            return response;
        }
        else {
            return data;
        }
    });
}
//# sourceMappingURL=request.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/ArcGISRequestError.js":
/*!*************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/ArcGISRequestError.js ***!
  \*************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ArcGISRequestError": () => (/* binding */ ArcGISRequestError)
/* harmony export */ });
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
// TypeScript 2.1 no longer allows you to extend built in types. See https://github.com/Microsoft/TypeScript/issues/12790#issuecomment-265981442
// and https://github.com/Microsoft/TypeScript-wiki/blob/master/Breaking-Changes.md#extending-built-ins-like-error-array-and-map-may-no-longer-work
//
// This code is from MDN https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error#Custom_Error_Types.
var ArcGISRequestError = /** @class */ (function () {
    /**
     * Create a new `ArcGISRequestError`  object.
     *
     * @param message - The error message from the API
     * @param code - The error code from the API
     * @param response - The original response from the API that caused the error
     * @param url - The original url of the request
     * @param options - The original options and parameters of the request
     */
    function ArcGISRequestError(message, code, response, url, options) {
        message = message || "UNKNOWN_ERROR";
        code = code || "UNKNOWN_ERROR_CODE";
        this.name = "ArcGISRequestError";
        this.message =
            code === "UNKNOWN_ERROR_CODE" ? message : code + ": " + message;
        this.originalMessage = message;
        this.code = code;
        this.response = response;
        this.url = url;
        this.options = options;
    }
    return ArcGISRequestError;
}());

ArcGISRequestError.prototype = Object.create(Error.prototype);
ArcGISRequestError.prototype.constructor = ArcGISRequestError;
//# sourceMappingURL=ArcGISRequestError.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js":
/*!***************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/append-custom-params.js ***!
  \***************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "appendCustomParams": () => (/* binding */ appendCustomParams)
/* harmony export */ });
/* harmony import */ var tslib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tslib */ "./node_modules/@esri/arcgis-rest-request/node_modules/tslib/tslib.es6.js");
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

/**
 * Helper for methods with lots of first order request options to pass through as request parameters.
 */
function appendCustomParams(customOptions, keys, baseOptions) {
    var requestOptionsKeys = [
        "params",
        "httpMethod",
        "rawResponse",
        "authentication",
        "portal",
        "fetch",
        "maxUrlLength",
        "headers"
    ];
    var options = (0,tslib__WEBPACK_IMPORTED_MODULE_0__.__assign)((0,tslib__WEBPACK_IMPORTED_MODULE_0__.__assign)({ params: {} }, baseOptions), customOptions);
    // merge all keys in customOptions into options.params
    options.params = keys.reduce(function (value, key) {
        if (customOptions[key] || typeof customOptions[key] === "boolean") {
            value[key] = customOptions[key];
        }
        return value;
    }, options.params);
    // now remove all properties in options that don't exist in IRequestOptions
    return requestOptionsKeys.reduce(function (value, key) {
        if (options[key]) {
            value[key] = options[key];
        }
        return value;
    }, {});
}
//# sourceMappingURL=append-custom-params.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js":
/*!****************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/clean-url.js ***!
  \****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "cleanUrl": () => (/* binding */ cleanUrl)
/* harmony export */ });
/* Copyright (c) 2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
/**
 * Helper method to ensure that user supplied urls don't include whitespace or a trailing slash.
 */
function cleanUrl(url) {
    // Guard so we don't try to trim something that's not a string
    if (typeof url !== "string") {
        return url;
    }
    // trim leading and trailing spaces, but not spaces inside the url
    url = url.trim();
    // remove the trailing slash to the url if one was included
    if (url[url.length - 1] === "/") {
        url = url.slice(0, -1);
    }
    return url;
}
//# sourceMappingURL=clean-url.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/decode-query-string.js":
/*!**************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/decode-query-string.js ***!
  \**************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "decodeParam": () => (/* binding */ decodeParam),
/* harmony export */   "decodeQueryString": () => (/* binding */ decodeQueryString)
/* harmony export */ });
/* Copyright (c) 2017-2020 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
function decodeParam(param) {
    var _a = param.split("="), key = _a[0], value = _a[1];
    return { key: decodeURIComponent(key), value: decodeURIComponent(value) };
}
/**
 * Decodes the passed query string as an object.
 *
 * @param query A string to be decoded.
 * @returns A decoded query param object.
 */
function decodeQueryString(query) {
    return query
        .replace(/^#/, "")
        .split("&")
        .reduce(function (acc, entry) {
        var _a = decodeParam(entry), key = _a.key, value = _a.value;
        acc[key] = value;
        return acc;
    }, {});
}
//# sourceMappingURL=decode-query-string.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-form-data.js":
/*!***********************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-form-data.js ***!
  \***********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "encodeFormData": () => (/* binding */ encodeFormData)
/* harmony export */ });
/* harmony import */ var _process_params__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./process-params */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js");
/* harmony import */ var _encode_query_string__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./encode-query-string */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */


/**
 * Encodes parameters in a [FormData](https://developer.mozilla.org/en-US/docs/Web/API/FormData) object in browsers or in a [FormData](https://github.com/form-data/form-data) in Node.js
 *
 * @param params An object to be encoded.
 * @returns The complete [FormData](https://developer.mozilla.org/en-US/docs/Web/API/FormData) object.
 */
function encodeFormData(params, forceFormData) {
    // see https://github.com/Esri/arcgis-rest-js/issues/499 for more info.
    var useFormData = (0,_process_params__WEBPACK_IMPORTED_MODULE_0__.requiresFormData)(params) || forceFormData;
    var newParams = (0,_process_params__WEBPACK_IMPORTED_MODULE_0__.processParams)(params);
    if (useFormData) {
        var formData_1 = new FormData();
        Object.keys(newParams).forEach(function (key) {
            if (typeof Blob !== "undefined" && newParams[key] instanceof Blob) {
                /* To name the Blob:
                 1. look to an alternate request parameter called 'fileName'
                 2. see if 'name' has been tacked onto the Blob manually
                 3. if all else fails, use the request parameter
                */
                var filename = newParams["fileName"] || newParams[key].name || key;
                formData_1.append(key, newParams[key], filename);
            }
            else {
                formData_1.append(key, newParams[key]);
            }
        });
        return formData_1;
    }
    else {
        return (0,_encode_query_string__WEBPACK_IMPORTED_MODULE_1__.encodeQueryString)(params);
    }
}
//# sourceMappingURL=encode-form-data.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js":
/*!**************************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/encode-query-string.js ***!
  \**************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "encodeParam": () => (/* binding */ encodeParam),
/* harmony export */   "encodeQueryString": () => (/* binding */ encodeQueryString)
/* harmony export */ });
/* harmony import */ var _process_params__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./process-params */ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js");
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */

/**
 * Encodes keys and parameters for use in a URL's query string.
 *
 * @param key Parameter's key
 * @param value Parameter's value
 * @returns Query string with key and value pairs separated by "&"
 */
function encodeParam(key, value) {
    // For array of arrays, repeat key=value for each element of containing array
    if (Array.isArray(value) && value[0] && Array.isArray(value[0])) {
        return value.map(function (arrayElem) { return encodeParam(key, arrayElem); }).join("&");
    }
    return encodeURIComponent(key) + "=" + encodeURIComponent(value);
}
/**
 * Encodes the passed object as a query string.
 *
 * @param params An object to be encoded.
 * @returns An encoded query string.
 */
function encodeQueryString(params) {
    var newParams = (0,_process_params__WEBPACK_IMPORTED_MODULE_0__.processParams)(params);
    return Object.keys(newParams)
        .map(function (key) {
        return encodeParam(key, newParams[key]);
    })
        .join("&");
}
//# sourceMappingURL=encode-query-string.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js":
/*!*********************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/process-params.js ***!
  \*********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "processParams": () => (/* binding */ processParams),
/* harmony export */   "requiresFormData": () => (/* binding */ requiresFormData)
/* harmony export */ });
/* Copyright (c) 2017 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
/**
 * Checks parameters to see if we should use FormData to send the request
 * @param params The object whose keys will be encoded.
 * @return A boolean indicating if FormData will be required.
 */
function requiresFormData(params) {
    return Object.keys(params).some(function (key) {
        var value = params[key];
        if (!value) {
            return false;
        }
        if (value && value.toParam) {
            value = value.toParam();
        }
        var type = value.constructor.name;
        switch (type) {
            case "Array":
                return false;
            case "Object":
                return false;
            case "Date":
                return false;
            case "Function":
                return false;
            case "Boolean":
                return false;
            case "String":
                return false;
            case "Number":
                return false;
            default:
                return true;
        }
    });
}
/**
 * Converts parameters to the proper representation to send to the ArcGIS REST API.
 * @param params The object whose keys will be encoded.
 * @return A new object with properly encoded values.
 */
function processParams(params) {
    var newParams = {};
    Object.keys(params).forEach(function (key) {
        var _a, _b;
        var param = params[key];
        if (param && param.toParam) {
            param = param.toParam();
        }
        if (!param &&
            param !== 0 &&
            typeof param !== "boolean" &&
            typeof param !== "string") {
            return;
        }
        var type = param.constructor.name;
        var value;
        // properly encodes objects, arrays and dates for arcgis.com and other services.
        // ported from https://github.com/Esri/esri-leaflet/blob/master/src/Request.js#L22-L30
        // also see https://github.com/Esri/arcgis-rest-js/issues/18:
        // null, undefined, function are excluded. If you want to send an empty key you need to send an empty string "".
        switch (type) {
            case "Array":
                // Based on the first element of the array, classify array as an array of arrays, an array of objects
                // to be stringified, or an array of non-objects to be comma-separated
                // eslint-disable-next-line no-case-declarations
                var firstElementType = (_b = (_a = param[0]) === null || _a === void 0 ? void 0 : _a.constructor) === null || _b === void 0 ? void 0 : _b.name;
                value =
                    firstElementType === "Array" ? param : // pass thru array of arrays
                        firstElementType === "Object" ? JSON.stringify(param) : // stringify array of objects
                            param.join(","); // join other types of array elements
                break;
            case "Object":
                value = JSON.stringify(param);
                break;
            case "Date":
                value = param.valueOf();
                break;
            case "Function":
                value = null;
                break;
            case "Boolean":
                value = param + "";
                break;
            default:
                value = param;
                break;
        }
        if (value || value === 0 || typeof value === "string" || Array.isArray(value)) {
            newParams[key] = value;
        }
    });
    return newParams;
}
//# sourceMappingURL=process-params.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/dist/esm/utils/warn.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/dist/esm/utils/warn.js ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "warn": () => (/* binding */ warn)
/* harmony export */ });
/* Copyright (c) 2017-2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0 */
/**
 * Method used internally to surface messages to developers.
 */
function warn(message) {
    if (console && console.warn) {
        console.warn.apply(console, [message]);
    }
}
//# sourceMappingURL=warn.js.map

/***/ }),

/***/ "./node_modules/@esri/arcgis-rest-request/node_modules/tslib/tslib.es6.js":
/*!********************************************************************************!*\
  !*** ./node_modules/@esri/arcgis-rest-request/node_modules/tslib/tslib.es6.js ***!
  \********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "__assign": () => (/* binding */ __assign),
/* harmony export */   "__asyncDelegator": () => (/* binding */ __asyncDelegator),
/* harmony export */   "__asyncGenerator": () => (/* binding */ __asyncGenerator),
/* harmony export */   "__asyncValues": () => (/* binding */ __asyncValues),
/* harmony export */   "__await": () => (/* binding */ __await),
/* harmony export */   "__awaiter": () => (/* binding */ __awaiter),
/* harmony export */   "__classPrivateFieldGet": () => (/* binding */ __classPrivateFieldGet),
/* harmony export */   "__classPrivateFieldSet": () => (/* binding */ __classPrivateFieldSet),
/* harmony export */   "__createBinding": () => (/* binding */ __createBinding),
/* harmony export */   "__decorate": () => (/* binding */ __decorate),
/* harmony export */   "__exportStar": () => (/* binding */ __exportStar),
/* harmony export */   "__extends": () => (/* binding */ __extends),
/* harmony export */   "__generator": () => (/* binding */ __generator),
/* harmony export */   "__importDefault": () => (/* binding */ __importDefault),
/* harmony export */   "__importStar": () => (/* binding */ __importStar),
/* harmony export */   "__makeTemplateObject": () => (/* binding */ __makeTemplateObject),
/* harmony export */   "__metadata": () => (/* binding */ __metadata),
/* harmony export */   "__param": () => (/* binding */ __param),
/* harmony export */   "__read": () => (/* binding */ __read),
/* harmony export */   "__rest": () => (/* binding */ __rest),
/* harmony export */   "__spread": () => (/* binding */ __spread),
/* harmony export */   "__spreadArrays": () => (/* binding */ __spreadArrays),
/* harmony export */   "__values": () => (/* binding */ __values)
/* harmony export */ });
/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    }
    return __assign.apply(this, arguments);
}

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

function __spreadArrays() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};

function __await(v) {
    return this instanceof __await ? (this.v = v, this) : new __await(v);
}

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
};

function __importStar(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}


/***/ }),

/***/ "./jimu-icons/svg/outlined/application/folder.svg":
/*!********************************************************!*\
  !*** ./jimu-icons/svg/outlined/application/folder.svg ***!
  \********************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M1.333 0h4c.737 0 1.334.597 1.334 1.333v1.334h8C15.403 2.667 16 3.264 16 4v10.667c0 .736-.597 1.333-1.333 1.333H1.333A1.333 1.333 0 0 1 0 14.667V1.333C0 .597.597 0 1.333 0Zm0 7.333v7.334h13.334V7.333H1.334Zm0-1.333h13.334V4H5.334V1.335h-4V6Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/application/setting.svg":
/*!*********************************************************!*\
  !*** ./jimu-icons/svg/outlined/application/setting.svg ***!
  \*********************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M9.438.994c.213 0 .397.146.44.35.151.722.257 1.34.316 1.852.374.16.725.362 1.048.599l1.728-.676a.455.455 0 0 1 .556.188l1.42 2.394a.43.43 0 0 1-.091.547 21.98 21.98 0 0 1-1.49 1.194 5.17 5.17 0 0 1-.007 1.183l1.464 1.119a.43.43 0 0 1 .111.563l-1.42 2.394a.454.454 0 0 1-.53.197 22.445 22.445 0 0 1-1.807-.66c-.325.233-.679.43-1.055.586l-.263 1.794a.446.446 0 0 1-.445.376H6.574a.446.446 0 0 1-.44-.35 21.019 21.019 0 0 1-.317-1.853 5.34 5.34 0 0 1-1.047-.598l-1.728.675a.455.455 0 0 1-.556-.187l-1.42-2.395a.43.43 0 0 1 .091-.546c.567-.49 1.063-.888 1.49-1.194a5.167 5.167 0 0 1 .008-1.183L1.19 6.243a.43.43 0 0 1-.112-.562l1.42-2.395a.455.455 0 0 1 .531-.196c.719.233 1.321.453 1.807.66.324-.233.679-.43 1.056-.587l.262-1.794A.446.446 0 0 1 6.6.994h2.839Zm-.365 1H6.985l-.28 1.866-.467.19c-.235.095-.46.21-.672.34l-.207.136-.42.293-.476-.197c-.328-.137-.718-.281-1.169-.433l-.221-.074-1.045 1.719L3.59 6.999l-.06.479a4.127 4.127 0 0 0-.021.816l.014.144.058.492-.419.294c-.288.203-.615.451-.979.746l-.177.145 1.043 1.72 1.845-.703.406.29c.204.146.42.274.645.384l.228.103.474.199.059.49c.04.338.103.731.19 1.177l.043.219h2.088l.282-1.867.466-.19c.236-.095.46-.21.672-.34l.207-.136.419-.293.476.198c.33.136.72.28 1.17.433l.22.072 1.044-1.718-1.56-1.165.06-.479a4.131 4.131 0 0 0 .02-.815l-.013-.144-.06-.492.42-.295a18.1 18.1 0 0 0 .98-.746l.176-.146-1.043-1.72-1.844.705-.406-.29a4.496 4.496 0 0 0-.646-.385l-.228-.103-.474-.199-.058-.49c-.032-.27-.08-.576-.14-.916l-.094-.48Zm-1.067 3a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm0 1a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/plus-circle.svg":
/*!********************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/plus-circle.svg ***!
  \********************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M14 8A6 6 0 1 1 2 8a6 6 0 0 1 12 0Zm1 0A7 7 0 1 1 1 8a7 7 0 0 1 14 0ZM7.5 4.5a.5.5 0 0 1 1 0v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/trash.svg":
/*!**************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/trash.svg ***!
  \**************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M6 6.5a.5.5 0 0 1 1 0v6a.5.5 0 0 1-1 0v-6ZM9.5 6a.5.5 0 0 0-.5.5v6a.5.5 0 0 0 1 0v-6a.5.5 0 0 0-.5-.5Z\" fill=\"#000\"></path><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M11 0H5a1 1 0 0 0-1 1v2H.5a.5.5 0 0 0 0 1h1.6l.81 11.1a1 1 0 0 0 .995.9h8.19a1 1 0 0 0 .995-.9L13.9 4h1.6a.5.5 0 0 0 0-1H12V1a1 1 0 0 0-1-1Zm0 3V1H5v2h6Zm1.895 1h-9.79l.8 11h8.19l.8-11Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/suggested/success.svg":
/*!*******************************************************!*\
  !*** ./jimu-icons/svg/outlined/suggested/success.svg ***!
  \*******************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"m7 11.5 5.354-5.354-.708-.707L7 10.086 4.354 7.439l-.708.707L7 11.5Z\" fill=\"#000\"></path><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M0 8a8 8 0 1 0 16 0A8 8 0 0 0 0 8Zm15 0A7 7 0 1 1 1 8a7 7 0 0 1 14 0Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/outlined/application/folder.tsx":
/*!****************************************************!*\
  !*** ./jimu-icons/outlined/application/folder.tsx ***!
  \****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "FolderOutlined": () => (/* binding */ FolderOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_application_folder_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/application/folder.svg */ "./jimu-icons/svg/outlined/application/folder.svg");
/* harmony import */ var _svg_outlined_application_folder_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_application_folder_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const FolderOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_application_folder_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/application/setting.tsx":
/*!*****************************************************!*\
  !*** ./jimu-icons/outlined/application/setting.tsx ***!
  \*****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SettingOutlined": () => (/* binding */ SettingOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_application_setting_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/application/setting.svg */ "./jimu-icons/svg/outlined/application/setting.svg");
/* harmony import */ var _svg_outlined_application_setting_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_application_setting_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const SettingOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_application_setting_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/editor/plus-circle.tsx":
/*!****************************************************!*\
  !*** ./jimu-icons/outlined/editor/plus-circle.tsx ***!
  \****************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "PlusCircleOutlined": () => (/* binding */ PlusCircleOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_editor_plus_circle_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/editor/plus-circle.svg */ "./jimu-icons/svg/outlined/editor/plus-circle.svg");
/* harmony import */ var _svg_outlined_editor_plus_circle_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_editor_plus_circle_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const PlusCircleOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_editor_plus_circle_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/editor/trash.tsx":
/*!**********************************************!*\
  !*** ./jimu-icons/outlined/editor/trash.tsx ***!
  \**********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "TrashOutlined": () => (/* binding */ TrashOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_editor_trash_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/editor/trash.svg */ "./jimu-icons/svg/outlined/editor/trash.svg");
/* harmony import */ var _svg_outlined_editor_trash_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_editor_trash_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const TrashOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_editor_trash_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/suggested/success.tsx":
/*!***************************************************!*\
  !*** ./jimu-icons/outlined/suggested/success.tsx ***!
  \***************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SuccessOutlined": () => (/* binding */ SuccessOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_suggested_success_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/suggested/success.svg */ "./jimu-icons/svg/outlined/suggested/success.svg");
/* harmony import */ var _svg_outlined_suggested_success_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_suggested_success_svg__WEBPACK_IMPORTED_MODULE_1__);
var __rest = (undefined && undefined.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};


const SuccessOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_suggested_success_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/api.ts":
/*!************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/api.ts ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "archiveTemplate": () => (/* binding */ archiveTemplate),
/* harmony export */   "checkParam": () => (/* binding */ checkParam),
/* harmony export */   "completeAssessment": () => (/* binding */ completeAssessment),
/* harmony export */   "createIncident": () => (/* binding */ createIncident),
/* harmony export */   "createNewIndicator": () => (/* binding */ createNewIndicator),
/* harmony export */   "createNewTemplate": () => (/* binding */ createNewTemplate),
/* harmony export */   "deleteHazard": () => (/* binding */ deleteHazard),
/* harmony export */   "deleteIncident": () => (/* binding */ deleteIncident),
/* harmony export */   "deleteIndicator": () => (/* binding */ deleteIndicator),
/* harmony export */   "deleteOrganization": () => (/* binding */ deleteOrganization),
/* harmony export */   "dispatchAction": () => (/* binding */ dispatchAction),
/* harmony export */   "getAssessmentNames": () => (/* binding */ getAssessmentNames),
/* harmony export */   "getHazards": () => (/* binding */ getHazards),
/* harmony export */   "getIncidents": () => (/* binding */ getIncidents),
/* harmony export */   "getOrganizations": () => (/* binding */ getOrganizations),
/* harmony export */   "getTemplates": () => (/* binding */ getTemplates),
/* harmony export */   "initializeAuth": () => (/* binding */ initializeAuth),
/* harmony export */   "loadAllAssessments": () => (/* binding */ loadAllAssessments),
/* harmony export */   "loadScaleFactors": () => (/* binding */ loadScaleFactors),
/* harmony export */   "passDataIntegrity": () => (/* binding */ passDataIntegrity),
/* harmony export */   "saveHazard": () => (/* binding */ saveHazard),
/* harmony export */   "saveNewAssessment": () => (/* binding */ saveNewAssessment),
/* harmony export */   "saveOrganization": () => (/* binding */ saveOrganization),
/* harmony export */   "selectTemplate": () => (/* binding */ selectTemplate),
/* harmony export */   "templCleanUp": () => (/* binding */ templCleanUp),
/* harmony export */   "updateIndicator": () => (/* binding */ updateIndicator),
/* harmony export */   "updateIndicatorName": () => (/* binding */ updateIndicatorName),
/* harmony export */   "updateLifelineStatus": () => (/* binding */ updateLifelineStatus),
/* harmony export */   "updateTemplateOrganizationAndHazard": () => (/* binding */ updateTemplateOrganizationAndHazard),
/* harmony export */   "useFetchData": () => (/* binding */ useFetchData)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./constants */ "./your-extensions/widgets/clss-application/src/extensions/constants.ts");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _esri_api__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./esri-api */ "./your-extensions/widgets/clss-application/src/extensions/esri-api.ts");
/* harmony import */ var _logger__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./logger */ "./your-extensions/widgets/clss-application/src/extensions/logger.ts");
/* harmony import */ var _auth__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./auth */ "./your-extensions/widgets/clss-application/src/extensions/auth.ts");
/* harmony import */ var _clss_store__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _utils__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./utils */ "./your-extensions/widgets/clss-application/src/extensions/utils.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};








//========================PUBLIC=============================================================
const initializeAuth = (appId) => __awaiter(void 0, void 0, void 0, function* () {
    console.log('initializeAuth called');
    let cred = yield (0,_auth__WEBPACK_IMPORTED_MODULE_5__.checkCurrentStatus)(appId, _constants__WEBPACK_IMPORTED_MODULE_1__.PORTAL_URL);
    if (!cred) {
        cred = yield (0,_auth__WEBPACK_IMPORTED_MODULE_5__.signIn)(appId, _constants__WEBPACK_IMPORTED_MODULE_1__.PORTAL_URL);
    }
    const credential = {
        expires: cred.expires,
        server: cred.server,
        ssl: cred.ssl,
        token: cred.token,
        userId: cred.userId
    };
    dispatchAction(_clss_store__WEBPACK_IMPORTED_MODULE_6__.CLSSActionKeys.AUTHENTICATE_ACTION, credential);
});
function updateLifelineStatus(lifelineStatus, config, assessmentObjectId, user) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('called updateLifelineStatus');
        checkParam(config.lifelineStatus, 'Lifeline Status URL not provided');
        const attributes = {
            OBJECTID: lifelineStatus.objectId,
            Score: lifelineStatus.score,
            Color: lifelineStatus.color,
            IsOverriden: lifelineStatus.isOverriden,
            OverridenScore: lifelineStatus.overrideScore,
            OverridenColor: lifelineStatus.overridenColor,
            OverridenBy: lifelineStatus.overridenBy,
            OverrideComment: lifelineStatus.overrideComment
        };
        let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.lifelineStatus, attributes, config);
        if (response.updateResults && response.updateResults.every(u => u.success)) {
            const iaFeatures = lifelineStatus.indicatorAssessments.map(i => {
                return {
                    attributes: {
                        OBJECTID: i.objectId,
                        status: i.status,
                        Comments: i.comments && i.comments.length > 0 ? JSON.stringify(i.comments) : ''
                    }
                };
            });
            response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeatures)(config.indicatorAssessments, iaFeatures, config);
            if (response.updateResults && response.updateResults.every(u => u.success)) {
                const assessFeature = {
                    OBJECTID: assessmentObjectId,
                    EditedDate: new Date().getTime(),
                    Editor: user
                };
                response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.assessments, assessFeature, config);
                if (response.updateResults && response.updateResults.every(u => u.success)) {
                    return {
                        data: true
                    };
                }
            }
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)('Updating Lifeline score failed', _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'updateLifelineStatus');
        return {
            errors: 'Updating Lifeline score failed'
        };
    });
}
function completeAssessment(assessment, config, userName) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.assessments, 'No Assessment Url provided');
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.assessments, {
            OBJECTID: assessment.objectId,
            Editor: userName,
            EditedDate: new Date().getTime(),
            IsCompleted: 1
        }, config);
        console.log(response);
        return {
            data: response.updateResults && response.updateResults.every(u => u.success)
        };
    });
}
const passDataIntegrity = (serviceUrl, fields, config) => __awaiter(void 0, void 0, void 0, function* () {
    checkParam(serviceUrl, 'Service URL not provided');
    // serviceUrl = `${serviceUrl}?f=json&token=${token}`;
    // const response = await fetch(serviceUrl, {
    //   method: "GET",
    //   headers: {
    //     'content-type': 'application/x-www-form-urlencoded'
    //   }
    // }
    // );
    // const json = await response.json();
    // const features = await queryTableFeatures(serviceUrl, '1=1', config);
    // const dataFields = features[0]. as IField[];
    // debugger;
    // if (fields.length > dataFields.length) {
    //   throw new Error('Number of fields do not match for ' + serviceUrl);
    // }
    // const allFieldsGood = fields.every(f => {
    //   const found = dataFields.find(f1 => f1.name === f.name && f1.type.toString() === f.type.toString() && f1.domain == f.domain);
    //   return found;
    // });
    // if (!allFieldsGood) {
    //   throw new Error('Invalid fields in the feature service ' + serviceUrl)
    // }
    return true;
});
function getIndicatorFeatures(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Indicators called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicators, query, config);
    });
}
function getWeightsFeatures(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Weights called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.weights, query, config);
    });
}
function getLifelineFeatures(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Lifeline called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.lifelines, query, config);
    });
}
function getComponentFeatures(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Components called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.components, query, config);
    });
}
function getTemplateFeatureSet(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Template called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatureSet)(config.templates, query, config);
    });
}
function getTemplates(config, templateId, queryString) {
    return __awaiter(this, void 0, void 0, function* () {
        const templateUrl = config.templates;
        const lifelineUrl = config.lifelines;
        const componentUrl = config.components;
        try {
            checkParam(templateUrl, _constants__WEBPACK_IMPORTED_MODULE_1__.TEMPLATE_URL_ERROR);
            checkParam(lifelineUrl, _constants__WEBPACK_IMPORTED_MODULE_1__.LIFELINE_URL_ERROR);
            checkParam(componentUrl, _constants__WEBPACK_IMPORTED_MODULE_1__.COMPONENT_URL_ERROR);
            const tempQuery = templateId ? `GlobalID='${templateId}` : (queryString ? queryString : '1=1');
            const response = yield Promise.all([
                getTemplateFeatureSet(tempQuery, config),
                getLifelineFeatures('1=1', config),
                getComponentFeatures('1=1', config)
            ]);
            const templateFeatureSet = response[0];
            const lifelineFeatures = response[1];
            const componentFeatures = response[2];
            const indicatorFeatures = yield getIndicatorFeatures('1=1', config);
            const weightFeatures = yield getWeightsFeatures('1=1', config);
            const templates = yield Promise.all(templateFeatureSet.features.map((templateFeature) => __awaiter(this, void 0, void 0, function* () {
                const templateIndicatorFeatures = indicatorFeatures.filter(i => i.attributes.TemplateID == templateFeature.attributes.GlobalID);
                return yield getTemplate(templateFeature, lifelineFeatures, componentFeatures, templateIndicatorFeatures, weightFeatures, templateFeatureSet.fields.find(f => f.name === 'Status').domain.codedValues);
            })));
            if (templates.filter(t => t.isSelected).length > 1 || templates.filter(t => t.isSelected).length == 0) {
                return {
                    data: templates.map(t => {
                        return Object.assign(Object.assign({}, t), { isSelected: t.name === _constants__WEBPACK_IMPORTED_MODULE_1__.BASELINE_TEMPLATE_NAME });
                    })
                };
            }
            if (templates.length === 1) {
                return {
                    data: templates.map(t => {
                        return Object.assign(Object.assign({}, t), { isSelected: true });
                    })
                };
            }
            return {
                data: templates
            };
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'getTemplates');
            return {
                errors: 'Templates request failed.'
            };
        }
    });
}
function useFetchData(url, callbackAdapter) {
    const [data, setData] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(null);
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(true);
    const [error, setError] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState('');
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        const controller = new AbortController();
        requestData(url, controller)
            .then((data) => {
            if (callbackAdapter) {
                setData(callbackAdapter(data));
            }
            else {
                setData(data);
            }
            setLoading(false);
        })
            .catch((err) => {
            console.log(err);
            setError(err);
        });
        return () => controller.abort();
    }, [url]);
    return [data, setData, loading, error];
}
function dispatchAction(type, val) {
    (0,jimu_core__WEBPACK_IMPORTED_MODULE_2__.getAppStore)().dispatch({
        type,
        val
    });
}
function getIncidents(config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get incidents called.');
        checkParam(config.incidents, _constants__WEBPACK_IMPORTED_MODULE_1__.INCIDENT_URL_ERROR);
        const features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.incidents, '1=1', config);
        const query = `GlobalID IN (${features.map(f => f.attributes.HazardID).map(id => `'${id}'`).join(',')})`;
        const hazardFeatureset = yield getHazardFeatures(config, query, 'getIncidents');
        return features.map((f) => {
            const hf = hazardFeatureset.features.find(h => h.attributes.GlobalID == f.attributes.HazardID);
            return {
                objectId: f.attributes.OBJECTID,
                id: f.attributes.GlobalID,
                name: f.attributes.Name,
                hazard: hf ? {
                    objectId: hf.attributes.OBJECTID,
                    id: hf.attributes.GlobalID,
                    name: hf.attributes.Name,
                    title: hf.attributes.DisplayTitle || hf.attributes.DisplayName || hf.attributes.Name,
                    type: hf.attributes.Type,
                    description: hf.attributes.Description,
                    domains: hazardFeatureset.fields.find(f => f.name === 'Type').domain.codedValues
                } : null,
                description: f.attributes.Description,
                startDate: Number(f.attributes.StartDate),
                endDate: Number(f.attributes.EndDate)
            };
        });
        return [];
    });
}
function getHazardFeatures(config, query, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Hazards called by ' + caller);
        checkParam(config.hazards, _constants__WEBPACK_IMPORTED_MODULE_1__.HAZARD_URL_ERROR);
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatureSet)(config.hazards, query, config);
    });
}
function getHazards(config, queryString, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        const featureSet = yield getHazardFeatures(config, queryString, caller);
        if (!featureSet || featureSet.features.length == 0) {
            return [];
        }
        return featureSet.features.map((f) => {
            return {
                objectId: f.attributes.OBJECTID,
                id: f.attributes.GlobalID,
                name: f.attributes.Name,
                title: f.attributes.DisplayTitle || f.attributes.DisplayName || f.attributes.Name,
                type: f.attributes.Type,
                description: f.attributes.Description,
                domains: featureSet.fields.find(f => f.name === 'Type').domain.codedValues
            };
        });
        return [];
    });
}
function getOrganizations(config, queryString) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Organizations called');
        checkParam(config.organizations, _constants__WEBPACK_IMPORTED_MODULE_1__.ORGANIZATION_URL_ERROR);
        const featureSet = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatureSet)(config.organizations, queryString, config);
        if (featureSet && featureSet.features && featureSet.features.length > 0) {
            return featureSet.features.map((f) => {
                return {
                    objectId: f.attributes.OBJECTID,
                    id: f.attributes.GlobalID,
                    name: f.attributes.Name,
                    title: f.attributes.Name,
                    type: f.attributes.Type,
                    parentId: f.attributes.ParentID,
                    description: f.attributes.Description,
                    domains: featureSet.fields.find(f => f.name === 'Type').domain.codedValues
                };
            });
        }
        return [];
    });
}
function createNewTemplate(config, template, userName, organization, hazard) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.templates, _constants__WEBPACK_IMPORTED_MODULE_1__.TEMPLATE_URL_ERROR);
        checkParam(template, 'Template data not provided');
        const createDate = new Date().getTime();
        const templateName = template.name[0].toLocaleUpperCase() + template.name.substring(1);
        let feature = {
            attributes: {
                OrganizationID: organization ? organization.id : null,
                OrganizationName: organization ? organization.name : null,
                OrganizationType: organization ? (organization.type.code ? organization.type.code : organization.type) : null,
                HazardID: hazard ? hazard.id : null,
                HazardName: hazard ? hazard.name : null,
                HazardType: hazard ? (hazard.type.code ? hazard.type.code : hazard.type) : null,
                Name: templateName,
                Creator: userName,
                CreatedDate: createDate,
                Status: 1,
                IsSelected: 0,
                Editor: userName,
                EditedDate: createDate
            }
        };
        let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.templates, [feature], config);
        if (response.addResults && response.addResults.every(r => r.success)) {
            const templateId = response.addResults[0].globalId;
            //create new indicators   
            const indicators = getTemplateIndicators(template);
            const indicatorFeatures = indicators.map(indicator => {
                return {
                    attributes: {
                        TemplateID: templateId,
                        ComponentID: indicator.componentId,
                        ComponentName: indicator.componentName,
                        Name: indicator.name,
                        TemplateName: templateName,
                        LifelineName: indicator.lifelineName
                    }
                };
            });
            response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.indicators, indicatorFeatures, config);
            if (response.addResults && response.addResults.every(r => r.success)) {
                const globalIds = `(${response.addResults.map(r => `'${r.globalId}'`).join(',')})`;
                const query = 'GlobalID IN ' + globalIds;
                const addedIndicatorFeatures = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicators, query, config);
                let weightsFeatures = [];
                for (let feature of addedIndicatorFeatures) {
                    const incomingIndicator = indicators.find(i => i.name === feature.attributes.Name);
                    if (incomingIndicator) {
                        const weightFeatures = incomingIndicator.weights.map(w => {
                            return {
                                attributes: {
                                    IndicatorID: feature.attributes.GlobalID,
                                    Name: w.name,
                                    Weight: w.weight,
                                    ScaleFactor: 0,
                                    AdjustedWeight: 0,
                                    MaxAdjustedWeight: 0
                                }
                            };
                        });
                        weightsFeatures = weightsFeatures.concat(weightFeatures);
                    }
                }
                response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.weights, weightsFeatures, config);
                if (response.addResults && response.addResults.every(r => r.success)) {
                    return {
                        data: true
                    };
                }
            }
            // const promises = indicators.map(indicator => createNewIndicator(indicator, config, templateId, templateName));
            // const promiseResponse = await Promise.all(promises);
            // if(promiseResponse.every(p => p.data)){
            //   return {
            //     data: true
            //   }
            // }
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'createNewTemplate');
        return {
            errors: 'Error occurred while creating the new template'
        };
    });
}
function updateTemplateOrganizationAndHazard(config, template, userName) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(template, 'Template not provided');
        checkParam(config.templates, _constants__WEBPACK_IMPORTED_MODULE_1__.TEMPLATE_URL_ERROR);
        const attributes = {
            OBJECTID: template.objectId,
            OrganizationID: template.organizationId,
            HazardID: template.hazardId,
            OrganizationName: template.organizationName,
            OrganizationType: template.organizationType,
            HazardName: template.hazardName,
            HazardType: template.hazardType,
            Name: template.name,
            Editor: userName,
            EditedDate: new Date().getTime(),
            Status: template.status.code,
            IsSelected: template.isSelected ? 1 : 0
        };
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.templates, attributes, config);
        if (response.updateResults && response.updateResults.every(u => u.success)) {
            return {
                data: true
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'updateTemplateOrganizationAndHazard');
        return {
            errors: 'Error occurred while updating template.'
        };
    });
}
function selectTemplate(objectId, objectIds, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('select Template called');
        try {
            checkParam(config.templates, _constants__WEBPACK_IMPORTED_MODULE_1__.TEMPLATE_URL_ERROR);
            //let features = await getTemplateFeatures('1=1', config)// await queryTableFeatures(config.templates, '1=1', config)
            const features = objectIds.map(oid => {
                return {
                    attributes: {
                        OBJECTID: oid,
                        IsSelected: oid === objectId ? 1 : 0
                    }
                };
            });
            const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeatures)(config.templates, features, config);
            if (response.updateResults && response.updateResults.every(u => u.success)) {
                return {
                    data: response.updateResults[0].globalId
                };
            }
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'selectTemplate');
            return {
                errors: e
            };
        }
    });
}
function loadScaleFactors(config) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.constants, 'Rating Scales url not provided');
        try {
            const features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.constants, '1=1', config);
            if (features && features.length > 0) {
                const scales = features.map(f => {
                    return {
                        name: f.attributes.Name,
                        value: f.attributes.Value
                    };
                });
                return {
                    data: scales
                };
            }
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)('Error occurred while requesting rating scales', _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'loadRatingScales');
            return {
                errors: 'Error occurred while requesting rating scales'
            };
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'loadRatingScales');
        }
    });
}
function createNewIndicator(indicator, config, templateId, templateName) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.indicators, _constants__WEBPACK_IMPORTED_MODULE_1__.INDICATOR_URL_ERROR);
        const indicatorFeature = {
            attributes: {
                TemplateID: templateId,
                ComponentID: indicator.componentId,
                ComponentName: indicator.componentName,
                Name: indicator.name,
                TemplateName: templateName,
                LifelineName: indicator.lifelineName
            }
        };
        let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.indicators, [indicatorFeature], config);
        if (response.addResults && response.addResults.every(r => r.success)) {
            const weightFeatures = indicator.weights.map(w => {
                return {
                    attributes: {
                        IndicatorID: response.addResults[0].globalId,
                        Name: w.name,
                        Weight: w.weight,
                        ScaleFactor: 0,
                        AdjustedWeight: 0,
                        MaxAdjustedWeight: 0
                    }
                };
            });
            response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.weights, weightFeatures, config);
            if (response.addResults && response.addResults.every(r => r.success)) {
                return {
                    data: true
                };
            }
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'createNewIndicator');
        return {
            errors: 'Error occurred while saving the indicator.'
        };
    });
}
function updateIndicatorName(config, indicatorTemp) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.indicators, _constants__WEBPACK_IMPORTED_MODULE_1__.INDICATOR_URL_ERROR);
        const attributes = {
            OBJECTID: indicatorTemp.objectId,
            Name: indicatorTemp.name,
            DisplayTitle: indicatorTemp.name,
            IsActive: 1
        };
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.indicators, attributes, config);
        if (response.updateResults && response.updateResults.every(u => u.success)) {
            return {
                data: true
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'updateIndicatorName');
        return {
            errors: 'Error occurred while updating indicator'
        };
    });
}
function updateIndicator(indicator, config) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.indicators, _constants__WEBPACK_IMPORTED_MODULE_1__.INCIDENT_URL_ERROR);
        let features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicators, `Name='${indicator.name}' AND TemplateName='${indicator.templateName}'`, config);
        if (features && features.length > 1) {
            return {
                errors: 'An indicator with the same name already exists'
            };
        }
        const response = yield updateIndicatorName(config, indicator);
        if (response.errors) {
            return {
                errors: response.errors
            };
        }
        features = indicator.weights.map(w => {
            return {
                attributes: {
                    OBJECTID: w.objectId,
                    Weight: Number(w.weight),
                    AdjustedWeight: Number(w.weight) * w.scaleFactor
                }
            };
        });
        const updateResponse = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeatures)(config.weights, features, config);
        if (updateResponse.updateResults && updateResponse.updateResults.every(u => u.success)) {
            return {
                data: true
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(updateResponse), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'updateIndicator');
        return {
            errors: 'Error occurred while updating indicator.'
        };
    });
}
function deleteIndicator(indicatorTemplate, config) {
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.indicators, _constants__WEBPACK_IMPORTED_MODULE_1__.INDICATOR_URL_ERROR);
        checkParam(config.weights, 'Weights URL not provided');
        let resp = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.indicators, [indicatorTemplate.objectId], config);
        if (resp.deleteResults && resp.deleteResults.every(d => d.success)) {
            const weightsObjectIds = indicatorTemplate.weights.map(w => w.objectId);
            resp = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.weights, weightsObjectIds, config);
            if (resp.deleteResults && resp.deleteResults.every(d => d.success)) {
                return {
                    data: true
                };
            }
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(resp), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'deleteIndicator');
        return {
            errors: 'Error occurred while deleting the indicator'
        };
    });
}
function archiveTemplate(objectId, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.updateTableFeature)(config.templates, {
            OBJECTID: objectId,
            IsSelected: 0,
            IsActive: 0
        }, config);
        console.log(response);
        if (response.updateResults && response.updateResults.every(e => e.success)) {
            return {
                data: true
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(JSON.stringify(response), _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'archiveTemplate');
        return {
            errors: 'The template cannot be archived.'
        };
    });
}
function saveOrganization(config, organization) {
    var _a;
    return __awaiter(this, void 0, void 0, function* () {
        checkParam(config.organizations, _constants__WEBPACK_IMPORTED_MODULE_1__.ORGANIZATION_URL_ERROR);
        checkParam(organization, 'Organization object not provided');
        const feature = {
            attributes: {
                Name: organization.name,
                Type: (_a = organization.type) === null || _a === void 0 ? void 0 : _a.code,
                DisplayTitle: organization.name,
                ParentID: organization === null || organization === void 0 ? void 0 : organization.parentId
            }
        };
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.organizations, [feature], config);
        if (response.addResults && response.addResults.every(r => r.success)) {
            return {
                data: Object.assign({}, organization) // (await getOrganizations(config, `GlobalID='${response.addResults[0].globalId}'`))[0]
            };
        }
        return {
            errors: JSON.stringify(response)
        };
    });
}
function saveHazard(config, hazard) {
    return __awaiter(this, void 0, void 0, function* () {
        const feature = {
            attributes: {
                Name: hazard.name,
                DisplayTitle: hazard.name,
                Type: hazard.type.code,
                Description: hazard.description
            }
        };
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.hazards, [feature], config);
        if (response.addResults && response.addResults.every(r => r.success)) {
            return {
                data: Object.assign(Object.assign({}, hazard), { objectId: response.addResults[0].objectId, id: response.addResults[0].globalId })
            };
        }
        (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(`Error occurred while saving hazard. Restarting the application may fix this issue.`, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'saveHazard');
        return {
            errors: 'Error occurred while saving hazard. Restarting the application may fix this issue.'
        };
    });
}
function deleteIncident(incident, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.incidents, [incident.objectId], config);
        if (response.deleteResults && response.deleteResults.every(d => d.success)) {
            return {
                data: true
            };
        }
        return {
            errors: JSON.stringify(response)
        };
    });
}
function deleteHazard(hazard, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.hazards, [hazard.objectId], config);
        if (response.deleteResults && response.deleteResults.every(d => d.success)) {
            return {
                data: true
            };
        }
        return {
            errors: JSON.stringify(response)
        };
    });
}
function deleteOrganization(organization, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.organizations, [organization.objectId], config);
        if (response.deleteResults && response.deleteResults.every(d => d.success)) {
            return {
                data: true
            };
        }
        return {
            errors: JSON.stringify(response)
        };
    });
}
function checkParam(param, error) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!param || param == null || param === '' || param == undefined) {
            throw new Error(error);
        }
    });
}
function templCleanUp(indUrl, aligUrl, token) {
    return __awaiter(this, void 0, void 0, function* () {
    });
}
function saveNewAssessment(newAssessment, template, config, prevAssessment) {
    return __awaiter(this, void 0, void 0, function* () {
        const resp = yield saveAssessment(newAssessment, config);
        if (resp.errors) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)('Unable to create the assessment.', _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'saveNewAssessment');
            return {
                errors: 'Unable to create the assessment.'
            };
        }
        try {
            const indicators = getTemplateIndicators(template);
            if (!indicators || indicators.length === 0) {
                (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)('Template indicators not found', _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'saveNewAssessment');
                throw new Error('Template indicators not found.');
            }
            const lifelineStatusFeatures = template.lifelineTemplates.map(lt => {
                return {
                    attributes: {
                        AssessmentID: resp.data,
                        Score: null,
                        Color: null,
                        LifelineID: lt.id,
                        IsOverriden: 0,
                        OverridenScore: null,
                        OverridenBy: null,
                        OverrideComment: null,
                        LifelineName: lt.title,
                        TemplateName: template.name
                    }
                };
            });
            let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.lifelineStatus, lifelineStatusFeatures, config);
            if (response && response.addResults && response.addResults.every(r => r.success)) {
                const query = 'GlobalID IN (' + response.addResults.map(r => `'${r.globalId}'`).join(',') + ")";
                const lsFeatures = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.lifelineStatus, query, config);
                const indicatorAssessmentFeatures = indicators.map(i => {
                    var _a, _b, _c, _d, _e;
                    const lifelineStatusFeature = lsFeatures.find(ls => ls.attributes.LifelineName.split(/[' '&_,]+/).join('_') === i.lifelineName);
                    if (!lifelineStatusFeature) {
                        console.log(`${i.lifelineName} not found`);
                        throw new Error(`${i.lifelineName} not found`);
                    }
                    return {
                        attributes: {
                            LifelineStatusID: lifelineStatusFeature ? lifelineStatusFeature.attributes.GlobalID : '',
                            IndicatorID: i.id,
                            TemplateName: i.templateName,
                            LifelineName: i.lifelineName,
                            ComponentName: i.componentName,
                            IndicatorName: i.name,
                            Comments: "",
                            Rank: (_a = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.RANK)) === null || _a === void 0 ? void 0 : _a.weight,
                            LifeSafety: (_b = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.LIFE_SAFETY)) === null || _b === void 0 ? void 0 : _b.weight,
                            PropertyProtection: (_c = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.PROPERTY_PROTECTION)) === null || _c === void 0 ? void 0 : _c.weight,
                            IncidentStabilization: (_d = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.INCIDENT_STABILIZATION)) === null || _d === void 0 ? void 0 : _d.weight,
                            EnvironmentPreservation: (_e = i.weights.find(w => w.name === _constants__WEBPACK_IMPORTED_MODULE_1__.ENVIRONMENT_PRESERVATION)) === null || _e === void 0 ? void 0 : _e.weight,
                            Status: 4 //unknown
                        }
                    };
                });
                response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.indicatorAssessments, indicatorAssessmentFeatures, config);
                if (response && response.addResults && response.addResults.every(r => r.success)) {
                    return {
                        data: resp.data
                    };
                }
                else {
                    throw new Error('Failed to add indicator assessment features');
                }
            }
            else {
                throw new Error('Failed to add Lifeline Status Features');
            }
        }
        catch (e) {
            yield cleanUpAssessmentFailedData(resp.data, config);
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'saveNewAssessment');
            return {
                errors: 'Error occurred while creating Assessment.'
            };
        }
    });
}
function cleanUpAssessmentFailedData(assessmentGlobalId, config) {
    return __awaiter(this, void 0, void 0, function* () {
        let features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.assessments, `GlobalID='${assessmentGlobalId}'`, config);
        if (features && features.length > 0) {
            yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.assessments, features.map(f => f.attributes.OBJECTID), config);
        }
        features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.lifelineStatus, `AssessmentID='${assessmentGlobalId}'`, config);
        if (features && features.length > 0) {
            yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.lifelineStatus, features.map(f => f.attributes.OBJECTID), config);
            const query = `LifelineStatusID IN (${features.map(f => f.attributes.GlobalID).join(',')})`;
            console.log('delete queries', query);
            features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicatorAssessments, query, config);
            if (features && features.length > 0) {
                yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.deleteTableFeatures)(config.indicatorAssessments, features.map(f => f.attributes.OBJECTID), config);
            }
        }
    });
}
function getAssessmentNames(config, templateName) {
    return __awaiter(this, void 0, void 0, function* () {
        const features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.assessments, `Template='${templateName}'`, config);
        if (features && features.length === 0) {
            return {
                data: []
            };
        }
        if (features && features.length > 0) {
            const assess = features.map(f => {
                return {
                    name: f.attributes.Name,
                    date: (0,_utils__WEBPACK_IMPORTED_MODULE_7__.parseDate)(Number(f.attributes.CreatedDate))
                };
            });
            return {
                data: assess
            };
        }
        return {
            errors: 'Request for assessment names failed.'
        };
    });
}
function getAssessmentFeatures(config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Assessment Features called.');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.assessments, `1=1`, config);
    });
}
function loadAllAssessments(config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const assessmentFeatures = yield getAssessmentFeatures(config);
            if (!assessmentFeatures || assessmentFeatures.length == 0) {
                return {
                    data: []
                };
            }
            const lsFeatures = yield getLifelineStatusFeatures(config, `1=1`);
            const query = `LifelineStatusID IN (${lsFeatures.map(f => `'${f.attributes.GlobalID}'`).join(',')})`;
            const indicatorAssessments = yield getIndicatorAssessments(query, config);
            if (assessmentFeatures && assessmentFeatures.length > 0) {
                const assessments = assessmentFeatures.map((feature) => {
                    const assessmentLsFeatures = lsFeatures.filter(l => l.attributes.AssessmentID == feature.attributes.GlobalID);
                    return loadAssessment(feature, assessmentLsFeatures, indicatorAssessments);
                });
                return {
                    data: assessments
                };
            }
            if (assessmentFeatures && assessmentFeatures.length == 0) {
                return {
                    data: []
                };
            }
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'loadAllAssessments');
            return {
                errors: e
            };
        }
    });
}
function createIncident(config, incident) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            checkParam(config.incidents, _constants__WEBPACK_IMPORTED_MODULE_1__.INCIDENT_URL_ERROR);
            checkParam(incident, 'Incident data not provided');
            const features = [{
                    attributes: {
                        HazardID: incident.hazard.id,
                        Name: incident.name,
                        Description: incident.description,
                        StartDate: String(incident.startDate),
                        EndDate: String(incident.endDate)
                    }
                }];
            const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.incidents, features, config);
            if (response.addResults && response.addResults.length > 0) {
                return {};
            }
            return {
                errors: 'Incident could not be saved.'
            };
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_4__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_4__.LogType.ERROR, 'createIncident');
            return {
                errors: 'Incident could not be saved.'
            };
        }
    });
}
//====================PRIVATE======================================
const requestData = (url, controller) => __awaiter(void 0, void 0, void 0, function* () {
    if (!controller) {
        controller = new AbortController();
    }
    const response = yield fetch(url, {
        method: "GET",
        headers: {
            'content-type': 'application/x-www-form-urlencoded'
        },
        signal: controller.signal
    });
    return response.json();
});
function getTemplate(templateFeature, lifelineFeatures, componentFeatures, indicatorsFeatures, weightsFeatures, templateDomains) {
    return __awaiter(this, void 0, void 0, function* () {
        const indicatorFeatures = indicatorsFeatures.filter(i => i.attributes.TemplateID = `'${templateFeature.attributes.GlobalID}'`); //  await getIndicatorFeatures(`TemplateID='${templateFeature.attributes.GlobalID}'`, config);
        //const query = indicatorFeatures.map(i => `IndicatorID='${i.attributes.GlobalID.toUpperCase()}'`).join(' OR ')
        const indicatorIds = indicatorFeatures.map(i => i.attributes.GlobalID);
        const weightFeatures = weightsFeatures.filter(w => indicatorIds.indexOf(w.attributes.IndicatorID)); //await getWeightsFeatures(query, config);
        const indicatorTemplates = indicatorFeatures.map((feature) => {
            const weights = weightsFeatures
                .filter(w => w.attributes.IndicatorID === feature.attributes.GlobalID)
                .map(w => {
                return {
                    objectId: w.attributes.OBJECTID,
                    name: w.attributes.Name,
                    weight: w.attributes.Weight,
                    scaleFactor: w.attributes.ScaleFactor,
                    adjustedWeight: w.attributes.AdjustedWeight,
                    maxAdjustedWeight: w.attributes.MaxAdjustedWeight
                };
            });
            return {
                objectId: feature.attributes.OBJECTID,
                id: feature.attributes.GlobalID,
                name: feature.attributes.Name,
                templateName: feature.attributes.TemplateName,
                weights,
                componentId: feature.attributes.ComponentID,
                templateId: feature.attributes.TemplateID,
                componentName: feature.attributes.ComponentName,
                lifelineName: feature.attributes.LifelineName
            };
        });
        const componentTemplates = componentFeatures.map((feature) => {
            return {
                id: feature.attributes.GlobalID,
                title: feature.attributes.DisplayName || feature.attributes.DisplayTitle,
                name: feature.attributes.Name,
                lifelineId: feature.attributes.LifelineID,
                indicators: indicatorTemplates.filter(i => i.componentId === feature.attributes.GlobalID).orderBy('name')
            };
        });
        const lifelineTemplates = lifelineFeatures.map((feature) => {
            return {
                id: feature.attributes.GlobalID,
                title: feature.attributes.DisplayName || feature.attributes.DisplayTitle,
                name: feature.attributes.Name,
                componentTemplates: componentTemplates.filter(c => c.lifelineId === feature.attributes.GlobalID).orderBy('title')
            };
        });
        const template = {
            objectId: templateFeature.attributes.OBJECTID,
            id: templateFeature.attributes.GlobalID,
            isSelected: templateFeature.attributes.IsSelected == 1,
            status: {
                code: templateFeature.attributes.Status,
                name: templateFeature.attributes.Status === 1 ? "Active" : 'Archived'
            },
            name: templateFeature.attributes.Name,
            hazardName: templateFeature.attributes.HazardName,
            hazardType: templateFeature.attributes.HazardType,
            organizationName: templateFeature.attributes.OrganizationName,
            organizationType: templateFeature.attributes.OrganizationType,
            creator: templateFeature.attributes.Creator,
            createdDate: Number(templateFeature.attributes.CreatedDate),
            editor: templateFeature.attributes.Editor,
            editedDate: Number(templateFeature.attributes.EditedDate),
            lifelineTemplates: lifelineTemplates.orderBy('title'),
            domains: templateDomains
        };
        return template;
    });
}
function saveAssessment(assessment, config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const feature = {
                attributes: {
                    Name: assessment.name,
                    Description: assessment.description,
                    AssessmentType: assessment.assessmentType,
                    Organization: assessment.organization,
                    Incident: assessment.incident,
                    Hazard: assessment.hazard,
                    Creator: assessment.creator,
                    CreatedDate: assessment.createdDate,
                    Editor: assessment.editor,
                    EditedDate: assessment.editedDate,
                    IsCompleted: assessment.isCompleted,
                    HazardType: assessment.hazardType,
                    OrganizationType: assessment.organizationType,
                    Template: assessment.template
                }
            };
            const response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.assessments, [feature], config);
            if (response.addResults && response.addResults.every(r => r.success)) {
                return { data: response.addResults[0].globalId };
            }
            return {
                errors: JSON.stringify(response)
            };
        }
        catch (e) {
            return {
                errors: e
            };
        }
    });
}
function getIndicatorAssessments(query, config) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Indicator Assessments called.');
        const features = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.indicatorAssessments, query, config);
        if (features && features.length > 0) {
            return features.map(feature => {
                return {
                    objectId: feature.attributes.OBJECTID,
                    id: feature.attributes.GlobalID,
                    indicatorId: feature.attributes.IndicatorID,
                    indicator: feature.attributes.IndicatorName,
                    template: feature.attributes.TemplateName,
                    lifeline: feature.attributes.LifelineName,
                    component: feature.attributes.ComponentName,
                    comments: parseComment(feature.attributes.Comments),
                    lifelineStatusId: feature.attributes.LifelineStatusID,
                    environmentPreservation: feature.attributes.EnvironmentPreservation,
                    incidentStabilization: feature.attributes.IncidentStabilization,
                    rank: feature.attributes.Rank,
                    lifeSafety: feature.attributes.LifeSafety,
                    propertyProtection: feature.attributes.PropertyProtection,
                    status: feature.attributes.Status
                };
            });
        }
    });
}
function parseComment(comments) {
    if (!comments || comments === "") {
        return [];
    }
    let parsedComments = JSON.parse(comments);
    if (parsedComments && parsedComments.length > 0) {
        parsedComments.map((commentData) => {
            return Object.assign(Object.assign({}, commentData), { datetime: Number(commentData.datetime) });
        });
        parsedComments = parsedComments.orderBy('datetime', true);
    }
    else {
        parsedComments = [];
    }
    return parsedComments;
}
function getLifelineStatusFeatures(config, query) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log('get Lifeline Status called');
        return yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.queryTableFeatures)(config.lifelineStatus, query, config);
    });
}
function loadAssessment(assessmentFeature, lsFeatures, indicatorAssessments) {
    const lifelineStatuses = lsFeatures.map((feature) => {
        return {
            objectId: feature.attributes.OBJECTID,
            id: feature.attributes.GlobalID,
            assessmentId: feature.attributes.AssessmentID,
            lifelineName: feature.attributes.LifelineName,
            indicatorAssessments: indicatorAssessments.filter(i => i.lifelineStatusId === feature.attributes.GlobalID),
            score: feature.attributes.Score,
            color: feature.attributes.Color,
            isOverriden: feature.attributes.IsOverriden,
            overrideScore: feature.attributes.OverridenScore,
            overridenBy: feature.attributes.OverridenBy,
            overridenColor: feature.attributes.OverridenColor,
            overrideComment: feature.attributes.OverrideComment
        };
    });
    const assessment = {
        objectId: assessmentFeature.attributes.OBJECTID,
        id: assessmentFeature.attributes.GlobalID,
        name: assessmentFeature.attributes.Name,
        assessmentType: assessmentFeature.attributes.AssessmentType,
        lifelineStatuses: lifelineStatuses,
        description: assessmentFeature.attributes.Description,
        template: assessmentFeature.attributes.Template,
        organization: assessmentFeature.attributes.Organization,
        organizationType: assessmentFeature.attributes.OrganizationType,
        incident: assessmentFeature.attributes.Incident,
        hazard: assessmentFeature.attributes.Hazard,
        hazardType: assessmentFeature.attributes.HazardType,
        creator: assessmentFeature.attributes.Creator,
        createdDate: Number(assessmentFeature.attributes.CreatedDate),
        editor: assessmentFeature.attributes.Editor,
        editedDate: Number(assessmentFeature.attributes.EditedDate),
        isSelected: false,
        isCompleted: assessmentFeature.attributes.IsCompleted,
    };
    return assessment;
}
function saveLifelineStatus(lifelineStatusFeature, lsIndAssessFeatures, config) {
    return __awaiter(this, void 0, void 0, function* () {
        let response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.lifelineStatus, [lifelineStatusFeature], config);
        if (response.addResults && response.addResults.every(e => e.success)) {
            const globalId = response.addResults[0].globalId;
            const indicatorAssessmentFeatures = lsIndAssessFeatures.map(ind => {
                ind.attributes.LifelineStatusID = globalId;
                return ind;
            });
            response = yield (0,_esri_api__WEBPACK_IMPORTED_MODULE_3__.addTableFeatures)(config.indicatorAssessments, indicatorAssessmentFeatures, config);
            if (response.addResults && response.addResults.every(e => e.success)) {
                return true;
            }
        }
    });
}
function getTemplateIndicators(template) {
    return [].concat.apply([], ([].concat.apply([], template.lifelineTemplates.map(l => l.componentTemplates)))
        .map((c) => c.indicators));
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/auth.ts":
/*!*************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/auth.ts ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "checkCurrentStatus": () => (/* binding */ checkCurrentStatus),
/* harmony export */   "signIn": () => (/* binding */ signIn),
/* harmony export */   "signOut": () => (/* binding */ signOut)
/* harmony export */ });
/* harmony import */ var jimu_arcgis__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-arcgis */ "jimu-arcgis");
//Adapted from //https://github.com/odoe/map-vue/blob/master/src/data/auth.ts
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};

/**
 * Attempt to sign in,
 * first check current status
 * if not signed in, then go through
 * steps to get credentials
 */
const signIn = (appId, portalUrl) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        return yield checkCurrentStatus(appId, portalUrl);
    }
    catch (error) {
        console.log(error);
        return yield fetchCredentials(appId, portalUrl);
    }
});
/**
 * Sign the user out, but if we checked credentials
 * manually, make sure they are registered with
 * IdentityManager, so it can destroy them properly
 */
const signOut = (appId, portalUrl) => __awaiter(void 0, void 0, void 0, function* () {
    const IdentityManager = yield loadModules(appId, portalUrl);
    yield signIn(appId, portalUrl);
    delete window['IdentityManager'];
    delete window['OAuthInfo'];
    IdentityManager.destroyCredentials();
});
/**
 * Get the credentials for the provided portal
 */
function fetchCredentials(appId, portalUrl) {
    return __awaiter(this, void 0, void 0, function* () {
        const IdentityManager = yield loadModules(appId, portalUrl);
        const credential = yield IdentityManager.getCredential(`${portalUrl}/sharing`, {
            error: null,
            oAuthPopupConfirmation: false,
            token: null
        });
        return credential;
    });
}
;
/**
 * Import Identity Manager, and OAuthInfo
 */
function loadModules(appId, portalUrl) {
    return __awaiter(this, void 0, void 0, function* () {
        let IdentityManager = window['IdentityManager'];
        if (!IdentityManager) {
            const modules = yield (0,jimu_arcgis__WEBPACK_IMPORTED_MODULE_0__.loadArcGISJSAPIModules)([
                'esri/identity/IdentityManager',
                'esri/identity/OAuthInfo'
            ]);
            window['IdentityManager'] = modules[0];
            window['OAuthInfo'] = modules[1];
            IdentityManager = modules[0];
            const OAuthInfo = modules[1];
            const oauthInfo = new OAuthInfo({
                appId,
                portalUrl,
                popup: false
            });
            IdentityManager.registerOAuthInfos([oauthInfo]);
        }
        return IdentityManager;
    });
}
/**
 * Check current logged in status for current portal
 */
const checkCurrentStatus = (appId, portalUrl) => __awaiter(void 0, void 0, void 0, function* () {
    const IdentityManager = yield loadModules(appId, portalUrl);
    return IdentityManager.checkSignInStatus(`${portalUrl}/sharing`);
});


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts":
/*!*******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/clss-store.ts ***!
  \*******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CLSSActionKeys": () => (/* binding */ CLSSActionKeys),
/* harmony export */   "default": () => (/* binding */ MyReduxStoreExtension)
/* harmony export */ });
var CLSSActionKeys;
(function (CLSSActionKeys) {
    CLSSActionKeys["AUTHENTICATE_ACTION"] = "[CLSS-APPLICATION] authenicate credentials";
    CLSSActionKeys["LOAD_HAZARDS_ACTION"] = "[CLSS-APPLICATION] load hazards";
    CLSSActionKeys["LOAD_HAZARD_TYPES_ACTION"] = "[CLSS-APPLICATION] load hazard types";
    CLSSActionKeys["LOAD_ORGANIZATIONS_ACTION"] = "[CLSS-APPLICATION] load organizations";
    CLSSActionKeys["LOAD_ORGANIZATION_TYPES_ACTION"] = "[CLSS-APPLICATION] load organization types";
    CLSSActionKeys["LOAD_TEMPLATES_ACTION"] = "[CLSS-APPLICATION] load templates";
    CLSSActionKeys["LOAD_PRIORITIES_ACTION"] = "[CLSS-APPLICATION] load priorities";
    CLSSActionKeys["SELECT_TEMPLATE_ACTION"] = "[CLSS-APPLICATION] select template";
    CLSSActionKeys["SEARCH_ACTION"] = "[CLSS-APPLICATION] search for template";
    CLSSActionKeys["SIGN_IN_ACTION"] = "[CLSS-APPLICATION] Sign in";
    CLSSActionKeys["SIGN_OUT_ACTION"] = "[CLSS-APPLICATION] Sign out";
    CLSSActionKeys["SET_USER_ACTION"] = "[CLSS-APPLICATION] Set CLSS User";
    CLSSActionKeys["SET_IDENTITY_ACTION"] = "[CLSS-APPLICATION] Set Identity";
    CLSSActionKeys["SET_ERRORS"] = "[CLSS-APPLICATION] Set global errors";
    CLSSActionKeys["TOGGLE_INDICATOR_EDITING"] = "[CLSS-APPLICATION] Toggle indicator editing";
    CLSSActionKeys["SELECT_LIFELINESTATUS_ACTION"] = "[CLSS-APPLICATION] Select a lifeline status";
    CLSSActionKeys["LOAD_ASSESSMENTS_ACTION"] = "[CLSS-APPLICATION] Load assessments";
    CLSSActionKeys["SELECT_ASSESSMENT_ACTION"] = "[CLSS-APPLICATION] Select assessment";
    CLSSActionKeys["LOAD_RATINGSCALES_ACTION"] = "[CLSS-APPLICATION] Load rating scales";
    CLSSActionKeys["LOAD_SCALEFACTORS_ACTION"] = "[CLSS-APPLICATION] Load constants";
})(CLSSActionKeys || (CLSSActionKeys = {}));
class MyReduxStoreExtension {
    constructor() {
        this.id = 'clss-redux-store-extension';
    }
    getActions() {
        return Object.keys(CLSSActionKeys).map(k => CLSSActionKeys[k]);
    }
    getInitLocalState() {
        return {
            selectedTemplate: null,
            templates: [],
            searchResults: [],
            user: null,
            auth: null,
            identity: null,
            newTemplateModalVisible: false,
            hazards: [],
            organizations: [],
            errors: '',
            isIndicatorEditing: false,
            selectedLifelineStatus: null,
            organizationTypes: [],
            hazardTypes: [],
            priorities: [],
            assessments: [],
            ratingScales: [],
            scaleFactors: [],
            authenticate: null
        };
    }
    getReducer() {
        return (localState, action, appState) => {
            switch (action.type) {
                case CLSSActionKeys.AUTHENTICATE_ACTION:
                    return localState.set('authenticate', action.val);
                case CLSSActionKeys.LOAD_SCALEFACTORS_ACTION:
                    return localState.set('scaleFactors', action.val);
                case CLSSActionKeys.LOAD_RATINGSCALES_ACTION:
                    return localState.set('ratingScales', action.val);
                case CLSSActionKeys.SELECT_ASSESSMENT_ACTION:
                    const assessments = localState.assessments.map(assess => {
                        return Object.assign(Object.assign({}, assess), { isSelected: assess.id === action.val.id.toLowerCase() });
                    });
                    return localState.set('assessments', assessments);
                case CLSSActionKeys.LOAD_ASSESSMENTS_ACTION:
                    return localState.set('assessments', action.val);
                case CLSSActionKeys.LOAD_PRIORITIES_ACTION:
                    return localState.set('priorities', action.val);
                case CLSSActionKeys.SELECT_LIFELINESTATUS_ACTION:
                    return localState.set('selectedLifelineStatus', action.val);
                case CLSSActionKeys.TOGGLE_INDICATOR_EDITING:
                    return localState.set('isIndicatorEditing', action.val);
                case CLSSActionKeys.SET_ERRORS:
                    return localState.set('errors', action.val);
                case CLSSActionKeys.LOAD_HAZARDS_ACTION:
                    return localState.set('hazards', action.val);
                case CLSSActionKeys.LOAD_HAZARD_TYPES_ACTION:
                    return localState.set('hazardTypes', action.val);
                case CLSSActionKeys.LOAD_ORGANIZATION_TYPES_ACTION:
                    return localState.set('organizationTypes', action.val);
                case CLSSActionKeys.LOAD_ORGANIZATIONS_ACTION:
                    return localState.set('organizations', action.val);
                case CLSSActionKeys.SET_IDENTITY_ACTION:
                    return localState.set('identity', action.val);
                case CLSSActionKeys.SET_USER_ACTION:
                    return localState.set('user', action.val);
                case CLSSActionKeys.LOAD_TEMPLATES_ACTION:
                    return localState.set('templates', action.val);
                case CLSSActionKeys.SELECT_TEMPLATE_ACTION:
                    let templates = [...localState.templates].map(t => {
                        return Object.assign(Object.assign({}, t), { isSelected: t.id === action.val });
                    });
                    return localState.set('templates', templates);
                default:
                    return localState;
            }
        };
    }
    getStoreKey() {
        return 'clssState';
    }
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/constants.ts":
/*!******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/constants.ts ***!
  \******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ALIGNMENT_URL_ERROR": () => (/* binding */ ALIGNMENT_URL_ERROR),
/* harmony export */   "ANALYSIS_REPORTING_TITLE": () => (/* binding */ ANALYSIS_REPORTING_TITLE),
/* harmony export */   "ASSESSMENT_URL_ERROR": () => (/* binding */ ASSESSMENT_URL_ERROR),
/* harmony export */   "BASELINE_TEMPLATE_NAME": () => (/* binding */ BASELINE_TEMPLATE_NAME),
/* harmony export */   "CLSS_ADMIN": () => (/* binding */ CLSS_ADMIN),
/* harmony export */   "CLSS_ASSESSOR": () => (/* binding */ CLSS_ASSESSOR),
/* harmony export */   "CLSS_EDITOR": () => (/* binding */ CLSS_EDITOR),
/* harmony export */   "CLSS_FOLLOWERS": () => (/* binding */ CLSS_FOLLOWERS),
/* harmony export */   "CLSS_VIEWER": () => (/* binding */ CLSS_VIEWER),
/* harmony export */   "COMMENT": () => (/* binding */ COMMENT),
/* harmony export */   "COMMENT_HELP": () => (/* binding */ COMMENT_HELP),
/* harmony export */   "COMPONENT_URL_ERROR": () => (/* binding */ COMPONENT_URL_ERROR),
/* harmony export */   "CRITICAL": () => (/* binding */ CRITICAL),
/* harmony export */   "CRITICAL_LOWER_BOUNDARY": () => (/* binding */ CRITICAL_LOWER_BOUNDARY),
/* harmony export */   "DATA_LIBRARY_TITLE": () => (/* binding */ DATA_LIBRARY_TITLE),
/* harmony export */   "DEFAULT_LISTITEM": () => (/* binding */ DEFAULT_LISTITEM),
/* harmony export */   "DEFAULT_PRIORITY_LEVELS": () => (/* binding */ DEFAULT_PRIORITY_LEVELS),
/* harmony export */   "DELETE_INDICATOR_CONFIRMATION": () => (/* binding */ DELETE_INDICATOR_CONFIRMATION),
/* harmony export */   "DESTABILIZING_SCALE_FACTOR": () => (/* binding */ DESTABILIZING_SCALE_FACTOR),
/* harmony export */   "ENVIRONMENT_PRESERVATION": () => (/* binding */ ENVIRONMENT_PRESERVATION),
/* harmony export */   "ENVIRONMENT_PRESERVATION_MESSAGE": () => (/* binding */ ENVIRONMENT_PRESERVATION_MESSAGE),
/* harmony export */   "GREEN_COLOR": () => (/* binding */ GREEN_COLOR),
/* harmony export */   "HAZARD_URL_ERROR": () => (/* binding */ HAZARD_URL_ERROR),
/* harmony export */   "INCIDENT_STABILIZATION": () => (/* binding */ INCIDENT_STABILIZATION),
/* harmony export */   "INCIDENT_STABILIZATION_MESSAGE": () => (/* binding */ INCIDENT_STABILIZATION_MESSAGE),
/* harmony export */   "INCIDENT_URL_ERROR": () => (/* binding */ INCIDENT_URL_ERROR),
/* harmony export */   "INCLUDE_INDICATOR": () => (/* binding */ INCLUDE_INDICATOR),
/* harmony export */   "INCLUDE_INDICATOR_HELP": () => (/* binding */ INCLUDE_INDICATOR_HELP),
/* harmony export */   "INDICATOR_COMMENT_LENGTH": () => (/* binding */ INDICATOR_COMMENT_LENGTH),
/* harmony export */   "INDICATOR_STATUS": () => (/* binding */ INDICATOR_STATUS),
/* harmony export */   "INDICATOR_STATUS_HELP": () => (/* binding */ INDICATOR_STATUS_HELP),
/* harmony export */   "INDICATOR_URL_ERROR": () => (/* binding */ INDICATOR_URL_ERROR),
/* harmony export */   "LIFELINE_URL_ERROR": () => (/* binding */ LIFELINE_URL_ERROR),
/* harmony export */   "LIFE_SAFETY": () => (/* binding */ LIFE_SAFETY),
/* harmony export */   "LIFE_SAFETY_MESSAGE": () => (/* binding */ LIFE_SAFETY_MESSAGE),
/* harmony export */   "LIFE_SAFETY_SCALE_FACTOR": () => (/* binding */ LIFE_SAFETY_SCALE_FACTOR),
/* harmony export */   "MAXIMUM_WEIGHT": () => (/* binding */ MAXIMUM_WEIGHT),
/* harmony export */   "MODERATE_LOWER_BOUNDARY": () => (/* binding */ MODERATE_LOWER_BOUNDARY),
/* harmony export */   "NODATA_COLOR": () => (/* binding */ NODATA_COLOR),
/* harmony export */   "NODATA_VALUE": () => (/* binding */ NODATA_VALUE),
/* harmony export */   "ORGANIZATION_URL_ERROR": () => (/* binding */ ORGANIZATION_URL_ERROR),
/* harmony export */   "OTHER_WEIGHTS_SCALE_FACTOR": () => (/* binding */ OTHER_WEIGHTS_SCALE_FACTOR),
/* harmony export */   "OVERWRITE_SCORE_MESSAGE": () => (/* binding */ OVERWRITE_SCORE_MESSAGE),
/* harmony export */   "PORTAL_URL": () => (/* binding */ PORTAL_URL),
/* harmony export */   "PRIORITY_URL_ERROR": () => (/* binding */ PRIORITY_URL_ERROR),
/* harmony export */   "PROPERTY_PROTECTION": () => (/* binding */ PROPERTY_PROTECTION),
/* harmony export */   "PROPERTY_PROTECTION_MESSAGE": () => (/* binding */ PROPERTY_PROTECTION_MESSAGE),
/* harmony export */   "RANK": () => (/* binding */ RANK),
/* harmony export */   "RANK_MESSAGE": () => (/* binding */ RANK_MESSAGE),
/* harmony export */   "RED_COLOR": () => (/* binding */ RED_COLOR),
/* harmony export */   "SAVING_SAME_AS_BASELINE_ERROR": () => (/* binding */ SAVING_SAME_AS_BASELINE_ERROR),
/* harmony export */   "SAVING_TIMER": () => (/* binding */ SAVING_TIMER),
/* harmony export */   "STABILIZING_SCALE_FACTOR": () => (/* binding */ STABILIZING_SCALE_FACTOR),
/* harmony export */   "TEMPLATE_URL_ERROR": () => (/* binding */ TEMPLATE_URL_ERROR),
/* harmony export */   "TOKEN_ERROR": () => (/* binding */ TOKEN_ERROR),
/* harmony export */   "UNCHANGED_SCALE_FACTOR": () => (/* binding */ UNCHANGED_SCALE_FACTOR),
/* harmony export */   "USER_BOX_ELEMENT_ID": () => (/* binding */ USER_BOX_ELEMENT_ID),
/* harmony export */   "UpdateAction": () => (/* binding */ UpdateAction),
/* harmony export */   "YELLOW_COLOR": () => (/* binding */ YELLOW_COLOR)
/* harmony export */ });
const CLSS_ADMIN = 'CLSS_Admin';
const CLSS_EDITOR = 'CLSS_Editor';
const CLSS_ASSESSOR = 'CLSS_Assessor';
const CLSS_VIEWER = 'CLSS_Viewer';
const CLSS_FOLLOWERS = 'CLSS Followers';
const BASELINE_TEMPLATE_NAME = 'Baseline';
const TOKEN_ERROR = 'Token not provided';
const TEMPLATE_URL_ERROR = 'Template FeatureLayer URL not provided';
const ASSESSMENT_URL_ERROR = 'Assessment FeatureLayer URL not provided';
const ORGANIZATION_URL_ERROR = 'Organization FeatureLayer URL not provided';
const HAZARD_URL_ERROR = 'Hazard FeatureLayer URL not provided';
const INDICATOR_URL_ERROR = 'Indicator FeatureLayer URL not provided';
const ALIGNMENT_URL_ERROR = 'Alignments FeatureLayer URL not provided';
const LIFELINE_URL_ERROR = 'Lifeline FeatureLayer URL not provided';
const COMPONENT_URL_ERROR = 'Component FeatureLayer URL not provided';
const PRIORITY_URL_ERROR = 'Priority FeatureLayer URL not provided';
const INCIDENT_URL_ERROR = 'Incident FeatureLayer URL not provided';
const SAVING_SAME_AS_BASELINE_ERROR = 'Baseline template cannot be updated. Change the template name to create a new one.';
const STABILIZING_SCALE_FACTOR = 'Stabilizing_Scale_Factor';
const DESTABILIZING_SCALE_FACTOR = 'Destabilizing_Scale_Factor';
const UNCHANGED_SCALE_FACTOR = 'Unchanged_Indicators';
const DEFAULT_PRIORITY_LEVELS = "Default_Priority_Levels";
const RANK = 'Importance of Indicator';
const LIFE_SAFETY = 'Life Safety';
const INCIDENT_STABILIZATION = 'Incident Stabilization';
const PROPERTY_PROTECTION = 'Property Protection';
const ENVIRONMENT_PRESERVATION = 'Environment Preservation';
const LIFE_SAFETY_SCALE_FACTOR = 200;
const OTHER_WEIGHTS_SCALE_FACTOR = 100;
const MAXIMUM_WEIGHT = 5;
var UpdateAction;
(function (UpdateAction) {
    UpdateAction["HEADER"] = "header";
    UpdateAction["INDICATOR_NAME"] = "Indicator Name";
    UpdateAction["PRIORITIES"] = "Indicator Priorities";
    UpdateAction["NEW_INDICATOR"] = "Create New Indicator";
    UpdateAction["DELETE_INDICATOR"] = "Delete Indicator";
})(UpdateAction || (UpdateAction = {}));
const INCLUDE_INDICATOR = 'Impacted - Yes or No';
const INCLUDE_INDICATOR_HELP = 'Yes: The indicator will be considered in the assessment.\nNo: The indicator will not be considered.\nUnknown: Not sure to include the indicator in assessment.';
const INDICATOR_STATUS = 'Indicator Impact Status';
const INDICATOR_STATUS_HELP = 'Stabilizing: Has the indicator been improved or improving.\nDestabilizing: Is the indicator degrading.\nUnchanged: No significant improvement since the last assessment.';
const COMMENT = 'Comment';
const COMMENT_HELP = 'Provide justification for the selected indicator status.';
const DELETE_INDICATOR_CONFIRMATION = 'Are you sure you want to delete indicator?';
//Cell Weight =  Trend * ( (-1*Rank) + 6
const CRITICAL = 25;
const CRITICAL_LOWER_BOUNDARY = 12.5;
const MODERATE_LOWER_BOUNDARY = 5.5;
const NODATA_COLOR = '#919395';
const NODATA_VALUE = 999999;
const RED_COLOR = '#C52038';
const YELLOW_COLOR = '#FBBA16';
const GREEN_COLOR = '#5E9C42';
const SAVING_TIMER = 1500;
const INDICATOR_COMMENT_LENGTH = 300;
const PORTAL_URL = 'https://www.arcgis.com';
const DEFAULT_LISTITEM = { id: '000', name: '-None-', title: '-None-' };
const RANK_MESSAGE = 'How important is the indicator to your jurisdiction or hazard?';
const LIFE_SAFETY_MESSAGE = 'How important is the indicator to Life Safety?';
const PROPERTY_PROTECTION_MESSAGE = 'How important is the indicator to Property Protection?';
const ENVIRONMENT_PRESERVATION_MESSAGE = 'How important is the indicator to Environment Preservation?';
const INCIDENT_STABILIZATION_MESSAGE = 'How important is the indicator to Incident Stabilization?';
const OVERWRITE_SCORE_MESSAGE = 'A completed assessment cannot be edited. Are you sure you want to complete this assessment?';
const USER_BOX_ELEMENT_ID = 'userBoxElement';
const DATA_LIBRARY_TITLE = 'Data Library';
const ANALYSIS_REPORTING_TITLE = 'Analysis & Reporting';


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/esri-api.ts":
/*!*****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/esri-api.ts ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "addTableFeatures": () => (/* binding */ addTableFeatures),
/* harmony export */   "deleteTableFeatures": () => (/* binding */ deleteTableFeatures),
/* harmony export */   "queryRelatedTableFeatures": () => (/* binding */ queryRelatedTableFeatures),
/* harmony export */   "queryTableFeatureSet": () => (/* binding */ queryTableFeatureSet),
/* harmony export */   "queryTableFeatures": () => (/* binding */ queryTableFeatures),
/* harmony export */   "updateTableFeature": () => (/* binding */ updateTableFeature),
/* harmony export */   "updateTableFeatures": () => (/* binding */ updateTableFeatures)
/* harmony export */ });
/* harmony import */ var _esri_arcgis_rest_auth__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @esri/arcgis-rest-auth */ "./node_modules/@esri/arcgis-rest-auth/dist/esm/UserSession.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/query.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/queryRelated.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/update.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/add.js");
/* harmony import */ var _esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @esri/arcgis-rest-feature-layer */ "./node_modules/@esri/arcgis-rest-feature-layer/dist/esm/delete.js");
/* harmony import */ var _logger__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./logger */ "./your-extensions/widgets/clss-application/src/extensions/logger.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};



function getAuthentication(config) {
    return __awaiter(this, void 0, void 0, function* () {
        return _esri_arcgis_rest_auth__WEBPACK_IMPORTED_MODULE_1__.UserSession.fromCredential(config.credential);
    });
}
function queryTableFeatureSet(url, where, config) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const authentication = yield getAuthentication(config);
            return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_2__.queryFeatures)({ url, where, authentication, hideToken: true })
                .then((response) => {
                return response;
            });
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_0__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_0__.LogType.ERROR, 'queryTableFeatureSet');
        }
    });
}
function queryTableFeatures(url, where, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        try {
            const response = yield (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_2__.queryFeatures)({ url, where, authentication, httpMethod: 'POST', hideToken: true });
            return response.features;
        }
        catch (e) {
            (0,_logger__WEBPACK_IMPORTED_MODULE_0__.log)(e, _logger__WEBPACK_IMPORTED_MODULE_0__.LogType.ERROR, 'queryTableFeatures');
            (0,_logger__WEBPACK_IMPORTED_MODULE_0__.log)(url, _logger__WEBPACK_IMPORTED_MODULE_0__.LogType.WRN, where);
        }
    });
}
function queryRelatedTableFeatures(objectIds, url, relationshipId, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        const response = yield (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_3__.queryRelated)({
            objectIds,
            url, relationshipId,
            authentication,
            hideToken: true
        });
        return response.relatedRecordGroups;
    });
}
function updateTableFeature(url, attributes, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_4__.updateFeatures)({
            url,
            authentication,
            features: [{
                    attributes
                }],
            rollbackOnFailure: true
        });
    });
}
function updateTableFeatures(url, features, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_4__.updateFeatures)({
            url,
            authentication,
            features
        });
    });
}
function addTableFeatures(url, features, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        try {
            return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_5__.addFeatures)({ url, features, authentication, rollbackOnFailure: true });
        }
        catch (e) {
            console.log(e);
        }
    });
}
function deleteTableFeatures(url, objectIds, config) {
    return __awaiter(this, void 0, void 0, function* () {
        const authentication = yield getAuthentication(config);
        return (0,_esri_arcgis_rest_feature_layer__WEBPACK_IMPORTED_MODULE_6__.deleteFeatures)({ url, objectIds, authentication, rollbackOnFailure: true });
    });
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/logger.ts":
/*!***************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/logger.ts ***!
  \***************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "LogType": () => (/* binding */ LogType),
/* harmony export */   "log": () => (/* binding */ log)
/* harmony export */ });
var LogType;
(function (LogType) {
    LogType["INFO"] = "Information";
    LogType["WRN"] = "Warning";
    LogType["ERROR"] = "Error";
})(LogType || (LogType = {}));
function log(message, type, func) {
    if (!type) {
        type = LogType.INFO;
    }
    if (func) {
        func = `(${func})`;
    }
    message = `[${new Date().toLocaleString()}]: ${message} ${func}`;
    switch (type) {
        case LogType.INFO:
            console.log(message);
            break;
        case LogType.WRN:
            console.warn(message);
            break;
        case LogType.ERROR:
            console.error(message);
            break;
        default:
            console.log(message);
    }
}


/***/ }),

/***/ "./your-extensions/widgets/clss-application/src/extensions/utils.ts":
/*!**************************************************************************!*\
  !*** ./your-extensions/widgets/clss-application/src/extensions/utils.ts ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "createGuid": () => (/* binding */ createGuid),
/* harmony export */   "parseDate": () => (/* binding */ parseDate),
/* harmony export */   "saveDate": () => (/* binding */ saveDate),
/* harmony export */   "sortObject": () => (/* binding */ sortObject)
/* harmony export */ });
const sortObject = (obj, prop, reverse) => {
    return obj.sort((a, b) => {
        if (a[prop] > b[prop]) {
            return reverse ? -1 : 1;
        }
        if (a[prop] < b[prop]) {
            return reverse ? 1 : -1;
        }
        return 0;
    });
};
const createGuid = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
};
const parseDate = (milliseconds) => {
    if (!milliseconds) {
        return;
    }
    return new Date(milliseconds).toLocaleString();
};
const saveDate = (date) => {
    return new Date(date).getMilliseconds();
};
//Reference: https://stackoverflow.com/questions/6195335/linear-regression-in-javascript
// export const linearRegression = (yValues: number[], xValues: number[]) =>{
//   debugger;
//   const y = yValues;
//   const x = xValues;
//   var lr = {slope: NaN, intercept: NaN, r2: NaN};
//   var n = y.length;
//   var sum_x = 0;
//   var sum_y = 0;
//   var sum_xy = 0;
//   var sum_xx = 0;
//   var sum_yy = 0;
//   for (var i = 0; i < y.length; i++) {
//       sum_x += x[i];
//       sum_y += y[i];
//       sum_xy += (x[i]*y[i]);
//       sum_xx += (x[i]*x[i]);
//       sum_yy += (y[i]*y[i]);
//   } 
//   lr.slope = (n * sum_xy - sum_x * sum_y) / (n*sum_xx - sum_x * sum_x);
//   lr.intercept = (sum_y - lr.slope * sum_x)/n;
//   lr.r2 = Math.pow((n*sum_xy - sum_x*sum_y)/Math.sqrt((n*sum_xx-sum_x*sum_x)*(n*sum_yy-sum_y*sum_y)),2);
//   return lr;
// }
String.prototype.toTitleCase = function () {
    return this.replace(/\w\S*/g, function (txt) { return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase(); });
};
Array.prototype.orderBy = function (prop, reverse) {
    return this.sort((a, b) => {
        if (a[prop] > b[prop]) {
            return reverse ? -1 : 1;
        }
        if (a[prop] < b[prop]) {
            return reverse ? 1 : -1;
        }
        return 0;
    });
};
Array.prototype.groupBy = function (key) {
    return this.reduce(function (rv, x) {
        (rv[x[key]] = rv[x[key]] || []).push(x);
        return rv;
    }, {});
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-add-hazard.tsx":
/*!****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-add-hazard.tsx ***!
  \****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "AddHazardWidget": () => (/* binding */ AddHazardWidget)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var _clss_modal__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./clss-modal */ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! jimu-core */ "jimu-core");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};








const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_6__.ReactRedux;
const AddHazardWidget = ({ props, visible, toggle, setHazard }) => {
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [isVisible, setVisible] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [name, setName] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [description, setDescription] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [hazardTypes, setHazardTypes] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState([]);
    const [selectedHazardType, setSelectedHazardType] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const [config, setConfig] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const credential = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.authenticate;
    });
    const hazards = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.hazards;
    });
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (credential) {
            setConfig(Object.assign(Object.assign({}, props.config), { credential: credential }));
        }
    }, [credential]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (hazards && hazards.length > 0) {
            const types = hazards[1].domains;
            types.orderBy('name');
            setHazardTypes(types);
        }
    }, [hazards]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setVisible(visible);
        setName('');
        setDescription('');
        setSelectedHazardType(null);
    }, [visible]);
    const saveNewHazard = () => __awaiter(void 0, void 0, void 0, function* () {
        const exist = hazards.find(h => h.name.toLowerCase() === name.toLowerCase().trim());
        if (exist) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.SET_ERRORS, `Hazard: ${name} already exists`);
            return;
        }
        setLoading(true);
        try {
            let newHazard = {
                name,
                title: name,
                type: selectedHazardType,
                description
            };
            const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.saveHazard)(config, newHazard);
            console.log(response);
            if (response.errors) {
                throw new Error(String(response.errors));
            }
            newHazard = response.data;
            newHazard.domains = hazards[1].domains;
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.LOAD_HAZARDS_ACTION, [...hazards, newHazard]);
            setHazard(newHazard);
            toggle(false);
        }
        catch (err) {
            console.log(err);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.SET_ERRORS, err.message);
        }
        finally {
            setLoading(false);
        }
    });
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_modal__WEBPACK_IMPORTED_MODULE_5__.ClssModal, { title: "Add New Hazard", disable: !(name && selectedHazardType), save: saveNewHazard, toggleVisibility: toggle, visible: isVisible, loading: loading },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "hazards" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Hazard Name",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, { onChange: (e) => setName(e.target.value), value: name })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Hazard Type",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_4__.ClssDropdown, { items: hazardTypes, item: selectedHazardType, deletable: false, setItem: setSelectedHazardType })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true }, "Description of Hazard (Optional)"),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextArea, { value: description, onChange: (e) => setDescription(e.target.value) })))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-add-organization.tsx":
/*!**********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-add-organization.tsx ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "AddOrganizatonWidget": () => (/* binding */ AddOrganizatonWidget)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_modal__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./clss-modal */ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx");
/* harmony import */ var _clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./clss-organizations-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};









const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_5__.ReactRedux;
const AddOrganizatonWidget = ({ propsConfig, visible, toggle, setOrganization }) => {
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [isVisible, setVisible] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [organizationName, setOrganizationName] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [organizationTypes, setOrganizationTypes] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState([]);
    const [selectedOrganizationType, setSelectedOrganizationType] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const [selectedParentOrganization, setSelectedParentOrganization] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const [config, setConfig] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    const organizations = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.organizations;
    });
    const credential = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.authenticate;
    });
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setVisible(visible);
        setOrganizationName('');
        setSelectedOrganizationType(null);
    }, [visible]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (credential) {
            setConfig(Object.assign(Object.assign({}, propsConfig), { credential }));
        }
    }, [credential]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (organizations && organizations.length > 0) {
            const types = organizations[1].domains;
            types === null || types === void 0 ? void 0 : types.orderBy('name');
            setOrganizationTypes(types);
        }
    }, [organizations]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setSelectedParentOrganization(organizations[0]);
    }, [organizations]);
    const save = () => __awaiter(void 0, void 0, void 0, function* () {
        const exists = organizations.find(o => o.name === organizationName);
        if (exists) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.SET_ERRORS, `Organization: ${organizationName} already exists`);
            return;
        }
        setLoading(true);
        try {
            let newOrganization = {
                name: organizationName,
                title: organizationName,
                type: selectedOrganizationType,
                parentId: selectedParentOrganization.id !== '000' ? selectedParentOrganization.id : null
            };
            const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.saveOrganization)(config, newOrganization);
            console.log(response);
            if (response.errors) {
                throw new Error(String(response.errors));
            }
            newOrganization = response.data;
            newOrganization.domains = organizations[1].domains;
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.LOAD_ORGANIZATIONS_ACTION, [...organizations, newOrganization]);
            setOrganization(response.data);
            toggle(false);
        }
        catch (err) {
            console.log(err);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_2__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_3__.CLSSActionKeys.SET_ERRORS, err.message);
        }
        finally {
            setLoading(false);
        }
    });
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_modal__WEBPACK_IMPORTED_MODULE_6__.ClssModal, { title: "Add New Organization", disable: !(organizationName && selectedOrganizationType), save: save, loading: loading, toggleVisibility: toggle, visible: isVisible },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "add-organization" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `
                        .add-organization{
                           display: flex;
                           flex-direction: column
                         }                         
                     `),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Organization Name",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, { "data-testid": "txtOrganizationName", size: "default", onChange: (e) => setOrganizationName(e.target.value), value: organizationName })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Organization Type",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_4__.ClssDropdown, { items: organizationTypes, item: selectedOrganizationType, deletable: false, setItem: setSelectedOrganizationType })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true }, "Organization's Parent (Optional)"),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_7__.OrganizationsDropdown, { config: config, toggleNewOrganizationModal: null, organizations: organizations, selectedOrganization: selectedParentOrganization, setOrganization: setSelectedParentOrganization, vertical: false })))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-add-template.tsx":
/*!******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-add-template.tsx ***!
  \******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "AddTemplateWidget": () => (/* binding */ AddTemplateWidget)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_templates_dropdown__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./clss-templates-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-templates-dropdown.tsx");
/* harmony import */ var _clss_hazards_dropdown__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./clss-hazards-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-hazards-dropdown.tsx");
/* harmony import */ var _clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./clss-organizations-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx");
/* harmony import */ var _clss_modal__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./clss-modal */ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};










const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_2__.ReactRedux;
const AddTemplateWidget = (props) => {
    const [error, setError] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [isVisible, setVisibility] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(props.visible);
    const [templateName, setTemplateName] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [selectedBasedOnTemplate, setSelectedBasedOnTemplate] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(null);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setVisibility(props.visible);
    }, [props]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        if (props.templates && props.templates.length === 1) {
            setSelectedBasedOnTemplate(props.templates[0]);
        }
    }, [props]);
    const saveNewTemplate = () => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        const exist = props.templates.find(t => t.name.toLowerCase().trim() === templateName.toLowerCase().trim());
        if (exist) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_4__.CLSSActionKeys.SET_ERRORS, `Template: ${templateName} already exists`);
            return;
        }
        setLoading(true);
        let newTemplate = Object.assign(Object.assign({}, selectedBasedOnTemplate), { name: templateName, title: templateName });
        let organization = null;
        if (props.selectedOrganization &&
            props.selectedOrganization.title !== '-None-') {
            organization = props.selectedOrganization;
        }
        let hazard = null;
        if (props.selectedHazard && props.selectedHazard.title !== '-None-') {
            hazard = props.selectedHazard;
        }
        const start = new Date().getTime();
        const resp = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.createNewTemplate)(props.config, newTemplate, (_a = props.user) === null || _a === void 0 ? void 0 : _a.userName, organization, hazard);
        console.log('Create Template Took', new Date().getTime() - start);
        setLoading(false);
        if (resp.errors) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_4__.CLSSActionKeys.SET_ERRORS, resp.errors);
            return;
        }
        props.saveTemplateCompleteCallback();
        setLoading(false);
        props.toggleVisibility(false);
    });
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_modal__WEBPACK_IMPORTED_MODULE_8__.ClssModal, { title: "Add New Template", disable: !(templateName && selectedBasedOnTemplate && !error), save: saveNewTemplate, loading: loading, toggleVisibility: props.toggleVisibility, visible: isVisible },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "new-template" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `                    
                      .new-template{
                        display: flex;
                        flex-direction: column;
                      }                      
                      .new-template .add-link {
                        width: 207px;
                        margin-left: -16px;
                      }
                    `),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Template Name",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, { "data-testid": "txtTemplateName", className: "template-input", size: "default", onChange: (e) => setTemplateName(e.target.value), value: templateName })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true },
                    "Base Template On",
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("span", { style: { color: 'red' } }, "*")),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_templates_dropdown__WEBPACK_IMPORTED_MODULE_5__.TemplatesDropdown, { templates: props.templates, selectedTemplate: selectedBasedOnTemplate, setTemplate: setSelectedBasedOnTemplate })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true }, "Template Hazard (Optional)"),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_hazards_dropdown__WEBPACK_IMPORTED_MODULE_6__.HazardsDropdown, { config: props.config, hazards: props.hazards, selectedHazard: props.selectedHazard, setHazard: props.setHazard, vertical: true, toggleNewHazardModal: props.toggleNewHazardModal })),
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "modal-item" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true }, "Template Organization (Optional)"),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_7__.OrganizationsDropdown, { config: props.config, vertical: true, organizations: props.organizations, selectedOrganization: props.selectedOrganization, setOrganization: props.setOrganization, toggleNewOrganizationModal: props.toggleNewOrganizationModal })))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx":
/*!**************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ClssDropdown": () => (/* binding */ ClssDropdown)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-icons/outlined/editor/trash */ "./jimu-icons/outlined/editor/trash.tsx");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! react */ "react");



const ClssDropdown = ({ items, item, deletable, setItem, deleteItem, menuWidth }) => {
    const buttonElement = react__WEBPACK_IMPORTED_MODULE_2__["default"].useRef();
    react__WEBPACK_IMPORTED_MODULE_2__["default"].useEffect(() => {
        if (items && items.length > 0) {
            if (!item) {
                setItem(items[0]);
            }
            else {
                setItem(item);
            }
        }
    }, [items]);
    const itemClick = (item) => {
        setItem(item);
        if (buttonElement && buttonElement.current) {
            buttonElement.current.click();
        }
    };
    const removeItem = (item) => {
        if (confirm('Remove ' + (item.title || item.name))) {
            deleteItem(item);
        }
    };
    return (react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement("div", { className: "clss-dropdown-container", style: { width: '100%' } },
        react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement("style", null, `
                  .dropdown-item-container{
                    height: 45px;
                    border-bottom: 1px solid rgb(227, 227, 227);
                    width: 100%;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                  }
                  .dropdown-item-container:hover{
                    background-color: rgb(227, 227, 227);
                  }
                  .jimu-dropdown-menu{
                    width: 35%;
                    max-height: 500px;
                    overflow: auto;
                  }
                  .jimu-dropdown-menu .dropdown-item-container:last-child{
                    border-bottom: none;
                  }
                  .modal-content .clss-dropdown-container button{
                    width: 100%;
                  }
                  .clss-dropdown-container .jimu-dropdown{
                    width: 100%;
                  }
                  .close-button{
                    margin: 10px;
                    color: gray;
                  }

                  .modal-content .clss-dropdown-container button span{
                     line-height: 30px !important;
                  }
                 
                  .dropdown-item-container label{
                    width: 100%;
                    height: 100%;
                    display: flex;
                    align-items: center;
                    font-size: 1.2em;
                    margin-left: 1em;
                    cursor: pointer;
                  }
                 `),
        react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Dropdown, { activeIcon: "true", size: "lg" },
            react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.DropdownButton, { className: "dropdownButton", ref: buttonElement, size: "lg", style: { textAlign: 'left' } }, (item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)),
            react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.DropdownMenu, { style: { width: menuWidth || "30%" } }, items === null || items === void 0 ? void 0 : items.map((item, idx) => {
                return (react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement("div", { id: (item === null || item === void 0 ? void 0 : item.name) || (item === null || item === void 0 ? void 0 : item.title), className: "dropdown-item-container" },
                    react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true, onClick: () => itemClick(item) }, (item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)),
                    (((item === null || item === void 0 ? void 0 : item.title) || (item === null || item === void 0 ? void 0 : item.name)) !== '-None-') && deletable ?
                        (react__WEBPACK_IMPORTED_MODULE_2__["default"].createElement(jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_1__.TrashOutlined, { title: 'Remove', className: "close-button", size: 20, onClick: () => removeItem(item) }))
                        : null));
            })))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-hazards-dropdown.tsx":
/*!**********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-hazards-dropdown.tsx ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "HazardsDropdown": () => (/* binding */ HazardsDropdown)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_outlined_editor_plus_circle__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/outlined/editor/plus-circle */ "./jimu-icons/outlined/editor/plus-circle.tsx");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};






const HazardsDropdown = ({ config, hazards, selectedHazard, setHazard, vertical, toggleNewHazardModal }) => {
    const [localHazards, setLocalHazards] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState([]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (hazards) {
            setLocalHazards([...hazards]);
        }
    }, [hazards]);
    const removeHazard = (hazard) => __awaiter(void 0, void 0, void 0, function* () {
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__.deleteHazard)(hazard, config);
        if (response.errors) {
            console.log(response.errors);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_ERRORS, response.errors);
            return;
        }
        console.log(`${hazard.title} deleted`);
        setLocalHazards([...localHazards.filter(h => h.id !== hazard.id)]);
    });
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { style: { display: vertical ? 'block' : 'flex',
            alignItems: 'center' } },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("style", null, `
                     .action-icon {
                        color: gray;
                        cursor: pointer;
                      }
                    `),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_1__.ClssDropdown, { items: localHazards, item: selectedHazard, deletable: true, setItem: setHazard, deleteItem: removeHazard }),
        vertical ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_2__.Button, { "data-testid": "btnShowAddOrganization", className: " add-link", type: "link", style: { textAlign: 'left' }, onClick: () => toggleNewHazardModal(true) }, "Add New Hazard")) : (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_outlined_editor_plus_circle__WEBPACK_IMPORTED_MODULE_3__.PlusCircleOutlined, { className: "action-icon", "data-testid": "btnAddNewHazard", title: "Add New Hazard", size: 30, color: 'gray', onClick: () => toggleNewHazardModal(true) }))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx":
/*!*************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-loading.tsx ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");


const ClssLoading = ({ message }) => {
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { style: {
            height: '100%',
            width: '100%',
            position: 'absolute',
            background: 'rgb(0 0 0 / 13%)',
            top: 0,
            left: 0,
            zIndex: 999999,
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center'
        } },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Loading, { className: "", type: "SECONDARY" }),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h3", null, message)));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (ClssLoading);


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx":
/*!***********************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-modal.tsx ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "ClssModal": () => (/* binding */ ClssModal)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_loading__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");



// export interface ModalProps {
//     title: string;
//     visible: boolean;
//     disable: boolean;
//     children: any;
//     toggleVisibility: Function;
//     save: Function;
//     cancel: Function;
// }
const ClssModal = (props) => {
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Modal, { isOpen: props.visible, centered: true, className: "clss-modal" },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("style", null, `
                        .clss-modal .modal-content{
                          font-size: 1.3rem;
                          display: flex;
                          flex-direction: column
                        }              
                        .clss-modal .modal-title{
                            font-size: 1.1em;
                        }         
                        .clss-modal input{
                            padding-left: 0px;
                        }                   
                        .clss-modal .jimu-input span{
                            height: 40px;
                            font-size: .9em;
                        }                         
                        .clss-modal label{
                            color: gray;
                        }    
                        .clss-modal .jimu-dropdown-button{
                            font-size: 1em;
                        }    
                        .clss-modal .modal-item{
                            margin: 10px 0;
                        }   
                        .clss-modal textarea{
                            font-size: 0.8em;
                        }  
                        .clss-modal .spacer{
                            width: 1em;
                        }
                    `),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.ModalHeader, { toggle: () => props.toggleVisibility(false) }, props.title),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.ModalBody, null, props.children),
        props.hideFooter && props.hideFooter == true ? null :
            (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.ModalFooter, null,
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Button, { onClick: () => (props.cancel ? props.cancel() : props.toggleVisibility(false)) }, props.noButtonTitle || 'Cancel'),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: "spacer" }),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Button, { "data-testid": "btnSave", disabled: props.disable, onClick: () => props.save() }, props.yesButtonTitle || 'Save'))),
        (props.loading) ? react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_loading__WEBPACK_IMPORTED_MODULE_2__["default"], null) : null));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx":
/*!****************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx ***!
  \****************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "OrganizationsDropdown": () => (/* binding */ OrganizationsDropdown)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_outlined_editor_plus_circle__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/outlined/editor/plus-circle */ "./jimu-icons/outlined/editor/plus-circle.tsx");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};






const OrganizationsDropdown = ({ config, organizations, selectedOrganization, setOrganization, vertical, toggleNewOrganizationModal }) => {
    const [localOrganizations, setLocalOrganizations] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState([]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (organizations) {
            setLocalOrganizations([...organizations]);
        }
    }, [organizations]);
    const removeOrganization = (organization) => __awaiter(void 0, void 0, void 0, function* () {
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__.deleteOrganization)(organization, config);
        if (response.errors) {
            console.log(response.errors);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_4__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_ERRORS, response.errors);
            return;
        }
        console.log(`${organization.title} deleted`);
        setLocalOrganizations([...localOrganizations.filter(o => o.id !== organization.id)]);
    });
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { style: { display: vertical ? 'block' : 'flex',
            alignItems: 'center' } },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_1__.ClssDropdown, { items: localOrganizations, item: selectedOrganization, deletable: true, setItem: setOrganization, deleteItem: removeOrganization }),
        toggleNewOrganizationModal ? (vertical ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_2__.Button, { "data-testid": "btnShowAddOrganization", className: " add-link", type: "link", style: { textAlign: 'left' }, onClick: () => toggleNewOrganizationModal(true) }, "Add New Organization")) : (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_outlined_editor_plus_circle__WEBPACK_IMPORTED_MODULE_3__.PlusCircleOutlined, { className: "action-icon", "data-testid": "btnAddNewOrganization", title: "Add New Organization", size: 30, color: 'gray', onClick: () => toggleNewOrganizationModal(true) }))) : null));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-search-template.tsx":
/*!*********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-search-template.tsx ***!
  \*********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CLSSSearchInput": () => (/* binding */ CLSSSearchInput)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");


const CLSSSearchInput = ({ title, onChange, defaultValue, props }) => {
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h4", { style: {
            width: '100%'
        } },
        title,
        ":",
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, Object.assign({ style: { fontSize: props.theme.typography.sizes.display4 }, "data-testid": 'templateSearchInput', placeholder: 'Search...', size: 'lg', allowClear: true, type: "text", value: defaultValue, onChange: (e) => onChange(e.target.value) }, props))));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-template-button.tsx":
/*!*********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-template-button.tsx ***!
  \*********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "TemplateButton": () => (/* binding */ TemplateButton)
/* harmony export */ });
/* harmony import */ var jimu_icons_outlined_application_setting__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-icons/outlined/application/setting */ "./jimu-icons/outlined/application/setting.tsx");
/* harmony import */ var jimu_icons_outlined_suggested_success__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-icons/outlined/suggested/success */ "./jimu-icons/outlined/suggested/success.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_icons_outlined_application_folder__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-icons/outlined/application/folder */ "./jimu-icons/outlined/application/folder.tsx");





const TemplateButton = ({ template, onClick, onDblClick, props }) => {
    var _a;
    const onDoubleClick = () => {
        // if(props.user.groups.find(g => g.title === CLSS_ADMIN) &&
        // template.name !== BASELINE_TEMPLATE_NAME){
        //     if(confirm('Archive the template?') == true){
        //         onDblClick(template.objectId);
        //     }
        // }
    };
    return (react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement("div", { "data-testid": "templateButton", className: "button-wrapper", onDoubleClick: onDoubleClick, onClick: () => onClick(template.objectId), style: {
            backgroundColor: (template.isSelected
                ? props.config.selectedButtonBackgroundColor
                : props.config.defaultButtonBackgroundColor)
        } },
        react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement("style", null, `
                    .button-wrapper{
                        display: flex;
                        border-radius: 10px;
                        width: 100%;
                        align-items: center;
                        font-size: 15px;
                        padding: 10px;
                        cursor: pointer;
                        justify-content: space-between;
                        margin: 5px 0;
                    }
                    .button-wrapper:hover{
                        opacity: 0.5;
                    }
                    .button-content{
                        display: flex;
                        justify-content:space-between;
                        align-items: center;
                    }
                    .button-label{
                        cursor: pointer;                        
                        width: 180px;
                        white-space: nowrap;
                        overflow: hidden;
                        text-overflow: ellipsis;
                        margin-bottom: 0 !important;
                    }
                    .pre-icon{
                        margin-right: 10px;
                    }
                `),
        react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement("div", { className: "button-content" },
            ((_a = template === null || template === void 0 ? void 0 : template.status) === null || _a === void 0 ? void 0 : _a.code) === 1 ? (react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement(jimu_icons_outlined_application_setting__WEBPACK_IMPORTED_MODULE_0__.SettingOutlined, { className: 'pre-icon', size: 20, color: template.isSelected
                    ? props.config.selectedButtonColor
                    : 'gray' })) :
                (react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement(jimu_icons_outlined_application_folder__WEBPACK_IMPORTED_MODULE_4__.FolderOutlined, { className: 'pre-icon', size: 15, color: template.isSelected
                        ? props.config.selectedButtonColor
                        : 'gray' })),
            react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_2__.Label, { style: {
                    color: template.isSelected
                        ? props.config.selectedButtonColor
                        : props.config.defaultTemplateButtonColor
                }, className: 'button-label' }, template.name)),
        template.isSelected ? react__WEBPACK_IMPORTED_MODULE_3__["default"].createElement(jimu_icons_outlined_suggested_success__WEBPACK_IMPORTED_MODULE_1__.SuccessOutlined, { className: 'post-icon', size: 20, color: props.config.selectedButtonColor }) : null));
};


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-templates-dropdown.tsx":
/*!************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-templates-dropdown.tsx ***!
  \************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "TemplatesDropdown": () => (/* binding */ TemplatesDropdown)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_dropdown__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");


const TemplatesDropdown = ({ templates, selectedTemplate, setTemplate }) => {
    const deleteTemplate = () => {
    };
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_dropdown__WEBPACK_IMPORTED_MODULE_1__.ClssDropdown, { items: templates, item: selectedTemplate, deletable: true, setItem: setTemplate, deleteItem: deleteTemplate }));
};


/***/ }),

/***/ "jimu-arcgis":
/*!******************************!*\
  !*** external "jimu-arcgis" ***!
  \******************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_arcgis__;

/***/ }),

/***/ "jimu-core":
/*!****************************!*\
  !*** external "jimu-core" ***!
  \****************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_core__;

/***/ }),

/***/ "react":
/*!**********************************!*\
  !*** external "jimu-core/react" ***!
  \**********************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_react__;

/***/ }),

/***/ "jimu-ui":
/*!**************************!*\
  !*** external "jimu-ui" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = __WEBPACK_EXTERNAL_MODULE_jimu_ui__;

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/publicPath */
/******/ 	(() => {
/******/ 		__webpack_require__.p = "";
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other entry modules.
(() => {
/*!******************************************!*\
  !*** ./jimu-core/lib/set-public-path.ts ***!
  \******************************************/
/**
 * Webpack will replace __webpack_public_path__ with __webpack_require__.p to set the public path dynamically.
 * The reason why we can't set the publicPath in webpack config is: we change the publicPath when download.
 * */
// eslint-disable-next-line
// @ts-ignore
__webpack_require__.p = window.jimuConfig.baseUrl;

})();

// This entry need to be wrapped in an IIFE because it need to be in strict mode.
(() => {
"use strict";
/*!***********************************************************************!*\
  !*** ./your-extensions/widgets/clss-templates/src/runtime/widget.tsx ***!
  \***********************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_custom_components_clss_search_template__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../clss-custom-components/clss-search-template */ "./your-extensions/widgets/clss-custom-components/clss-search-template.tsx");
/* harmony import */ var _clss_custom_components_clss_template_button__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../clss-custom-components/clss-template-button */ "./your-extensions/widgets/clss-custom-components/clss-template-button.tsx");
/* harmony import */ var _clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../../clss-custom-components/clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../clss-application/src/extensions/constants */ "./your-extensions/widgets/clss-application/src/extensions/constants.ts");
/* harmony import */ var _clss_custom_components_clss_add_template__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-template */ "./your-extensions/widgets/clss-custom-components/clss-add-template.tsx");
/* harmony import */ var _clss_custom_components_clss_add_organization__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-organization */ "./your-extensions/widgets/clss-custom-components/clss-add-organization.tsx");
/* harmony import */ var _clss_custom_components_clss_add_hazard__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-hazard */ "./your-extensions/widgets/clss-custom-components/clss-add-hazard.tsx");
/* harmony import */ var _clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../../../clss-application/src/extensions/utils */ "./your-extensions/widgets/clss-application/src/extensions/utils.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};












const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_0__.ReactRedux;
const Widget = (props) => {
    var _a, _b, _c;
    const [loading, setLoading] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [isAddTemplateModalVisible, setAddTemplateModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [isAddOrganizationModalVisible, setAddOrganizationModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [isAddHazardModalVisible, setAddHazardModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [selectedHazard, setSelectedHazard] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [selectedOrganization, setSelectedOrganization] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [searchResult, setSearchResults] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState([]);
    const [config, setConfig] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [selectedFilter, setSelectedFilter] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState('All');
    const [searchText, setSearchText] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState('');
    const state = useSelector((state) => {
        return state.clssState;
    });
    const user = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.user;
    });
    const credential = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.authenticate;
    });
    const errors = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.errors;
    });
    const templates = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.templates;
    });
    const hazards = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.hazards;
    });
    const organizations = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.organizations;
    });
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.initializeAuth)(props.config.appId);
    }, []);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (config) {
            if (!hazards || hazards.length === 0) {
                const start = new Date().getTime();
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.getHazards)(config, '1=1', 'clss-templates')
                    .then((hazards) => {
                    if (hazards && hazards.length > 0) {
                        hazards.orderBy('name');
                        hazards.unshift(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.DEFAULT_LISTITEM);
                        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.LOAD_HAZARDS_ACTION, hazards);
                    }
                    console.log('Hazards took: ' + (new Date().getTime() - start) + " ms");
                });
            }
        }
    }, [config]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (config) {
            if (!organizations || organizations.length === 0) {
                const start = new Date().getTime();
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.getOrganizations)(config, '1=1')
                    .then((organizations) => {
                    if (organizations && organizations.length > 0) {
                        organizations.orderBy('name');
                        organizations.unshift(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.DEFAULT_LISTITEM);
                        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.LOAD_ORGANIZATIONS_ACTION, organizations);
                    }
                    console.log('Organizations took: ' + (new Date().getTime() - start) + " ms");
                });
            }
        }
    }, [config]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (credential) {
            setConfig(Object.assign(Object.assign({}, props.config), { credential: credential }));
        }
    }, [credential]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (config) {
            loadTemplates();
        }
    }, [config]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (errors) {
            alert(errors);
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_ERRORS, '');
        }
    }, [errors]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        var _a, _b, _c, _d, _e;
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_USER_ACTION, {
            userName: (_a = props.user) === null || _a === void 0 ? void 0 : _a.username,
            firstName: (_b = props.user) === null || _b === void 0 ? void 0 : _b.firstName,
            lastName: (_c = props.user) === null || _c === void 0 ? void 0 : _c.lastName,
            groups: (_e = (_d = props.user) === null || _d === void 0 ? void 0 : _d.groups) === null || _e === void 0 ? void 0 : _e.map(g => g.title)
        });
    }, [props.user]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (templates && templates.length > 0) {
            filterSelectionChange(selectedFilter, templates);
        }
    }, [templates]);
    const loadTemplates = () => __awaiter(void 0, void 0, void 0, function* () {
        setLoading(true);
        const start = new Date().getTime();
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.getTemplates)(config, null, null);
        console.log('Templates Took', new Date().getTime() - start);
        setLoading(false);
        if (response.errors) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.SET_ERRORS, response.errors);
            return;
        }
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.LOAD_TEMPLATES_ACTION, response.data);
        yield filterSelectionChange(selectedFilter, response.data);
    });
    const performSearch = (text) => {
        setSearchText(text);
        let copiedTemplates = [...templates];
        if (!text || text === '' || text === null) {
            return (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.sortObject)(copiedTemplates, 'createdDate');
        }
        let searchResults = copiedTemplates.filter(t => {
            var _a, _b, _c, _d, _e, _f, _g, _h;
            return ((_a = t.name) === null || _a === void 0 ? void 0 : _a.toLocaleLowerCase().includes(text.toLocaleLowerCase())) ||
                ((_b = t.organizationName) === null || _b === void 0 ? void 0 : _b.toLocaleLowerCase().includes(text.toLocaleLowerCase())) ||
                ((_c = t.hazardName) === null || _c === void 0 ? void 0 : _c.toLocaleLowerCase().includes(text.toLocaleLowerCase())) ||
                ((_d = t.hazardType) === null || _d === void 0 ? void 0 : _d.toLocaleLowerCase().includes(text.toLocaleLowerCase())) ||
                ((_e = (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.parseDate)(t.createdDate)) === null || _e === void 0 ? void 0 : _e.split(',')[0].trim()) == text ||
                ((_f = (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.parseDate)(t.createdDate)) === null || _f === void 0 ? void 0 : _f.includes(text)) ||
                ((_g = (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.parseDate)(t.editedDate)) === null || _g === void 0 ? void 0 : _g.includes(text)) ||
                ((_h = (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.parseDate)(t.editedDate)) === null || _h === void 0 ? void 0 : _h.split(',')[0].trim()) == text;
        });
        return (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_11__.sortObject)(searchResults, 'createdDate');
    };
    const onSearchTemplates = (text) => {
        filterSelectionChange(selectedFilter, performSearch(text));
    };
    const onSelectTemplate = (objectId) => __awaiter(void 0, void 0, void 0, function* () {
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_6__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_5__.CLSSActionKeys.LOAD_TEMPLATES_ACTION, templates.map(t => {
            return Object.assign(Object.assign({}, t), { isSelected: t.objectId === objectId });
        }));
        if (templates.find(t => t.objectId === objectId).status.code !== 1) {
            return;
        }
        //await selectTemplate(objectId, templates.map(t => t.objectId), config); 
    });
    const onArchiveTemplate = (objectId) => __awaiter(void 0, void 0, void 0, function* () {
        // setLoading(true);
        // const res = await archiveTemplate(objectId, props.config);
        // if(!res.errors && res.data){
        //   await loadTemplates();
        // }  
        // setLoading(false);
    });
    const saveTemplate = () => __awaiter(void 0, void 0, void 0, function* () {
        yield loadTemplates();
        setAddTemplateModalVisibility(false);
    });
    const selectFilter = (id) => {
        filterSelectionChange(id, performSearch(searchText));
    };
    const filterSelectionChange = (id, _templates) => __awaiter(void 0, void 0, void 0, function* () {
        if (_templates == null) {
            return;
        }
        setSelectedFilter(id);
        switch (id) {
            case 'All':
                setSearchResults([..._templates]);
                break;
            case 'Selected':
                setSearchResults(_templates.filter(t => t.isSelected));
                break;
            case 'Active':
                setSearchResults(_templates.filter(t => t.status.code === 1));
                break;
            case 'Archived':
                setSearchResults(_templates.filter(t => t.status.code === 0));
                break;
        }
    });
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-clss-templates-container jimu-widget", style: {
            backgroundColor: props.theme.surfaces[2].bg
        } },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
          .widget-clss-templates-container{       
            overflow: hidden; 
          }
          .search-templates{
              width: 100%;
              flex: 1;
              padding-bottom: 10px;
              overflow-y: auto;
              overflow-x: hidden;
          }
          .clss-templates-header{
            height: 50px;
            display: flex;
            justify-content: center;
            align-items: center;               
          }
          .template-buttons-content{
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding: 20px 10px;
            height: calc(100% - 50px);
            
          }
          .create-assessment-button{               
            height: 65px;
            width: 100%;
            font-weight: bold;
            font-size: 1.5em;
            border-radius: 5px;
            line-height: 1.5em;
          }
          .create-assessment-button:hover{
              opacity: 0.8
          }
          .create-new-template{
            height: 50px;
            font-weight: bold;
          }
          .create-new-template:hover{
            opacity: .8
          }          
          .widget-clss-templates-container .editor-icon{                    
            color: #534c4c;
            cursor: pointer;
            margin: 10px;
          }
          .widget-clss-templates-container .editor-icon:hover{
            opacity: .8
          }
          .widget-clss-templates-container .save-cancel, 
          .widget-clss-templates-container .save-icon{
            position: absolute;
            right: 10px;
            top: 10px;
          }
          .widget-clss-templates-container .data-dropdown, 
          .widget-clss-templates-container .data-input{
            width: 100%;
            display: flex;
          }
          .widget-clss-templates-container .data-dropdown 
          .widget-clss-templates-container .jimu-dropdown{
            width: 300px;
          }
          .widget-clss-templates-container .data-dropdown-menu{
            width: 300px;
          }
          .widget-clss-templates-container .error{
            color: red;
            font-size: 15px;
          }
          .widget-clss-templates-container .dropdown-item{
              font-size: 1.3em;
          }
          .widget-clss-templates-container .organization{
            display: flex;
            flex-direction: column;
          }
          .widget-clss-templates-container .end-widget{
            margin-bottom: 15px;
          }
          .widget-clss-templates-container .data-input{
            width: 30.7%
          }
          .widget-clss-templates-container .title.template{
            width: 142px;
          }

          .widget-clss-templates-container td label, 
          .widget-clss-templates-container td input{ 
            font-size: 1.5em;
          }
          .widget-clss-templates-container td label{
            width: 128px;
          }
          .widget-clss-templates-container td label.value{
            font-weight: bold;
            width: auto;
          }
          .widget-clss-templates-container tr.td-under>td{
            padding-bottom: 1em;
          }
          .widget-clss-templates-container  .template-input input{
            padding-left: 20px;
            height: 40px;
            font-size: 16px;
          }
          .widget-clss-templates-container  .template-input span{
            height: 40px !important;
          }
          .template-filter-actions .actions{
            display: flex;
            justify-content: space-around;
            align-items: center;
          }
          .template-filter-actions .jimu-checkbox{
            margin-right: 10px;
          }
        `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "clss-templates-header", style: {
                backgroundColor: props.config.headerBackgroundColor || props.theme.colors.secondary,
                color: props.config.headerTextColor || props.theme.colors.palette.primary[900],
                boxShadow: props.theme.boxShadows.default,
                fontSize: props.theme.typography.sizes.display3,
                fontWeight: props.theme.typography.weights.bold
            } },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { check: true }, "Templates")),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'template-buttons-content' },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "template-filter-actions" },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h4", null, "Filter templates by:"),
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "actions", "aria-label": "Filter templates by", role: "group" },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { centric: true },
                        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Checkbox, { id: 'All', "aria-label": "Checkbox", checked: selectedFilter === 'All', onChange: (e) => selectFilter(e.target.id) }),
                        "All"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { centric: true },
                        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Checkbox, { id: 'Active', "aria-label": "Checkbox", checked: selectedFilter === 'Active', onChange: (e) => selectFilter(e.target.id) }),
                        "Active"),
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { centric: true, check: true },
                        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Checkbox, { id: 'Archived', "aria-label": "Checkbox", checked: selectedFilter === 'Archived', onChange: (e) => selectFilter(e.target.id) }),
                        "Archived"))),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'search-templates' },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_search_template__WEBPACK_IMPORTED_MODULE_2__.CLSSSearchInput, { title: 'Search Templates', onChange: onSearchTemplates, props: props }), searchResult === null || searchResult === void 0 ? void 0 :
                searchResult.map((temp) => {
                    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_template_button__WEBPACK_IMPORTED_MODULE_3__.TemplateButton, { key: temp.id, props: props, template: temp, onClick: () => onSelectTemplate(temp.objectId), onDblClick: onArchiveTemplate }));
                })),
            (user && ((_a = user.groups) === null || _a === void 0 ? void 0 : _a.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.CLSS_ADMIN)) ||
                user && ((_b = user.groups) === null || _b === void 0 ? void 0 : _b.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.CLSS_EDITOR)) ||
                user && ((_c = user.groups) === null || _c === void 0 ? void 0 : _c.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_7__.CLSS_FOLLOWERS))) ?
                (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Button, { "data-testid": "btnCreateNewTemplate", className: 'create-new-template', style: { background: props.config.headerBackgroundColor }, size: 'lg', onClick: () => setAddTemplateModalVisibility(true) }, "Create Template")) : null,
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_template__WEBPACK_IMPORTED_MODULE_8__.AddTemplateWidget, { config: config, hazards: hazards, selectedHazard: selectedHazard, setHazard: setSelectedHazard, selectedOrganization: selectedOrganization, organizations: organizations, setOrganization: setSelectedOrganization, templates: templates, user: user, visible: isAddTemplateModalVisible, toggleVisibility: setAddTemplateModalVisibility, saveTemplateCompleteCallback: saveTemplate, toggleNewHazardModal: setAddHazardModalVisibility, toggleNewOrganizationModal: setAddOrganizationModalVisibility }),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_organization__WEBPACK_IMPORTED_MODULE_9__.AddOrganizatonWidget, { propsConfig: props === null || props === void 0 ? void 0 : props.config, visible: isAddOrganizationModalVisible, setOrganization: setSelectedOrganization, toggle: setAddOrganizationModalVisibility }),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_hazard__WEBPACK_IMPORTED_MODULE_10__.AddHazardWidget, { props: props, visible: isAddHazardModalVisible, setHazard: setSelectedHazard, toggle: setAddHazardModalVisibility })),
        loading ? jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_4__["default"], null) : null));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Widget);

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXRlbXBsYXRlcy9kaXN0L3J1bnRpbWUvd2lkZ2V0LmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQ0E7QUFDaUM7QUFDcUY7QUFDckU7QUFDTjtBQUN5QjtBQUNWO0FBQzFEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVksY0FBYztBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGNBQWMsbUVBQVE7QUFDdEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQixlQUFlO0FBQ2pDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLDhCQUE4QjtBQUM5QjtBQUNBO0FBQ0E7QUFDQSxpQkFBaUIsK0NBQVE7QUFDekI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsOEJBQThCLDRFQUFpQjtBQUMvQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxtQ0FBbUMsc0VBQWU7QUFDbEQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGlCQUFpQjtBQUNqQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSw4QkFBOEI7QUFDOUIsaUJBQWlCLCtDQUFRLEdBQUcsNERBQTREO0FBQ3hGO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLDBCQUEwQixzRUFBZTtBQUN6QztBQUNBO0FBQ0EsMEJBQTBCLHNFQUFlO0FBQ3pDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxhQUFhO0FBQ2I7QUFDQSxxQkFBcUIsNEVBQWlCO0FBQ3RDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esb0NBQW9DLDBDQUEwQztBQUM5RTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxxQ0FBcUMsdUNBQXVDO0FBQzVFLFNBQVM7QUFDVDtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxpQkFBaUIsK0NBQVEsR0FBRyw4REFBOEQ7QUFDMUY7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxpQkFBaUIsK0NBQVE7QUFDekI7QUFDQTtBQUNBLFNBQVM7QUFDVCxlQUFlLHdEQUFVO0FBQ3pCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxhQUFhO0FBQ2IsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxhQUFhO0FBQ2IsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQUFRO0FBQ1I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGtFQUFrRTtBQUNsRTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHVDQUF1QztBQUN2QyxVQUFVO0FBQ1Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsMEJBQTBCLCtDQUFRLENBQUMsK0NBQVEsR0FBRyx5Q0FBeUMscUJBQXFCLG9CQUFvQjtBQUNoSSx1Q0FBdUMsa0VBQU87QUFDOUM7QUFDQTtBQUNBO0FBQ0EsYUFBYTtBQUNiO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHFDQUFxQztBQUNyQyxVQUFVO0FBQ1Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsMEJBQTBCLCtDQUFRLENBQUMsK0NBQVEsR0FBRyx5Q0FBeUMscUJBQXFCLG9CQUFvQjtBQUNoSSx5Q0FBeUMsa0VBQU87QUFDaEQ7QUFDQTtBQUNBO0FBQ0EsYUFBYTtBQUNiO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGtDQUFrQztBQUNsQyxVQUFVO0FBQ1Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsYUFBYTtBQUNiO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsWUFBWSxvRUFBaUI7QUFDN0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLG1CQUFtQix1RUFBaUI7QUFDcEMsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esa0NBQWtDLHNFQUFlO0FBQ2pEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsbUJBQW1CLG1FQUFRO0FBQzNCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsK0NBQStDO0FBQy9DO0FBQ0E7QUFDQTtBQUNBLDRCQUE0QjtBQUM1QjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EseUJBQXlCO0FBQ3pCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsbUJBQW1CLGtFQUFPO0FBQzFCO0FBQ0EsYUFBYTtBQUNiO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EseUJBQXlCLDhEQUFXO0FBQ3BDLGtDQUFrQyxzRUFBZTtBQUNqRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsK0JBQStCLGtFQUFPO0FBQ3RDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EscUJBQXFCO0FBQ3JCO0FBQ0E7QUFDQSw4QkFBOEIsc0VBQWU7QUFDN0M7QUFDQSxhQUFhO0FBQ2I7QUFDQTtBQUNBLGFBQWE7QUFDYjtBQUNBO0FBQ0E7QUFDQSwyQkFBMkIsOERBQWE7QUFDeEM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHlCQUF5QjtBQUN6QixxQkFBcUI7QUFDckI7QUFDQTtBQUNBO0FBQ0EsMkJBQTJCLDhEQUFhO0FBQ3hDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSx5QkFBeUI7QUFDekIscUJBQXFCO0FBQ3JCO0FBQ0E7QUFDQTtBQUNBLHFCQUFxQjtBQUNyQjtBQUNBLGFBQWE7QUFDYjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGFBQWE7QUFDYixTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxhQUFhO0FBQ2I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esc0JBQXNCLCtDQUFRLEdBQUc7QUFDakM7QUFDQTtBQUNBO0FBQ0EsZUFBZTtBQUNmLGVBQWUsOERBQWE7QUFDNUI7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxzQkFBc0IsK0NBQVEsR0FBRztBQUNqQztBQUNBO0FBQ0E7QUFDQSxlQUFlO0FBQ2YsZUFBZSx3REFBVTtBQUN6QjtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxzQkFBc0IsK0NBQVEsR0FBRztBQUNqQztBQUNBO0FBQ0E7QUFDQTtBQUNBLGVBQWU7QUFDZixlQUFlLHdEQUFVO0FBQ3pCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSwyQ0FBMkMsa0NBQWtDO0FBQzdFO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsaUJBQWlCO0FBQ2pCO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBLENBQUM7QUFDc0I7QUFDdkI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDdDRCcUQ7QUFDckQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUCw4QkFBOEIsbUVBQVE7QUFDdEMsb0NBQW9DLG1FQUFRO0FBQzVDO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7O0FDMURBO0FBQ0E7QUFDb0Q7QUFDN0M7QUFDUDtBQUNBO0FBQ0E7QUFDQSxXQUFXLGtFQUFPO0FBQ2xCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7O0FDdEJBO0FBQ0E7QUFDb0Y7QUFDN0U7QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsaUNBQWlDLG9GQUE2QjtBQUM5RDtBQUNBLFdBQVcsa0VBQU87QUFDbEI7QUFDQTs7Ozs7Ozs7Ozs7Ozs7OztBQ2hCQTtBQUNBO0FBQ29EO0FBQ3BEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVksb0JBQW9CO0FBQ2hDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQUFRO0FBQ1I7QUFDQTtBQUNBO0FBQ0E7QUFDQSxJQUFJO0FBQ0o7QUFDQTtBQUNBLDBCQUEwQixTQUFTO0FBQ25DLHVCQUF1QixTQUFTO0FBQ2hDLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQLDZCQUE2QjtBQUM3QjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBLFdBQVcsa0VBQU87QUFDbEI7QUFDQTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ25EQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxXQUFXLGdCQUFnQixzQ0FBc0Msa0JBQWtCO0FBQ25GLDBCQUEwQjtBQUMxQjtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0Esb0JBQW9CO0FBQ3BCO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQSxpREFBaUQsT0FBTztBQUN4RDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBLDZEQUE2RCxjQUFjO0FBQzNFO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBLDZDQUE2QyxRQUFRO0FBQ3JEO0FBQ0E7QUFDQTtBQUNPO0FBQ1Asb0NBQW9DO0FBQ3BDO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNPO0FBQ1AsNEJBQTRCLCtEQUErRCxpQkFBaUI7QUFDNUc7QUFDQSxvQ0FBb0MsTUFBTSwrQkFBK0IsWUFBWTtBQUNyRixtQ0FBbUMsTUFBTSxtQ0FBbUMsWUFBWTtBQUN4RixnQ0FBZ0M7QUFDaEM7QUFDQSxLQUFLO0FBQ0w7QUFDQTtBQUNPO0FBQ1AsY0FBYyw2QkFBNkIsMEJBQTBCLGNBQWMscUJBQXFCO0FBQ3hHLGlCQUFpQixvREFBb0QscUVBQXFFLGNBQWM7QUFDeEosdUJBQXVCLHNCQUFzQjtBQUM3QztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSx3Q0FBd0M7QUFDeEMsbUNBQW1DLFNBQVM7QUFDNUMsbUNBQW1DLFdBQVcsVUFBVTtBQUN4RCwwQ0FBMEMsY0FBYztBQUN4RDtBQUNBLDhHQUE4RyxPQUFPO0FBQ3JILGlGQUFpRixpQkFBaUI7QUFDbEcseURBQXlELGdCQUFnQixRQUFRO0FBQ2pGLCtDQUErQyxnQkFBZ0IsZ0JBQWdCO0FBQy9FO0FBQ0Esa0NBQWtDO0FBQ2xDO0FBQ0E7QUFDQSxVQUFVLFlBQVksYUFBYSxTQUFTLFVBQVU7QUFDdEQsb0NBQW9DLFNBQVM7QUFDN0M7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EscUJBQXFCO0FBQ3JCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLG9CQUFvQixNQUFNO0FBQzFCO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUCw2QkFBNkIsc0JBQXNCO0FBQ25EO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUCxrREFBa0QsUUFBUTtBQUMxRCx5Q0FBeUMsUUFBUTtBQUNqRCx5REFBeUQsUUFBUTtBQUNqRTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0EsaUJBQWlCLHVGQUF1RixjQUFjO0FBQ3RILHVCQUF1QixnQ0FBZ0MscUNBQXFDLDJDQUEyQztBQUN2SSw0QkFBNEIsTUFBTSxpQkFBaUIsWUFBWTtBQUMvRCx1QkFBdUI7QUFDdkIsOEJBQThCO0FBQzlCLDZCQUE2QjtBQUM3Qiw0QkFBNEI7QUFDNUI7QUFDQTtBQUNPO0FBQ1A7QUFDQSxpQkFBaUIsNkNBQTZDLFVBQVUsc0RBQXNELGNBQWM7QUFDNUksMEJBQTBCLDZCQUE2QixvQkFBb0IsZ0RBQWdELGtCQUFrQjtBQUM3STtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0EsMkdBQTJHLHVGQUF1RixjQUFjO0FBQ2hOLHVCQUF1Qiw4QkFBOEIsZ0RBQWdELHdEQUF3RDtBQUM3Siw2Q0FBNkMsc0NBQXNDLFVBQVUsbUJBQW1CLElBQUk7QUFDcEg7QUFDQTtBQUNPO0FBQ1AsaUNBQWlDLHVDQUF1QyxZQUFZLEtBQUssT0FBTztBQUNoRztBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUCw2Q0FBNkM7QUFDN0M7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDek5BO0FBQ0E7QUFDaUM7QUFDaUQ7QUFDbEY7QUFDQTtBQUNBLFlBQVksY0FBYztBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLG1CQUFtQixvQ0FBb0MsY0FBYztBQUNyRSxxQkFBcUI7QUFDckIsTUFBTTtBQUNOLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1AsY0FBYyxtRUFBUTtBQUN0QjtBQUNBLGtCQUFrQiw2RUFBa0Isd0ZBQXdGLFFBQVEsK0NBQVEsR0FBRywwQkFBMEI7QUFDekssV0FBVyxrRUFBTztBQUNsQjtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDNUJBO0FBQ0E7QUFDaUM7QUFDaUQ7QUFDbEY7QUFDQTtBQUNBLFlBQVksaUJBQWlCO0FBQzdCO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1AsY0FBYyxtRUFBUTtBQUN0QjtBQUNBLGtCQUFrQiw2RUFBa0I7QUFDcEM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVMsUUFBUSwrQ0FBUSxHQUFHLDBCQUEwQjtBQUN0RCxXQUFXLGtFQUFPO0FBQ2xCO0FBQ0E7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDOUJBO0FBQ0E7QUFDaUM7QUFDaUQ7QUFDbEY7QUFDQTtBQUNBLFlBQVksYUFBYTtBQUN6QjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxJQUFJO0FBQ0oseUNBQXlDO0FBQ3pDLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQLGNBQWMsbUVBQVE7QUFDdEI7QUFDQSxrQkFBa0IsK0NBQVEsR0FBRyxtQkFBbUI7QUFDaEQsV0FBVyxrRUFBTztBQUNsQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQSxZQUFZLGdCQUFnQjtBQUM1QjtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1AsdUJBQXVCLDZFQUFrQjtBQUN6QztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsZ0JBQWdCLCtDQUFRO0FBQ3hCO0FBQ0EsMENBQTBDO0FBQzFDLEtBQUs7QUFDTCxXQUFXLGtFQUFPLENBQUMsbUVBQVE7QUFDM0I7QUFDQTs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQzlGQTtBQUNBO0FBQ2lDO0FBQ2lEO0FBQ2xGO0FBQ0E7QUFDQTtBQUNBLFlBQVksZUFBZTtBQUMzQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLGNBQWM7QUFDZCxJQUFJO0FBQ0o7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQLGtCQUFrQiw2RUFBa0I7QUFDcEM7QUFDQSxnQkFBZ0IsK0NBQVE7QUFDeEI7QUFDQSw0RUFBNEU7QUFDNUUsS0FBSztBQUNMLFdBQVcsa0VBQU8sQ0FBQyxtRUFBUTtBQUMzQjtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDOUJBO0FBQ0E7QUFDaUM7QUFDaUQ7QUFDbEY7QUFDQTtBQUNBO0FBQ0EsWUFBWSxpQkFBaUI7QUFDN0I7QUFDQTtBQUNBO0FBQ0E7QUFDQSxtQkFBbUIsb0NBQW9DLGNBQWM7QUFDckUscUJBQXFCO0FBQ3JCLE1BQU07QUFDTixJQUFJO0FBQ0o7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUCxjQUFjLG1FQUFRO0FBQ3RCO0FBQ0Esa0JBQWtCLDZFQUFrQiwyR0FBMkcsUUFBUSwrQ0FBUSxHQUFHLDBCQUEwQjtBQUM1TCxXQUFXLGtFQUFPO0FBQ2xCO0FBQ0E7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUM1QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsV0FBVyxnQkFBZ0Isc0NBQXNDLGtCQUFrQjtBQUNuRiwwQkFBMEI7QUFDMUI7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBLG9CQUFvQjtBQUNwQjtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0EsaURBQWlELE9BQU87QUFDeEQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQSw2REFBNkQsY0FBYztBQUMzRTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQSw2Q0FBNkMsUUFBUTtBQUNyRDtBQUNBO0FBQ0E7QUFDTztBQUNQLG9DQUFvQztBQUNwQztBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDTztBQUNQLDRCQUE0QiwrREFBK0QsaUJBQWlCO0FBQzVHO0FBQ0Esb0NBQW9DLE1BQU0sK0JBQStCLFlBQVk7QUFDckYsbUNBQW1DLE1BQU0sbUNBQW1DLFlBQVk7QUFDeEYsZ0NBQWdDO0FBQ2hDO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDTztBQUNQLGNBQWMsNkJBQTZCLDBCQUEwQixjQUFjLHFCQUFxQjtBQUN4RyxpQkFBaUIsb0RBQW9ELHFFQUFxRSxjQUFjO0FBQ3hKLHVCQUF1QixzQkFBc0I7QUFDN0M7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esd0NBQXdDO0FBQ3hDLG1DQUFtQyxTQUFTO0FBQzVDLG1DQUFtQyxXQUFXLFVBQVU7QUFDeEQsMENBQTBDLGNBQWM7QUFDeEQ7QUFDQSw4R0FBOEcsT0FBTztBQUNySCxpRkFBaUYsaUJBQWlCO0FBQ2xHLHlEQUF5RCxnQkFBZ0IsUUFBUTtBQUNqRiwrQ0FBK0MsZ0JBQWdCLGdCQUFnQjtBQUMvRTtBQUNBLGtDQUFrQztBQUNsQztBQUNBO0FBQ0EsVUFBVSxZQUFZLGFBQWEsU0FBUyxVQUFVO0FBQ3RELG9DQUFvQyxTQUFTO0FBQzdDO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHFCQUFxQjtBQUNyQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxvQkFBb0IsTUFBTTtBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQjtBQUNsQjtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1AsNkJBQTZCLHNCQUFzQjtBQUNuRDtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1Asa0RBQWtELFFBQVE7QUFDMUQseUNBQXlDLFFBQVE7QUFDakQseURBQXlELFFBQVE7QUFDakU7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBLGlCQUFpQix1RkFBdUYsY0FBYztBQUN0SCx1QkFBdUIsZ0NBQWdDLHFDQUFxQywyQ0FBMkM7QUFDdkksNEJBQTRCLE1BQU0saUJBQWlCLFlBQVk7QUFDL0QsdUJBQXVCO0FBQ3ZCLDhCQUE4QjtBQUM5Qiw2QkFBNkI7QUFDN0IsNEJBQTRCO0FBQzVCO0FBQ0E7QUFDTztBQUNQO0FBQ0EsaUJBQWlCLDZDQUE2QyxVQUFVLHNEQUFzRCxjQUFjO0FBQzVJLDBCQUEwQiw2QkFBNkIsb0JBQW9CLGdEQUFnRCxrQkFBa0I7QUFDN0k7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBLDJHQUEyRyx1RkFBdUYsY0FBYztBQUNoTix1QkFBdUIsOEJBQThCLGdEQUFnRCx3REFBd0Q7QUFDN0osNkNBQTZDLHNDQUFzQyxVQUFVLG1CQUFtQixJQUFJO0FBQ3BIO0FBQ0E7QUFDTztBQUNQLGlDQUFpQyx1Q0FBdUMsWUFBWSxLQUFLLE9BQU87QUFDaEc7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1AsNkNBQTZDO0FBQzdDO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ3pOQTtBQUNBO0FBQzRDO0FBQ2M7QUFDTTtBQUNOO0FBQ007QUFDNUI7QUFDN0I7QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxZQUFZLDJCQUEyQjtBQUN2QztBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQSxRQUFRLGlEQUFJO0FBQ1o7QUFDQTtBQUNBO0FBQ0E7QUFDQSxJQUFJLGdEQUFTO0FBQ2I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxrQ0FBa0M7QUFDbEMsK0JBQStCO0FBQy9CO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxxQ0FBcUM7QUFDckM7QUFDQTtBQUNBO0FBQ0E7QUFDQSxpQ0FBaUMsK0NBQVEsQ0FBQywrQ0FBUSxHQUFHLG9CQUFvQix5QkFBeUI7QUFDbEc7QUFDQTtBQUNBLGFBQWE7QUFDYjtBQUNBO0FBQ0EsYUFBYTtBQUNiO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsYUFBYTtBQUNiO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsQ0FBQyxDQUFDLHlFQUFrQjtBQUNPO0FBQzNCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0Esa0JBQWtCLHlFQUFrQjtBQUNwQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQix5RUFBa0I7QUFDcEM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esa0JBQWtCLHlFQUFrQjtBQUNwQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsWUFBWSxVQUFVO0FBQ3RCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0EsZUFBZTtBQUNmLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUCxxQ0FBcUMsbUJBQW1CLFVBQVU7QUFDbEUsa0JBQWtCLCtDQUFRLENBQUMsK0NBQVEsQ0FBQywrQ0FBUSxHQUFHLG9CQUFvQjtBQUNuRSxnQkFBZ0IsK0NBQVEsQ0FBQywrQ0FBUSxHQUFHO0FBQ3BDLGlCQUFpQiwrQ0FBUSxDQUFDLCtDQUFRLEdBQUc7QUFDckMsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGlCQUFpQiwrQ0FBUSxHQUFHLFdBQVc7QUFDdkM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSx5Q0FBeUMsc0JBQXNCO0FBQy9EO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxTQUFTO0FBQ1Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsOEJBQThCLDZFQUFpQjtBQUMvQztBQUNBLDRFQUE0RSw2RUFBaUI7QUFDN0Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGdDQUFnQyx1RUFBYztBQUM5QztBQUNBO0FBQ0EsK0JBQStCLCtDQUFRLENBQUMsK0NBQVEsR0FBRztBQUNuRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsYUFBYSx1RUFBZ0I7QUFDN0I7QUFDQTtBQUNBO0FBQ0E7QUFDQSxLQUFLO0FBQ0w7QUFDQTtBQUNBO0FBQ0E7QUFDQSxzQkFBc0IseUVBQWtCO0FBQ3hDO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxLQUFLO0FBQ0w7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7QUM5VUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLENBQUM7QUFDNkI7QUFDOUI7QUFDQTtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7O0FDakNBO0FBQ0E7QUFDaUM7QUFDakM7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQiwrQ0FBUSxDQUFDLCtDQUFRLEdBQUcsWUFBWTtBQUNsRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxLQUFLO0FBQ0w7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsS0FBSyxJQUFJO0FBQ1Q7QUFDQTs7Ozs7Ozs7Ozs7Ozs7O0FDakNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7O0FDbEJBO0FBQ0E7QUFDTztBQUNQO0FBQ0EsYUFBYTtBQUNiO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUssSUFBSTtBQUNUO0FBQ0E7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDdEJBO0FBQ0E7QUFDbUU7QUFDVDtBQUMxRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0Esc0JBQXNCLGlFQUFnQjtBQUN0QyxvQkFBb0IsOERBQWE7QUFDakM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsU0FBUztBQUNUO0FBQ0E7QUFDQTtBQUNBLGVBQWUsdUVBQWlCO0FBQ2hDO0FBQ0E7QUFDQTs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNwQ0E7QUFDQTtBQUNpRDtBQUNqRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBLGdEQUFnRCxxQ0FBcUM7QUFDckY7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUCxvQkFBb0IsOERBQWE7QUFDakM7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTs7Ozs7Ozs7Ozs7Ozs7OztBQy9CQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSw2Q0FBNkM7QUFDN0M7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7Ozs7Ozs7Ozs7Ozs7OztBQy9GQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDVkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsV0FBVyxnQkFBZ0Isc0NBQXNDLGtCQUFrQjtBQUNuRiwwQkFBMEI7QUFDMUI7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBLG9CQUFvQjtBQUNwQjtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0EsaURBQWlELE9BQU87QUFDeEQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQSw2REFBNkQsY0FBYztBQUMzRTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQSw2Q0FBNkMsUUFBUTtBQUNyRDtBQUNBO0FBQ0E7QUFDTztBQUNQLG9DQUFvQztBQUNwQztBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDTztBQUNQLDRCQUE0QiwrREFBK0QsaUJBQWlCO0FBQzVHO0FBQ0Esb0NBQW9DLE1BQU0sK0JBQStCLFlBQVk7QUFDckYsbUNBQW1DLE1BQU0sbUNBQW1DLFlBQVk7QUFDeEYsZ0NBQWdDO0FBQ2hDO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDTztBQUNQLGNBQWMsNkJBQTZCLDBCQUEwQixjQUFjLHFCQUFxQjtBQUN4RyxpQkFBaUIsb0RBQW9ELHFFQUFxRSxjQUFjO0FBQ3hKLHVCQUF1QixzQkFBc0I7QUFDN0M7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esd0NBQXdDO0FBQ3hDLG1DQUFtQyxTQUFTO0FBQzVDLG1DQUFtQyxXQUFXLFVBQVU7QUFDeEQsMENBQTBDLGNBQWM7QUFDeEQ7QUFDQSw4R0FBOEcsT0FBTztBQUNySCxpRkFBaUYsaUJBQWlCO0FBQ2xHLHlEQUF5RCxnQkFBZ0IsUUFBUTtBQUNqRiwrQ0FBK0MsZ0JBQWdCLGdCQUFnQjtBQUMvRTtBQUNBLGtDQUFrQztBQUNsQztBQUNBO0FBQ0EsVUFBVSxZQUFZLGFBQWEsU0FBUyxVQUFVO0FBQ3RELG9DQUFvQyxTQUFTO0FBQzdDO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHFCQUFxQjtBQUNyQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxvQkFBb0IsTUFBTTtBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQjtBQUNsQjtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1AsNkJBQTZCLHNCQUFzQjtBQUNuRDtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1Asa0RBQWtELFFBQVE7QUFDMUQseUNBQXlDLFFBQVE7QUFDakQseURBQXlELFFBQVE7QUFDakU7QUFDQTtBQUNBO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBLGlCQUFpQix1RkFBdUYsY0FBYztBQUN0SCx1QkFBdUIsZ0NBQWdDLHFDQUFxQywyQ0FBMkM7QUFDdkksNEJBQTRCLE1BQU0saUJBQWlCLFlBQVk7QUFDL0QsdUJBQXVCO0FBQ3ZCLDhCQUE4QjtBQUM5Qiw2QkFBNkI7QUFDN0IsNEJBQTRCO0FBQzVCO0FBQ0E7QUFDTztBQUNQO0FBQ0EsaUJBQWlCLDZDQUE2QyxVQUFVLHNEQUFzRCxjQUFjO0FBQzVJLDBCQUEwQiw2QkFBNkIsb0JBQW9CLGdEQUFnRCxrQkFBa0I7QUFDN0k7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBLDJHQUEyRyx1RkFBdUYsY0FBYztBQUNoTix1QkFBdUIsOEJBQThCLGdEQUFnRCx3REFBd0Q7QUFDN0osNkNBQTZDLHNDQUFzQyxVQUFVLG1CQUFtQixJQUFJO0FBQ3BIO0FBQ0E7QUFDTztBQUNQLGlDQUFpQyx1Q0FBdUMsWUFBWSxLQUFLLE9BQU87QUFDaEc7QUFDQTtBQUNBO0FBQ087QUFDUDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1AsNkNBQTZDO0FBQzdDO0FBQ0E7QUFDTztBQUNQO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPO0FBQ1A7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7Ozs7Ozs7OztBQ3pOQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7O0FDQUE7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7OztBQ0FBOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ0E2QztBQUVjO0FBRXBELE1BQU0sY0FBYyxHQUFHLENBQUMsS0FBd0IsRUFBRSxFQUFFO0lBQ3pELE1BQU0sR0FBRyxHQUFHLE1BQU0sQ0FBQyxHQUFHO0lBQ3RCLE1BQU0sRUFBRSxTQUFTLEtBQWdCLEtBQUssRUFBaEIsTUFBTSxVQUFLLEtBQUssRUFBaEMsYUFBd0IsQ0FBUTtJQUV0QyxNQUFNLE9BQU8sR0FBRyxxREFBVSxDQUFDLCtCQUErQixFQUFFLFNBQVMsQ0FBQztJQUN0RSxJQUFJLENBQUMsR0FBRztRQUFFLE9BQU8sa0ZBQUssU0FBUyxFQUFFLE9BQU8sSUFBTSxNQUFhLEVBQUk7SUFDL0QsT0FBTywyREFBQyxHQUFHLGtCQUFDLFNBQVMsRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLDZFQUFHLElBQU0sTUFBTSxFQUFJO0FBQzFELENBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1g0QztBQUVlO0FBRXJELE1BQU0sZUFBZSxHQUFHLENBQUMsS0FBd0IsRUFBRSxFQUFFO0lBQzFELE1BQU0sR0FBRyxHQUFHLE1BQU0sQ0FBQyxHQUFHO0lBQ3RCLE1BQU0sRUFBRSxTQUFTLEtBQWdCLEtBQUssRUFBaEIsTUFBTSxVQUFLLEtBQUssRUFBaEMsYUFBd0IsQ0FBUTtJQUV0QyxNQUFNLE9BQU8sR0FBRyxxREFBVSxDQUFDLCtCQUErQixFQUFFLFNBQVMsQ0FBQztJQUN0RSxJQUFJLENBQUMsR0FBRztRQUFFLE9BQU8sa0ZBQUssU0FBUyxFQUFFLE9BQU8sSUFBTSxNQUFhLEVBQUk7SUFDL0QsT0FBTywyREFBQyxHQUFHLGtCQUFDLFNBQVMsRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLDhFQUFHLElBQU0sTUFBTSxFQUFJO0FBQzFELENBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ1g0QztBQUVjO0FBRXBELE1BQU0sa0JBQWtCLEdBQUcsQ0FBQyxLQUF3QixFQUFFLEVBQUU7SUFDN0QsTUFBTSxHQUFHLEdBQUcsTUFBTSxDQUFDLEdBQUc7SUFDdEIsTUFBTSxFQUFFLFNBQVMsS0FBZ0IsS0FBSyxFQUFoQixNQUFNLFVBQUssS0FBSyxFQUFoQyxhQUF3QixDQUFRO0lBRXRDLE1BQU0sT0FBTyxHQUFHLHFEQUFVLENBQUMsK0JBQStCLEVBQUUsU0FBUyxDQUFDO0lBQ3RFLElBQUksQ0FBQyxHQUFHO1FBQUUsT0FBTyxrRkFBSyxTQUFTLEVBQUUsT0FBTyxJQUFNLE1BQWEsRUFBSTtJQUMvRCxPQUFPLDJEQUFDLEdBQUcsa0JBQUMsU0FBUyxFQUFFLE9BQU8sRUFBRSxHQUFHLEVBQUUsNkVBQUcsSUFBTSxNQUFNLEVBQUk7QUFDMUQsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDWDRDO0FBRVE7QUFFOUMsTUFBTSxhQUFhLEdBQUcsQ0FBQyxLQUF3QixFQUFFLEVBQUU7SUFDeEQsTUFBTSxHQUFHLEdBQUcsTUFBTSxDQUFDLEdBQUc7SUFDdEIsTUFBTSxFQUFFLFNBQVMsS0FBZ0IsS0FBSyxFQUFoQixNQUFNLFVBQUssS0FBSyxFQUFoQyxhQUF3QixDQUFRO0lBRXRDLE1BQU0sT0FBTyxHQUFHLHFEQUFVLENBQUMsK0JBQStCLEVBQUUsU0FBUyxDQUFDO0lBQ3RFLElBQUksQ0FBQyxHQUFHO1FBQUUsT0FBTyxrRkFBSyxTQUFTLEVBQUUsT0FBTyxJQUFNLE1BQWEsRUFBSTtJQUMvRCxPQUFPLDJEQUFDLEdBQUcsa0JBQUMsU0FBUyxFQUFFLE9BQU8sRUFBRSxHQUFHLEVBQUUsdUVBQUcsSUFBTSxNQUFNLEVBQUk7QUFDMUQsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDWDRDO0FBRWE7QUFFbkQsTUFBTSxlQUFlLEdBQUcsQ0FBQyxLQUF3QixFQUFFLEVBQUU7SUFDMUQsTUFBTSxHQUFHLEdBQUcsTUFBTSxDQUFDLEdBQUc7SUFDdEIsTUFBTSxFQUFFLFNBQVMsS0FBZ0IsS0FBSyxFQUFoQixNQUFNLFVBQUssS0FBSyxFQUFoQyxhQUF3QixDQUFRO0lBRXRDLE1BQU0sT0FBTyxHQUFHLHFEQUFVLENBQUMsK0JBQStCLEVBQUUsU0FBUyxDQUFDO0lBQ3RFLElBQUksQ0FBQyxHQUFHO1FBQUUsT0FBTyxrRkFBSyxTQUFTLEVBQUUsT0FBTyxJQUFNLE1BQWEsRUFBSTtJQUMvRCxPQUFPLDJEQUFDLEdBQUcsa0JBQUMsU0FBUyxFQUFFLE9BQU8sRUFBRSxHQUFHLEVBQUUsNEVBQUcsSUFBTSxNQUFNLEVBQUk7QUFDMUQsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNYeUI7QUF1QmU7QUFDRDtBQUs0QztBQUM1QztBQUVZO0FBQ047QUFFVjtBQUdwQyw2RkFBNkY7QUFFdEYsTUFBTSxjQUFjLEdBQUcsQ0FBTSxLQUFhLEVBQUUsRUFBRTtJQUNuRCxPQUFPLENBQUMsR0FBRyxDQUFDLHVCQUF1QixDQUFDO0lBQ3BDLElBQUksSUFBSSxHQUFHLE1BQU0seURBQWtCLENBQUMsS0FBSyxFQUFFLGtEQUFVLENBQUMsQ0FBQztJQUV2RCxJQUFHLENBQUMsSUFBSSxFQUFDO1FBQ1AsSUFBSSxHQUFHLE1BQU0sNkNBQU0sQ0FBQyxLQUFLLEVBQUUsa0RBQVUsQ0FBQyxDQUFDO0tBQ3hDO0lBRUQsTUFBTSxVQUFVLEdBQUc7UUFDakIsT0FBTyxFQUFFLElBQUksQ0FBQyxPQUFPO1FBQ3JCLE1BQU0sRUFBRSxJQUFJLENBQUMsTUFBTTtRQUNuQixHQUFHLEVBQUUsSUFBSSxDQUFDLEdBQUc7UUFDYixLQUFLLEVBQUUsSUFBSSxDQUFDLEtBQUs7UUFDakIsTUFBTSxFQUFFLElBQUksQ0FBQyxNQUFNO0tBQ0w7SUFFaEIsY0FBYyxDQUFDLDJFQUFrQyxFQUFFLFVBQVUsQ0FBQyxDQUFDO0FBQ2pFLENBQUM7QUFDTSxTQUFlLG9CQUFvQixDQUFDLGNBQThCLEVBQ3ZFLE1BQXVCLEVBQUUsa0JBQTBCLEVBQUcsSUFBWTs7UUFFbEUsT0FBTyxDQUFDLEdBQUcsQ0FBQyw2QkFBNkIsQ0FBQztRQUMxQyxVQUFVLENBQUMsTUFBTSxDQUFDLGNBQWMsRUFBRSxrQ0FBa0MsQ0FBQyxDQUFDO1FBRXRFLE1BQU0sVUFBVSxHQUFHO1lBQ2pCLFFBQVEsRUFBRSxjQUFjLENBQUMsUUFBUTtZQUNqQyxLQUFLLEVBQUUsY0FBYyxDQUFDLEtBQUs7WUFDM0IsS0FBSyxFQUFFLGNBQWMsQ0FBQyxLQUFLO1lBQzNCLFdBQVcsRUFBRSxjQUFjLENBQUMsV0FBVztZQUN2QyxjQUFjLEVBQUUsY0FBYyxDQUFDLGFBQWE7WUFDNUMsY0FBYyxFQUFFLGNBQWMsQ0FBQyxjQUFjO1lBQzdDLFdBQVcsRUFBRSxjQUFjLENBQUMsV0FBVztZQUN2QyxlQUFlLEVBQUUsY0FBYyxDQUFDLGVBQWU7U0FDaEQ7UUFDRCxJQUFJLFFBQVEsR0FBSSxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxjQUFjLEVBQUUsVUFBVSxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQ3BGLElBQUcsUUFBUSxDQUFDLGFBQWEsSUFBSSxRQUFRLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztZQUV4RSxNQUFNLFVBQVUsR0FBRyxjQUFjLENBQUMsb0JBQW9CLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFO2dCQUM3RCxPQUFPO29CQUNMLFVBQVUsRUFBRTt3QkFDVixRQUFRLEVBQUUsQ0FBQyxDQUFDLFFBQVE7d0JBQ3BCLE1BQU0sRUFBRSxDQUFDLENBQUMsTUFBTTt3QkFDaEIsUUFBUSxFQUFFLENBQUMsQ0FBQyxRQUFRLElBQUksQ0FBQyxDQUFDLFFBQVEsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQyxRQUFRLENBQUMsRUFBQyxDQUFDLEVBQUU7cUJBQy9FO2lCQUNGO1lBQ0gsQ0FBQyxDQUFDO1lBRUYsUUFBUSxHQUFHLE1BQU0sOERBQW1CLENBQUMsTUFBTSxDQUFDLG9CQUFvQixFQUFFLFVBQVUsRUFBRSxNQUFNLENBQUMsQ0FBQztZQUN0RixJQUFHLFFBQVEsQ0FBQyxhQUFhLElBQUksUUFBUSxDQUFDLGFBQWEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLEVBQUM7Z0JBRXhFLE1BQU0sYUFBYSxHQUFHO29CQUNwQixRQUFRLEVBQUUsa0JBQWtCO29CQUM1QixVQUFVLEVBQUUsSUFBSSxJQUFJLEVBQUUsQ0FBQyxPQUFPLEVBQUU7b0JBQ2hDLE1BQU0sRUFBRSxJQUFJO2lCQUNiO2dCQUNELFFBQVEsR0FBRyxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxXQUFXLEVBQUUsYUFBYSxFQUFFLE1BQU0sQ0FBQztnQkFDOUUsSUFBRyxRQUFRLENBQUMsYUFBYSxJQUFJLFFBQVEsQ0FBQyxhQUFhLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO29CQUN4RSxPQUFPO3dCQUNMLElBQUksRUFBRSxJQUFJO3FCQUNYO2lCQUNGO2FBQ0Y7U0FDRjtRQUNELDRDQUFHLENBQUMsZ0NBQWdDLEVBQUUsa0RBQWEsRUFBRSxzQkFBc0IsQ0FBQyxDQUFDO1FBQzdFLE9BQU87WUFDTCxNQUFNLEVBQUUsZ0NBQWdDO1NBQ3pDO0lBQ0gsQ0FBQztDQUFBO0FBRU0sU0FBZSxrQkFBa0IsQ0FBQyxVQUFzQixFQUM3RCxNQUF1QixFQUFFLFFBQWdCOztRQUN4QyxVQUFVLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSw0QkFBNEIsQ0FBQyxDQUFDO1FBRTdELE1BQU0sUUFBUSxHQUFJLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRTtZQUM1RCxRQUFRLEVBQUUsVUFBVSxDQUFDLFFBQVE7WUFDN0IsTUFBTSxFQUFFLFFBQVE7WUFDaEIsVUFBVSxFQUFFLElBQUksSUFBSSxFQUFFLENBQUMsT0FBTyxFQUFFO1lBQ2hDLFdBQVcsRUFBRSxDQUFDO1NBQ2hCLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDWCxPQUFPLENBQUMsR0FBRyxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ3RCLE9BQU07WUFDSixJQUFJLEVBQUUsUUFBUSxDQUFDLGFBQWEsSUFBSSxRQUFRLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7U0FDN0U7SUFDSixDQUFDO0NBQUE7QUFFTSxNQUFNLGlCQUFpQixHQUFHLENBQU8sVUFBa0IsRUFBRSxNQUFnQixFQUFFLE1BQXVCLEVBQUUsRUFBRTtJQUV2RyxVQUFVLENBQUMsVUFBVSxFQUFFLDBCQUEwQixDQUFDLENBQUM7SUFFbkQsc0RBQXNEO0lBQ3RELDZDQUE2QztJQUM3QyxtQkFBbUI7SUFDbkIsZUFBZTtJQUNmLDBEQUEwRDtJQUMxRCxNQUFNO0lBQ04sSUFBSTtJQUNKLEtBQUs7SUFDTCxzQ0FBc0M7SUFFdEMsd0VBQXdFO0lBRXhFLCtDQUErQztJQUUvQyxZQUFZO0lBQ1osMkNBQTJDO0lBQzNDLHdFQUF3RTtJQUN4RSxJQUFJO0lBRUosNENBQTRDO0lBQzVDLGtJQUFrSTtJQUNsSSxrQkFBa0I7SUFDbEIsTUFBTTtJQUVOLHdCQUF3QjtJQUN4QiwyRUFBMkU7SUFDM0UsSUFBSTtJQUNKLE9BQU8sSUFBSSxDQUFDO0FBQ2QsQ0FBQztBQUVELFNBQWUsb0JBQW9CLENBQUMsS0FBYSxFQUFFLE1BQXVCOztRQUN4RSxPQUFPLENBQUMsR0FBRyxDQUFDLHVCQUF1QixDQUFDLENBQUM7UUFDckMsT0FBTyxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUUsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBQ3BFLENBQUM7Q0FBQTtBQUVELFNBQWUsa0JBQWtCLENBQUMsS0FBYSxFQUFFLE1BQXVCOztRQUN0RSxPQUFPLENBQUMsR0FBRyxDQUFDLG9CQUFvQixDQUFDLENBQUM7UUFDbEMsT0FBTyxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBQ2pFLENBQUM7Q0FBQTtBQUVELFNBQWUsbUJBQW1CLENBQUMsS0FBYSxFQUFFLE1BQXVCOztRQUN2RSxPQUFPLENBQUMsR0FBRyxDQUFDLHFCQUFxQixDQUFDLENBQUM7UUFDbkMsT0FBTyxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBQ25FLENBQUM7Q0FBQTtBQUVELFNBQWUsb0JBQW9CLENBQUMsS0FBYSxFQUFFLE1BQXVCOztRQUN4RSxPQUFPLENBQUMsR0FBRyxDQUFDLHVCQUF1QixDQUFDLENBQUM7UUFDckMsT0FBTyxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUUsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBQ3BFLENBQUM7Q0FBQTtBQUVELFNBQWUscUJBQXFCLENBQUMsS0FBYSxFQUFFLE1BQXVCOztRQUN6RSxPQUFPLENBQUMsR0FBRyxDQUFDLHFCQUFxQixDQUFDLENBQUM7UUFDbkMsT0FBTyxNQUFNLCtEQUFvQixDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBQ3JFLENBQUM7Q0FBQTtBQUVNLFNBQWUsWUFBWSxDQUFDLE1BQXVCLEVBQUUsVUFBbUIsRUFBRSxXQUFtQjs7UUFFbEcsTUFBTSxXQUFXLEdBQUcsTUFBTSxDQUFDLFNBQVMsQ0FBQztRQUNyQyxNQUFNLFdBQVcsR0FBRyxNQUFNLENBQUMsU0FBUyxDQUFDO1FBQ3JDLE1BQU0sWUFBWSxHQUFHLE1BQU0sQ0FBQyxVQUFVLENBQUM7UUFFdkMsSUFBRztZQUNELFVBQVUsQ0FBQyxXQUFXLEVBQUUsMERBQWtCLENBQUMsQ0FBQztZQUM1QyxVQUFVLENBQUMsV0FBVyxFQUFFLDBEQUFrQixDQUFDLENBQUM7WUFDNUMsVUFBVSxDQUFDLFlBQVksRUFBRSwyREFBbUIsQ0FBQyxDQUFDO1lBRTlDLE1BQU0sU0FBUyxHQUFHLFVBQVUsQ0FBQyxDQUFDLENBQUMsYUFBYSxVQUFVLEVBQUUsQ0FBQyxDQUFDLEVBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBRSxDQUFDO1lBRS9GLE1BQU0sUUFBUSxHQUFHLE1BQU0sT0FBTyxDQUFDLEdBQUcsQ0FBQztnQkFDakMscUJBQXFCLENBQUMsU0FBUyxFQUFFLE1BQU0sQ0FBQztnQkFDeEMsbUJBQW1CLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQztnQkFDbEMsb0JBQW9CLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQzthQUFDLENBQUMsQ0FBQztZQUV4QyxNQUFNLGtCQUFrQixHQUFHLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUN2QyxNQUFNLGdCQUFnQixHQUFHLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUNyQyxNQUFNLGlCQUFpQixHQUFHLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUV0QyxNQUFNLGlCQUFpQixHQUFHLE1BQU0sb0JBQW9CLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1lBQ3BFLE1BQU0sY0FBYyxHQUFHLE1BQU0sa0JBQWtCLENBQUMsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1lBRS9ELE1BQU0sU0FBUyxHQUFHLE1BQU0sT0FBTyxDQUFDLEdBQUcsQ0FBQyxrQkFBa0IsQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLENBQU8sZUFBeUIsRUFBRSxFQUFFO2dCQUN0RyxNQUFNLHlCQUF5QixHQUFHLGlCQUFpQixDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFDLENBQUMsVUFBVSxDQUFDLFVBQVUsSUFBSSxlQUFlLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQztnQkFDOUgsT0FBTyxNQUFNLFdBQVcsQ0FBQyxlQUFlLEVBQUUsZ0JBQWdCLEVBQUUsaUJBQWlCLEVBQzNFLHlCQUF5QixFQUFFLGNBQWMsRUFDekMsa0JBQWtCLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLEtBQUssUUFBUSxDQUFDLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQztZQUNoRixDQUFDLEVBQUMsQ0FBQyxDQUFDO1lBRUosSUFBRyxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxDQUFDLE1BQU0sR0FBRyxDQUFDLElBQUksU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsQ0FBQyxNQUFNLElBQUksQ0FBQyxFQUFDO2dCQUNuRyxPQUFPO29CQUNMLElBQUksRUFBRSxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFO3dCQUN0Qix1Q0FDSyxDQUFDLEtBQ0osVUFBVSxFQUFFLENBQUMsQ0FBQyxJQUFJLEtBQUssOERBQXNCLElBQzlDO29CQUNILENBQUMsQ0FBQztpQkFDSDthQUNGO1lBRUQsSUFBRyxTQUFTLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBQztnQkFDeEIsT0FBTztvQkFDTCxJQUFJLEVBQUUsU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRTt3QkFDdEIsdUNBQ0ssQ0FBQyxLQUNKLFVBQVUsRUFBRSxJQUFJLElBQ2pCO29CQUNILENBQUMsQ0FBQztpQkFDSDthQUNGO1lBQ0QsT0FBTztnQkFDTCxJQUFJLEVBQUUsU0FBUzthQUNoQjtTQUNGO1FBQ0QsT0FBTSxDQUFDLEVBQUM7WUFDTiw0Q0FBRyxDQUFDLENBQUMsRUFBRSxrREFBYSxFQUFFLGNBQWMsQ0FBQyxDQUFDO1lBQ3RDLE9BQU87Z0JBQ0wsTUFBTSxFQUFFLDJCQUEyQjthQUNwQztTQUNGO0lBQ0gsQ0FBQztDQUFBO0FBRU0sU0FBUyxZQUFZLENBQUksR0FBVyxFQUFFLGVBQTBCO0lBQ3JFLE1BQU0sQ0FBQyxJQUFJLEVBQUUsT0FBTyxDQUFDLEdBQUcsc0RBQWMsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUM3QyxNQUFNLENBQUMsT0FBTyxFQUFFLFVBQVUsQ0FBQyxHQUFHLHNEQUFjLENBQUMsSUFBSSxDQUFDLENBQUM7SUFDbkQsTUFBTSxDQUFDLEtBQUssRUFBRSxRQUFRLENBQUMsR0FBRyxzREFBYyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBRTdDLHVEQUFlLENBQUMsR0FBRyxFQUFFO1FBQ25CLE1BQU0sVUFBVSxHQUFHLElBQUksZUFBZSxFQUFFLENBQUM7UUFDekMsV0FBVyxDQUFDLEdBQUcsRUFBRSxVQUFVLENBQUM7YUFDekIsSUFBSSxDQUFDLENBQUMsSUFBSSxFQUFFLEVBQUU7WUFDYixJQUFJLGVBQWUsRUFBRTtnQkFDbkIsT0FBTyxDQUFDLGVBQWUsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDO2FBQ2hDO2lCQUFNO2dCQUNMLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQzthQUNmO1lBQ0QsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDO1FBQ3BCLENBQUMsQ0FBQzthQUNELEtBQUssQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFO1lBQ2IsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUNqQixRQUFRLENBQUMsR0FBRyxDQUFDLENBQUM7UUFDaEIsQ0FBQyxDQUFDO1FBQ0osT0FBTyxHQUFHLEVBQUUsQ0FBQyxVQUFVLENBQUMsS0FBSyxFQUFFLENBQUM7SUFDbEMsQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFDLENBQUM7SUFFVCxPQUFPLENBQUMsSUFBSSxFQUFFLE9BQU8sRUFBRSxPQUFPLEVBQUUsS0FBSyxDQUFDO0FBQ3hDLENBQUM7QUFFTSxTQUFTLGNBQWMsQ0FBQyxJQUFTLEVBQUUsR0FBUTtJQUNoRCxzREFBVyxFQUFFLENBQUMsUUFBUSxDQUFDO1FBQ3JCLElBQUk7UUFDSixHQUFHO0tBQ0osQ0FBQyxDQUFDO0FBQ0wsQ0FBQztBQUVNLFNBQWUsWUFBWSxDQUFDLE1BQXVCOztRQUV4RCxPQUFPLENBQUMsR0FBRyxDQUFDLHVCQUF1QixDQUFDO1FBQ3BDLFVBQVUsQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLDBEQUFrQixDQUFDLENBQUM7UUFFakQsTUFBTSxRQUFRLEdBQUcsTUFBTSw2REFBa0IsQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLEtBQUssRUFBRSxNQUFNLENBQUMsQ0FBQztRQUUzRSxNQUFNLEtBQUssR0FBRyxnQkFBZ0IsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFDLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsSUFBSSxFQUFFLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDO1FBRXpHLE1BQU0sZ0JBQWdCLEdBQUcsTUFBTSxpQkFBaUIsQ0FBQyxNQUFNLEVBQUUsS0FBSyxFQUFFLGNBQWMsQ0FBQyxDQUFDO1FBRWhGLE9BQU8sUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQVcsRUFBRSxFQUFFO1lBQ2hDLE1BQU0sRUFBRSxHQUFHLGdCQUFnQixDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsVUFBVSxDQUFDLFFBQVEsSUFBSSxDQUFDLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQztZQUM5RixPQUFPO2dCQUNMLFFBQVEsRUFBRSxDQUFDLENBQUMsVUFBVSxDQUFDLFFBQVE7Z0JBQy9CLEVBQUUsRUFBRSxDQUFDLENBQUMsVUFBVSxDQUFDLFFBQVE7Z0JBQ3pCLElBQUksRUFBRSxDQUFDLENBQUMsVUFBVSxDQUFDLElBQUk7Z0JBQ3ZCLE1BQU0sRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFDO29CQUNYLFFBQVEsRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLFFBQVE7b0JBQ2hDLEVBQUUsRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLFFBQVE7b0JBQzFCLElBQUksRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLElBQUk7b0JBQ3hCLEtBQUssRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLFlBQVksSUFBSSxFQUFFLENBQUMsVUFBVSxDQUFDLFdBQVcsSUFBSSxFQUFFLENBQUMsVUFBVSxDQUFDLElBQUk7b0JBQ3BGLElBQUksRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLElBQUk7b0JBQ3hCLFdBQVcsRUFBRSxFQUFFLENBQUMsVUFBVSxDQUFDLFdBQVc7b0JBQ3RDLE9BQU8sRUFBRSxnQkFBZ0IsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyxNQUFNLENBQUMsQ0FBQyxNQUFNLENBQUMsV0FBVztpQkFDakYsQ0FBQyxDQUFDLENBQUMsSUFBSTtnQkFDUixXQUFXLEVBQUUsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxXQUFXO2dCQUNyQyxTQUFTLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsU0FBUyxDQUFDO2dCQUN6QyxPQUFPLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsT0FBTyxDQUFDO2FBQzFCLENBQUM7UUFDbEIsQ0FBQyxDQUFDLENBQUM7UUFDSCxPQUFPLEVBQUUsQ0FBQztJQUNaLENBQUM7Q0FBQTtBQUVELFNBQWUsaUJBQWlCLENBQUUsTUFBdUIsRUFBRSxLQUFhLEVBQUUsTUFBYzs7UUFDdEYsT0FBTyxDQUFDLEdBQUcsQ0FBQyx3QkFBd0IsR0FBQyxNQUFNLENBQUM7UUFDNUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsd0RBQWdCLENBQUMsQ0FBQztRQUM3QyxPQUFPLE1BQU0sK0RBQW9CLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxLQUFLLEVBQUUsTUFBTSxDQUFDLENBQUM7SUFDbkUsQ0FBQztDQUFBO0FBRU0sU0FBZSxVQUFVLENBQUMsTUFBdUIsRUFBRSxXQUFtQixFQUFFLE1BQWM7O1FBRTNGLE1BQU0sVUFBVSxHQUFHLE1BQU0saUJBQWlCLENBQUMsTUFBTSxFQUFFLFdBQVcsRUFBRSxNQUFNLENBQUMsQ0FBQztRQUN4RSxJQUFHLENBQUMsVUFBVSxJQUFJLFVBQVUsQ0FBQyxRQUFRLENBQUMsTUFBTSxJQUFJLENBQUMsRUFBQztZQUNoRCxPQUFPLEVBQUUsQ0FBQztTQUNYO1FBQ0QsT0FBTyxVQUFVLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQVcsRUFBRSxFQUFFO1lBQzdDLE9BQU87Z0JBQ0wsUUFBUSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsUUFBUTtnQkFDL0IsRUFBRSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsUUFBUTtnQkFDekIsSUFBSSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsSUFBSTtnQkFDdkIsS0FBSyxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsWUFBWSxJQUFJLENBQUMsQ0FBQyxVQUFVLENBQUMsV0FBVyxJQUFJLENBQUMsQ0FBQyxVQUFVLENBQUMsSUFBSTtnQkFDakYsSUFBSSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsSUFBSTtnQkFDdkIsV0FBVyxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsV0FBVztnQkFDckMsT0FBTyxFQUFFLFVBQVUsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyxNQUFNLENBQUMsQ0FBQyxNQUFNLENBQUMsV0FBVzthQUNqRTtRQUNiLENBQUMsQ0FBQztRQUNGLE9BQU8sRUFBRSxDQUFDO0lBQ1osQ0FBQztDQUFBO0FBRU0sU0FBZSxnQkFBZ0IsQ0FBQyxNQUF1QixFQUFFLFdBQW1COztRQUNqRixPQUFPLENBQUMsR0FBRyxDQUFDLDBCQUEwQixDQUFDO1FBQ3ZDLFVBQVUsQ0FBQyxNQUFNLENBQUMsYUFBYSxFQUFFLDhEQUFzQixDQUFDLENBQUM7UUFFekQsTUFBTSxVQUFVLEdBQUcsTUFBTSwrREFBb0IsQ0FBQyxNQUFNLENBQUMsYUFBYSxFQUFFLFdBQVcsRUFBRSxNQUFNLENBQUMsQ0FBQztRQUV6RixJQUFHLFVBQVUsSUFBSSxVQUFVLENBQUMsUUFBUSxJQUFJLFVBQVUsQ0FBQyxRQUFRLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBQztZQUNyRSxPQUFPLFVBQVUsQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBVyxFQUFFLEVBQUU7Z0JBQzdDLE9BQU87b0JBQ0wsUUFBUSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsUUFBUTtvQkFDL0IsRUFBRSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsUUFBUTtvQkFDekIsSUFBSSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsSUFBSTtvQkFDdkIsS0FBSyxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsSUFBSTtvQkFDeEIsSUFBSSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsSUFBSTtvQkFDdkIsUUFBUSxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsUUFBUTtvQkFDL0IsV0FBVyxFQUFFLENBQUMsQ0FBQyxVQUFVLENBQUMsV0FBVztvQkFDckMsT0FBTyxFQUFFLFVBQVUsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyxNQUFNLENBQUMsQ0FBQyxNQUFNLENBQUMsV0FBVztpQkFDM0Q7WUFDbkIsQ0FBQyxDQUFDO1NBQ0g7UUFDRCxPQUFPLEVBQUUsQ0FBQztJQUNaLENBQUM7Q0FBQTtBQUVNLFNBQWUsaUJBQWlCLENBQUMsTUFBdUIsRUFBRSxRQUFzQixFQUN0RixRQUFnQixFQUFFLFlBQTBCLEVBQUUsTUFBYzs7UUFFM0QsVUFBVSxDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsMERBQWtCLENBQUMsQ0FBQztRQUNqRCxVQUFVLENBQUMsUUFBUSxFQUFFLDRCQUE0QixDQUFDLENBQUM7UUFFbkQsTUFBTSxVQUFVLEdBQUcsSUFBSSxJQUFJLEVBQUUsQ0FBQyxPQUFPLEVBQUUsQ0FBQztRQUN4QyxNQUFNLFlBQVksR0FBRyxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLGlCQUFpQixFQUFFLEdBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFFckYsSUFBSSxPQUFPLEdBQUc7WUFDWixVQUFVLEVBQUU7Z0JBQ1YsY0FBYyxFQUFFLFlBQVksQ0FBQyxDQUFDLENBQUMsWUFBWSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUUsSUFBSTtnQkFDdEQsZ0JBQWdCLEVBQUUsWUFBWSxDQUFDLENBQUMsQ0FBQyxZQUFZLENBQUMsSUFBSSxFQUFDLENBQUMsSUFBSTtnQkFDeEQsZ0JBQWdCLEVBQUUsWUFBWSxDQUFDLENBQUMsQ0FBQyxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxZQUFZLENBQUMsSUFBSSxDQUFDLElBQUksRUFBQyxDQUFDLFlBQVksQ0FBQyxJQUFJLENBQUUsRUFBQyxDQUFDLElBQUk7Z0JBQzVHLFFBQVEsRUFBRyxNQUFNLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUk7Z0JBQ3BDLFVBQVUsRUFBRyxNQUFNLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLElBQUk7Z0JBQ3hDLFVBQVUsRUFBRyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUk7Z0JBQ2hGLElBQUksRUFBRSxZQUFZO2dCQUNsQixPQUFPLEVBQUUsUUFBUTtnQkFDakIsV0FBVyxFQUFFLFVBQVU7Z0JBQ3ZCLE1BQU0sRUFBRSxDQUFDO2dCQUNULFVBQVUsRUFBRSxDQUFDO2dCQUNiLE1BQU0sRUFBRSxRQUFRO2dCQUNoQixVQUFVLEVBQUUsVUFBVTthQUN2QjtTQUNGO1FBQ0QsSUFBSSxRQUFRLEdBQUcsTUFBTSwyREFBZ0IsQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLENBQUMsT0FBTyxDQUFDLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDM0UsSUFBRyxRQUFRLENBQUMsVUFBVSxJQUFJLFFBQVEsQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO1lBRWxFLE1BQU0sVUFBVSxHQUFHLFFBQVEsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUMsUUFBUSxDQUFDO1lBQ25ELDBCQUEwQjtZQUMxQixNQUFNLFVBQVUsR0FBRyxxQkFBcUIsQ0FBQyxRQUFRLENBQUMsQ0FBQztZQUNuRCxNQUFNLGlCQUFpQixHQUFHLFVBQVUsQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLEVBQUU7Z0JBQ25ELE9BQU87b0JBQ0wsVUFBVSxFQUFFO3dCQUNWLFVBQVUsRUFBRSxVQUFVO3dCQUN0QixXQUFXLEVBQUUsU0FBUyxDQUFDLFdBQVc7d0JBQ2xDLGFBQWEsRUFBRSxTQUFTLENBQUMsYUFBYTt3QkFDdEMsSUFBSSxFQUFFLFNBQVMsQ0FBQyxJQUFJO3dCQUNwQixZQUFZLEVBQUUsWUFBWTt3QkFDMUIsWUFBWSxFQUFFLFNBQVMsQ0FBQyxZQUFZO3FCQUNyQztpQkFDRjtZQUNILENBQUMsQ0FBQztZQUNGLFFBQVEsR0FBRyxNQUFNLDJEQUFnQixDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSxDQUFDLENBQUM7WUFDaEYsSUFBRyxRQUFRLENBQUMsVUFBVSxJQUFJLFFBQVEsQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO2dCQUVsRSxNQUFNLFNBQVMsR0FBRyxJQUFJLFFBQVEsQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsSUFBSSxDQUFDLENBQUMsUUFBUSxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQztnQkFDbkYsTUFBTSxLQUFLLEdBQUcsY0FBYyxHQUFDLFNBQVMsQ0FBQztnQkFDdkMsTUFBTSxzQkFBc0IsR0FBRyxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUMsS0FBSyxFQUFHLE1BQU0sQ0FBQyxDQUFDO2dCQUV6RixJQUFJLGVBQWUsR0FBRyxFQUFFLENBQUM7Z0JBQ3pCLEtBQUksSUFBSSxPQUFPLElBQUksc0JBQXNCLEVBQUM7b0JBQ3hDLE1BQU0saUJBQWlCLEdBQUcsVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLEtBQUssT0FBTyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQztvQkFDbkYsSUFBRyxpQkFBaUIsRUFBQzt3QkFDcEIsTUFBTSxjQUFjLEdBQUcsaUJBQWlCLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRTs0QkFDdkQsT0FBTztnQ0FDTCxVQUFVLEVBQUU7b0NBQ1YsV0FBVyxFQUFFLE9BQU8sQ0FBQyxVQUFVLENBQUMsUUFBUTtvQ0FDeEMsSUFBSSxFQUFFLENBQUMsQ0FBQyxJQUFJO29DQUNaLE1BQU0sRUFBRSxDQUFDLENBQUMsTUFBTTtvQ0FDaEIsV0FBVyxFQUFFLENBQUM7b0NBQ2QsY0FBYyxFQUFHLENBQUM7b0NBQ2xCLGlCQUFpQixFQUFDLENBQUM7aUNBQ3BCOzZCQUNGO3dCQUNILENBQUMsQ0FBQyxDQUFDO3dCQUNILGVBQWUsR0FBRyxlQUFlLENBQUMsTUFBTSxDQUFDLGNBQWMsQ0FBQztxQkFDeEQ7aUJBQ0Y7Z0JBRUQsUUFBUSxHQUFHLE1BQU0sMkRBQWdCLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxlQUFlLEVBQUUsTUFBTSxDQUFDLENBQUM7Z0JBQzNFLElBQUcsUUFBUSxDQUFDLFVBQVUsSUFBSSxRQUFRLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztvQkFDbkUsT0FBTzt3QkFDTCxJQUFJLEVBQUUsSUFBSTtxQkFDWDtpQkFDRDthQUNIO1lBQ0QsaUhBQWlIO1lBRWpILHVEQUF1RDtZQUN2RCwwQ0FBMEM7WUFDMUMsYUFBYTtZQUNiLGlCQUFpQjtZQUNqQixNQUFNO1lBQ04sSUFBSTtTQUNMO1FBRUQsNENBQUcsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQyxFQUFFLGtEQUFhLEVBQUUsbUJBQW1CLENBQUM7UUFDakUsT0FBTztZQUNMLE1BQU0sRUFBRSxnREFBZ0Q7U0FDekQ7SUFDSCxDQUFDO0NBQUE7QUFFTSxTQUFlLG1DQUFtQyxDQUFDLE1BQXVCLEVBQy9FLFFBQXNCLEVBQUUsUUFBZ0I7O1FBRXhDLFVBQVUsQ0FBQyxRQUFRLEVBQUUsdUJBQXVCLENBQUMsQ0FBQztRQUM5QyxVQUFVLENBQUMsTUFBTSxDQUFDLFNBQVMsRUFBRSwwREFBa0IsQ0FBQyxDQUFDO1FBRWpELE1BQU0sVUFBVSxHQUFHO1lBQ2pCLFFBQVEsRUFBRSxRQUFRLENBQUMsUUFBUTtZQUMzQixjQUFjLEVBQUUsUUFBUSxDQUFDLGNBQWM7WUFDdkMsUUFBUSxFQUFFLFFBQVEsQ0FBQyxRQUFRO1lBQzNCLGdCQUFnQixFQUFFLFFBQVEsQ0FBQyxnQkFBZ0I7WUFDM0MsZ0JBQWdCLEVBQUUsUUFBUSxDQUFDLGdCQUFnQjtZQUMzQyxVQUFVLEVBQUUsUUFBUSxDQUFDLFVBQVU7WUFDL0IsVUFBVSxFQUFFLFFBQVEsQ0FBQyxVQUFVO1lBQy9CLElBQUksRUFBRSxRQUFRLENBQUMsSUFBSTtZQUNuQixNQUFNLEVBQUUsUUFBUTtZQUNoQixVQUFVLEVBQUUsSUFBSSxJQUFJLEVBQUUsQ0FBQyxPQUFPLEVBQUU7WUFDaEMsTUFBTSxFQUFFLFFBQVEsQ0FBQyxNQUFNLENBQUMsSUFBSTtZQUM1QixVQUFVLEVBQUUsUUFBUSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFDLENBQUMsQ0FBQztTQUN2QztRQUNELE1BQU0sUUFBUSxHQUFJLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLFNBQVMsRUFBRSxVQUFVLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDakYsSUFBRyxRQUFRLENBQUMsYUFBYSxJQUFJLFFBQVEsQ0FBQyxhQUFhLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO1lBQ3hFLE9BQU87Z0JBQ0wsSUFBSSxFQUFFLElBQUk7YUFDWDtTQUNGO1FBQ0QsNENBQUcsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQyxFQUFFLGtEQUFhLEVBQUUscUNBQXFDLENBQUM7UUFDbkYsT0FBTztZQUNMLE1BQU0sRUFBRSx5Q0FBeUM7U0FDbEQ7SUFDSCxDQUFDO0NBQUE7QUFFTSxTQUFlLGNBQWMsQ0FBQyxRQUFnQixFQUFFLFNBQW1CLEVBQUUsTUFBdUI7O1FBRS9GLE9BQU8sQ0FBQyxHQUFHLENBQUMsd0JBQXdCLENBQUM7UUFDckMsSUFBRztZQUNELFVBQVUsQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLDBEQUFrQixDQUFDLENBQUM7WUFFakQscUhBQXFIO1lBRXJILE1BQU0sUUFBUSxHQUFJLFNBQVMsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEVBQUU7Z0JBQ3BDLE9BQU87b0JBQ0wsVUFBVSxFQUFFO3dCQUNWLFFBQVEsRUFBRSxHQUFHO3dCQUNiLFVBQVUsRUFBRSxHQUFHLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7cUJBQ3JDO2lCQUNGO1lBQ0gsQ0FBQyxDQUFDO1lBQ0YsTUFBTSxRQUFRLEdBQUcsTUFBTSw4REFBbUIsQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLFFBQVEsRUFBRSxNQUFNLENBQUM7WUFDOUUsSUFBRyxRQUFRLENBQUMsYUFBYSxJQUFJLFFBQVEsQ0FBQyxhQUFhLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO2dCQUN2RSxPQUFPO29CQUNOLElBQUksRUFBRSxRQUFRLENBQUMsYUFBYSxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVE7aUJBQ2hCLENBQUM7YUFDNUI7U0FDRjtRQUFBLE9BQU0sQ0FBQyxFQUFFO1lBQ1IsNENBQUcsQ0FBQyxDQUFDLEVBQUUsa0RBQWEsRUFBRSxnQkFBZ0IsQ0FBQyxDQUFDO1lBQ3hDLE9BQU87Z0JBQ0wsTUFBTSxFQUFFLENBQUM7YUFDVjtTQUNGO0lBQ0wsQ0FBQztDQUFBO0FBRU0sU0FBZSxnQkFBZ0IsQ0FBQyxNQUF1Qjs7UUFFNUQsVUFBVSxDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsZ0NBQWdDLENBQUMsQ0FBQztRQUUvRCxJQUFHO1lBRUYsTUFBTSxRQUFRLEdBQUcsTUFBTSw2REFBa0IsQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLEtBQUssRUFBRSxNQUFNLENBQUMsQ0FBQztZQUMzRSxJQUFHLFFBQVEsSUFBSSxRQUFRLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBQztnQkFDakMsTUFBTSxNQUFNLEdBQUksUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRTtvQkFDL0IsT0FBTzt3QkFDTCxJQUFJLEVBQUUsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxJQUFJO3dCQUN2QixLQUFLLEVBQUUsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxLQUFLO3FCQUNYLENBQUM7Z0JBQ25CLENBQUMsQ0FBQztnQkFFRixPQUFPO29CQUNOLElBQUksRUFBRSxNQUFNO2lCQUNrQjthQUNoQztZQUVELDRDQUFHLENBQUMsK0NBQStDLEVBQUUsa0RBQWEsRUFBRSxrQkFBa0IsQ0FBQztZQUN2RixPQUFPO2dCQUNMLE1BQU0sRUFBRSwrQ0FBK0M7YUFDeEQ7U0FDRDtRQUFDLE9BQU0sQ0FBQyxFQUFDO1lBQ1AsNENBQUcsQ0FBQyxDQUFDLEVBQUUsa0RBQWEsRUFBRSxrQkFBa0IsQ0FBQyxDQUFDO1NBQzVDO0lBRUgsQ0FBQztDQUFBO0FBRU0sU0FBZSxrQkFBa0IsQ0FBQyxTQUE0QixFQUFFLE1BQXVCLEVBQUUsVUFBa0IsRUFBRSxZQUFvQjs7UUFFdEksVUFBVSxDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUUsMkRBQW1CLENBQUMsQ0FBQztRQUVuRCxNQUFNLGdCQUFnQixHQUFHO1lBQ3ZCLFVBQVUsRUFBRTtnQkFDVixVQUFVLEVBQUUsVUFBVTtnQkFDdEIsV0FBVyxFQUFFLFNBQVMsQ0FBQyxXQUFXO2dCQUNsQyxhQUFhLEVBQUUsU0FBUyxDQUFDLGFBQWE7Z0JBQ3RDLElBQUksRUFBRSxTQUFTLENBQUMsSUFBSTtnQkFDcEIsWUFBWSxFQUFFLFlBQVk7Z0JBQzFCLFlBQVksRUFBRSxTQUFTLENBQUMsWUFBWTthQUNyQztTQUNGO1FBRUQsSUFBSSxRQUFRLEdBQUcsTUFBTSwyREFBZ0IsQ0FBQyxNQUFNLENBQUMsVUFBVSxFQUFFLENBQUMsZ0JBQWdCLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQztRQUNyRixJQUFHLFFBQVEsQ0FBQyxVQUFVLElBQUksUUFBUSxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLEVBQUM7WUFFbEUsTUFBTSxjQUFjLEdBQUcsU0FBUyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUU7Z0JBRTlDLE9BQU87b0JBQ04sVUFBVSxFQUFFO3dCQUNWLFdBQVcsRUFBRSxRQUFRLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVE7d0JBQzVDLElBQUksRUFBRSxDQUFDLENBQUMsSUFBSTt3QkFDWixNQUFNLEVBQUUsQ0FBQyxDQUFDLE1BQU07d0JBQ2hCLFdBQVcsRUFBRSxDQUFDO3dCQUNkLGNBQWMsRUFBRyxDQUFDO3dCQUNsQixpQkFBaUIsRUFBQyxDQUFDO3FCQUNwQjtpQkFDRjtZQUNILENBQUMsQ0FBQyxDQUFDO1lBRUgsUUFBUSxHQUFHLE1BQU0sMkRBQWdCLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxjQUFjLEVBQUUsTUFBTSxDQUFDLENBQUM7WUFDMUUsSUFBRyxRQUFRLENBQUMsVUFBVSxJQUFJLFFBQVEsQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO2dCQUNqRSxPQUFPO29CQUNOLElBQUksRUFBRSxJQUFJO2lCQUNWO2FBQ0g7U0FDRjtRQUVELDRDQUFHLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsRUFBRSxrREFBYSxFQUFFLG9CQUFvQixDQUFDLENBQUM7UUFDbkUsT0FBTztZQUNMLE1BQU0sRUFBRSw0Q0FBNEM7U0FDckQ7SUFFSCxDQUFDO0NBQUE7QUFFTSxTQUFlLG1CQUFtQixDQUFDLE1BQXVCLEVBQUUsYUFBK0I7O1FBRWhHLFVBQVUsQ0FBQyxNQUFNLENBQUMsVUFBVSxFQUFFLDJEQUFtQixDQUFDLENBQUM7UUFFbkQsTUFBTSxVQUFVLEdBQUc7WUFDakIsUUFBUSxFQUFFLGFBQWEsQ0FBQyxRQUFRO1lBQ2hDLElBQUksRUFBRSxhQUFhLENBQUMsSUFBSTtZQUN4QixZQUFZLEVBQUUsYUFBYSxDQUFDLElBQUk7WUFDaEMsUUFBUSxFQUFFLENBQUM7U0FDWjtRQUNELE1BQU0sUUFBUSxHQUFJLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLFVBQVUsRUFBRSxVQUFVLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDbEYsSUFBRyxRQUFRLENBQUMsYUFBYSxJQUFJLFFBQVEsQ0FBQyxhQUFhLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO1lBQ3ZFLE9BQU87Z0JBQ04sSUFBSSxFQUFFLElBQUk7YUFDVjtTQUNIO1FBQ0QsNENBQUcsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQyxFQUFFLGtEQUFhLEVBQUUscUJBQXFCLENBQUM7UUFDbkUsT0FBTztZQUNMLE1BQU0sRUFBRSx5Q0FBeUM7U0FDbEQ7SUFDSCxDQUFDO0NBQUE7QUFFTSxTQUFlLGVBQWUsQ0FBQyxTQUE0QixFQUFFLE1BQXVCOztRQUV6RixVQUFVLENBQUMsTUFBTSxDQUFDLFVBQVUsRUFBRSwwREFBa0IsQ0FBQyxDQUFDO1FBRWxELElBQUksUUFBUSxHQUFHLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLFVBQVUsRUFBRSxTQUFTLFNBQVMsQ0FBQyxJQUFJLHVCQUF1QixTQUFTLENBQUMsWUFBWSxHQUFHLEVBQUUsTUFBTSxDQUFDO1FBRTNJLElBQUcsUUFBUSxJQUFJLFFBQVEsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFDO1lBQ2pDLE9BQU87Z0JBQ0wsTUFBTSxFQUFFLGdEQUFnRDthQUN6RDtTQUNGO1FBQ0QsTUFBTSxRQUFRLEdBQUcsTUFBTSxtQkFBbUIsQ0FBQyxNQUFNLEVBQUUsU0FBUyxDQUFDLENBQUM7UUFFOUQsSUFBRyxRQUFRLENBQUMsTUFBTSxFQUFDO1lBQ2pCLE9BQU87Z0JBQ0wsTUFBTSxFQUFFLFFBQVEsQ0FBQyxNQUFNO2FBQ3hCO1NBQ0Y7UUFFQSxRQUFRLEdBQUcsU0FBUyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUU7WUFDbkMsT0FBTztnQkFDTCxVQUFVLEVBQUU7b0JBQ1QsUUFBUSxFQUFFLENBQUMsQ0FBQyxRQUFRO29CQUNwQixNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUM7b0JBQ3hCLGNBQWMsRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxXQUFXO2lCQUNsRDthQUNGO1FBQ0gsQ0FBQyxDQUFDLENBQUM7UUFFSCxNQUFNLGNBQWMsR0FBRyxNQUFNLDhEQUFtQixDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsUUFBUSxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQ25GLElBQUcsY0FBYyxDQUFDLGFBQWEsSUFBSSxjQUFjLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztZQUNwRixPQUFPO2dCQUNOLElBQUksRUFBRSxJQUFJO2FBQ1Y7U0FDRjtRQUVELDRDQUFHLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxjQUFjLENBQUMsRUFBRSxrREFBYSxFQUFFLGlCQUFpQixDQUFDLENBQUM7UUFDdEUsT0FBTztZQUNMLE1BQU0sRUFBRSwwQ0FBMEM7U0FDbkQ7SUFDSixDQUFDO0NBQUE7QUFFTSxTQUFlLGVBQWUsQ0FBQyxpQkFBb0MsRUFBRSxNQUF1Qjs7UUFFakcsVUFBVSxDQUFDLE1BQU0sQ0FBQyxVQUFVLEVBQUUsMkRBQW1CLENBQUMsQ0FBQztRQUNuRCxVQUFVLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSwwQkFBMEIsQ0FBQyxDQUFDO1FBRXZELElBQUksSUFBSSxHQUFHLE1BQU0sOERBQW1CLENBQUMsTUFBTSxDQUFDLFVBQVUsRUFBRSxDQUFDLGlCQUFpQixDQUFDLFFBQVEsQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQzlGLElBQUcsSUFBSSxDQUFDLGFBQWEsSUFBSSxJQUFJLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztZQUMvRCxNQUFNLGdCQUFnQixHQUFHLGlCQUFpQixDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUM7WUFDeEUsSUFBSSxHQUFHLE1BQU0sOERBQW1CLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxNQUFNLENBQUMsQ0FBQztZQUMzRSxJQUFHLElBQUksQ0FBQyxhQUFhLElBQUksSUFBSSxDQUFDLGFBQWEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLEVBQUM7Z0JBQ2pFLE9BQU87b0JBQ0wsSUFBSSxFQUFFLElBQUk7aUJBQ1g7YUFDRDtTQUNIO1FBRUQsNENBQUcsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxFQUFFLGtEQUFhLEVBQUUsaUJBQWlCLENBQUM7UUFDM0QsT0FBTztZQUNMLE1BQU0sRUFBRSw2Q0FBNkM7U0FDdEQ7SUFDSCxDQUFDO0NBQUE7QUFFTSxTQUFlLGVBQWUsQ0FBQyxRQUFnQixFQUFFLE1BQXVCOztRQUU3RSxNQUFNLFFBQVEsR0FBSSxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUU7WUFDM0QsUUFBUSxFQUFFLFFBQVE7WUFDbEIsVUFBVSxFQUFFLENBQUM7WUFDYixRQUFRLEVBQUUsQ0FBQztTQUNaLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDWCxPQUFPLENBQUMsR0FBRyxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQ3RCLElBQUcsUUFBUSxDQUFDLGFBQWEsSUFBSSxRQUFRLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztZQUN4RSxPQUFPO2dCQUNMLElBQUksRUFBRSxJQUFJO2FBQ1g7U0FDRjtRQUNELDRDQUFHLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsRUFBRSxrREFBYSxFQUFFLGlCQUFpQixDQUFDLENBQUM7UUFDaEUsT0FBTztZQUNMLE1BQU0sRUFBRSxrQ0FBa0M7U0FDM0M7SUFDSCxDQUFDO0NBQUE7QUFFTSxTQUFlLGdCQUFnQixDQUFDLE1BQXVCLEVBQUUsWUFBMEI7OztRQUV4RixVQUFVLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSw4REFBc0IsQ0FBQyxDQUFDO1FBQ3pELFVBQVUsQ0FBQyxZQUFZLEVBQUUsa0NBQWtDLENBQUMsQ0FBQztRQUU3RCxNQUFNLE9BQU8sR0FBRztZQUNkLFVBQVUsRUFBRTtnQkFDVixJQUFJLEVBQUUsWUFBWSxDQUFDLElBQUk7Z0JBQ3ZCLElBQUksRUFBRSxrQkFBWSxDQUFDLElBQUksMENBQUUsSUFBSTtnQkFDN0IsWUFBWSxFQUFFLFlBQVksQ0FBQyxJQUFJO2dCQUMvQixRQUFRLEVBQUUsWUFBWSxhQUFaLFlBQVksdUJBQVosWUFBWSxDQUFFLFFBQVE7YUFDakM7U0FDRjtRQUNELE1BQU0sUUFBUSxHQUFJLE1BQU0sMkRBQWdCLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSxDQUFDLE9BQU8sQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQ2xGLElBQUcsUUFBUSxDQUFDLFVBQVUsSUFBSSxRQUFRLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztZQUNsRSxPQUFPO2dCQUNMLElBQUksRUFBRSxrQkFDRCxZQUFZLENBQ0EsQ0FBQyx1RkFBdUY7YUFDMUc7U0FDRjtRQUNELE9BQU87WUFDTCxNQUFNLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUM7U0FDakM7O0NBQ0Y7QUFFTSxTQUFlLFVBQVUsQ0FBQyxNQUF1QixFQUFFLE1BQWM7O1FBRXRFLE1BQU0sT0FBTyxHQUFHO1lBQ2QsVUFBVSxFQUFFO2dCQUNWLElBQUksRUFBRSxNQUFNLENBQUMsSUFBSTtnQkFDakIsWUFBWSxFQUFFLE1BQU0sQ0FBQyxJQUFJO2dCQUN6QixJQUFJLEVBQUUsTUFBTSxDQUFDLElBQUksQ0FBQyxJQUFJO2dCQUN0QixXQUFXLEVBQUUsTUFBTSxDQUFDLFdBQVc7YUFDaEM7U0FDRjtRQUVELE1BQU0sUUFBUSxHQUFJLE1BQU0sMkRBQWdCLENBQUMsTUFBTSxDQUFDLE9BQU8sRUFBRSxDQUFDLE9BQU8sQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQzVFLElBQUcsUUFBUSxDQUFDLFVBQVUsSUFBSSxRQUFRLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztZQUNoRSxPQUFPO2dCQUNMLElBQUksRUFBRSxnQ0FDRCxNQUFNLEtBQ1QsUUFBUSxFQUFFLFFBQVEsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLENBQUMsUUFBUSxFQUN6QyxFQUFFLEVBQUUsUUFBUSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxRQUFRLEdBQzFCO2FBQ1o7U0FDSjtRQUVELDRDQUFHLENBQUMsb0ZBQW9GLEVBQUUsa0RBQWEsRUFBRSxZQUFZLENBQUM7UUFDdEgsT0FBTztZQUNMLE1BQU0sRUFBRSxvRkFBb0Y7U0FDN0Y7SUFDSCxDQUFDO0NBQUE7QUFFTSxTQUFlLGNBQWMsQ0FBQyxRQUFrQixFQUFFLE1BQXVCOztRQUM5RSxNQUFNLFFBQVEsR0FBRyxNQUFNLDhEQUFtQixDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDMUYsSUFBRyxRQUFRLENBQUMsYUFBYSxJQUFJLFFBQVEsQ0FBQyxhQUFhLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO1lBQ3ZFLE9BQU87Z0JBQ0wsSUFBSSxFQUFFLElBQUk7YUFDWDtTQUNIO1FBQ0QsT0FBTztZQUNOLE1BQU0sRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQztTQUNoQztJQUNILENBQUM7Q0FBQTtBQUVNLFNBQWUsWUFBWSxDQUFDLE1BQWMsRUFBRSxNQUF1Qjs7UUFDdkUsTUFBTSxRQUFRLEdBQUcsTUFBTSw4REFBbUIsQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQ3RGLElBQUcsUUFBUSxDQUFDLGFBQWEsSUFBSSxRQUFRLENBQUMsYUFBYSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztZQUN2RSxPQUFPO2dCQUNMLElBQUksRUFBRSxJQUFJO2FBQ1g7U0FDSDtRQUNELE9BQU87WUFDTixNQUFNLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUM7U0FDaEM7SUFDSixDQUFDO0NBQUE7QUFFTSxTQUFlLGtCQUFrQixDQUFDLFlBQTBCLEVBQUUsTUFBdUI7O1FBQzFGLE1BQU0sUUFBUSxHQUFHLE1BQU0sOERBQW1CLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSxDQUFDLFlBQVksQ0FBQyxRQUFRLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQztRQUNsRyxJQUFHLFFBQVEsQ0FBQyxhQUFhLElBQUksUUFBUSxDQUFDLGFBQWEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLEVBQUM7WUFDdkUsT0FBTztnQkFDTCxJQUFJLEVBQUUsSUFBSTthQUNYO1NBQ0g7UUFDRCxPQUFPO1lBQ04sTUFBTSxFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsUUFBUSxDQUFDO1NBQ2hDO0lBQ0gsQ0FBQztDQUFBO0FBRU0sU0FBZSxVQUFVLENBQUMsS0FBVSxFQUFFLEtBQWE7O1FBQ3hELElBQUksQ0FBQyxLQUFLLElBQUksS0FBSyxJQUFJLElBQUksSUFBSSxLQUFLLEtBQUssRUFBRSxJQUFJLEtBQUssSUFBSSxTQUFTLEVBQUU7WUFDakUsTUFBTSxJQUFJLEtBQUssQ0FBQyxLQUFLLENBQUM7U0FDdkI7SUFDSCxDQUFDO0NBQUE7QUFFTSxTQUFlLFlBQVksQ0FBQyxNQUFjLEVBQUUsT0FBZSxFQUFFLEtBQWE7O0lBR2pGLENBQUM7Q0FBQTtBQUVNLFNBQWUsaUJBQWlCLENBQUMsYUFBeUIsRUFBRSxRQUFzQixFQUN2RSxNQUF1QixFQUFFLGNBQTJCOztRQUVoRSxNQUFNLElBQUksR0FBRyxNQUFNLGNBQWMsQ0FBQyxhQUFhLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDekQsSUFBRyxJQUFJLENBQUMsTUFBTSxFQUFDO1lBQ2IsNENBQUcsQ0FBQyxrQ0FBa0MsRUFBRSxrREFBYSxFQUFFLG1CQUFtQixDQUFDLENBQUM7WUFFNUUsT0FBTztnQkFDTCxNQUFNLEVBQUUsa0NBQWtDO2FBQzNDO1NBQ0Y7UUFFRCxJQUFHO1lBRUQsTUFBTSxVQUFVLEdBQUcscUJBQXFCLENBQUMsUUFBUSxDQUFDLENBQUM7WUFDbkQsSUFBRyxDQUFDLFVBQVUsSUFBSSxVQUFVLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBQztnQkFDeEMsNENBQUcsQ0FBQywrQkFBK0IsRUFBRSxrREFBYSxFQUFFLG1CQUFtQixDQUFDLENBQUM7Z0JBQ3pFLE1BQU0sSUFBSSxLQUFLLENBQUMsZ0NBQWdDLENBQUM7YUFDbEQ7WUFFRCxNQUFNLHNCQUFzQixHQUFHLFFBQVEsQ0FBQyxpQkFBaUIsQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEVBQUU7Z0JBQ2hFLE9BQU87b0JBQ04sVUFBVSxFQUFFO3dCQUNWLFlBQVksRUFBRyxJQUFJLENBQUMsSUFBSTt3QkFDeEIsS0FBSyxFQUFFLElBQUk7d0JBQ1gsS0FBSyxFQUFFLElBQUk7d0JBQ1gsVUFBVSxFQUFFLEVBQUUsQ0FBQyxFQUFFO3dCQUNqQixXQUFXLEVBQUUsQ0FBQzt3QkFDZCxjQUFjLEVBQUUsSUFBSTt3QkFDcEIsV0FBVyxFQUFFLElBQUk7d0JBQ2pCLGVBQWUsRUFBRSxJQUFJO3dCQUNyQixZQUFZLEVBQUUsRUFBRSxDQUFDLEtBQUs7d0JBQ3RCLFlBQVksRUFBRSxRQUFRLENBQUMsSUFBSTtxQkFDNUI7aUJBQ0Y7WUFDSCxDQUFDLENBQUM7WUFDRixJQUFJLFFBQVEsR0FBRyxNQUFNLDJEQUFnQixDQUFDLE1BQU0sQ0FBQyxjQUFjLEVBQUUsc0JBQXNCLEVBQUUsTUFBTSxDQUFDLENBQUM7WUFDN0YsSUFBRyxRQUFRLElBQUksUUFBUSxDQUFDLFVBQVUsSUFBSSxRQUFRLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztnQkFDN0UsTUFBTSxLQUFLLEdBQUcsZUFBZSxHQUFFLFFBQVEsQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsSUFBSSxDQUFDLENBQUMsUUFBUSxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUMsR0FBRyxDQUFDO2dCQUM3RixNQUFNLFVBQVUsR0FBRyxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxjQUFjLEVBQUUsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO2dCQUVsRixNQUFNLDJCQUEyQixHQUFHLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUU7O29CQUV0RCxNQUFNLHFCQUFxQixHQUFHLFVBQVUsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FDL0MsRUFBRSxDQUFDLFVBQVUsQ0FBQyxZQUFZLENBQUMsS0FBSyxDQUFDLFdBQVcsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsS0FBTSxDQUFDLENBQUMsWUFBWSxDQUFDLENBQUM7b0JBQ2pGLElBQUcsQ0FBQyxxQkFBcUIsRUFBQzt3QkFDeEIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxZQUFZLFlBQVksQ0FBQyxDQUFDO3dCQUMzQyxNQUFNLElBQUksS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLFlBQVksWUFBWSxDQUFDLENBQUM7cUJBQ2hEO29CQUNELE9BQU87d0JBQ0wsVUFBVSxFQUFFOzRCQUNWLGdCQUFnQixFQUFHLHFCQUFxQixFQUFDLENBQUMscUJBQXFCLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsRUFBRTs0QkFDeEYsV0FBVyxFQUFFLENBQUMsQ0FBQyxFQUFFOzRCQUNqQixZQUFZLEVBQUUsQ0FBQyxDQUFDLFlBQVk7NEJBQzVCLFlBQVksRUFBRSxDQUFDLENBQUMsWUFBWTs0QkFDNUIsYUFBYSxFQUFFLENBQUMsQ0FBQyxhQUFhOzRCQUM5QixhQUFhLEVBQUUsQ0FBQyxDQUFDLElBQUk7NEJBQ3JCLFFBQVEsRUFBRSxFQUFFOzRCQUNaLElBQUksRUFBRSxPQUFDLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLEtBQUssNENBQUksQ0FBQywwQ0FBRSxNQUFNOzRCQUNsRCxVQUFVLEVBQUUsT0FBQyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxLQUFLLG1EQUFXLENBQUMsMENBQUUsTUFBTTs0QkFDL0Qsa0JBQWtCLEVBQUUsT0FBQyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxLQUFLLDJEQUFtQixDQUFDLDBDQUFFLE1BQU07NEJBQy9FLHFCQUFxQixFQUFFLE9BQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyw4REFBc0IsQ0FBQywwQ0FBRSxNQUFNOzRCQUNyRix1QkFBdUIsRUFBRSxPQUFDLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLEtBQUssZ0VBQXdCLENBQUMsMENBQUUsTUFBTTs0QkFDekYsTUFBTSxFQUFFLENBQUMsQ0FBQyxTQUFTO3lCQUNwQjtxQkFDRjtnQkFDRixDQUFDLENBQUM7Z0JBRUYsUUFBUSxHQUFHLE1BQU0sMkRBQWdCLENBQUMsTUFBTSxDQUFDLG9CQUFvQixFQUFFLDJCQUEyQixFQUFFLE1BQU0sQ0FBQyxDQUFDO2dCQUNwRyxJQUFHLFFBQVEsSUFBSSxRQUFRLENBQUMsVUFBVSxJQUFJLFFBQVEsQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFDO29CQUMvRSxPQUFPO3dCQUNMLElBQUksRUFBRSxJQUFJLENBQUMsSUFBSTtxQkFDaEI7aUJBQ0Q7cUJBQUk7b0JBQ0osTUFBTSxJQUFJLEtBQUssQ0FBQyw2Q0FBNkMsQ0FBQyxDQUFDO2lCQUMvRDthQUNIO2lCQUNHO2dCQUNGLE1BQU0sSUFBSSxLQUFLLENBQUMsd0NBQXdDLENBQUMsQ0FBQzthQUMzRDtTQUVGO1FBQUEsT0FBTSxDQUFDLEVBQUM7WUFDUCxNQUFNLDJCQUEyQixDQUFDLElBQUksQ0FBQyxJQUFJLEVBQUUsTUFBTSxDQUFDLENBQUM7WUFDckQsNENBQUcsQ0FBQyxDQUFDLEVBQUUsa0RBQWEsRUFBRSxtQkFBbUIsQ0FBQztZQUMxQyxPQUFPO2dCQUNMLE1BQU0sRUFBQywyQ0FBMkM7YUFDbkQ7U0FDRjtJQUVQLENBQUM7Q0FBQTtBQUVELFNBQWUsMkJBQTJCLENBQUMsa0JBQTBCLEVBQUUsTUFBdUI7O1FBRTNGLElBQUksUUFBUSxHQUFHLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxhQUFhLGtCQUFrQixHQUFHLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDeEcsSUFBRyxRQUFRLElBQUksUUFBUSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUM7WUFDakMsTUFBTSw4REFBbUIsQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1NBQ2pHO1FBRUQsUUFBUSxHQUFHLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLGNBQWMsRUFBRSxpQkFBaUIsa0JBQWtCLEdBQUcsRUFBRSxNQUFNLENBQUMsQ0FBQztRQUMzRyxJQUFHLFFBQVEsSUFBSSxRQUFRLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBQztZQUNsQyxNQUFNLDhEQUFtQixDQUFDLE1BQU0sQ0FBQyxjQUFjLEVBQUUsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFDLEVBQUUsTUFBTSxDQUFDLENBQUM7WUFFbkcsTUFBTSxLQUFLLEdBQUcsd0JBQXdCLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDO1lBQzVGLE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0JBQWdCLEVBQUUsS0FBSyxDQUFDO1lBQ3BDLFFBQVEsR0FBRyxNQUFNLDZEQUFrQixDQUFDLE1BQU0sQ0FBQyxvQkFBb0IsRUFBRSxLQUFLLEVBQUUsTUFBTSxDQUFDLENBQUM7WUFDaEYsSUFBRyxRQUFRLElBQUksUUFBUSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUM7Z0JBQ2pDLE1BQU0sOERBQW1CLENBQUMsTUFBTSxDQUFDLG9CQUFvQixFQUFFLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFDO2FBQzFHO1NBQ0Q7SUFDSixDQUFDO0NBQUE7QUFFTSxTQUFlLGtCQUFrQixDQUFDLE1BQXVCLEVBQUUsWUFBb0I7O1FBRXBGLE1BQU0sUUFBUSxHQUFHLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxhQUFhLFlBQVksR0FBRyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQ3BHLElBQUcsUUFBUSxJQUFJLFFBQVEsQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFDO1lBQ25DLE9BQU87Z0JBQ0wsSUFBSSxFQUFFLEVBQUU7YUFDVDtTQUNGO1FBQ0QsSUFBRyxRQUFRLElBQUksUUFBUSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUM7WUFFaEMsTUFBTSxNQUFNLEdBQUksUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRTtnQkFDaEMsT0FBTztvQkFDTCxJQUFJLEVBQUUsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxJQUFJO29CQUN2QixJQUFJLEVBQUUsaURBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxXQUFXLENBQUMsQ0FBQztpQkFDbEQ7WUFDRixDQUFDLENBQUMsQ0FBQztZQUNILE9BQU87Z0JBQ0wsSUFBSSxFQUFFLE1BQU07YUFDYjtTQUNIO1FBQ0QsT0FBTztZQUNMLE1BQU0sRUFBRSxzQ0FBc0M7U0FDL0M7SUFFSCxDQUFDO0NBQUE7QUFFRCxTQUFlLHFCQUFxQixDQUFDLE1BQU07O1FBQ3hDLE9BQU8sQ0FBQyxHQUFHLENBQUMsaUNBQWlDLENBQUMsQ0FBQztRQUMvQyxPQUFPLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxLQUFLLEVBQUUsTUFBTSxDQUFDLENBQUM7SUFDdEUsQ0FBQztDQUFBO0FBRU0sU0FBZSxrQkFBa0IsQ0FBQyxNQUF1Qjs7UUFFN0QsSUFBRztZQUNGLE1BQU0sa0JBQWtCLEdBQUcsTUFBTSxxQkFBcUIsQ0FBQyxNQUFNLENBQUMsQ0FBQztZQUMvRCxJQUFHLENBQUMsa0JBQWtCLElBQUksa0JBQWtCLENBQUMsTUFBTSxJQUFJLENBQUMsRUFBQztnQkFDdkQsT0FBTztvQkFDTCxJQUFJLEVBQUUsRUFBRTtpQkFDVDthQUNGO1lBRUQsTUFBTSxVQUFVLEdBQUcsTUFBTSx5QkFBeUIsQ0FBQyxNQUFNLEVBQUUsS0FBSyxDQUFDLENBQUM7WUFFbEUsTUFBTSxLQUFLLEdBQUcsd0JBQXdCLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxJQUFJLENBQUMsQ0FBQyxVQUFVLENBQUMsUUFBUSxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUc7WUFFcEcsTUFBTSxvQkFBb0IsR0FBRyxNQUFNLHVCQUF1QixDQUFDLEtBQUssRUFBRSxNQUFNLENBQUMsQ0FBQztZQUUxRSxJQUFHLGtCQUFrQixJQUFJLGtCQUFrQixDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUM7Z0JBQ3JELE1BQU0sV0FBVyxHQUFHLGtCQUFrQixDQUFDLEdBQUcsQ0FBQyxDQUFDLE9BQWlCLEVBQUUsRUFBRTtvQkFDL0QsTUFBTSxvQkFBb0IsR0FBRyxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUMsQ0FBQyxVQUFVLENBQUMsWUFBWSxJQUFJLE9BQU8sQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFDO29CQUM1RyxPQUFPLGNBQWMsQ0FBQyxPQUFPLEVBQUUsb0JBQW9CLEVBQUUsb0JBQW9CLENBQUMsQ0FBQztnQkFDN0UsQ0FBQyxDQUFDLENBQUM7Z0JBRUgsT0FBTztvQkFDTCxJQUFJLEVBQUUsV0FBVztpQkFDbEI7YUFDRjtZQUVELElBQUcsa0JBQWtCLElBQUksa0JBQWtCLENBQUMsTUFBTSxJQUFJLENBQUMsRUFBQztnQkFDdEQsT0FBTztvQkFDTCxJQUFJLEVBQUUsRUFBRTtpQkFDVDthQUNGO1NBQ0Q7UUFBQSxPQUFNLENBQUMsRUFBQztZQUNSLDRDQUFHLENBQUMsQ0FBQyxFQUFFLGtEQUFhLEVBQUUsb0JBQW9CLENBQUMsQ0FBQztZQUM1QyxPQUFPO2dCQUNMLE1BQU0sRUFBRSxDQUFDO2FBQ1Y7U0FDRDtJQUNKLENBQUM7Q0FBQTtBQUVNLFNBQWUsY0FBYyxDQUFDLE1BQXVCLEVBQUUsUUFBa0I7O1FBRTVFLElBQUc7WUFDRCxVQUFVLENBQUMsTUFBTSxDQUFDLFNBQVMsRUFBRSwwREFBa0IsQ0FBQyxDQUFDO1lBQ2pELFVBQVUsQ0FBQyxRQUFRLEVBQUUsNEJBQTRCLENBQUMsQ0FBQztZQUVuRCxNQUFNLFFBQVEsR0FBRyxDQUFDO29CQUNoQixVQUFVLEVBQUc7d0JBQ1gsUUFBUSxFQUFFLFFBQVEsQ0FBQyxNQUFNLENBQUMsRUFBRTt3QkFDNUIsSUFBSSxFQUFHLFFBQVEsQ0FBQyxJQUFJO3dCQUNwQixXQUFXLEVBQUUsUUFBUSxDQUFDLFdBQVc7d0JBQ2pDLFNBQVMsRUFBRyxNQUFNLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQzt3QkFDdEMsT0FBTyxFQUFHLE1BQU0sQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDO3FCQUNuQztpQkFDRixDQUFDO1lBRUYsTUFBTSxRQUFRLEdBQUcsTUFBTSwyREFBZ0IsQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLFFBQVEsRUFBRSxNQUFNLENBQUMsQ0FBQztZQUU1RSxJQUFHLFFBQVEsQ0FBQyxVQUFVLElBQUksUUFBUSxDQUFDLFVBQVUsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFDO2dCQUN2RCxPQUFNLEVBQUU7YUFDVDtZQUNELE9BQU87Z0JBQ0wsTUFBTSxFQUFFLDhCQUE4QjthQUN2QztTQUNGO1FBQUEsT0FBTSxDQUFDLEVBQUU7WUFDUiw0Q0FBRyxDQUFDLENBQUMsRUFBRSxrREFBYSxFQUFFLGdCQUFnQixDQUFDLENBQUM7WUFDeEMsT0FBTztnQkFDTCxNQUFNLEVBQUUsOEJBQThCO2FBQ3ZDO1NBQ0Y7SUFDTCxDQUFDO0NBQUE7QUFFRCxtRUFBbUU7QUFFbkUsTUFBTSxXQUFXLEdBQUcsQ0FBTyxHQUFXLEVBQUUsVUFBZ0IsRUFBd0IsRUFBRTtJQUNoRixJQUFJLENBQUMsVUFBVSxFQUFFO1FBQ2YsVUFBVSxHQUFHLElBQUksZUFBZSxFQUFFLENBQUM7S0FDcEM7SUFDRCxNQUFNLFFBQVEsR0FBRyxNQUFNLEtBQUssQ0FBQyxHQUFHLEVBQUU7UUFDaEMsTUFBTSxFQUFFLEtBQUs7UUFDYixPQUFPLEVBQUU7WUFDUCxjQUFjLEVBQUUsbUNBQW1DO1NBQ3BEO1FBQ0QsTUFBTSxFQUFFLFVBQVUsQ0FBQyxNQUFNO0tBQzFCLENBQ0EsQ0FBQztJQUNGLE9BQU8sUUFBUSxDQUFDLElBQUksRUFBRSxDQUFDO0FBQ3pCLENBQUM7QUFHRCxTQUFlLFdBQVcsQ0FDeEIsZUFBeUIsRUFDekIsZ0JBQTRCLEVBQzVCLGlCQUE2QixFQUM3QixrQkFBOEIsRUFDOUIsZUFBMkIsRUFDM0IsZUFBOEI7O1FBRTlCLE1BQU0saUJBQWlCLEdBQUcsa0JBQWtCLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxVQUFVLEdBQUcsSUFBSSxlQUFlLENBQUMsVUFBVSxDQUFDLFFBQVEsR0FBRyxDQUFDLGdHQUE4RjtRQUU1TiwrR0FBK0c7UUFFL0csTUFBTSxZQUFZLEdBQUcsaUJBQWlCLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxRQUFRLENBQUMsQ0FBQztRQUN2RSxNQUFNLGNBQWMsR0FBRyxlQUFlLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsWUFBWSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsVUFBVSxDQUFDLFdBQVcsQ0FBQyxDQUFDLEVBQUMsMENBQTBDO1FBRTdJLE1BQU0sa0JBQWtCLEdBQUcsaUJBQWlCLENBQUMsR0FBRyxDQUFDLENBQUMsT0FBaUIsRUFBRSxFQUFFO1lBRXBFLE1BQU0sT0FBTyxHQUFHLGVBQWU7aUJBQzdCLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsV0FBVyxLQUFHLE9BQU8sQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFDO2lCQUNuRSxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUU7Z0JBQ1IsT0FBTztvQkFDTixRQUFRLEVBQUUsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxRQUFRO29CQUMvQixJQUFJLEVBQUUsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxJQUFJO29CQUN2QixNQUFNLEVBQUUsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxNQUFNO29CQUMzQixXQUFXLEVBQUcsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxXQUFXO29CQUN0QyxjQUFjLEVBQUUsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxjQUFjO29CQUMzQyxpQkFBaUIsRUFBRSxDQUFDLENBQUMsVUFBVSxDQUFDLGlCQUFpQjtpQkFDOUI7WUFDdEIsQ0FBQyxDQUFDO1lBRUYsT0FBTztnQkFDTixRQUFRLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxRQUFRO2dCQUNyQyxFQUFFLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxRQUFRO2dCQUMvQixJQUFJLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxJQUFJO2dCQUM3QixZQUFZLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxZQUFZO2dCQUM3QyxPQUFPO2dCQUNQLFdBQVcsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLFdBQVc7Z0JBQzNDLFVBQVUsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLFVBQVU7Z0JBQ3pDLGFBQWEsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLGFBQWE7Z0JBQy9DLFlBQVksRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLFlBQVk7YUFDeEI7UUFDekIsQ0FBQyxDQUFDLENBQUM7UUFFSCxNQUFNLGtCQUFrQixHQUFHLGlCQUFpQixDQUFDLEdBQUcsQ0FBQyxDQUFDLE9BQWlCLEVBQUUsRUFBRTtZQUNwRSxPQUFPO2dCQUNKLEVBQUUsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLFFBQVE7Z0JBQy9CLEtBQUssRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLFdBQVcsSUFBSSxPQUFPLENBQUMsVUFBVSxDQUFDLFlBQVk7Z0JBQ3hFLElBQUksRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLElBQUk7Z0JBQzdCLFVBQVUsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLFVBQVU7Z0JBQ3pDLFVBQVUsRUFBRyxrQkFBa0IsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsV0FBVyxLQUFLLE9BQU8sQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFTLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQzthQUNwSDtRQUNKLENBQUMsQ0FBQyxDQUFDO1FBRUgsTUFBTSxpQkFBaUIsR0FBRyxnQkFBZ0IsQ0FBQyxHQUFHLENBQUMsQ0FBQyxPQUFpQixFQUFFLEVBQUU7WUFDbkUsT0FBTztnQkFDTCxFQUFFLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxRQUFRO2dCQUMvQixLQUFLLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxXQUFXLElBQUksT0FBTyxDQUFDLFVBQVUsQ0FBQyxZQUFZO2dCQUN4RSxJQUFJLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxJQUFJO2dCQUM3QixrQkFBa0IsRUFBRyxrQkFBa0IsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsVUFBVSxLQUFLLE9BQU8sQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFTLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQzthQUN2RyxDQUFDO1FBQ3hCLENBQUMsQ0FBQyxDQUFDO1FBRUgsTUFBTSxRQUFRLEdBQUc7WUFDYixRQUFRLEVBQUUsZUFBZSxDQUFDLFVBQVUsQ0FBQyxRQUFRO1lBQzdDLEVBQUUsRUFBRSxlQUFlLENBQUMsVUFBVSxDQUFDLFFBQVE7WUFDdkMsVUFBVSxFQUFFLGVBQWUsQ0FBQyxVQUFVLENBQUMsVUFBVSxJQUFJLENBQUM7WUFDdEQsTUFBTSxFQUFFO2dCQUNOLElBQUksRUFBRSxlQUFlLENBQUMsVUFBVSxDQUFDLE1BQU07Z0JBQ3ZDLElBQUksRUFBRSxlQUFlLENBQUMsVUFBVSxDQUFDLE1BQU0sS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsRUFBQyxDQUFDLFVBQVU7YUFDdEQ7WUFDaEIsSUFBSSxFQUFFLGVBQWUsQ0FBQyxVQUFVLENBQUMsSUFBSTtZQUNyQyxVQUFVLEVBQUUsZUFBZSxDQUFDLFVBQVUsQ0FBQyxVQUFVO1lBQ2pELFVBQVUsRUFBRSxlQUFlLENBQUMsVUFBVSxDQUFDLFVBQVU7WUFDakQsZ0JBQWdCLEVBQUUsZUFBZSxDQUFDLFVBQVUsQ0FBQyxnQkFBZ0I7WUFDN0QsZ0JBQWdCLEVBQUUsZUFBZSxDQUFDLFVBQVUsQ0FBQyxnQkFBZ0I7WUFDN0QsT0FBTyxFQUFFLGVBQWUsQ0FBQyxVQUFVLENBQUMsT0FBTztZQUMzQyxXQUFXLEVBQUUsTUFBTSxDQUFDLGVBQWUsQ0FBQyxVQUFVLENBQUMsV0FBVyxDQUFDO1lBQzNELE1BQU0sRUFBRSxlQUFlLENBQUMsVUFBVSxDQUFDLE1BQU07WUFDekMsVUFBVSxFQUFFLE1BQU0sQ0FBQyxlQUFlLENBQUMsVUFBVSxDQUFDLFVBQVUsQ0FBQztZQUN6RCxpQkFBaUIsRUFBSSxpQkFBeUIsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDO1lBQy9ELE9BQU8sRUFBRSxlQUFlO1NBQ1gsQ0FBQztRQUVsQixPQUFPLFFBQVEsQ0FBQztJQUNsQixDQUFDO0NBQUE7QUFFRCxTQUFlLGNBQWMsQ0FBQyxVQUFzQixFQUFFLE1BQXVCOztRQUUzRSxJQUFHO1lBQ0QsTUFBTSxPQUFPLEdBQUc7Z0JBQ2QsVUFBVSxFQUFFO29CQUNWLElBQUksRUFBRSxVQUFVLENBQUMsSUFBSTtvQkFDckIsV0FBVyxFQUFFLFVBQVUsQ0FBQyxXQUFXO29CQUNuQyxjQUFjLEVBQUUsVUFBVSxDQUFDLGNBQWM7b0JBQ3pDLFlBQVksRUFBRSxVQUFVLENBQUMsWUFBWTtvQkFDckMsUUFBUSxFQUFFLFVBQVUsQ0FBQyxRQUFRO29CQUM3QixNQUFNLEVBQUUsVUFBVSxDQUFDLE1BQU07b0JBQ3pCLE9BQU8sRUFBRSxVQUFVLENBQUMsT0FBTztvQkFDM0IsV0FBVyxFQUFFLFVBQVUsQ0FBQyxXQUFXO29CQUNuQyxNQUFNLEVBQUUsVUFBVSxDQUFDLE1BQU07b0JBQ3pCLFVBQVUsRUFBRSxVQUFVLENBQUMsVUFBVTtvQkFDakMsV0FBVyxFQUFFLFVBQVUsQ0FBQyxXQUFXO29CQUNuQyxVQUFVLEVBQUUsVUFBVSxDQUFDLFVBQVU7b0JBQ2pDLGdCQUFnQixFQUFDLFVBQVUsQ0FBQyxnQkFBZ0I7b0JBQzVDLFFBQVEsRUFBRSxVQUFVLENBQUMsUUFBUTtpQkFDOUI7YUFDRjtZQUNELE1BQU0sUUFBUSxHQUFHLE1BQU0sMkRBQWdCLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBQyxDQUFDLE9BQU8sQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1lBQzlFLElBQUcsUUFBUSxDQUFDLFVBQVUsSUFBSSxRQUFRLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztnQkFDbEUsT0FBTSxFQUFFLElBQUksRUFBRSxRQUFRLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsRUFBQzthQUMvQztZQUNELE9BQU87Z0JBQ0wsTUFBTSxFQUFHLElBQUksQ0FBQyxTQUFTLENBQUMsUUFBUSxDQUFDO2FBQ2xDO1NBRUY7UUFBQSxPQUFNLENBQUMsRUFBQztZQUNQLE9BQU87Z0JBQ0wsTUFBTSxFQUFFLENBQUM7YUFDVjtTQUNGO0lBQ0gsQ0FBQztDQUFBO0FBRUQsU0FBZSx1QkFBdUIsQ0FBQyxLQUFhLEVBQUUsTUFBdUI7O1FBQzNFLE9BQU8sQ0FBQyxHQUFHLENBQUMsbUNBQW1DLENBQUM7UUFFaEQsTUFBTSxRQUFRLEdBQUcsTUFBTSw2REFBa0IsQ0FBQyxNQUFNLENBQUMsb0JBQW9CLEVBQUUsS0FBSyxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQ3RGLElBQUcsUUFBUSxJQUFJLFFBQVEsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFDO1lBQ2hDLE9BQU8sUUFBUSxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsRUFBRTtnQkFDM0IsT0FBTztvQkFDTCxRQUFRLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxRQUFRO29CQUNyQyxFQUFFLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxRQUFRO29CQUMvQixXQUFXLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxXQUFXO29CQUMzQyxTQUFTLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxhQUFhO29CQUMzQyxRQUFRLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxZQUFZO29CQUN6QyxRQUFRLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxZQUFZO29CQUN6QyxTQUFTLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxhQUFhO29CQUMzQyxRQUFRLEVBQUUsWUFBWSxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsUUFBUSxDQUFDO29CQUNuRCxnQkFBZ0IsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLGdCQUFnQjtvQkFDckQsdUJBQXVCLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyx1QkFBdUI7b0JBQ25FLHFCQUFxQixFQUFFLE9BQU8sQ0FBQyxVQUFVLENBQUMscUJBQXFCO29CQUMvRCxJQUFJLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxJQUFJO29CQUM3QixVQUFVLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxVQUFVO29CQUN6QyxrQkFBa0IsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLGtCQUFrQjtvQkFDekQsTUFBTSxFQUFFLE9BQU8sQ0FBQyxVQUFVLENBQUMsTUFBTTtpQkFDWCxDQUFDO1lBQzVCLENBQUMsQ0FBQztTQUNKO0lBRUgsQ0FBQztDQUFBO0FBRUQsU0FBUyxZQUFZLENBQUMsUUFBZ0I7SUFDcEMsSUFBRyxDQUFDLFFBQVEsSUFBSSxRQUFRLEtBQUssRUFBRSxFQUFDO1FBQzlCLE9BQU8sRUFBRSxDQUFDO0tBQ1g7SUFDRCxJQUFJLGNBQWMsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBZ0IsQ0FBQztJQUV6RCxJQUFHLGNBQWMsSUFBSSxjQUFjLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBQztRQUM3QyxjQUFjLENBQUMsR0FBRyxDQUFDLENBQUMsV0FBc0IsRUFBRSxFQUFFO1lBQzFDLE9BQU8sZ0NBQ0EsV0FBVyxLQUNkLFFBQVEsRUFBRSxNQUFNLENBQUMsV0FBVyxDQUFDLFFBQVEsQ0FBQyxHQUM1QjtRQUNsQixDQUFDLENBQUMsQ0FBQztRQUNILGNBQWMsR0FBSSxjQUFzQixDQUFDLE9BQU8sQ0FBQyxVQUFVLEVBQUUsSUFBSSxDQUFDLENBQUM7S0FDcEU7U0FBSTtRQUNILGNBQWMsR0FBRyxFQUFFLENBQUM7S0FDckI7SUFFRCxPQUFPLGNBQWMsQ0FBQztBQUN4QixDQUFDO0FBRUQsU0FBZSx5QkFBeUIsQ0FBQyxNQUFNLEVBQUUsS0FBSzs7UUFDcEQsT0FBTyxDQUFDLEdBQUcsQ0FBQyw0QkFBNEIsQ0FBQztRQUN6QyxPQUFPLE1BQU0sNkRBQWtCLENBQUMsTUFBTSxDQUFDLGNBQWMsRUFBRSxLQUFLLEVBQUUsTUFBTSxDQUFDLENBQUM7SUFDeEUsQ0FBQztDQUFBO0FBRUQsU0FBUyxjQUFjLENBQUMsaUJBQTJCLEVBQUUsVUFBc0IsRUFDekUsb0JBQTJDO0lBRTNDLE1BQU0sZ0JBQWdCLEdBQUcsVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFDLE9BQU8sRUFBRSxFQUFFO1FBQ2xELE9BQU87WUFDTCxRQUFRLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxRQUFRO1lBQ3JDLEVBQUUsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLFFBQVE7WUFDL0IsWUFBWSxFQUFFLE9BQU8sQ0FBQyxVQUFVLENBQUMsWUFBWTtZQUM3QyxZQUFZLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxZQUFZO1lBQzdDLG9CQUFvQixFQUFFLG9CQUFvQixDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxnQkFBZ0IsS0FBSyxPQUFPLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQztZQUMxRyxLQUFLLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxLQUFLO1lBQy9CLEtBQUssRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLEtBQUs7WUFDL0IsV0FBVyxFQUFFLE9BQU8sQ0FBQyxVQUFVLENBQUMsV0FBVztZQUMzQyxhQUFhLEVBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxjQUFjO1lBQy9DLFdBQVcsRUFBRSxPQUFPLENBQUMsVUFBVSxDQUFDLFdBQVc7WUFDM0MsY0FBYyxFQUFFLE9BQU8sQ0FBQyxVQUFVLENBQUMsY0FBYztZQUNqRCxlQUFlLEVBQUUsT0FBTyxDQUFDLFVBQVUsQ0FBQyxlQUFlO1NBQ2xDLENBQUM7SUFDdEIsQ0FBQyxDQUFDLENBQUM7SUFFSCxNQUFNLFVBQVUsR0FBRztRQUNqQixRQUFRLEVBQUUsaUJBQWlCLENBQUMsVUFBVSxDQUFDLFFBQVE7UUFDL0MsRUFBRSxFQUFFLGlCQUFpQixDQUFDLFVBQVUsQ0FBQyxRQUFRO1FBQ3pDLElBQUksRUFBRSxpQkFBaUIsQ0FBQyxVQUFVLENBQUMsSUFBSTtRQUN2QyxjQUFjLEVBQUUsaUJBQWlCLENBQUMsVUFBVSxDQUFDLGNBQWM7UUFDM0QsZ0JBQWdCLEVBQUUsZ0JBQWdCO1FBQ2xDLFdBQVcsRUFBRSxpQkFBaUIsQ0FBQyxVQUFVLENBQUMsV0FBVztRQUNyRCxRQUFRLEVBQUUsaUJBQWlCLENBQUMsVUFBVSxDQUFDLFFBQVE7UUFDL0MsWUFBWSxFQUFFLGlCQUFpQixDQUFDLFVBQVUsQ0FBQyxZQUFZO1FBQ3ZELGdCQUFnQixFQUFFLGlCQUFpQixDQUFDLFVBQVUsQ0FBQyxnQkFBZ0I7UUFDL0QsUUFBUSxFQUFFLGlCQUFpQixDQUFDLFVBQVUsQ0FBQyxRQUFRO1FBQy9DLE1BQU0sRUFBRSxpQkFBaUIsQ0FBQyxVQUFVLENBQUMsTUFBTTtRQUMzQyxVQUFVLEVBQUUsaUJBQWlCLENBQUMsVUFBVSxDQUFDLFVBQVU7UUFDbkQsT0FBTyxFQUFFLGlCQUFpQixDQUFDLFVBQVUsQ0FBQyxPQUFPO1FBQzdDLFdBQVcsRUFBRSxNQUFNLENBQUMsaUJBQWlCLENBQUMsVUFBVSxDQUFDLFdBQVcsQ0FBQztRQUM3RCxNQUFNLEVBQUUsaUJBQWlCLENBQUMsVUFBVSxDQUFDLE1BQU07UUFDM0MsVUFBVSxFQUFFLE1BQU0sQ0FBQyxpQkFBaUIsQ0FBQyxVQUFVLENBQUMsVUFBVSxDQUFDO1FBQzNELFVBQVUsRUFBRSxLQUFLO1FBQ2pCLFdBQVcsRUFBRSxpQkFBaUIsQ0FBQyxVQUFVLENBQUMsV0FBVztLQUN4QztJQUVmLE9BQU8sVUFBVSxDQUFDO0FBQ3BCLENBQUM7QUFFRCxTQUFlLGtCQUFrQixDQUFDLHFCQUErQixFQUFFLG1CQUErQixFQUFFLE1BQU07O1FBQ3hHLElBQUksUUFBUSxHQUFHLE1BQU0sMkRBQWdCLENBQUMsTUFBTSxDQUFDLGNBQWMsRUFBRSxDQUFDLHFCQUFxQixDQUFDLEVBQUUsTUFBTSxDQUFDO1FBQzdGLElBQUcsUUFBUSxDQUFDLFVBQVUsSUFBSSxRQUFRLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBQztZQUNqRSxNQUFNLFFBQVEsR0FBRyxRQUFRLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQztZQUVqRCxNQUFNLDJCQUEyQixHQUFHLG1CQUFtQixDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsRUFBRTtnQkFDL0QsR0FBRyxDQUFDLFVBQVUsQ0FBQyxnQkFBZ0IsR0FBRyxRQUFRO2dCQUMxQyxPQUFPLEdBQUcsQ0FBQztZQUNkLENBQUMsQ0FBQztZQUNGLFFBQVEsR0FBRyxNQUFNLDJEQUFnQixDQUFDLE1BQU0sQ0FBQyxvQkFBb0IsRUFBRSwyQkFBMkIsRUFBRSxNQUFNLENBQUMsQ0FBQztZQUNwRyxJQUFHLFFBQVEsQ0FBQyxVQUFVLElBQUksUUFBUSxDQUFDLFVBQVUsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLEVBQUM7Z0JBQ2xFLE9BQU8sSUFBSSxDQUFDO2FBQ2I7U0FDSDtJQUNILENBQUM7Q0FBQTtBQUVELFNBQVMscUJBQXFCLENBQUMsUUFBc0I7SUFDbkQsT0FBTyxFQUFFLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxFQUFFLEVBQUUsQ0FBQyxFQUFFLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxFQUFFLEVBQzdDLFFBQVEsQ0FBQyxpQkFBaUIsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsa0JBQWtCLENBQUMsQ0FBQyxDQUFDO1NBQzFELEdBQUcsQ0FBQyxDQUFDLENBQW9CLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDO0FBQ2pELENBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUM1dkNELDZFQUE2RTs7Ozs7Ozs7OztBQUV4QjtBQUVyRDs7Ozs7R0FLRztBQUNJLE1BQU0sTUFBTSxHQUFHLENBQU8sS0FBYSxFQUFFLFNBQWlCLEVBQUUsRUFBRTtJQUM3RCxJQUFJO1FBQ0EsT0FBTyxNQUFNLGtCQUFrQixDQUFDLEtBQUssRUFBRSxTQUFTLENBQUMsQ0FBQztLQUNyRDtJQUFDLE9BQU8sS0FBSyxFQUFFO1FBQ1osT0FBTyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUNuQixPQUFPLE1BQU0sZ0JBQWdCLENBQUMsS0FBSyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0tBQ25EO0FBQ0wsQ0FBQyxFQUFDO0FBRUY7Ozs7R0FJRztBQUNJLE1BQU0sT0FBTyxHQUFHLENBQU8sS0FBYSxFQUFFLFNBQWlCLEVBQUUsRUFBRTtJQUM5RCxNQUFNLGVBQWUsR0FBRyxNQUFNLFdBQVcsQ0FBQyxLQUFLLEVBQUUsU0FBUyxDQUFDLENBQUM7SUFDNUQsTUFBTSxNQUFNLENBQUMsS0FBSyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0lBRS9CLE9BQU8sTUFBTSxDQUFDLGlCQUFpQixDQUFDLENBQUM7SUFDakMsT0FBTyxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUM7SUFDM0IsZUFBZSxDQUFDLGtCQUFrQixFQUFFLENBQUM7QUFFekMsQ0FBQyxFQUFDO0FBRUY7O0dBRUc7QUFDSCxTQUFlLGdCQUFnQixDQUFDLEtBQWEsRUFBRSxTQUFpQjs7UUFDNUQsTUFBTSxlQUFlLEdBQUcsTUFBTSxXQUFXLENBQUMsS0FBSyxFQUFFLFNBQVMsQ0FBQyxDQUFDO1FBQzVELE1BQU0sVUFBVSxHQUFHLE1BQU0sZUFBZSxDQUFDLGFBQWEsQ0FBQyxHQUFHLFNBQVMsVUFBVSxFQUFFO1lBQzNFLEtBQUssRUFBRSxJQUFXO1lBQ2xCLHNCQUFzQixFQUFFLEtBQUs7WUFDN0IsS0FBSyxFQUFFLElBQVc7U0FDckIsQ0FBQyxDQUFDO1FBQ0gsT0FBTyxVQUFVLENBQUM7SUFDdEIsQ0FBQztDQUFBO0FBQUEsQ0FBQztBQUVGOztHQUVHO0FBQ0gsU0FBZSxXQUFXLENBQUMsS0FBYSxFQUFFLFNBQWlCOztRQUN2RCxJQUFJLGVBQWUsR0FBRyxNQUFNLENBQUMsaUJBQWlCLENBQUM7UUFDL0MsSUFBRyxDQUFDLGVBQWUsRUFBQztZQUNoQixNQUFNLE9BQU8sR0FBRyxNQUFNLG1FQUFzQixDQUFDO2dCQUN6QywrQkFBK0I7Z0JBQy9CLHlCQUF5QjthQUFDLENBQUMsQ0FBQztZQUU1QixNQUFNLENBQUMsaUJBQWlCLENBQUMsR0FBRyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDdkMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUVyQyxlQUFlLEdBQUcsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQzdCLE1BQU0sU0FBUyxHQUFHLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUU3QixNQUFNLFNBQVMsR0FBRyxJQUFJLFNBQVMsQ0FBQztnQkFDNUIsS0FBSztnQkFDTCxTQUFTO2dCQUNULEtBQUssRUFBRSxLQUFLO2FBQ2YsQ0FBQyxDQUFDO1lBQ0gsZUFBZSxDQUFDLGtCQUFrQixDQUFDLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQztTQUNuRDtRQUNELE9BQU8sZUFBZSxDQUFDO0lBQzNCLENBQUM7Q0FBQTtBQUVEOztHQUVHO0FBQ0ksTUFBTSxrQkFBa0IsR0FBRyxDQUFPLEtBQWEsRUFBRSxTQUFpQixFQUFFLEVBQUU7SUFDekUsTUFBTSxlQUFlLEdBQUcsTUFBTSxXQUFXLENBQUMsS0FBSyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0lBQzVELE9BQU8sZUFBZSxDQUFDLGlCQUFpQixDQUFDLEdBQUcsU0FBUyxVQUFVLENBQUMsQ0FBQztBQUNyRSxDQUFDLEVBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDdEVGLElBQVksY0FxQlg7QUFyQkQsV0FBWSxjQUFjO0lBQ3hCLG9GQUFrRTtJQUNsRSx5RUFBdUQ7SUFDdkQsbUZBQWlFO0lBQ2pFLHFGQUFtRTtJQUNuRSwrRkFBNkU7SUFDN0UsNkVBQTJEO0lBQzNELCtFQUE2RDtJQUM3RCwrRUFBNkQ7SUFDN0QsMEVBQXdEO0lBQ3hELCtEQUE2QztJQUM3QyxpRUFBK0M7SUFDL0Msc0VBQW9EO0lBQ3BELHlFQUF1RDtJQUN2RCxxRUFBbUQ7SUFDbkQsMEZBQXdFO0lBQ3hFLDhGQUE0RTtJQUM1RSxpRkFBK0Q7SUFDL0QsbUZBQWlFO0lBQ2pFLG9GQUFrRTtJQUNsRSxnRkFBOEQ7QUFDaEUsQ0FBQyxFQXJCVyxjQUFjLEtBQWQsY0FBYyxRQXFCekI7QUFtSWMsTUFBTSxxQkFBcUI7SUFBMUM7UUFDRSxPQUFFLEdBQUcsNEJBQTRCLENBQUM7SUF5R3BDLENBQUM7SUF2R0MsVUFBVTtRQUNSLE9BQU8sTUFBTSxDQUFDLElBQUksQ0FBQyxjQUFjLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxjQUFjLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUNqRSxDQUFDO0lBRUQsaUJBQWlCO1FBQ2YsT0FBTztZQUNKLGdCQUFnQixFQUFFLElBQUk7WUFDdEIsU0FBUyxFQUFFLEVBQUU7WUFDYixhQUFhLEVBQUUsRUFBRTtZQUNqQixJQUFJLEVBQUUsSUFBSTtZQUNWLElBQUksRUFBRSxJQUFJO1lBQ1YsUUFBUSxFQUFFLElBQUk7WUFDZCx1QkFBdUIsRUFBRSxLQUFLO1lBQzlCLE9BQU8sRUFBRSxFQUFFO1lBQ1gsYUFBYSxFQUFFLEVBQUU7WUFDakIsTUFBTSxFQUFFLEVBQUU7WUFDVixrQkFBa0IsRUFBRSxLQUFLO1lBQ3pCLHNCQUFzQixFQUFFLElBQUk7WUFDNUIsaUJBQWlCLEVBQUUsRUFBRTtZQUNyQixXQUFXLEVBQUUsRUFBRTtZQUNmLFVBQVUsRUFBRSxFQUFFO1lBQ2QsV0FBVyxFQUFFLEVBQUU7WUFDZixZQUFZLEVBQUUsRUFBRTtZQUNoQixZQUFZLEVBQUUsRUFBRTtZQUNoQixZQUFZLEVBQUUsSUFBSTtTQUNOLENBQUM7SUFDbEIsQ0FBQztJQUVELFVBQVU7UUFDUixPQUFPLENBQUMsVUFBcUIsRUFBRSxNQUFtQixFQUFFLFFBQWlCLEVBQWEsRUFBRTtZQUVsRixRQUFRLE1BQU0sQ0FBQyxJQUFJLEVBQUU7Z0JBRW5CLEtBQUssY0FBYyxDQUFDLG1CQUFtQjtvQkFDckMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLGNBQWMsRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBRXBELEtBQUssY0FBYyxDQUFDLHdCQUF3QjtvQkFDMUMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLGNBQWMsRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBRXBELEtBQUssY0FBYyxDQUFDLHdCQUF3QjtvQkFDMUMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLGNBQWMsRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBRXBELEtBQUssY0FBYyxDQUFDLHdCQUF3QjtvQkFDMUMsTUFBTSxXQUFXLEdBQUcsVUFBVSxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLEVBQUU7d0JBQ3JELHVDQUNJLE1BQU0sS0FDVCxVQUFVLEVBQUUsTUFBTSxDQUFDLEVBQUUsS0FBSyxNQUFNLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxXQUFXLEVBQUUsSUFDckQ7b0JBQ0osQ0FBQyxDQUFDO29CQUNGLE9BQU8sVUFBVSxDQUFDLEdBQUcsQ0FBQyxhQUFhLEVBQUUsV0FBVyxDQUFDLENBQUM7Z0JBRXBELEtBQUssY0FBYyxDQUFDLHVCQUF1QjtvQkFDekMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLGFBQWEsRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBRW5ELEtBQUssY0FBYyxDQUFDLHNCQUFzQjtvQkFDeEMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLFlBQVksRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBRWxELEtBQUssY0FBYyxDQUFDLDRCQUE0QjtvQkFDOUMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLHdCQUF3QixFQUFFLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFFOUQsS0FBSyxjQUFjLENBQUMsd0JBQXdCO29CQUMxQyxPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsb0JBQW9CLEVBQUUsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO2dCQUUxRCxLQUFLLGNBQWMsQ0FBQyxVQUFVO29CQUM1QixPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsUUFBUSxFQUFFLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFFOUMsS0FBSyxjQUFjLENBQUMsbUJBQW1CO29CQUNyQyxPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsU0FBUyxFQUFFLE1BQU0sQ0FBQyxHQUFHLENBQUM7Z0JBRTlDLEtBQUssY0FBYyxDQUFDLHdCQUF3QjtvQkFDMUMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLGFBQWEsRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDO2dCQUVsRCxLQUFLLGNBQWMsQ0FBQyw4QkFBOEI7b0JBQ2hELE9BQU8sVUFBVSxDQUFDLEdBQUcsQ0FBQyxtQkFBbUIsRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDO2dCQUV4RCxLQUFLLGNBQWMsQ0FBQyx5QkFBeUI7b0JBQ3pDLE9BQU8sVUFBVSxDQUFDLEdBQUcsQ0FBQyxlQUFlLEVBQUUsTUFBTSxDQUFDLEdBQUcsQ0FBQztnQkFFdEQsS0FBSyxjQUFjLENBQUMsbUJBQW1CO29CQUNyQyxPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsVUFBVSxFQUFFLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFDaEQsS0FBSyxjQUFjLENBQUMsZUFBZTtvQkFDakMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLE1BQU0sRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBRTVDLEtBQUssY0FBYyxDQUFDLHFCQUFxQjtvQkFDdkMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLFdBQVcsRUFBRSxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBRWpELEtBQUssY0FBYyxDQUFDLHNCQUFzQjtvQkFDeEMsSUFBSSxTQUFTLEdBQUcsQ0FBQyxHQUFHLFVBQVUsQ0FBQyxTQUFTLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUU7d0JBQy9DLHVDQUNJLENBQUMsS0FDSixVQUFVLEVBQUUsQ0FBQyxDQUFDLEVBQUUsS0FBSyxNQUFNLENBQUMsR0FBRyxJQUMvQjtvQkFDSixDQUFDLENBQUM7b0JBQ0YsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLFdBQVcsRUFBRSxTQUFTLENBQUM7Z0JBQy9DO29CQUNFLE9BQU8sVUFBVSxDQUFDO2FBQ3JCO1FBQ0gsQ0FBQztJQUNILENBQUM7SUFFRCxXQUFXO1FBQ1QsT0FBTyxXQUFXLENBQUM7SUFDckIsQ0FBQztDQUNGOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQzNRTSxNQUFNLFVBQVUsR0FBRyxZQUFZLENBQUM7QUFDaEMsTUFBTSxXQUFXLEdBQUcsYUFBYSxDQUFDO0FBQ2xDLE1BQU0sYUFBYSxHQUFHLGVBQWUsQ0FBQztBQUN0QyxNQUFNLFdBQVcsR0FBRyxhQUFhLENBQUM7QUFDbEMsTUFBTSxjQUFjLEdBQUcsZ0JBQWdCLENBQUM7QUFFeEMsTUFBTSxzQkFBc0IsR0FBRyxVQUFVLENBQUM7QUFDMUMsTUFBTSxXQUFXLEdBQUcsb0JBQW9CLENBQUM7QUFDekMsTUFBTSxrQkFBa0IsR0FBRyx3Q0FBd0MsQ0FBQztBQUNwRSxNQUFNLG9CQUFvQixHQUFHLDBDQUEwQyxDQUFDO0FBQ3hFLE1BQU0sc0JBQXNCLEdBQUcsNENBQTRDLENBQUM7QUFDNUUsTUFBTSxnQkFBZ0IsR0FBRyxzQ0FBc0MsQ0FBQztBQUNoRSxNQUFNLG1CQUFtQixHQUFHLHlDQUF5QyxDQUFDO0FBQ3RFLE1BQU0sbUJBQW1CLEdBQUcsMENBQTBDLENBQUM7QUFDdkUsTUFBTSxrQkFBa0IsR0FBRyx3Q0FBd0MsQ0FBQztBQUNwRSxNQUFNLG1CQUFtQixHQUFHLHlDQUF5QyxDQUFDO0FBQ3RFLE1BQU0sa0JBQWtCLEdBQUcsd0NBQXdDLENBQUM7QUFDcEUsTUFBTSxrQkFBa0IsR0FBRyx3Q0FBd0MsQ0FBQztBQUNwRSxNQUFNLDZCQUE2QixHQUFHLG9GQUFvRjtBQUUxSCxNQUFNLHdCQUF3QixHQUFHLDBCQUEwQixDQUFDO0FBQzVELE1BQU0sMEJBQTBCLEdBQUcsNEJBQTRCLENBQUM7QUFDaEUsTUFBTSxzQkFBc0IsR0FBRyxzQkFBc0IsQ0FBQztBQUN0RCxNQUFNLHVCQUF1QixHQUFHLHlCQUF5QixDQUFDO0FBQzFELE1BQU0sSUFBSSxHQUFHLHlCQUF5QixDQUFDO0FBQ3ZDLE1BQU0sV0FBVyxHQUFHLGFBQWEsQ0FBQztBQUNsQyxNQUFNLHNCQUFzQixHQUFHLHdCQUF3QixDQUFDO0FBQ3hELE1BQU0sbUJBQW1CLEdBQUcscUJBQXFCLENBQUM7QUFDbEQsTUFBTSx3QkFBd0IsR0FBRywwQkFBMEIsQ0FBQztBQUU1RCxNQUFNLHdCQUF3QixHQUFHLEdBQUcsQ0FBQztBQUNyQyxNQUFNLDBCQUEwQixHQUFHLEdBQUcsQ0FBQztBQUN2QyxNQUFNLGNBQWMsR0FBRyxDQUFDLENBQUM7QUFFaEMsSUFBWSxZQU1YO0FBTkQsV0FBWSxZQUFZO0lBQ3BCLGlDQUFpQjtJQUNqQixpREFBaUM7SUFDakMsbURBQW1DO0lBQ25DLHNEQUFzQztJQUN0QyxxREFBcUM7QUFDekMsQ0FBQyxFQU5XLFlBQVksS0FBWixZQUFZLFFBTXZCO0FBRU0sTUFBTSxpQkFBaUIsR0FBRyxzQkFBc0IsQ0FBQztBQUNqRCxNQUFNLHNCQUFzQixHQUFHLGdLQUFnSyxDQUFDO0FBRWhNLE1BQU0sZ0JBQWdCLEdBQUcseUJBQXlCLENBQUM7QUFDbkQsTUFBTSxxQkFBcUIsR0FBRywwS0FBMEssQ0FBQztBQUV6TSxNQUFNLE9BQU8sR0FBRyxTQUFTLENBQUM7QUFDMUIsTUFBTSxZQUFZLEdBQUcsMERBQTBELENBQUM7QUFFaEYsTUFBTSw2QkFBNkIsR0FBRyw0Q0FBNEMsQ0FBQztBQUUxRix3Q0FBd0M7QUFDakMsTUFBTSxRQUFRLEdBQUcsRUFBRSxDQUFDO0FBQ3BCLE1BQU0sdUJBQXVCLEdBQUcsSUFBSSxDQUFDO0FBQ3JDLE1BQU0sdUJBQXVCLEdBQUcsR0FBRyxDQUFDO0FBQ3BDLE1BQU0sWUFBWSxHQUFHLFNBQVMsQ0FBQztBQUMvQixNQUFNLFlBQVksR0FBRyxNQUFNLENBQUM7QUFDNUIsTUFBTSxTQUFTLEdBQUcsU0FBUyxDQUFDO0FBQzVCLE1BQU0sWUFBWSxHQUFHLFNBQVMsQ0FBQztBQUMvQixNQUFNLFdBQVcsR0FBRyxTQUFTLENBQUM7QUFDOUIsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDO0FBQzFCLE1BQU0sd0JBQXdCLEdBQUcsR0FBRyxDQUFDO0FBRXJDLE1BQU0sVUFBVSxHQUFHLHdCQUF3QixDQUFDO0FBRTVDLE1BQU0sZ0JBQWdCLEdBQUcsRUFBQyxFQUFFLEVBQUUsS0FBSyxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsS0FBSyxFQUFFLFFBQVEsRUFBUSxDQUFDO0FBRTdFLE1BQU0sWUFBWSxHQUFHLGdFQUFnRSxDQUFDO0FBQ3RGLE1BQU0sbUJBQW1CLEdBQUcsZ0RBQWdELENBQUM7QUFDN0UsTUFBTSwyQkFBMkIsR0FBRyx3REFBd0QsQ0FBQztBQUM3RixNQUFNLGdDQUFnQyxHQUFHLDZEQUE2RCxDQUFDO0FBQ3ZHLE1BQU0sOEJBQThCLEdBQUcsMkRBQTJELENBQUM7QUFFbkcsTUFBTSx1QkFBdUIsR0FBRyw2RkFBNkYsQ0FBQztBQUU5SCxNQUFNLG1CQUFtQixHQUFHLGdCQUFnQixDQUFDO0FBRTdDLE1BQU0sa0JBQWtCLEdBQUcsY0FBYyxDQUFDO0FBQzFDLE1BQU0sd0JBQXdCLEdBQUcsc0JBQXNCLENBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDaEZWO0FBR29CO0FBR2pDO0FBRXhDLFNBQWUsaUJBQWlCLENBQUMsTUFBdUI7O1FBQ3RELE9BQU8sOEVBQTBCLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDO0lBQ3ZELENBQUM7Q0FBQTtBQUVNLFNBQWUsb0JBQW9CLENBQUMsR0FBVyxFQUFFLEtBQWEsRUFDbkUsTUFBdUI7O1FBRXJCLElBQUc7WUFFRCxNQUFNLGNBQWMsR0FBRyxNQUFNLGlCQUFpQixDQUFDLE1BQU0sQ0FBQyxDQUFDO1lBQ3ZELE9BQU8sOEVBQWEsQ0FBQyxFQUFFLEdBQUcsRUFBRSxLQUFLLEVBQUUsY0FBYyxFQUFFLFNBQVMsRUFBRSxJQUFJLEVBQUUsQ0FBQztpQkFDcEUsSUFBSSxDQUFDLENBQUMsUUFBZ0MsRUFBRSxFQUFFO2dCQUN6QyxPQUFPLFFBQVE7WUFDakIsQ0FBQyxDQUFDO1NBRUg7UUFBQSxPQUFNLENBQUMsRUFBQztZQUNQLDRDQUFHLENBQUMsQ0FBQyxFQUFFLGtEQUFhLEVBQUUsc0JBQXNCLENBQUM7U0FDOUM7SUFDTCxDQUFDO0NBQUE7QUFFTSxTQUFlLGtCQUFrQixDQUFDLEdBQVcsRUFBRSxLQUFhLEVBQUUsTUFBdUI7O1FBRTNGLE1BQU0sY0FBYyxHQUFHLE1BQU0saUJBQWlCLENBQUMsTUFBTSxDQUFDLENBQUM7UUFFdEQsSUFBRztZQUNDLE1BQU0sUUFBUSxHQUFHLE1BQU0sOEVBQWEsQ0FBQyxFQUFFLEdBQUcsRUFBRSxLQUFLLEVBQUUsY0FBYyxFQUFHLFVBQVUsRUFBQyxNQUFNLEVBQUUsU0FBUyxFQUFFLElBQUksRUFBRSxDQUFDO1lBQ3pHLE9BQVEsUUFBbUMsQ0FBQyxRQUFRLENBQUM7U0FDeEQ7UUFBQSxPQUFNLENBQUMsRUFBQztZQUNMLDRDQUFHLENBQUMsQ0FBQyxFQUFFLGtEQUFhLEVBQUUsb0JBQW9CLENBQUM7WUFDM0MsNENBQUcsQ0FBQyxHQUFHLEVBQUUsZ0RBQVcsRUFBRSxLQUFLLENBQUMsQ0FBQztTQUNoQztJQUNILENBQUM7Q0FBQTtBQUVNLFNBQWdCLHlCQUF5QixDQUFDLFNBQW1CLEVBQ3BFLEdBQVcsRUFBRSxjQUFzQixFQUFFLE1BQXVCOztRQUU1RCxNQUFNLGNBQWMsR0FBRyxNQUFNLGlCQUFpQixDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBRXZELE1BQU0sUUFBUSxHQUFHLE1BQU0sNkVBQVksQ0FBQztZQUNoQyxTQUFTO1lBQ1QsR0FBRyxFQUFFLGNBQWM7WUFDbkIsY0FBYztZQUNkLFNBQVMsRUFBRSxJQUFJO1NBQ2xCLENBQUMsQ0FBQztRQUNILE9BQU8sUUFBUSxDQUFDLG1CQUFtQixDQUFDO0lBQ3BDLENBQUM7Q0FBQTtBQUVNLFNBQWdCLGtCQUFrQixDQUFDLEdBQVcsRUFBRSxVQUFlLEVBQUUsTUFBdUI7O1FBQzdGLE1BQU0sY0FBYyxHQUFHLE1BQU0saUJBQWlCLENBQUMsTUFBTSxDQUFDLENBQUM7UUFFdkQsT0FBTywrRUFBYyxDQUFDO1lBQ2xCLEdBQUc7WUFDSCxjQUFjO1lBQ2QsUUFBUSxFQUFFLENBQUM7b0JBQ1gsVUFBVTtpQkFDVCxDQUFDO1lBQ0YsaUJBQWlCLEVBQUUsSUFBSTtTQUMxQixDQUFDO0lBQ0osQ0FBQztDQUFBO0FBRU0sU0FBZ0IsbUJBQW1CLENBQUMsR0FBVyxFQUFFLFFBQW9CLEVBQUUsTUFBdUI7O1FBQ25HLE1BQU0sY0FBYyxHQUFHLE1BQU0saUJBQWlCLENBQUMsTUFBTSxDQUFDLENBQUM7UUFDdkQsT0FBTywrRUFBYyxDQUFDO1lBQ2xCLEdBQUc7WUFDSCxjQUFjO1lBQ2QsUUFBUTtTQUNYLENBQUM7SUFDSixDQUFDO0NBQUE7QUFFTSxTQUFnQixnQkFBZ0IsQ0FBQyxHQUFXLEVBQUUsUUFBZSxFQUFFLE1BQXVCOztRQUUzRixNQUFNLGNBQWMsR0FBRyxNQUFNLGlCQUFpQixDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBRXZELElBQUc7WUFDRCxPQUFPLDRFQUFXLENBQUMsRUFBRSxHQUFHLEVBQUUsUUFBUSxFQUFFLGNBQWMsRUFBRSxpQkFBaUIsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO1NBQ2hGO1FBQUEsT0FBTSxDQUFDLEVBQUM7WUFDUCxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO1NBQ2hCO0lBQ0gsQ0FBQztDQUFBO0FBRU0sU0FBZ0IsbUJBQW1CLENBQUMsR0FBVyxFQUFFLFNBQW1CLEVBQUUsTUFBdUI7O1FBRWhHLE1BQU0sY0FBYyxHQUFHLE1BQU0saUJBQWlCLENBQUMsTUFBTSxDQUFDLENBQUM7UUFDdkQsT0FBTywrRUFBYyxDQUFDLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxjQUFjLEVBQUUsaUJBQWlCLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztJQUN2RixDQUFDO0NBQUE7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDNUZELElBQVksT0FJWDtBQUpELFdBQVksT0FBTztJQUNmLCtCQUFvQjtJQUNwQiwwQkFBZTtJQUNmLDBCQUFlO0FBQ25CLENBQUMsRUFKVyxPQUFPLEtBQVAsT0FBTyxRQUlsQjtBQUVNLFNBQVMsR0FBRyxDQUFDLE9BQWUsRUFBRSxJQUFjLEVBQUUsSUFBYTtJQUM5RCxJQUFHLENBQUMsSUFBSSxFQUFDO1FBQ0wsSUFBSSxHQUFHLE9BQU8sQ0FBQyxJQUFJO0tBQ3RCO0lBRUQsSUFBRyxJQUFJLEVBQUM7UUFDSixJQUFJLEdBQUcsSUFBSSxJQUFJLEdBQUcsQ0FBQztLQUN0QjtJQUVELE9BQU8sR0FBRyxJQUFJLElBQUksSUFBSSxFQUFFLENBQUMsY0FBYyxFQUFFLE1BQU0sT0FBTyxJQUFJLElBQUksRUFBRSxDQUFDO0lBRWpFLFFBQU8sSUFBSSxFQUFDO1FBQ1IsS0FBSyxPQUFPLENBQUMsSUFBSTtZQUNiLE9BQU8sQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLENBQUM7WUFDckIsTUFBTTtRQUNWLEtBQUssT0FBTyxDQUFDLEdBQUc7WUFDWixPQUFPLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO1lBQ3RCLE1BQU07UUFDVixLQUFLLE9BQU8sQ0FBQyxLQUFLO1lBQ2QsT0FBTyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQztZQUN2QixNQUFNO1FBQ1Y7WUFDSSxPQUFPLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxDQUFDO0tBQzVCO0FBQ0wsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQzdCTSxNQUFNLFVBQVUsR0FBRyxDQUFJLEdBQVEsRUFBRSxJQUFZLEVBQUUsT0FBZ0IsRUFBTyxFQUFFO0lBQzVFLE9BQU8sR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUcsRUFBRSxDQUFHLEVBQUUsRUFBRTtRQUMxQixJQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEVBQUM7WUFDbkIsT0FBTyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1NBQ3hCO1FBQ0QsSUFBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxFQUFDO1lBQ25CLE9BQU8sT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztTQUN4QjtRQUNELE9BQU8sQ0FBQyxDQUFDO0lBQ2IsQ0FBQyxDQUFDLENBQUM7QUFDTCxDQUFDO0FBRU0sTUFBTSxVQUFVLEdBQUcsR0FBRyxFQUFFO0lBQzdCLE9BQU8sc0NBQXNDLENBQUMsT0FBTyxDQUFDLE9BQU8sRUFBRSxVQUFTLENBQUM7UUFDdkUsSUFBSSxDQUFDLEdBQUcsSUFBSSxDQUFDLE1BQU0sRUFBRSxHQUFHLEVBQUUsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLENBQUMsSUFBSSxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsR0FBRyxHQUFHLEdBQUcsQ0FBQyxDQUFDO1FBQ25FLE9BQU8sQ0FBQyxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN4QixDQUFDLENBQUMsQ0FBQztBQUNMLENBQUM7QUFFTSxNQUFNLFNBQVMsR0FBRyxDQUFDLFlBQW9CLEVBQVUsRUFBRTtJQUN4RCxJQUFHLENBQUMsWUFBWSxFQUFDO1FBQ2YsT0FBTTtLQUNQO0lBQ0EsT0FBTyxJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsQ0FBQyxjQUFjLEVBQUUsQ0FBQztBQUNsRCxDQUFDO0FBRU0sTUFBTSxRQUFRLEdBQUcsQ0FBQyxJQUFZLEVBQVUsRUFBRTtJQUM5QyxPQUFPLElBQUksSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLGVBQWUsRUFBRSxDQUFDO0FBQzNDLENBQUM7QUFHRCx3RkFBd0Y7QUFDeEYsNkVBQTZFO0FBQzdFLGNBQWM7QUFDZCx1QkFBdUI7QUFDdkIsdUJBQXVCO0FBRXZCLG9EQUFvRDtBQUNwRCxzQkFBc0I7QUFDdEIsbUJBQW1CO0FBQ25CLG1CQUFtQjtBQUNuQixvQkFBb0I7QUFDcEIsb0JBQW9CO0FBQ3BCLG9CQUFvQjtBQUVwQix5Q0FBeUM7QUFFekMsdUJBQXVCO0FBQ3ZCLHVCQUF1QjtBQUN2QiwrQkFBK0I7QUFDL0IsK0JBQStCO0FBQy9CLCtCQUErQjtBQUMvQixPQUFPO0FBRVAsMEVBQTBFO0FBQzFFLGlEQUFpRDtBQUNqRCwyR0FBMkc7QUFDM0csZUFBZTtBQUNmLElBQUk7QUFFSixNQUFNLENBQUMsU0FBUyxDQUFDLFdBQVcsR0FBRztJQUM3QixPQUFPLElBQUksQ0FBQyxPQUFPLENBQUMsUUFBUSxFQUFFLFVBQVMsR0FBRyxJQUFFLE9BQU8sR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxXQUFXLEVBQUUsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDLEVBQUMsQ0FBQyxDQUFDO0FBQ2xILENBQUMsQ0FBQztBQUVGLEtBQUssQ0FBQyxTQUFTLENBQUMsT0FBTyxHQUFHLFVBQVksSUFBSSxFQUFFLE9BQU87SUFDakQsT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBRyxFQUFFLENBQUcsRUFBRSxFQUFFO1FBQzVCLElBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsRUFBQztZQUNuQixPQUFPLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDeEI7UUFDRCxJQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEVBQUM7WUFDbkIsT0FBTyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1NBQ3hCO1FBQ0QsT0FBTyxDQUFDLENBQUM7SUFDWCxDQUFDLENBQUMsQ0FBQztBQUNMLENBQUM7QUFFRCxLQUFLLENBQUMsU0FBUyxDQUFDLE9BQU8sR0FBRyxVQUFTLEdBQUc7SUFDcEMsT0FBTyxJQUFJLENBQUMsTUFBTSxDQUFDLFVBQVMsRUFBRSxFQUFFLENBQUM7UUFDL0IsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQztRQUN4QyxPQUFPLEVBQUUsQ0FBQztJQUNaLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQztBQUNULENBQUMsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNsRjJDO0FBQ3BCO0FBRUg7QUFFOEQ7QUFFTjtBQUNoQztBQUNMO0FBQ0g7QUFDdEMsTUFBTSxFQUFFLFdBQVcsRUFBRSxHQUFHLGlEQUFVLENBQUM7QUFFNUIsTUFBTSxlQUFlLEdBQUMsQ0FBQyxFQUFDLEtBQUssRUFBRSxPQUFPLEVBQUUsTUFBTSxFQUFFLFNBQVMsRUFDQSxFQUFFLEVBQUU7SUFFaEUsTUFBTSxDQUFDLE9BQU8sRUFBRSxVQUFVLENBQUMsR0FBRyxzREFBYyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQ3BELE1BQU0sQ0FBQyxTQUFTLEVBQUUsVUFBVSxDQUFDLEdBQUcsc0RBQWMsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUN0RCxNQUFNLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQyxHQUFHLHNEQUFjLENBQUMsRUFBRSxDQUFDLENBQUM7SUFDM0MsTUFBTSxDQUFDLFdBQVcsRUFBRSxjQUFjLENBQUMsR0FBRyxzREFBYyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3pELE1BQU0sQ0FBQyxXQUFXLEVBQUUsY0FBYyxDQUFDLEdBQUcsc0RBQWMsQ0FBZ0IsRUFBRSxDQUFDLENBQUM7SUFDeEUsTUFBTSxDQUFDLGtCQUFrQixFQUFFLHFCQUFxQixDQUFDLEdBQUcsc0RBQWMsQ0FBYyxJQUFJLENBQUMsQ0FBQztJQUN0RixNQUFNLENBQUMsTUFBTSxFQUFFLFNBQVMsQ0FBQyxHQUFHLHNEQUFjLENBQUMsSUFBSSxDQUFDO0lBRWhELE1BQU0sVUFBVSxHQUFHLFdBQVcsQ0FBQyxDQUFDLEtBQVUsRUFBRSxFQUFFOztRQUMxQyxPQUFPLFdBQUssQ0FBQyxTQUFTLDBDQUFFLFlBQVksQ0FBQztJQUN6QyxDQUFDLENBQUM7SUFFRixNQUFNLE9BQU8sR0FBRyxXQUFXLENBQUMsQ0FBQyxLQUFVLEVBQUUsRUFBRTs7UUFDdkMsT0FBTyxXQUFLLENBQUMsU0FBUywwQ0FBRSxPQUFtQixDQUFDO0lBQy9DLENBQUMsQ0FBQztJQUVILHVEQUFlLENBQUMsR0FBRyxFQUFFO1FBQ2pCLElBQUcsVUFBVSxFQUFDO1lBQ1gsU0FBUyxpQ0FBTSxLQUFLLENBQUMsTUFBTSxLQUFFLFVBQVUsRUFBQyxVQUFVLElBQUUsQ0FBQztTQUN2RDtJQUNMLENBQUMsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFDO0lBRWhCLHVEQUFlLENBQUMsR0FBRyxFQUFFO1FBQ2pCLElBQUcsT0FBTyxJQUFJLE9BQU8sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFDO1lBQzdCLE1BQU0sS0FBSyxHQUFHLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7WUFDaEMsS0FBYSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQztZQUM5QixjQUFjLENBQUMsS0FBSyxDQUFDLENBQ2pDO1NBQVM7SUFDTixDQUFDLEVBQUUsQ0FBQyxPQUFPLENBQUMsQ0FBQztJQUViLHVEQUFlLENBQUMsR0FBRSxFQUFFO1FBQ2hCLFVBQVUsQ0FBQyxPQUFPLENBQUMsQ0FBQztRQUNwQixPQUFPLENBQUMsRUFBRSxDQUFDLENBQUM7UUFDWixjQUFjLENBQUMsRUFBRSxDQUFDLENBQUM7UUFDbkIscUJBQXFCLENBQUMsSUFBSSxDQUFDLENBQUM7SUFDaEMsQ0FBQyxFQUFFLENBQUMsT0FBTyxDQUFDLENBQUM7SUFFYixNQUFNLGFBQWEsR0FBQyxHQUFRLEVBQUU7UUFFMUIsTUFBTSxLQUFLLEdBQUcsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsV0FBVyxFQUFFLEtBQUssSUFBSSxDQUFDLFdBQVcsRUFBRSxDQUFDLElBQUksRUFBRSxDQUFDLENBQUM7UUFDcEYsSUFBRyxLQUFLLEVBQUM7WUFDTCxvRkFBYyxDQUFDLGtHQUF5QixFQUFFLFdBQVcsSUFBSSxpQkFBaUIsQ0FBQyxDQUFDO1lBQzVFLE9BQU87U0FDVjtRQUVELFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUVqQixJQUFHO1lBQ0MsSUFBSSxTQUFTLEdBQUc7Z0JBQ1osSUFBSTtnQkFDSixLQUFLLEVBQUUsSUFBSTtnQkFDWCxJQUFJLEVBQUUsa0JBQWtCO2dCQUN4QixXQUFXO2FBQ0osQ0FBQztZQUNaLE1BQU0sUUFBUSxHQUFHLE1BQU0sZ0ZBQVUsQ0FBQyxNQUFNLEVBQUUsU0FBUyxDQUFDLENBQUM7WUFDckQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxRQUFRLENBQUMsQ0FBQztZQUN0QixJQUFHLFFBQVEsQ0FBQyxNQUFNLEVBQUM7Z0JBQ2hCLE1BQU0sSUFBSSxLQUFLLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO2FBQzNDO1lBRUQsU0FBUyxHQUFHLFFBQVEsQ0FBQyxJQUFJLENBQUM7WUFDMUIsU0FBUyxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDO1lBRXZDLG9GQUFjLENBQUMsMkdBQWtDLEVBQzlDLENBQUMsR0FBRyxPQUFPLEVBQUUsU0FBUyxDQUFDLENBQUM7WUFFM0IsU0FBUyxDQUFDLFNBQVMsQ0FBQyxDQUFDO1lBQ3JCLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztTQUNqQjtRQUFBLE9BQU0sR0FBRyxFQUFDO1lBQ1IsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUNqQixvRkFBYyxDQUFDLGtHQUF5QixFQUFFLEdBQUcsQ0FBQyxPQUFPLENBQUMsQ0FBQztTQUN6RDtnQkFBTztZQUNKLFVBQVUsQ0FBQyxLQUFLLENBQUMsQ0FBQztTQUNyQjtJQUNMLENBQUM7SUFFRCxPQUFPLENBQ0gsNERBQUMsa0RBQVMsSUFBQyxLQUFLLEVBQUMsZ0JBQWdCLEVBQzdCLE9BQU8sRUFBRSxDQUFDLENBQUMsSUFBSSxJQUFJLGtCQUFrQixDQUFDLEVBQUcsSUFBSSxFQUFFLGFBQWEsRUFDNUQsZ0JBQWdCLEVBQUUsTUFBTSxFQUFFLE9BQU8sRUFBRSxTQUFTLEVBQzVDLE9BQU8sRUFBRSxPQUFPO1FBRWhCLHFFQUFLLFNBQVMsRUFBQyxTQUFTO1lBQ3BCLHFFQUFLLFNBQVMsRUFBQyxZQUFZO2dCQUN2Qiw0REFBQywwQ0FBSyxJQUFDLEtBQUs7O29CQUFZLHNFQUFNLEtBQUssRUFBRSxFQUFDLEtBQUssRUFBRSxLQUFLLEVBQUMsUUFBVSxDQUFRO2dCQUNyRSw0REFBQyw4Q0FBUyxJQUFDLFFBQVEsRUFBRSxDQUFDLENBQUMsRUFBQyxFQUFFLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLEVBQ2xELEtBQUssRUFBRSxJQUFJLEdBQWMsQ0FDdkI7WUFFTixxRUFBSyxTQUFTLEVBQUMsWUFBWTtnQkFDdkIsNERBQUMsMENBQUssSUFBQyxLQUFLOztvQkFBWSxzRUFBTSxLQUFLLEVBQUUsRUFBQyxLQUFLLEVBQUUsS0FBSyxFQUFDLFFBQVUsQ0FBUTtnQkFDckUsNERBQUMsd0RBQVksSUFBQyxLQUFLLEVBQUUsV0FBVyxFQUN4QixJQUFJLEVBQUUsa0JBQWtCLEVBQ3hCLFNBQVMsRUFBRSxLQUFLLEVBQ2hCLE9BQU8sRUFBRSxxQkFBcUIsR0FBSSxDQUN4QztZQUVOLHFFQUFLLFNBQVMsRUFBQyxZQUFZO2dCQUN2Qiw0REFBQywwQ0FBSyxJQUFDLEtBQUssNkNBQXlDO2dCQUNyRCw0REFBQyw2Q0FBUSxJQUNMLEtBQUssRUFBRSxXQUFXLEVBQ2xCLFFBQVEsRUFBRSxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsY0FBYyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLEdBQ2pELENBQ0EsQ0FDSixDQUNFLENBQ2Y7QUFDTCxDQUFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUMzSHNGO0FBQzlEO0FBQ007QUFFMEQ7QUFDWDtBQUcvQjtBQUNUO0FBQ0U7QUFDNkI7QUFDckUsTUFBTSxFQUFFLFdBQVcsRUFBRSxHQUFHLGlEQUFVLENBQUM7QUFFNUIsTUFBTSxvQkFBb0IsR0FBQyxDQUFDLEVBQUMsV0FBVyxFQUFFLE9BQU8sRUFBRSxNQUFNLEVBQUUsZUFBZSxFQUFDLEVBQUUsRUFBRTtJQUVsRixNQUFNLENBQUMsT0FBTyxFQUFFLFVBQVUsQ0FBQyxHQUFHLHNEQUFjLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDcEQsTUFBTSxDQUFDLFNBQVMsRUFBRSxVQUFVLENBQUMsR0FBRyxzREFBYyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQ3RELE1BQU0sQ0FBQyxnQkFBZ0IsRUFBRSxtQkFBbUIsQ0FBQyxHQUFHLHNEQUFjLENBQUMsRUFBRSxDQUFDLENBQUM7SUFDbkUsTUFBTSxDQUFDLGlCQUFpQixFQUFFLG9CQUFvQixDQUFDLEdBQUcsc0RBQWMsQ0FBZ0IsRUFBRSxDQUFDLENBQUM7SUFDcEYsTUFBTSxDQUFDLHdCQUF3QixFQUFFLDJCQUEyQixDQUFDLEdBQUcsc0RBQWMsQ0FBYyxJQUFJLENBQUMsQ0FBQztJQUNsRyxNQUFNLENBQUMsMEJBQTBCLEVBQUUsNkJBQTZCLENBQUMsR0FBRyxzREFBYyxDQUFlLElBQUksQ0FBQyxDQUFDO0lBQ3ZHLE1BQU0sQ0FBQyxNQUFNLEVBQUUsU0FBUyxDQUFDLEdBQUcsc0RBQWMsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUVqRCxNQUFNLGFBQWEsR0FBRyxXQUFXLENBQUMsQ0FBQyxLQUFVLEVBQUUsRUFBRTs7UUFDN0MsT0FBTyxXQUFLLENBQUMsU0FBUywwQ0FBRSxhQUErQixDQUFDO0lBQzNELENBQUMsQ0FBQztJQUVGLE1BQU0sVUFBVSxHQUFHLFdBQVcsQ0FBQyxDQUFDLEtBQVUsRUFBRSxFQUFFOztRQUMzQyxPQUFPLFdBQUssQ0FBQyxTQUFTLDBDQUFFLFlBQVksQ0FBQztJQUN6QyxDQUFDLENBQUM7SUFFRix1REFBZSxDQUFDLEdBQUUsRUFBRTtRQUNoQixVQUFVLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDcEIsbUJBQW1CLENBQUMsRUFBRSxDQUFDLENBQUM7UUFDeEIsMkJBQTJCLENBQUMsSUFBSSxDQUFDLENBQUM7SUFDdEMsQ0FBQyxFQUFFLENBQUMsT0FBTyxDQUFDLENBQUM7SUFFYix1REFBZSxDQUFDLEdBQUcsRUFBRTtRQUNqQixJQUFHLFVBQVUsRUFBQztZQUNYLFNBQVMsaUNBQUssV0FBVyxLQUFFLFVBQVUsSUFBRSxDQUFDO1NBQzFDO0lBQ0wsQ0FBQyxFQUFFLENBQUMsVUFBVSxDQUFDLENBQUM7SUFFaEIsdURBQWUsQ0FBQyxHQUFHLEVBQUU7UUFDbkIsSUFBRyxhQUFhLElBQUksYUFBYSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUM7WUFDM0MsTUFBTSxLQUFLLEdBQUcsYUFBYSxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQztZQUN0QyxLQUFhLGFBQWIsS0FBSyx1QkFBTCxLQUFLLENBQVUsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDO1lBQ2hDLG9CQUFvQixDQUFDLEtBQUssQ0FBQyxDQUFDO1NBQzdCO0lBQ0gsQ0FBQyxFQUFFLENBQUMsYUFBYSxDQUFDLENBQUM7SUFFbkIsdURBQWUsQ0FBQyxHQUFFLEVBQUU7UUFDaEIsNkJBQTZCLENBQUMsYUFBYSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDcEQsQ0FBQyxFQUFFLENBQUMsYUFBYSxDQUFDLENBQUM7SUFFbkIsTUFBTSxJQUFJLEdBQUcsR0FBUyxFQUFFO1FBQ3BCLE1BQU0sTUFBTSxHQUFHLGFBQWEsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxLQUFLLGdCQUFnQixDQUFDLENBQUM7UUFDcEUsSUFBRyxNQUFNLEVBQUM7WUFDTixvRkFBYyxDQUFDLGtHQUF5QixFQUFFLGlCQUFpQixnQkFBZ0IsaUJBQWlCLENBQUMsQ0FBQztZQUM5RixPQUFPO1NBQ1Y7UUFDRCxVQUFVLENBQUMsSUFBSSxDQUFDLENBQUM7UUFDakIsSUFBRztZQUNDLElBQUksZUFBZSxHQUFHO2dCQUNsQixJQUFJLEVBQUUsZ0JBQWdCO2dCQUN0QixLQUFLLEVBQUUsZ0JBQWdCO2dCQUN2QixJQUFJLEVBQUUsd0JBQXdCO2dCQUM5QixRQUFRLEVBQUUsMEJBQTBCLENBQUMsRUFBRSxLQUFLLEtBQUssQ0FBQyxDQUFDLENBQUMsMEJBQTBCLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxJQUFJO2FBQzNFO1lBRWpCLE1BQU0sUUFBUSxHQUFHLE1BQU0sc0ZBQWdCLENBQUMsTUFBTSxFQUFFLGVBQWUsQ0FBQyxDQUFDO1lBQ2pFLE9BQU8sQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDLENBQUM7WUFDdEIsSUFBRyxRQUFRLENBQUMsTUFBTSxFQUFDO2dCQUNmLE1BQU0sSUFBSSxLQUFLLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsQ0FBQzthQUMzQztZQUVELGVBQWUsR0FBRyxRQUFRLENBQUMsSUFBSSxDQUFDO1lBQ2hDLGVBQWUsQ0FBQyxPQUFPLEdBQUcsYUFBYSxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQztZQUVuRCxvRkFBYyxDQUNWLGlIQUF3QyxFQUN6QyxDQUFDLEdBQUcsYUFBYSxFQUFFLGVBQWUsQ0FBQyxDQUFDLENBQUM7WUFFeEMsZUFBZSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUM7WUFDOUIsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO1NBQ2pCO1FBQUEsT0FBTSxHQUFHLEVBQUM7WUFDUixPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ2pCLG9GQUFjLENBQUMsa0dBQXlCLEVBQUUsR0FBRyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1NBQ3pEO2dCQUFPO1lBQ0osVUFBVSxDQUFDLEtBQUssQ0FBQyxDQUFDO1NBQ3JCO0lBQ0wsQ0FBQztJQUVELE9BQU0sQ0FDSiw0REFBQyxrREFBUyxJQUFDLEtBQUssRUFBQyxzQkFBc0IsRUFDckMsT0FBTyxFQUFFLENBQUMsQ0FBQyxnQkFBZ0IsSUFBSSx3QkFBd0IsQ0FBQyxFQUN4RCxJQUFJLEVBQUUsSUFBSSxFQUNWLE9BQU8sRUFBRSxPQUFPLEVBQ2hCLGdCQUFnQixFQUFFLE1BQU0sRUFBRSxPQUFPLEVBQUUsU0FBUztRQUUzQyxxRUFBSyxTQUFTLEVBQUMsa0JBQWtCO1lBQzdCLDJFQUVROzs7OztzQkFLQyxDQUVEO1lBQ1IscUVBQUssU0FBUyxFQUFDLFlBQVk7Z0JBQ3hCLDREQUFDLDBDQUFLLElBQUMsS0FBSzs7b0JBQWtCLHNFQUFNLEtBQUssRUFBRSxFQUFDLEtBQUssRUFBRSxLQUFLLEVBQUMsUUFBVSxDQUFRO2dCQUMzRSw0REFBQyw4Q0FBUyxtQkFBYSxxQkFBcUIsRUFBQyxJQUFJLEVBQUMsU0FBUyxFQUN2RCxRQUFRLEVBQUUsQ0FBQyxDQUFDLEVBQUMsRUFBRSxDQUFDLG1CQUFtQixDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLEVBQ25ELEtBQUssRUFBRSxnQkFBZ0IsR0FDZixDQUNWO1lBRU4scUVBQUssU0FBUyxFQUFDLFlBQVk7Z0JBQ3ZCLDREQUFDLDBDQUFLLElBQUMsS0FBSzs7b0JBQWtCLHNFQUFNLEtBQUssRUFBRSxFQUFDLEtBQUssRUFBRSxLQUFLLEVBQUMsUUFBVSxDQUFRO2dCQUMzRSw0REFBQyx3REFBWSxJQUFDLEtBQUssRUFBRSxpQkFBaUIsRUFDbEMsSUFBSSxFQUFFLHdCQUF3QixFQUM5QixTQUFTLEVBQUUsS0FBSyxFQUNoQixPQUFPLEVBQUUsMkJBQTJCLEdBQUcsQ0FDekM7WUFFTixxRUFBSyxTQUFTLEVBQUMsWUFBWTtnQkFDdkIsNERBQUMsMENBQUssSUFBQyxLQUFLLDZDQUF5QztnQkFDckQsNERBQUMsK0VBQXFCLElBQ2xCLE1BQU0sRUFBRSxNQUFNLEVBQ2QsMEJBQTBCLEVBQUUsSUFBSSxFQUNoQyxhQUFhLEVBQUUsYUFBYSxFQUM1QixvQkFBb0IsRUFBRSwwQkFBMEIsRUFDaEQsZUFBZSxFQUFFLDZCQUE2QixFQUM5QyxRQUFRLEVBQUUsS0FBSyxHQUFHLENBQ3BCLENBQ0gsQ0FFRyxDQUNiO0FBQ0wsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQzlJa0M7QUFDVjtBQUVKO0FBRWlCO0FBQ29EO0FBQ1o7QUFDakI7QUFDSjtBQUNZO0FBQzdCO0FBQ3hDLE1BQU0sRUFBRSxXQUFXLEVBQUUsR0FBRyxpREFBVSxDQUFDO0FBbUI1QixNQUFNLGlCQUFpQixHQUFDLENBQUMsS0FBbUIsRUFBRSxFQUFFO0lBRW5ELE1BQU0sQ0FBQyxLQUFLLEVBQUUsUUFBUSxDQUFDLEdBQUcsc0RBQWMsQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUM3QyxNQUFLLENBQUMsT0FBTyxFQUFFLFVBQVUsQ0FBQyxHQUFHLHNEQUFjLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDbkQsTUFBTSxDQUFDLFNBQVMsRUFBRSxhQUFhLENBQUMsR0FBRyxzREFBYyxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQztJQUNqRSxNQUFNLENBQUMsWUFBWSxFQUFFLGVBQWUsQ0FBQyxHQUFHLHNEQUFjLENBQUMsRUFBRSxDQUFDLENBQUM7SUFDM0QsTUFBTSxDQUFDLHVCQUF1QixFQUFFLDBCQUEwQixDQUFDLEdBQUcsc0RBQWMsQ0FBZSxJQUFJLENBQUMsQ0FBQztJQUVqRyx1REFBZSxDQUFDLEdBQUUsRUFBRTtRQUNoQixhQUFhLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQztJQUNoQyxDQUFDLEVBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUdWLHVEQUFlLENBQUMsR0FBRSxFQUFFO1FBQ2hCLElBQUcsS0FBSyxDQUFDLFNBQVMsSUFBSSxLQUFLLENBQUMsU0FBUyxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUM7WUFDaEQsMEJBQTBCLENBQUMsS0FBSyxDQUFDLFNBQVMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1NBQ2pEO0lBQ0osQ0FBQyxFQUFFLENBQUMsS0FBSyxDQUFDLENBQUM7SUFFWixNQUFNLGVBQWUsR0FBQyxHQUFRLEVBQUU7O1FBQzVCLE1BQU0sS0FBSyxHQUFHLEtBQUssQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxXQUFXLEVBQUUsQ0FBQyxJQUFJLEVBQUUsS0FBSyxZQUFZLENBQUMsV0FBVyxFQUFFLENBQUMsSUFBSSxFQUFFLENBQUMsQ0FBQztRQUMzRyxJQUFHLEtBQUssRUFBQztZQUNMLG9GQUFjLENBQUMsa0dBQXlCLEVBQUUsYUFBYSxZQUFZLGlCQUFpQixDQUFDLENBQUM7WUFDdEYsT0FBTztTQUNWO1FBQ0QsVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFDO1FBRWpCLElBQUksV0FBVyxHQUFHLGdDQUNYLHVCQUF1QixLQUMxQixJQUFJLEVBQUUsWUFBWSxFQUNsQixLQUFLLEVBQUUsWUFBWSxHQUNOLENBQUM7UUFFbEIsSUFBSSxZQUFZLEdBQUcsSUFBSSxDQUFDO1FBQ3hCLElBQUcsS0FBSyxDQUFDLG9CQUFvQjtZQUN6QixLQUFLLENBQUMsb0JBQW9CLENBQUMsS0FBSyxLQUFLLFFBQVEsRUFBQztZQUMxQyxZQUFZLEdBQUcsS0FBSyxDQUFDLG9CQUFvQixDQUFDO1NBQzdDO1FBRUwsSUFBSSxNQUFNLEdBQUcsSUFBSSxDQUFDO1FBQ2xCLElBQUcsS0FBSyxDQUFDLGNBQWMsSUFBSSxLQUFLLENBQUMsY0FBYyxDQUFDLEtBQUssS0FBSyxRQUFRLEVBQUM7WUFDL0QsTUFBTSxHQUFHLEtBQUssQ0FBQyxjQUFjLENBQUM7U0FDakM7UUFFRCxNQUFNLEtBQUssR0FBRyxJQUFJLElBQUksRUFBRSxDQUFDLE9BQU8sRUFBRSxDQUFDO1FBQ25DLE1BQU0sSUFBSSxHQUFHLE1BQU0sdUZBQWlCLENBQUMsS0FBSyxDQUFDLE1BQU0sRUFBRSxXQUFXLEVBQUUsV0FBSyxDQUFDLElBQUksMENBQUUsUUFBUSxFQUNoRixZQUFZLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFFMUIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxzQkFBc0IsRUFBRSxJQUFJLElBQUksRUFBRSxDQUFDLE9BQU8sRUFBRSxHQUFHLEtBQUssQ0FBQyxDQUFDO1FBQ2xFLFVBQVUsQ0FBQyxLQUFLLENBQUMsQ0FBQztRQUNsQixJQUFHLElBQUksQ0FBQyxNQUFNLEVBQUM7WUFDWCxvRkFBYyxDQUFDLGtHQUF5QixFQUFFLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQztZQUN2RCxPQUFPO1NBQ1Y7UUFDRCxLQUFLLENBQUMsNEJBQTRCLEVBQUUsQ0FBQztRQUNyQyxVQUFVLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDbEIsS0FBSyxDQUFDLGdCQUFnQixDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQ2xDLENBQUM7SUFDRCxPQUFNLENBQ0YsNERBQUMsa0RBQVMsSUFBQyxLQUFLLEVBQUMsa0JBQWtCLEVBQy9CLE9BQU8sRUFBRSxDQUFDLENBQUMsWUFBWSxJQUFJLHVCQUF1QixJQUFJLENBQUMsS0FBSyxDQUFDLEVBQzdELElBQUksRUFBRSxlQUFlLEVBQ3JCLE9BQU8sRUFBRSxPQUFPLEVBQ2hCLGdCQUFnQixFQUFFLEtBQUssQ0FBQyxnQkFBZ0IsRUFDeEMsT0FBTyxFQUFFLFNBQVM7UUFDbEIscUVBQUssU0FBUyxFQUFDLGNBQWM7WUFDN0IsMkVBRVE7Ozs7Ozs7OztxQkFTQyxDQUVEO1lBQ0oscUVBQUssU0FBUyxFQUFDLFlBQVk7Z0JBQ3ZCLDREQUFDLDBDQUFLLElBQUMsS0FBSzs7b0JBQWMsc0VBQU0sS0FBSyxFQUFFLEVBQUMsS0FBSyxFQUFFLEtBQUssRUFBQyxRQUFVLENBQVE7Z0JBQ3ZFLDREQUFDLDhDQUFTLG1CQUFhLGlCQUFpQixFQUNwQyxTQUFTLEVBQUMsZ0JBQWdCLEVBQUMsSUFBSSxFQUFDLFNBQVMsRUFDekMsUUFBUSxFQUFFLENBQUMsQ0FBQyxFQUFDLEVBQUUsQ0FBQyxlQUFlLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsRUFDL0MsS0FBSyxFQUFFLFlBQVksR0FBYyxDQUNuQztZQUVOLHFFQUFLLFNBQVMsRUFBQyxZQUFZO2dCQUN2Qiw0REFBQywwQ0FBSyxJQUFDLEtBQUs7O29CQUFpQixzRUFBTSxLQUFLLEVBQUUsRUFBQyxLQUFLLEVBQUUsS0FBSyxFQUFDLFFBQVUsQ0FBUTtnQkFDMUUsNERBQUMsdUVBQWlCLElBQ2QsU0FBUyxFQUFFLEtBQUssQ0FBQyxTQUFTLEVBQzFCLGdCQUFnQixFQUFFLHVCQUF1QixFQUN6QyxXQUFXLEVBQUUsMEJBQTBCLEdBQUcsQ0FDNUM7WUFFTixxRUFBSyxTQUFTLEVBQUMsWUFBWTtnQkFDdkIsNERBQUMsMENBQUssSUFBQyxLQUFLLHVDQUFtQztnQkFDL0MsNERBQUMsbUVBQWUsSUFDWCxNQUFNLEVBQUUsS0FBSyxDQUFDLE1BQU0sRUFDckIsT0FBTyxFQUFFLEtBQUssQ0FBQyxPQUFPLEVBQ3RCLGNBQWMsRUFBRSxLQUFLLENBQUMsY0FBYyxFQUNwQyxTQUFTLEVBQUUsS0FBSyxDQUFDLFNBQVMsRUFDMUIsUUFBUSxFQUFFLElBQUksRUFDZCxvQkFBb0IsRUFBRSxLQUFLLENBQUMsb0JBQW9CLEdBQUcsQ0FDckQ7WUFFTixxRUFBSyxTQUFTLEVBQUMsWUFBWTtnQkFDdkIsNERBQUMsMENBQUssSUFBQyxLQUFLLDZDQUF5QztnQkFDckQsNERBQUMsK0VBQXFCLElBQ2xCLE1BQU0sRUFBRSxLQUFLLENBQUMsTUFBTSxFQUNwQixRQUFRLEVBQUUsSUFBSSxFQUNkLGFBQWEsRUFBRSxLQUFLLENBQUMsYUFBYSxFQUNsQyxvQkFBb0IsRUFBRSxLQUFLLENBQUMsb0JBQW9CLEVBQ2hELGVBQWUsRUFBRSxLQUFLLENBQUMsZUFBZSxFQUN0QywwQkFBMEIsRUFBRSxLQUFLLENBQUMsMEJBQTBCLEdBQUcsQ0FDakUsQ0FDSixDQUNFLENBQ2Y7QUFDTCxDQUFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDdkp1RTtBQUNQO0FBQ3hDO0FBRWxCLE1BQU0sWUFBWSxHQUFHLENBQUMsRUFBQyxLQUFLLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxPQUFPLEVBQUUsVUFBVSxFQUFFLFNBQVMsRUFFcEMsRUFBQyxFQUFFO0lBRS9DLE1BQU0sYUFBYSxHQUFHLG9EQUFZLEVBQWUsQ0FBQztJQUVsRCx1REFBZSxDQUFDLEdBQUcsRUFBRTtRQUNsQixJQUFHLEtBQUssSUFBSSxLQUFLLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBQztZQUMxQixJQUFHLENBQUMsSUFBSSxFQUFDO2dCQUNQLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUM7YUFDbEI7aUJBQUk7Z0JBQ0gsT0FBTyxDQUFDLElBQUksQ0FBQyxDQUFDO2FBQ2Y7U0FDSDtJQUNKLENBQUMsRUFBRSxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBRVgsTUFBTSxTQUFTLEdBQUcsQ0FBQyxJQUFJLEVBQUMsRUFBRTtRQUN0QixPQUFPLENBQUMsSUFBSSxDQUFDLENBQUM7UUFDZCxJQUFHLGFBQWEsSUFBSSxhQUFhLENBQUMsT0FBTyxFQUFDO1lBQ3RDLGFBQWEsQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLENBQUM7U0FDakM7SUFDTCxDQUFDO0lBRUQsTUFBTSxVQUFVLEdBQUUsQ0FBQyxJQUFJLEVBQUUsRUFBRTtRQUN2QixJQUFHLE9BQU8sQ0FBQyxTQUFTLEdBQUMsQ0FBQyxJQUFJLENBQUMsS0FBSyxJQUFJLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxFQUFDO1lBQzVDLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQztTQUNwQjtJQUNMLENBQUM7SUFFRCxPQUFPLENBQ0gscUVBQUssU0FBUyxFQUFDLHlCQUF5QixFQUFDLEtBQUssRUFBRSxFQUFDLEtBQUssRUFBRSxNQUFNLEVBQUM7UUFDM0QsMkVBRUs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O2tCQTRDQyxDQUVFO1FBQ1IsNERBQUMsNkNBQVEsSUFBRSxVQUFVLEVBQUMsTUFBTSxFQUFDLElBQUksRUFBQyxJQUFJO1lBQ2xDLDREQUFDLG1EQUFjLElBQUMsU0FBUyxFQUFDLGdCQUFnQixFQUFDLEdBQUcsRUFBRSxhQUFhLEVBQUcsSUFBSSxFQUFDLElBQUksRUFBQyxLQUFLLEVBQUUsRUFBQyxTQUFTLEVBQUUsTUFBTSxFQUFDLElBQy9GLEtBQUksYUFBSixJQUFJLHVCQUFKLElBQUksQ0FBRSxLQUFLLE1BQUksSUFBSSxhQUFKLElBQUksdUJBQUosSUFBSSxDQUFFLElBQUksRUFDYjtZQUNqQiw0REFBQyxpREFBWSxJQUFDLEtBQUssRUFBRSxFQUFDLEtBQUssRUFBRSxTQUFTLElBQUksS0FBSyxFQUFDLElBRTVDLEtBQUssYUFBTCxLQUFLLHVCQUFMLEtBQUssQ0FBRSxHQUFHLENBQUMsQ0FBQyxJQUFJLEVBQUUsR0FBRyxFQUFFLEVBQUU7Z0JBQ3JCLE9BQU8sQ0FDSCxxRUFBSyxFQUFFLEVBQUUsS0FBSSxhQUFKLElBQUksdUJBQUosSUFBSSxDQUFFLElBQUksTUFBSSxJQUFJLGFBQUosSUFBSSx1QkFBSixJQUFJLENBQUUsS0FBSyxHQUFFLFNBQVMsRUFBQyx5QkFBeUI7b0JBQ25FLDREQUFDLDBDQUFLLElBQUMsS0FBSyxRQUFDLE9BQU8sRUFBRSxHQUFHLEVBQUUsQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLElBQUcsS0FBSSxhQUFKLElBQUksdUJBQUosSUFBSSxDQUFFLEtBQUssTUFBSSxJQUFJLGFBQUosSUFBSSx1QkFBSixJQUFJLENBQUUsSUFBSSxFQUFTO29CQUU1RSxDQUFDLENBQUMsS0FBSSxhQUFKLElBQUksdUJBQUosSUFBSSxDQUFFLEtBQUssTUFBSSxJQUFJLGFBQUosSUFBSSx1QkFBSixJQUFJLENBQUUsSUFBSSxFQUFDLEtBQUssUUFBUSxDQUFDLElBQUksU0FBUyxDQUFDLENBQUM7d0JBQ3pELENBQUMsNERBQUMsMkVBQWEsSUFBQyxLQUFLLEVBQUMsUUFBUSxFQUFDLFNBQVMsRUFBQyxjQUFjLEVBQUMsSUFBSSxFQUFFLEVBQUUsRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUM7d0JBQ3JHLENBQUMsQ0FBQyxJQUFJLENBRVIsQ0FFVDtZQUNMLENBQUMsQ0FBQyxDQUVTLENBQ1IsQ0FDVCxDQUNUO0FBQ0wsQ0FBQzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQzVHd0I7QUFDcUI7QUFFYjtBQUMyQztBQUNVO0FBQ1A7QUFHeEUsTUFBTSxlQUFlLEdBQUUsQ0FBQyxFQUFDLE1BQU0sRUFBRSxPQUFPLEVBQUUsY0FBYyxFQUFFLFNBQVMsRUFBRSxRQUFRLEVBQUUsb0JBQW9CLEVBQUMsRUFBQyxFQUFFO0lBRTFHLE1BQU0sQ0FBQyxZQUFZLEVBQUUsZUFBZSxDQUFDLEdBQUcsc0RBQWMsQ0FBVyxFQUFFLENBQUMsQ0FBQztJQUVyRSx1REFBZSxDQUFDLEdBQUUsRUFBRTtRQUNoQixJQUFHLE9BQU8sRUFBQztZQUNQLGVBQWUsQ0FBQyxDQUFDLEdBQUcsT0FBTyxDQUFhLENBQUM7U0FDNUM7SUFDTCxDQUFDLEVBQUUsQ0FBQyxPQUFPLENBQUMsQ0FBQztJQUViLE1BQU0sWUFBWSxHQUFFLENBQU8sTUFBYyxFQUFDLEVBQUU7UUFDeEMsTUFBTSxRQUFRLEdBQUcsTUFBTSxrRkFBWSxDQUFDLE1BQU0sRUFBRSxNQUFNLENBQUMsQ0FBQztRQUNyRCxJQUFHLFFBQVEsQ0FBQyxNQUFNLEVBQUM7WUFDbEIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDN0Isb0ZBQWMsQ0FBQyxrR0FBeUIsRUFBRSxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDM0QsT0FBTztTQUNQO1FBQ0QsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxLQUFLLFVBQVUsQ0FBQyxDQUFDO1FBQ3ZDLGVBQWUsQ0FBQyxDQUFDLEdBQUcsWUFBWSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxFQUFFLEtBQUssTUFBTSxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUN0RSxDQUFDO0lBRUQsT0FBTyxDQUNILHFFQUFLLEtBQUssRUFBRSxFQUFDLE9BQU8sRUFBRSxRQUFRLENBQUMsQ0FBQyxDQUFDLE9BQU8sRUFBQyxDQUFDLE1BQU07WUFDNUMsVUFBVSxFQUFFLFFBQVEsRUFBQztRQUNyQiwyRUFFUTs7Ozs7cUJBS0MsQ0FFRDtRQUNSLDREQUFDLHdEQUFZLElBQUMsS0FBSyxFQUFFLFlBQVksRUFDN0IsSUFBSSxFQUFFLGNBQWMsRUFDcEIsU0FBUyxFQUFFLElBQUksRUFDZixPQUFPLEVBQUUsU0FBUyxFQUNsQixVQUFVLEVBQUUsWUFBWSxHQUFHO1FBRTVCLFFBQVEsRUFBQyxDQUFDLENBQ1QsNERBQUMsMkNBQU0sbUJBQWEsd0JBQXdCLEVBQUUsU0FBUyxFQUFDLFdBQVcsRUFDOUQsSUFBSSxFQUFDLE1BQU0sRUFBQyxLQUFLLEVBQUUsRUFBQyxTQUFTLEVBQUUsTUFBTSxFQUFDLEVBQ3ZDLE9BQU8sRUFBRSxHQUFFLEVBQUUsQ0FBQyxvQkFBb0IsQ0FBQyxJQUFJLENBQUMscUJBRW5DLENBQ1QsRUFBQyxFQUNELDREQUFDLHNGQUFrQixJQUFDLFNBQVMsRUFBQyxhQUFhLGlCQUMzQixpQkFBaUIsRUFDN0IsS0FBSyxFQUFDLGdCQUFnQixFQUFDLElBQUksRUFBRSxFQUFFLEVBQUUsS0FBSyxFQUFFLE1BQU0sRUFDOUMsT0FBTyxFQUFFLEdBQUUsRUFBRSxDQUFDLG9CQUFvQixDQUFDLElBQUksQ0FBQyxHQUFHLENBRS9DLENBR0YsQ0FDVDtBQUNMLENBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ2xFZ0M7QUFDUjtBQUV6QixNQUFNLFdBQVcsR0FBRSxDQUFDLEVBQUMsT0FBTyxFQUFtQixFQUFFLEVBQUU7SUFDL0MsT0FBTSxDQUNGLHFFQUNJLEtBQUssRUFBRTtZQUNILE1BQU0sRUFBRSxNQUFNO1lBQ2QsS0FBSyxFQUFFLE1BQU07WUFDYixRQUFRLEVBQUUsVUFBVTtZQUNwQixVQUFVLEVBQUUsa0JBQWtCO1lBQzlCLEdBQUcsRUFBRSxDQUFDO1lBQ04sSUFBSSxFQUFFLENBQUM7WUFDUCxNQUFNLEVBQUUsTUFBTTtZQUNkLE9BQU8sRUFBRSxNQUFNO1lBQ2YsY0FBYyxFQUFFLFFBQVE7WUFDeEIsVUFBVSxFQUFFLFFBQVE7U0FDdkI7UUFFRCw0REFBQyw0Q0FBTyxJQUNKLFNBQVMsRUFBQyxFQUFFLEVBQ1osSUFBSSxFQUFDLFdBQVcsR0FDbEI7UUFDRix3RUFBSyxPQUFPLENBQU0sQ0FDaEIsQ0FDVDtBQUNMLENBQUM7QUFDRCxpRUFBZSxXQUFXLEVBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUMxQkY7QUFDbUQ7QUFDcEM7QUFFeEMsZ0NBQWdDO0FBQ2hDLHFCQUFxQjtBQUNyQix3QkFBd0I7QUFDeEIsd0JBQXdCO0FBQ3hCLHFCQUFxQjtBQUNyQixrQ0FBa0M7QUFDbEMsc0JBQXNCO0FBQ3RCLHdCQUF3QjtBQUN4QixJQUFJO0FBRUcsTUFBTSxTQUFTLEdBQUUsQ0FBQyxLQUFLLEVBQUMsRUFBRTtJQUM3QixPQUFPLENBQ0gsNERBQUMsMENBQUssSUFBQyxNQUFNLEVBQUUsS0FBSyxDQUFDLE9BQU8sRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBQyxZQUFZO1FBQ2hFLDJFQUVROzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O3FCQStCQyxDQUVEO1FBQ1IsNERBQUMsZ0RBQVcsSUFBQyxNQUFNLEVBQUUsR0FBRSxFQUFFLE1BQUssQ0FBQyxnQkFBZ0IsQ0FBQyxLQUFLLENBQUMsSUFDakQsS0FBSyxDQUFDLEtBQUssQ0FDRjtRQUNkLDREQUFDLDhDQUFTLFFBQ0wsS0FBSyxDQUFDLFFBQVEsQ0FDUDtRQUVSLEtBQUssQ0FBQyxVQUFVLElBQUksS0FBSyxDQUFDLFVBQVUsSUFBSSxJQUFJLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUFDO1lBQ3JELENBQ0ksNERBQUMsZ0RBQVc7Z0JBQ1IsNERBQUMsMkNBQU0sSUFBQyxPQUFPLEVBQUUsR0FBRyxFQUFFLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxLQUFLLENBQUMsQ0FBQyxJQUNqRixLQUFLLENBQUMsYUFBYSxJQUFJLFFBQVEsQ0FDM0I7Z0JBQ1QscUVBQUssU0FBUyxFQUFDLFFBQVEsR0FBRTtnQkFDekIsNERBQUMsMkNBQU0sbUJBQWEsU0FBUyxFQUN6QixRQUFRLEVBQUUsS0FBSyxDQUFDLE9BQU8sRUFDdkIsT0FBTyxFQUFFLEdBQUcsRUFBRSxDQUFDLEtBQUssQ0FBQyxJQUFJLEVBQUUsSUFDMUIsS0FBSyxDQUFDLGNBQWMsSUFBSSxNQUFNLENBQzFCLENBQ0MsQ0FDakI7UUFHSixDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUMsNERBQUMscURBQVcsT0FBRSxDQUFDLENBQUMsQ0FBQyxJQUFJLENBRXBDLENBQ1g7QUFDTCxDQUFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FDakZ3QjtBQUNxQjtBQUNkO0FBQzJDO0FBQ2dCO0FBRWI7QUFHdkUsTUFBTSxxQkFBcUIsR0FBRSxDQUFDLEVBQUMsTUFBTSxFQUFFLGFBQWEsRUFBRSxvQkFBb0IsRUFDN0UsZUFBZSxFQUFFLFFBQVEsRUFBRSwwQkFBMEIsRUFBQyxFQUFDLEVBQUU7SUFFekQsTUFBTSxDQUFDLGtCQUFrQixFQUFFLHFCQUFxQixDQUFDLEdBQUcsc0RBQWMsQ0FBaUIsRUFBRSxDQUFDLENBQUM7SUFFdkYsdURBQWUsQ0FBQyxHQUFFLEVBQUU7UUFDaEIsSUFBRyxhQUFhLEVBQUM7WUFDYixxQkFBcUIsQ0FBQyxDQUFDLEdBQUcsYUFBYSxDQUFtQixDQUFDO1NBQzlEO0lBQ0wsQ0FBQyxFQUFFLENBQUMsYUFBYSxDQUFDLENBQUM7SUFFbkIsTUFBTSxrQkFBa0IsR0FBRSxDQUFPLFlBQTBCLEVBQUMsRUFBRTtRQUM1RCxNQUFNLFFBQVEsR0FBRyxNQUFNLHdGQUFrQixDQUFDLFlBQVksRUFBRSxNQUFNLENBQUMsQ0FBQztRQUNoRSxJQUFHLFFBQVEsQ0FBQyxNQUFNLEVBQUM7WUFDbEIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDN0Isb0ZBQWMsQ0FBQyxrR0FBeUIsRUFBRSxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDM0QsT0FBTztTQUNQO1FBQ0QsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLFlBQVksQ0FBQyxLQUFLLFVBQVUsQ0FBQztRQUM1QyxxQkFBcUIsQ0FBQyxDQUFDLEdBQUcsa0JBQWtCLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUUsS0FBSyxZQUFZLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ3ZGLENBQUM7SUFDRCxPQUFPLENBQ0gscUVBQUssS0FBSyxFQUFFLEVBQUMsT0FBTyxFQUFFLFFBQVEsQ0FBQyxDQUFDLENBQUMsT0FBTyxFQUFDLENBQUMsTUFBTTtZQUM1QyxVQUFVLEVBQUUsUUFBUSxFQUFDO1FBQ3BCLDREQUFDLHdEQUFZLElBQUMsS0FBSyxFQUFFLGtCQUFrQixFQUNwQyxJQUFJLEVBQUUsb0JBQW9CLEVBQzFCLFNBQVMsRUFBRSxJQUFJLEVBQ2YsT0FBTyxFQUFFLGVBQWUsRUFDeEIsVUFBVSxFQUFFLGtCQUFrQixHQUFHO1FBRWxDLDBCQUEwQixDQUFDLENBQUMsQ0FBQyxDQUM1QixRQUFRLEVBQUMsQ0FBQyxDQUNOLDREQUFDLDJDQUFNLG1CQUFhLHdCQUF3QixFQUFFLFNBQVMsRUFBQyxXQUFXLEVBQzlELElBQUksRUFBQyxNQUFNLEVBQUMsS0FBSyxFQUFFLEVBQUMsU0FBUyxFQUFFLE1BQU0sRUFBQyxFQUN2QyxPQUFPLEVBQUUsR0FBRSxFQUFFLENBQUMsMEJBQTBCLENBQUMsSUFBSSxDQUFDLDJCQUV6QyxDQUNULEVBQUMsRUFDRCw0REFBQyxzRkFBa0IsSUFBQyxTQUFTLEVBQUMsYUFBYSxpQkFDM0IsdUJBQXVCLEVBQ25DLEtBQUssRUFBQyxzQkFBc0IsRUFBQyxJQUFJLEVBQUUsRUFBRSxFQUFFLEtBQUssRUFBRSxNQUFNLEVBQ3BELE9BQU8sRUFBRSxHQUFFLEVBQUUsQ0FBQywwQkFBMEIsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUNyRCxDQUNKLEVBQUMsQ0FBQyxJQUFJLENBRVIsQ0FDVDtBQUNMLENBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ3hEa0M7QUFDVjtBQUVsQixNQUFNLGVBQWUsR0FBRyxDQUFDLEVBQUMsS0FBSyxFQUFFLFFBQVEsRUFBRSxZQUFZLEVBQUUsS0FBSyxFQUNLLEVBQUUsRUFBRTtJQUMxRSxPQUFPLENBQ0gsb0VBQUksS0FBSyxFQUFFO1lBQ1AsS0FBSyxFQUFFLE1BQU07U0FDZDtRQUNGLEtBQUs7O1FBQ04sNERBQUMsOENBQVMsa0JBQUMsS0FBSyxFQUFFLEVBQUMsUUFBUSxFQUFFLEtBQUssQ0FBQyxLQUFLLENBQUMsVUFBVSxDQUFDLEtBQUssQ0FBQyxRQUFRLEVBQUMsaUJBQ25ELHFCQUFxQixFQUNqQyxXQUFXLEVBQUMsV0FBVyxFQUN2QixJQUFJLEVBQUMsSUFBSSxFQUNULFVBQVUsUUFDVixJQUFJLEVBQUMsTUFBTSxFQUNYLEtBQUssRUFBRSxZQUFZLEVBQ25CLFFBQVEsRUFBRSxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLElBQ3JDLEtBQUssRUFBRyxDQUNYLENBQ1I7QUFDTCxDQUFDOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNyQnlFO0FBQ0Y7QUFDeEM7QUFDTjtBQUc2QztBQUVoRSxNQUFNLGNBQWMsR0FBRSxDQUFDLEVBQUMsUUFBUSxFQUFFLE9BQU8sRUFBRSxVQUFVLEVBQUUsS0FBSyxFQUNJLEVBQUMsRUFBRTs7SUFFdEUsTUFBTSxhQUFhLEdBQUMsR0FBRSxFQUFFO1FBQ3BCLDREQUE0RDtRQUM1RCw2Q0FBNkM7UUFFN0Msb0RBQW9EO1FBQ3BELHlDQUF5QztRQUN6QyxRQUFRO1FBQ1IsSUFBSTtJQUNSLENBQUM7SUFDRCxPQUFPLENBQ0gsb0ZBQWlCLGdCQUFnQixFQUFDLFNBQVMsRUFBQyxnQkFBZ0IsRUFDNUQsYUFBYSxFQUFFLGFBQWEsRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsRUFDbkUsS0FBSyxFQUFFO1lBQ0MsZUFBZSxFQUFDLENBQUMsUUFBUSxDQUFDLFVBQVU7Z0JBQ2hDLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLDZCQUE2QjtnQkFDNUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsNEJBQTRCLENBQUM7U0FDaEQ7UUFDSiwyRUFDRzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztpQkErQkYsQ0FDTztRQUNaLHFFQUFLLFNBQVMsRUFBQyxnQkFBZ0I7WUFFdkIsZUFBUSxhQUFSLFFBQVEsdUJBQVIsUUFBUSxDQUFFLE1BQU0sMENBQUUsSUFBSSxNQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FDM0IsNERBQUMsb0ZBQWUsSUFBQyxTQUFTLEVBQUMsVUFBVSxFQUFDLElBQUksRUFBRSxFQUFFLEVBQUUsS0FBSyxFQUNqRCxRQUFRLENBQUMsVUFBVTtvQkFDbkIsQ0FBQyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsbUJBQW1CO29CQUNsQyxDQUFDLENBQUMsTUFBTSxHQUFJLENBQ25CLEVBQUM7Z0JBQ0YsQ0FDSSw0REFBQyxrRkFBYyxJQUFDLFNBQVMsRUFBQyxVQUFVLEVBQUMsSUFBSSxFQUFFLEVBQUUsRUFBRSxLQUFLLEVBQ2hELFFBQVEsQ0FBQyxVQUFVO3dCQUNuQixDQUFDLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxtQkFBbUI7d0JBQ2xDLENBQUMsQ0FBQyxNQUFNLEdBQUksQ0FDbkI7WUFHTCw0REFBQywwQ0FBSyxJQUFDLEtBQUssRUFBRTtvQkFDTixLQUFLLEVBQUUsUUFBUSxDQUFDLFVBQVU7d0JBQzFCLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLG1CQUFtQjt3QkFDbEMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsMEJBQTBCO2lCQUM1QyxFQUFFLFNBQVMsRUFBQyxjQUFjLElBQUUsUUFBUSxDQUFDLElBQUksQ0FBUyxDQUNyRDtRQUVGLFFBQVEsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFFLDREQUFDLGtGQUFlLElBQUMsU0FBUyxFQUFDLFdBQVcsRUFBQyxJQUFJLEVBQUUsRUFBRSxFQUFFLEtBQUssRUFBRSxLQUFLLENBQUMsTUFBTSxDQUFDLG1CQUFtQixHQUFHLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FFM0gsQ0FDVDtBQUNMLENBQUM7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ3pGd0I7QUFDcUI7QUFHdkMsTUFBTSxpQkFBaUIsR0FBRSxDQUFDLEVBQUMsU0FBUyxFQUFFLGdCQUFnQixFQUFFLFdBQVcsRUFBQyxFQUFDLEVBQUU7SUFFMUUsTUFBTSxjQUFjLEdBQUUsR0FBRSxFQUFFO0lBRTFCLENBQUM7SUFDRCxPQUFPLENBQ0gsNERBQUMsd0RBQVksSUFBQyxLQUFLLEVBQUUsU0FBUyxFQUMxQixJQUFJLEVBQUUsZ0JBQWdCLEVBQ3RCLFNBQVMsRUFBRSxJQUFJLEVBQ2YsT0FBTyxFQUFFLFdBQVcsRUFDcEIsVUFBVSxFQUFFLGNBQWMsR0FBRyxDQUNwQztBQUNMLENBQUM7Ozs7Ozs7Ozs7OztBQ2hCRDs7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7Ozs7QUNBQTs7Ozs7Ozs7Ozs7QUNBQTs7Ozs7O1VDQUE7VUFDQTs7VUFFQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTs7VUFFQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTs7Ozs7V0N0QkE7V0FDQTtXQUNBO1dBQ0E7V0FDQTtXQUNBLGlDQUFpQyxXQUFXO1dBQzVDO1dBQ0E7Ozs7O1dDUEE7V0FDQTtXQUNBO1dBQ0E7V0FDQSx5Q0FBeUMsd0NBQXdDO1dBQ2pGO1dBQ0E7V0FDQTs7Ozs7V0NQQTs7Ozs7V0NBQTtXQUNBO1dBQ0E7V0FDQSx1REFBdUQsaUJBQWlCO1dBQ3hFO1dBQ0EsZ0RBQWdELGFBQWE7V0FDN0Q7Ozs7O1dDTkE7Ozs7Ozs7Ozs7QUNBQTs7O0tBR0s7QUFDTCwyQkFBMkI7QUFDM0IsYUFBYTtBQUNiLHFCQUF1QixHQUFHLE1BQU0sQ0FBQyxVQUFVLENBQUMsT0FBTzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNMWTtBQUd0QztBQUM0RDtBQUNDO0FBQ2Y7QUFDYztBQUtmO0FBRXlEO0FBQ3pDO0FBQ087QUFDWDtBQUVLO0FBQ3ZGLE1BQU0sRUFBRSxXQUFXLEVBQUUsR0FBRyxpREFBVSxDQUFDO0FBRW5DLE1BQU0sTUFBTSxHQUFHLENBQUMsS0FBK0IsRUFBRSxFQUFFOztJQUVqRCxNQUFNLENBQUMsT0FBTyxFQUFFLFVBQVUsQ0FBQyxHQUFHLHFEQUFjLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDcEQsTUFBTSxDQUFDLHlCQUF5QixFQUFFLDZCQUE2QixDQUFDLEdBQUcscURBQWMsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUN6RixNQUFNLENBQUMsNkJBQTZCLEVBQUUsaUNBQWlDLENBQUMsR0FBRyxxREFBYyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQ2pHLE1BQU0sQ0FBQyx1QkFBdUIsRUFBRSwyQkFBMkIsQ0FBQyxHQUFHLHFEQUFjLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDckYsTUFBTSxDQUFDLGNBQWMsRUFBRSxpQkFBaUIsQ0FBQyxHQUFDLHFEQUFjLENBQVMsSUFBSSxDQUFDLENBQUM7SUFDdkUsTUFBTSxDQUFDLG9CQUFvQixFQUFFLHVCQUF1QixDQUFDLEdBQUMscURBQWMsQ0FBZSxJQUFJLENBQUMsQ0FBQztJQUN6RixNQUFNLENBQUMsWUFBWSxFQUFFLGdCQUFnQixDQUFDLEdBQUcscURBQWMsQ0FBaUIsRUFBRSxDQUFDO0lBQzNFLE1BQU0sQ0FBQyxNQUFNLEVBQUUsU0FBUyxDQUFDLEdBQUcscURBQWMsQ0FBQyxJQUFJLENBQUM7SUFDaEQsTUFBSyxDQUFDLGNBQWMsRUFBRSxpQkFBaUIsQ0FBQyxHQUFHLHFEQUFjLENBQUMsS0FBSyxDQUFDO0lBQ2hFLE1BQUssQ0FBQyxVQUFVLEVBQUUsYUFBYSxDQUFDLEdBQUcscURBQWMsQ0FBQyxFQUFFLENBQUM7SUFFckQsTUFBTSxLQUFLLEdBQUksV0FBVyxDQUFDLENBQUMsS0FBVSxFQUFFLEVBQUU7UUFDeEMsT0FBTyxLQUFLLENBQUMsU0FBdUIsQ0FBQztJQUN2QyxDQUFDLENBQUM7SUFFRixNQUFNLElBQUksR0FBRyxXQUFXLENBQUMsQ0FBQyxLQUFVLEVBQUUsRUFBRTs7UUFDckMsT0FBTyxXQUFLLENBQUMsU0FBUywwQ0FBRSxJQUFnQixDQUFDO0lBQzVDLENBQUMsQ0FBQztJQUVGLE1BQU0sVUFBVSxHQUFHLFdBQVcsQ0FBQyxDQUFDLEtBQVUsRUFBRSxFQUFFOztRQUM1QyxPQUFPLFdBQUssQ0FBQyxTQUFTLDBDQUFFLFlBQVksQ0FBQztJQUN2QyxDQUFDLENBQUM7SUFFRixNQUFNLE1BQU0sR0FBRyxXQUFXLENBQUMsQ0FBQyxLQUFVLEVBQUUsRUFBRTs7UUFDeEMsT0FBTyxXQUFLLENBQUMsU0FBUywwQ0FBRSxNQUFNLENBQUM7SUFDakMsQ0FBQyxDQUFDO0lBRUYsTUFBTSxTQUFTLEdBQUksV0FBVyxDQUFDLENBQUMsS0FBVSxFQUFFLEVBQUU7O1FBQzVDLE9BQU8sV0FBSyxDQUFDLFNBQVMsMENBQUUsU0FBMkIsQ0FBQztJQUN0RCxDQUFDLENBQUM7SUFFRixNQUFNLE9BQU8sR0FBSSxXQUFXLENBQUMsQ0FBQyxLQUFVLEVBQUUsRUFBRTs7UUFDMUMsT0FBTyxXQUFLLENBQUMsU0FBUywwQ0FBRSxPQUFtQixDQUFDO0lBQzlDLENBQUMsQ0FBQztJQUVGLE1BQU0sYUFBYSxHQUFJLFdBQVcsQ0FBQyxDQUFDLEtBQVUsRUFBRSxFQUFFOztRQUNoRCxPQUFPLFdBQUssQ0FBQyxTQUFTLDBDQUFFLGFBQStCLENBQUM7SUFDMUQsQ0FBQyxDQUFDO0lBRUYsc0RBQWUsQ0FBQyxHQUFFLEVBQUU7UUFDbEIsb0ZBQWMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQ3JDLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQztJQUVQLHNEQUFlLENBQUMsR0FBRSxFQUFFO1FBQ2xCLElBQUcsTUFBTSxFQUFDO1lBQ1IsSUFBRyxDQUFDLE9BQU8sSUFBSSxPQUFPLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBQztnQkFDbEMsTUFBTSxLQUFLLEdBQUcsSUFBSSxJQUFJLEVBQUUsQ0FBQyxPQUFPLEVBQUUsQ0FBQztnQkFDbkMsZ0ZBQVUsQ0FBQyxNQUFNLEVBQUUsS0FBSyxFQUFFLGdCQUFnQixDQUFDO3FCQUMxQyxJQUFJLENBQUMsQ0FBQyxPQUFpQixFQUFFLEVBQUU7b0JBQ3hCLElBQUcsT0FBTyxJQUFJLE9BQU8sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFDO3dCQUM5QixPQUFlLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQzt3QkFDaEMsT0FBTyxDQUFDLE9BQU8sQ0FBQyx3RkFBZ0IsQ0FBQzt3QkFDakMsb0ZBQWMsQ0FBQywyR0FBa0MsRUFBRSxPQUFPLENBQUMsQ0FBQztxQkFDN0Q7b0JBQ0QsT0FBTyxDQUFDLEdBQUcsQ0FBQyxnQkFBZ0IsR0FBRyxDQUFDLElBQUksSUFBSSxFQUFFLENBQUMsT0FBTyxFQUFFLEdBQUcsS0FBSyxDQUFDLEdBQUUsS0FBSyxDQUFDO2dCQUN6RSxDQUFDLENBQUMsQ0FBQzthQUNKO1NBQ0Y7SUFDSCxDQUFDLEVBQUUsQ0FBQyxNQUFNLENBQUMsQ0FBQztJQUVaLHNEQUFlLENBQUMsR0FBRSxFQUFFO1FBQ2xCLElBQUcsTUFBTSxFQUFDO1lBQ1IsSUFBRyxDQUFDLGFBQWEsSUFBSSxhQUFhLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtnQkFDL0MsTUFBTSxLQUFLLEdBQUcsSUFBSSxJQUFJLEVBQUUsQ0FBQyxPQUFPLEVBQUUsQ0FBQztnQkFDbEMsc0ZBQWdCLENBQUMsTUFBTSxFQUFFLEtBQUssQ0FBQztxQkFDN0IsSUFBSSxDQUFDLENBQUMsYUFBNkIsRUFBRSxFQUFFO29CQUN0QyxJQUFHLGFBQWEsSUFBSSxhQUFhLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBQzt3QkFDMUMsYUFBcUIsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7d0JBQ3ZDLGFBQWEsQ0FBQyxPQUFPLENBQUMsd0ZBQWdCLENBQUMsQ0FBQzt3QkFDeEMsb0ZBQWMsQ0FBQyxpSEFBd0MsRUFBRSxhQUFhLENBQUMsQ0FBQztxQkFDekU7b0JBQ0QsT0FBTyxDQUFDLEdBQUcsQ0FBQyxzQkFBc0IsR0FBQyxDQUFDLElBQUksSUFBSSxFQUFFLENBQUMsT0FBTyxFQUFFLEdBQUcsS0FBSyxDQUFDLEdBQUMsS0FBSyxDQUFDO2dCQUMxRSxDQUFDLENBQUM7YUFDTDtTQUNGO0lBQ0gsQ0FBQyxFQUFFLENBQUMsTUFBTSxDQUFDLENBQUM7SUFFWixzREFBZSxDQUFDLEdBQUUsRUFBRTtRQUNsQixJQUFHLFVBQVUsRUFBQztZQUNYLFNBQVMsaUNBQU0sS0FBSyxDQUFDLE1BQU0sS0FBRSxVQUFVLEVBQUMsVUFBVSxJQUFFO1NBQ3REO0lBQ0gsQ0FBQyxFQUFFLENBQUMsVUFBVSxDQUFDLENBQUM7SUFFaEIsc0RBQWUsQ0FBQyxHQUFFLEVBQUU7UUFDbkIsSUFBRyxNQUFNLEVBQUM7WUFDUCxhQUFhLEVBQUUsQ0FBQztTQUNsQjtJQUNGLENBQUMsRUFBRSxDQUFDLE1BQU0sQ0FBQyxDQUFDO0lBRVosc0RBQWUsQ0FBQyxHQUFHLEVBQUU7UUFDbkIsSUFBRyxNQUFNLEVBQUM7WUFDUixLQUFLLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDZCxvRkFBYyxDQUFDLGtHQUF5QixFQUFFLEVBQUUsQ0FBQztTQUM5QztJQUNILENBQUMsRUFBRSxDQUFDLE1BQU0sQ0FBQyxDQUFDO0lBRVosc0RBQWUsQ0FBQyxHQUFFLEVBQUU7O1FBQ2xCLG9GQUFjLENBQUMsdUdBQThCLEVBQzNDO1lBQ0UsUUFBUSxFQUFFLFdBQUssQ0FBQyxJQUFJLDBDQUFFLFFBQVE7WUFDOUIsU0FBUyxFQUFFLFdBQUssQ0FBQyxJQUFJLDBDQUFFLFNBQVM7WUFDaEMsUUFBUSxFQUFDLFdBQUssQ0FBQyxJQUFJLDBDQUFFLFFBQVE7WUFDN0IsTUFBTSxFQUFFLGlCQUFLLENBQUMsSUFBSSwwQ0FBRSxNQUFNLDBDQUFFLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUM7U0FDOUMsQ0FDRjtJQUNILENBQUMsRUFBRSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDO0lBRWpCLHNEQUFlLENBQUMsR0FBRyxFQUFFO1FBQ25CLElBQUcsU0FBUyxJQUFJLFNBQVMsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxFQUFDO1lBQ25DLHFCQUFxQixDQUFDLGNBQWMsRUFBRSxTQUFTLENBQUMsQ0FBQztTQUNsRDtJQUNILENBQUMsRUFBQyxDQUFDLFNBQVMsQ0FBQyxDQUFDO0lBRWQsTUFBTSxhQUFhLEdBQUMsR0FBUSxFQUFFO1FBQzVCLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUVqQixNQUFNLEtBQUssR0FBRyxJQUFJLElBQUksRUFBRSxDQUFDLE9BQU8sRUFBRSxDQUFDO1FBQ25DLE1BQU0sUUFBUSxHQUFHLE1BQU0sa0ZBQVksQ0FBQyxNQUFNLEVBQUUsSUFBSSxFQUFFLElBQUksQ0FBQyxDQUFDO1FBQ3hELE9BQU8sQ0FBQyxHQUFHLENBQUMsZ0JBQWdCLEVBQUUsSUFBSSxJQUFJLEVBQUUsQ0FBQyxPQUFPLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztRQUM1RCxVQUFVLENBQUMsS0FBSyxDQUFDO1FBRWpCLElBQUcsUUFBUSxDQUFDLE1BQU0sRUFBQztZQUNqQixvRkFBYyxDQUFDLGtHQUF5QixFQUFFLFFBQVEsQ0FBQyxNQUFNLENBQUMsQ0FBQztZQUMzRCxPQUFPO1NBQ1I7UUFDRCxvRkFBYyxDQUFDLDZHQUFvQyxFQUFFLFFBQVEsQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUNwRSxNQUFNLHFCQUFxQixDQUFDLGNBQWMsRUFBRSxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUM7SUFDN0QsQ0FBQztJQUVELE1BQU0sYUFBYSxHQUFFLENBQUMsSUFBWSxFQUFDLEVBQUU7UUFFbkMsYUFBYSxDQUFDLElBQUksQ0FBQyxDQUFDO1FBRXBCLElBQUksZUFBZSxHQUFHLENBQUMsR0FBRyxTQUFTLENBQUMsQ0FBQztRQUVyQyxJQUFHLENBQUMsSUFBSSxJQUFJLElBQUksS0FBSyxFQUFFLElBQUksSUFBSSxLQUFLLElBQUksRUFBQztZQUN2QyxPQUFPLG1GQUFVLENBQUMsZUFBZSxFQUFFLGFBQWEsQ0FBQyxDQUFDO1NBQ25EO1FBQ0QsSUFBSSxhQUFhLEdBQUcsZUFBZSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRTs7WUFDN0MsZUFBQyxDQUFDLElBQUksMENBQUUsaUJBQWlCLEdBQUcsUUFBUSxDQUFDLElBQUksQ0FBQyxpQkFBaUIsRUFBRSxDQUFDO2lCQUM5RCxPQUFDLENBQUMsZ0JBQWdCLDBDQUFFLGlCQUFpQixHQUFHLFFBQVEsQ0FBQyxJQUFJLENBQUMsaUJBQWlCLEVBQUUsQ0FBQztpQkFDMUUsT0FBQyxDQUFDLFVBQVUsMENBQUUsaUJBQWlCLEdBQUcsUUFBUSxDQUFDLElBQUksQ0FBQyxpQkFBaUIsRUFBRSxDQUFDO2lCQUNwRSxPQUFDLENBQUMsVUFBVSwwQ0FBRSxpQkFBaUIsR0FBRyxRQUFRLENBQUMsSUFBSSxDQUFDLGlCQUFpQixFQUFFLENBQUM7Z0JBQ3BFLHlGQUFTLENBQUMsQ0FBQyxDQUFDLFdBQVcsQ0FBQywwQ0FBRSxLQUFLLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSSxJQUFJO2lCQUN0RCx3RkFBUyxDQUFDLENBQUMsQ0FBQyxXQUFXLENBQUMsMENBQUUsUUFBUSxDQUFDLElBQUksQ0FBQztpQkFDeEMsd0ZBQVMsQ0FBQyxDQUFDLENBQUMsVUFBVSxDQUFDLDBDQUFFLFFBQVEsQ0FBQyxJQUFJLENBQUM7Z0JBQ3ZDLHlGQUFTLENBQUMsQ0FBQyxDQUFDLFVBQVUsQ0FBQywwQ0FBRSxLQUFLLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxJQUFJLEVBQUUsS0FBSSxJQUFJO1NBQUEsQ0FBQyxDQUFDO1FBRXZELE9BQU8sbUZBQVUsQ0FBQyxhQUFhLEVBQUUsYUFBYSxDQUFDLENBQUM7SUFDcEQsQ0FBQztJQUVELE1BQU0saUJBQWlCLEdBQUMsQ0FBQyxJQUFZLEVBQUMsRUFBRTtRQUN0QyxxQkFBcUIsQ0FBQyxjQUFjLEVBQUUsYUFBYSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUM7SUFDN0QsQ0FBQztJQUVELE1BQU0sZ0JBQWdCLEdBQUMsQ0FBTyxRQUFnQixFQUFDLEVBQUU7UUFFL0Msb0ZBQWMsQ0FBQyw2R0FBb0MsRUFBRSxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFO1lBQ3JFLHVDQUNLLENBQUMsS0FDSixVQUFVLEVBQUUsQ0FBQyxDQUFDLFFBQVEsS0FBSyxRQUFRLElBQ3BDO1FBQ0gsQ0FBQyxDQUFDLENBQUM7UUFFSCxJQUFHLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsUUFBUSxLQUFLLFFBQVEsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxFQUFDO1lBQ2hFLE9BQU87U0FDUjtRQUNELDBFQUEwRTtJQUM1RSxDQUFDO0lBRUQsTUFBTSxpQkFBaUIsR0FBQyxDQUFPLFFBQWdCLEVBQUMsRUFBRTtRQUNoRCxvQkFBb0I7UUFFcEIsNkRBQTZEO1FBQzdELCtCQUErQjtRQUMvQiwyQkFBMkI7UUFDM0IsTUFBTTtRQUNOLHFCQUFxQjtJQUN2QixDQUFDO0lBRUQsTUFBTSxZQUFZLEdBQUUsR0FBUSxFQUFFO1FBQzVCLE1BQU0sYUFBYSxFQUFFLENBQUM7UUFDdEIsNkJBQTZCLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDdkMsQ0FBQztJQUVELE1BQU0sWUFBWSxHQUFFLENBQUMsRUFBVSxFQUFDLEVBQUU7UUFDaEMscUJBQXFCLENBQUMsRUFBRSxFQUFHLGFBQWEsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDO0lBQ3hELENBQUM7SUFFRCxNQUFNLHFCQUFxQixHQUFFLENBQU8sRUFBRSxFQUFFLFVBQVUsRUFBQyxFQUFFO1FBQ2xELElBQUcsVUFBVSxJQUFJLElBQUksRUFBQztZQUNyQixPQUFPO1NBQ1A7UUFFRCxpQkFBaUIsQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUV0QixRQUFPLEVBQUUsRUFBQztZQUNULEtBQUssS0FBSztnQkFDUixnQkFBZ0IsQ0FBQyxDQUFDLEdBQUcsVUFBVSxDQUFDLENBQUM7Z0JBQ2pDLE1BQU07WUFDUixLQUFLLFVBQVU7Z0JBQ2IsZ0JBQWdCLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsQ0FBQztnQkFDdEQsTUFBTTtZQUNSLEtBQUssUUFBUTtnQkFDYixnQkFBZ0IsQ0FBQyxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxDQUFDLENBQUM7Z0JBQzNELE1BQU07WUFDUixLQUFLLFVBQVU7Z0JBQ2IsZ0JBQWdCLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsQ0FBQyxDQUFDO2dCQUM3RCxNQUFNO1NBQ1I7SUFDSixDQUFDO0lBRUQsT0FBTyxDQUNMLG9FQUFLLFNBQVMsRUFBQyw2Q0FBNkMsRUFDMUQsS0FBSyxFQUFFO1lBQ0wsZUFBZSxFQUFFLEtBQUssQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUU7U0FDNUM7UUFDRCwwRUFDRzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O1NBd0hBLENBQ0s7UUFDUixvRUFBSyxTQUFTLEVBQUMsdUJBQXVCLEVBQUMsS0FBSyxFQUFFO2dCQUMxQyxlQUFlLEVBQUUsS0FBSyxDQUFDLE1BQU0sQ0FBQyxxQkFBcUIsSUFBSSxLQUFLLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxTQUFTO2dCQUNuRixLQUFLLEVBQUUsS0FBSyxDQUFDLE1BQU0sQ0FBQyxlQUFlLElBQUksS0FBSyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUM7Z0JBQzlFLFNBQVMsRUFBRSxLQUFLLENBQUMsS0FBSyxDQUFDLFVBQVUsQ0FBQyxPQUFPO2dCQUN6QyxRQUFRLEVBQUUsS0FBSyxDQUFDLEtBQUssQ0FBQyxVQUFVLENBQUMsS0FBSyxDQUFDLFFBQVE7Z0JBQy9DLFVBQVUsRUFBRSxLQUFLLENBQUMsS0FBSyxDQUFDLFVBQVUsQ0FBQyxPQUFPLENBQUMsSUFBSTthQUNoRDtZQUNELDJEQUFDLDBDQUFLLElBQUMsS0FBSyxzQkFFSixDQUNKO1FBQ04sb0VBQUssU0FBUyxFQUFDLDBCQUEwQjtZQUN2QyxvRUFBSyxTQUFTLEVBQUMseUJBQXlCO2dCQUNwQyw4RkFFSztnQkFDTCxvRUFBSyxTQUFTLEVBQUMsU0FBUyxnQkFBWSxxQkFBcUIsRUFBRSxJQUFJLEVBQUMsT0FBTztvQkFXckUsMkRBQUMsMENBQUssSUFBQyxPQUFPO3dCQUNaLDJEQUFDLDZDQUFRLElBQ1AsRUFBRSxFQUFFLEtBQUssZ0JBQ0UsVUFBVSxFQUNyQixPQUFPLEVBQUUsY0FBYyxLQUFLLEtBQUssRUFDakMsUUFBUSxFQUFFLENBQUMsQ0FBQyxFQUFDLEVBQUUsQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxFQUFFLENBQUMsR0FDekM7OEJBRUk7b0JBRVIsMkRBQUMsMENBQUssSUFBQyxPQUFPO3dCQUNaLDJEQUFDLDZDQUFRLElBQ1AsRUFBRSxFQUFDLFFBQVEsZ0JBQ0EsVUFBVSxFQUNyQixPQUFPLEVBQUUsY0FBYyxLQUFLLFFBQVEsRUFDcEMsUUFBUSxFQUFFLENBQUMsQ0FBQyxFQUFDLEVBQUUsQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxFQUFFLENBQUMsR0FDekM7aUNBRUk7b0JBRVIsMkRBQUMsMENBQUssSUFBQyxPQUFPLFFBQUMsS0FBSzt3QkFDbEIsMkRBQUMsNkNBQVEsSUFDUCxFQUFFLEVBQUMsVUFBVSxnQkFDRixVQUFVLEVBQ3JCLE9BQU8sRUFBRSxjQUFjLEtBQUssVUFBVSxFQUN0QyxRQUFRLEVBQUUsQ0FBQyxDQUFDLEVBQUMsRUFBRSxDQUFDLFlBQVksQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLEVBQUUsQ0FBQyxHQUN6QzttQ0FFSSxDQUNKLENBQ0o7WUFDTixvRUFBSyxTQUFTLEVBQUMsa0JBQWtCO2dCQUMvQiwyREFBQyx5RkFBZSxJQUFDLEtBQUssRUFBRSxrQkFBa0IsRUFDeEMsUUFBUSxFQUFFLGlCQUFpQixFQUFFLEtBQUssRUFBRSxLQUFLLEdBQUcsRUFFMUMsWUFBWSxhQUFaLFlBQVk7Z0JBQVosWUFBWSxDQUFFLEdBQUcsQ0FBQyxDQUFDLElBQWtCLEVBQUUsRUFBRTtvQkFDdkMsT0FBTyxDQUNMLDJEQUFDLHdGQUFjLElBQUMsR0FBRyxFQUFFLElBQUksQ0FBQyxFQUFFLEVBQUUsS0FBSyxFQUFFLEtBQUssRUFDeEMsUUFBUSxFQUFFLElBQUksRUFDZCxPQUFPLEVBQUUsR0FBRyxFQUFFLENBQUMsZ0JBQWdCLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxFQUM5QyxVQUFVLEVBQUUsaUJBQWlCLEdBQUcsQ0FDbkM7Z0JBQ0gsQ0FBQyxDQUFDLENBRUY7WUFFSixDQUFDLElBQUksS0FBSSxVQUFJLENBQUMsTUFBTSwwQ0FBRSxRQUFRLENBQUMsa0ZBQVUsQ0FBQztnQkFDeEMsSUFBSSxLQUFJLFVBQUksQ0FBQyxNQUFNLDBDQUFFLFFBQVEsQ0FBQyxtRkFBVyxDQUFDO2dCQUMxQyxJQUFJLEtBQUksVUFBSSxDQUFDLE1BQU0sMENBQUUsUUFBUSxDQUFDLHNGQUFjLENBQUMsRUFBQyxDQUFDLENBQUM7Z0JBQ2xELENBQUUsMkRBQUMsMkNBQU0sbUJBQWEsc0JBQXNCLEVBQzVDLFNBQVMsRUFBQyxxQkFBcUIsRUFDL0IsS0FBSyxFQUFFLEVBQUMsVUFBVSxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMscUJBQXFCLEVBQUMsRUFDdkQsSUFBSSxFQUFDLElBQUksRUFBQyxPQUFPLEVBQUUsR0FBRyxFQUFFLENBQUMsNkJBQTZCLENBQUMsSUFBSSxDQUFDLHNCQUEwQixDQUNyRixFQUFDLENBQUMsSUFBSTtZQUVULDJEQUFDLHdGQUFpQixJQUNoQixNQUFNLEVBQUUsTUFBTSxFQUNkLE9BQU8sRUFBRSxPQUFPLEVBQ2hCLGNBQWMsRUFBRSxjQUFjLEVBQzlCLFNBQVMsRUFBRSxpQkFBaUIsRUFDNUIsb0JBQW9CLEVBQUUsb0JBQW9CLEVBQzFDLGFBQWEsRUFBRSxhQUFhLEVBQzVCLGVBQWUsRUFBRSx1QkFBdUIsRUFDeEMsU0FBUyxFQUFFLFNBQVMsRUFDcEIsSUFBSSxFQUFFLElBQUksRUFDVixPQUFPLEVBQUUseUJBQXlCLEVBQ2xDLGdCQUFnQixFQUFFLDZCQUE2QixFQUMvQyw0QkFBNEIsRUFBRSxZQUFZLEVBQzFDLG9CQUFvQixFQUFFLDJCQUEyQixFQUNqRCwwQkFBMEIsRUFBRSxpQ0FBaUMsR0FBRztZQUVsRSwyREFBQywrRkFBb0IsSUFDbkIsV0FBVyxFQUFFLEtBQUssYUFBTCxLQUFLLHVCQUFMLEtBQUssQ0FBRSxNQUFNLEVBQzFCLE9BQU8sRUFBRSw2QkFBNkIsRUFDdEMsZUFBZSxFQUFFLHVCQUF1QixFQUN4QyxNQUFNLEVBQUUsaUNBQWlDLEdBQUc7WUFFOUMsMkRBQUMscUZBQWUsSUFDZCxLQUFLLEVBQUUsS0FBSyxFQUNaLE9BQU8sRUFBRSx1QkFBdUIsRUFDaEMsU0FBUyxFQUFFLGlCQUFpQixFQUM1QixNQUFNLEVBQUUsMkJBQTJCLEdBQUcsQ0FDcEM7UUFFSixPQUFPLENBQUMsQ0FBQyxDQUFDLDJEQUFDLDRFQUFXLE9BQUUsRUFBQyxDQUFDLElBQUksQ0FFNUIsQ0FDUDtBQUNILENBQUM7QUFDRCxpRUFBZSxNQUFNIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL1VzZXJTZXNzaW9uLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9mZWRlcmF0aW9uLXV0aWxzLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9mZXRjaC10b2tlbi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vZ2VuZXJhdGUtdG9rZW4uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL3ZhbGlkYXRlLWFwcC1hY2Nlc3MuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL2FkZC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vZGVsZXRlLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9xdWVyeS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vcXVlcnlSZWxhdGVkLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS91cGRhdGUuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3JlcXVlc3QuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL0FyY0dJU1JlcXVlc3RFcnJvci5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvYXBwZW5kLWN1c3RvbS1wYXJhbXMuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2NsZWFuLXVybC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZGVjb2RlLXF1ZXJ5LXN0cmluZy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZW5jb2RlLWZvcm0tZGF0YS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZW5jb2RlLXF1ZXJ5LXN0cmluZy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvcHJvY2Vzcy1wYXJhbXMuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL3dhcm4uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvc3ZnL291dGxpbmVkL2FwcGxpY2F0aW9uL2ZvbGRlci5zdmciLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvc3ZnL291dGxpbmVkL2FwcGxpY2F0aW9uL3NldHRpbmcuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9lZGl0b3IvcGx1cy1jaXJjbGUuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9lZGl0b3IvdHJhc2guc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9zdWdnZXN0ZWQvc3VjY2Vzcy5zdmciLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvb3V0bGluZWQvYXBwbGljYXRpb24vZm9sZGVyLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9vdXRsaW5lZC9hcHBsaWNhdGlvbi9zZXR0aW5nLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvcGx1cy1jaXJjbGUudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL291dGxpbmVkL2VkaXRvci90cmFzaC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvb3V0bGluZWQvc3VnZ2VzdGVkL3N1Y2Nlc3MudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaS50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hdXRoLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmUudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY29uc3RhbnRzLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2VzcmktYXBpLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2xvZ2dlci50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy91dGlscy50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFkZC1oYXphcmQudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtYWRkLW9yZ2FuaXphdGlvbi50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1hZGQtdGVtcGxhdGUudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtZHJvcGRvd24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtaGF6YXJkcy1kcm9wZG93bi50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1sb2FkaW5nLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLW1vZGFsLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLW9yZ2FuaXphdGlvbnMtZHJvcGRvd24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3Mtc2VhcmNoLXRlbXBsYXRlLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLXRlbXBsYXRlLWJ1dHRvbi50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy10ZW1wbGF0ZXMtZHJvcGRvd24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1hcmNnaXNcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtY29yZVwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1jb3JlL3JlYWN0XCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LXVpXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9jb21wYXQgZ2V0IGRlZmF1bHQgZXhwb3J0Iiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2RlZmluZSBwcm9wZXJ0eSBnZXR0ZXJzIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2hhc093blByb3BlcnR5IHNob3J0aGFuZCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9tYWtlIG5hbWVzcGFjZSBvYmplY3QiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvcHVibGljUGF0aCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1jb3JlL2xpYi9zZXQtcHVibGljLXBhdGgudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtdGVtcGxhdGVzL3NyYy9ydW50aW1lL3dpZGdldC50c3giXSwic291cmNlc0NvbnRlbnQiOlsiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTkgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIEFyY0dJU0F1dGhFcnJvciwgY2xlYW5VcmwsIGVuY29kZVF1ZXJ5U3RyaW5nLCBkZWNvZGVRdWVyeVN0cmluZywgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuaW1wb3J0IHsgZ2VuZXJhdGVUb2tlbiB9IGZyb20gXCIuL2dlbmVyYXRlLXRva2VuXCI7XG5pbXBvcnQgeyBmZXRjaFRva2VuIH0gZnJvbSBcIi4vZmV0Y2gtdG9rZW5cIjtcbmltcG9ydCB7IGNhblVzZU9ubGluZVRva2VuLCBpc0ZlZGVyYXRlZCB9IGZyb20gXCIuL2ZlZGVyYXRpb24tdXRpbHNcIjtcbmltcG9ydCB7IHZhbGlkYXRlQXBwQWNjZXNzIH0gZnJvbSBcIi4vdmFsaWRhdGUtYXBwLWFjY2Vzc1wiO1xuZnVuY3Rpb24gZGVmZXIoKSB7XG4gICAgdmFyIGRlZmVycmVkID0ge1xuICAgICAgICBwcm9taXNlOiBudWxsLFxuICAgICAgICByZXNvbHZlOiBudWxsLFxuICAgICAgICByZWplY3Q6IG51bGwsXG4gICAgfTtcbiAgICBkZWZlcnJlZC5wcm9taXNlID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlID0gcmVzb2x2ZTtcbiAgICAgICAgZGVmZXJyZWQucmVqZWN0ID0gcmVqZWN0O1xuICAgIH0pO1xuICAgIHJldHVybiBkZWZlcnJlZDtcbn1cbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IFVzZXJTZXNzaW9uIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aCc7XG4gKiBVc2VyU2Vzc2lvbi5iZWdpbk9BdXRoMih7XG4gKiAgIC8vIHJlZ2lzdGVyIGFuIGFwcCBvZiB5b3VyIG93biB0byBjcmVhdGUgYSB1bmlxdWUgY2xpZW50SWRcbiAqICAgY2xpZW50SWQ6IFwiYWJjMTIzXCIsXG4gKiAgIHJlZGlyZWN0VXJpOiAnaHR0cHM6Ly95b3VyYXBwLmNvbS9hdXRoZW50aWNhdGUuaHRtbCdcbiAqIH0pXG4gKiAgIC50aGVuKHNlc3Npb24pXG4gKiAvLyBvclxuICogbmV3IFVzZXJTZXNzaW9uKHtcbiAqICAgdXNlcm5hbWU6IFwianNtaXRoXCIsXG4gKiAgIHBhc3N3b3JkOiBcIjEyMzQ1NlwiXG4gKiB9KVxuICogLy8gb3JcbiAqIFVzZXJTZXNzaW9uLmRlc2VyaWFsaXplKGNhY2hlKVxuICogYGBgXG4gKiBVc2VkIHRvIGF1dGhlbnRpY2F0ZSBib3RoIEFyY0dJUyBPbmxpbmUgYW5kIEFyY0dJUyBFbnRlcnByaXNlIHVzZXJzLiBgVXNlclNlc3Npb25gIGluY2x1ZGVzIGhlbHBlciBtZXRob2RzIGZvciBbT0F1dGggMi4wXSgvYXJjZ2lzLXJlc3QtanMvZ3VpZGVzL2Jyb3dzZXItYXV0aGVudGljYXRpb24vKSBpbiBib3RoIGJyb3dzZXIgYW5kIHNlcnZlciBhcHBsaWNhdGlvbnMuXG4gKi9cbnZhciBVc2VyU2Vzc2lvbiA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBVc2VyU2Vzc2lvbihvcHRpb25zKSB7XG4gICAgICAgIHRoaXMuY2xpZW50SWQgPSBvcHRpb25zLmNsaWVudElkO1xuICAgICAgICB0aGlzLl9yZWZyZXNoVG9rZW4gPSBvcHRpb25zLnJlZnJlc2hUb2tlbjtcbiAgICAgICAgdGhpcy5fcmVmcmVzaFRva2VuRXhwaXJlcyA9IG9wdGlvbnMucmVmcmVzaFRva2VuRXhwaXJlcztcbiAgICAgICAgdGhpcy51c2VybmFtZSA9IG9wdGlvbnMudXNlcm5hbWU7XG4gICAgICAgIHRoaXMucGFzc3dvcmQgPSBvcHRpb25zLnBhc3N3b3JkO1xuICAgICAgICB0aGlzLl90b2tlbiA9IG9wdGlvbnMudG9rZW47XG4gICAgICAgIHRoaXMuX3Rva2VuRXhwaXJlcyA9IG9wdGlvbnMudG9rZW5FeHBpcmVzO1xuICAgICAgICB0aGlzLnBvcnRhbCA9IG9wdGlvbnMucG9ydGFsXG4gICAgICAgICAgICA/IGNsZWFuVXJsKG9wdGlvbnMucG9ydGFsKVxuICAgICAgICAgICAgOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgICAgIHRoaXMuc3NsID0gb3B0aW9ucy5zc2w7XG4gICAgICAgIHRoaXMucHJvdmlkZXIgPSBvcHRpb25zLnByb3ZpZGVyIHx8IFwiYXJjZ2lzXCI7XG4gICAgICAgIHRoaXMudG9rZW5EdXJhdGlvbiA9IG9wdGlvbnMudG9rZW5EdXJhdGlvbiB8fCAyMDE2MDtcbiAgICAgICAgdGhpcy5yZWRpcmVjdFVyaSA9IG9wdGlvbnMucmVkaXJlY3RVcmk7XG4gICAgICAgIHRoaXMucmVmcmVzaFRva2VuVFRMID0gb3B0aW9ucy5yZWZyZXNoVG9rZW5UVEwgfHwgMjAxNjA7XG4gICAgICAgIHRoaXMuc2VydmVyID0gb3B0aW9ucy5zZXJ2ZXI7XG4gICAgICAgIHRoaXMuZmVkZXJhdGVkU2VydmVycyA9IHt9O1xuICAgICAgICB0aGlzLnRydXN0ZWREb21haW5zID0gW107XG4gICAgICAgIC8vIGlmIGEgbm9uLWZlZGVyYXRlZCBzZXJ2ZXIgd2FzIHBhc3NlZCBleHBsaWNpdGx5LCBpdCBzaG91bGQgYmUgdHJ1c3RlZC5cbiAgICAgICAgaWYgKG9wdGlvbnMuc2VydmVyKSB7XG4gICAgICAgICAgICAvLyBpZiB0aGUgdXJsIGluY2x1ZGVzIG1vcmUgdGhhbiAnL2FyY2dpcy8nLCB0cmltIHRoZSByZXN0XG4gICAgICAgICAgICB2YXIgcm9vdCA9IHRoaXMuZ2V0U2VydmVyUm9vdFVybChvcHRpb25zLnNlcnZlcik7XG4gICAgICAgICAgICB0aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF0gPSB7XG4gICAgICAgICAgICAgICAgdG9rZW46IG9wdGlvbnMudG9rZW4sXG4gICAgICAgICAgICAgICAgZXhwaXJlczogb3B0aW9ucy50b2tlbkV4cGlyZXMsXG4gICAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzID0ge307XG4gICAgfVxuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwidG9rZW5cIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGN1cnJlbnQgQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZSBgdG9rZW5gLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fdG9rZW47XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInRva2VuRXhwaXJlc1wiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgZXhwaXJhdGlvbiB0aW1lIG9mIHRoZSBjdXJyZW50IGB0b2tlbmAuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl90b2tlbkV4cGlyZXM7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInJlZnJlc2hUb2tlblwiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgY3VycmVudCB0b2tlbiB0byBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcmVmcmVzaFRva2VuO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJyZWZyZXNoVG9rZW5FeHBpcmVzXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBleHBpcmF0aW9uIHRpbWUgb2YgdGhlIGN1cnJlbnQgYHJlZnJlc2hUb2tlbmAuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9yZWZyZXNoVG9rZW5FeHBpcmVzO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJ0cnVzdGVkU2VydmVyc1wiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBEZXByZWNhdGVkLCB1c2UgYGZlZGVyYXRlZFNlcnZlcnNgIGluc3RlYWQuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBkZXByZWNhdGVkXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiREVQUkVDQVRFRDogdXNlIGZlZGVyYXRlZFNlcnZlcnMgaW5zdGVhZFwiKTtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmZlZGVyYXRlZFNlcnZlcnM7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICAvKipcbiAgICAgKiBCZWdpbnMgYSBuZXcgYnJvd3Nlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbi4gSWYgYG9wdGlvbnMucG9wdXBgIGlzIGB0cnVlYCB0aGVcbiAgICAgKiBhdXRoZW50aWNhdGlvbiB3aW5kb3cgd2lsbCBvcGVuIGluIGEgbmV3IHRhYi93aW5kb3cgYW5kIHRoZSBmdW5jdGlvbiB3aWxsIHJldHVyblxuICAgICAqIFByb21pc2UmbHQ7VXNlclNlc3Npb24mZ3Q7LiBPdGhlcndpc2UsIHRoZSB1c2VyIHdpbGwgYmUgcmVkaXJlY3RlZCB0byB0aGVcbiAgICAgKiBhdXRob3JpemF0aW9uIHBhZ2UgaW4gdGhlaXIgY3VycmVudCB0YWIvd2luZG93IGFuZCB0aGUgZnVuY3Rpb24gd2lsbCByZXR1cm4gYHVuZGVmaW5lZGAuXG4gICAgICpcbiAgICAgKiBAYnJvd3Nlck9ubHlcbiAgICAgKi9cbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIFVzZXJTZXNzaW9uLmJlZ2luT0F1dGgyID0gZnVuY3Rpb24gKG9wdGlvbnMsIHdpbikge1xuICAgICAgICBpZiAod2luID09PSB2b2lkIDApIHsgd2luID0gd2luZG93OyB9XG4gICAgICAgIGlmIChvcHRpb25zLmR1cmF0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkRFUFJFQ0FURUQ6ICdkdXJhdGlvbicgaXMgZGVwcmVjYXRlZCAtIHVzZSAnZXhwaXJhdGlvbicgaW5zdGVhZFwiKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7XG4gICAgICAgICAgICBwb3J0YWw6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHByb3ZpZGVyOiBcImFyY2dpc1wiLFxuICAgICAgICAgICAgZXhwaXJhdGlvbjogMjAxNjAsXG4gICAgICAgICAgICBwb3B1cDogdHJ1ZSxcbiAgICAgICAgICAgIHBvcHVwV2luZG93RmVhdHVyZXM6IFwiaGVpZ2h0PTQwMCx3aWR0aD02MDAsbWVudWJhcj1ubyxsb2NhdGlvbj15ZXMscmVzaXphYmxlPXllcyxzY3JvbGxiYXJzPXllcyxzdGF0dXM9eWVzXCIsXG4gICAgICAgICAgICBzdGF0ZTogb3B0aW9ucy5jbGllbnRJZCxcbiAgICAgICAgICAgIGxvY2FsZTogXCJcIixcbiAgICAgICAgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgcHJvdmlkZXIgPSBfYS5wcm92aWRlciwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgZXhwaXJhdGlvbiA9IF9hLmV4cGlyYXRpb24sIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmksIHBvcHVwID0gX2EucG9wdXAsIHBvcHVwV2luZG93RmVhdHVyZXMgPSBfYS5wb3B1cFdpbmRvd0ZlYXR1cmVzLCBzdGF0ZSA9IF9hLnN0YXRlLCBsb2NhbGUgPSBfYS5sb2NhbGUsIHBhcmFtcyA9IF9hLnBhcmFtcztcbiAgICAgICAgdmFyIHVybDtcbiAgICAgICAgaWYgKHByb3ZpZGVyID09PSBcImFyY2dpc1wiKSB7XG4gICAgICAgICAgICB1cmwgPSBwb3J0YWwgKyBcIi9vYXV0aDIvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImcmVzcG9uc2VfdHlwZT10b2tlbiZleHBpcmF0aW9uPVwiICsgKG9wdGlvbnMuZHVyYXRpb24gfHwgZXhwaXJhdGlvbikgKyBcIiZyZWRpcmVjdF91cmk9XCIgKyBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICsgXCImc3RhdGU9XCIgKyBzdGF0ZSArIFwiJmxvY2FsZT1cIiArIGxvY2FsZTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHVybCA9IHBvcnRhbCArIFwiL29hdXRoMi9zb2NpYWwvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImc29jaWFsTG9naW5Qcm92aWRlck5hbWU9XCIgKyBwcm92aWRlciArIFwiJmF1dG9BY2NvdW50Q3JlYXRlRm9yU29jaWFsPXRydWUmcmVzcG9uc2VfdHlwZT10b2tlbiZleHBpcmF0aW9uPVwiICsgKG9wdGlvbnMuZHVyYXRpb24gfHwgZXhwaXJhdGlvbikgKyBcIiZyZWRpcmVjdF91cmk9XCIgKyBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICsgXCImc3RhdGU9XCIgKyBzdGF0ZSArIFwiJmxvY2FsZT1cIiArIGxvY2FsZTtcbiAgICAgICAgfVxuICAgICAgICAvLyBhcHBlbmQgYWRkaXRpb25hbCBwYXJhbXNcbiAgICAgICAgaWYgKHBhcmFtcykge1xuICAgICAgICAgICAgdXJsID0gdXJsICsgXCImXCIgKyBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghcG9wdXApIHtcbiAgICAgICAgICAgIHdpbi5sb2NhdGlvbi5ocmVmID0gdXJsO1xuICAgICAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgICAgfVxuICAgICAgICB2YXIgc2Vzc2lvbiA9IGRlZmVyKCk7XG4gICAgICAgIHdpbltcIl9fRVNSSV9SRVNUX0FVVEhfSEFORExFUl9cIiArIGNsaWVudElkXSA9IGZ1bmN0aW9uIChlcnJvclN0cmluZywgb2F1dGhJbmZvU3RyaW5nKSB7XG4gICAgICAgICAgICBpZiAoZXJyb3JTdHJpbmcpIHtcbiAgICAgICAgICAgICAgICB2YXIgZXJyb3IgPSBKU09OLnBhcnNlKGVycm9yU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uLnJlamVjdChuZXcgQXJjR0lTQXV0aEVycm9yKGVycm9yLmVycm9yTWVzc2FnZSwgZXJyb3IuZXJyb3IpKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAob2F1dGhJbmZvU3RyaW5nKSB7XG4gICAgICAgICAgICAgICAgdmFyIG9hdXRoSW5mbyA9IEpTT04ucGFyc2Uob2F1dGhJbmZvU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uLnJlc29sdmUobmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgICAgICAgICAgY2xpZW50SWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICAgICAgc3NsOiBvYXV0aEluZm8uc3NsLFxuICAgICAgICAgICAgICAgICAgICB0b2tlbjogb2F1dGhJbmZvLnRva2VuLFxuICAgICAgICAgICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG5ldyBEYXRlKG9hdXRoSW5mby5leHBpcmVzKSxcbiAgICAgICAgICAgICAgICAgICAgdXNlcm5hbWU6IG9hdXRoSW5mby51c2VybmFtZSxcbiAgICAgICAgICAgICAgICB9KSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgICAgIHdpbi5vcGVuKHVybCwgXCJvYXV0aC13aW5kb3dcIiwgcG9wdXBXaW5kb3dGZWF0dXJlcyk7XG4gICAgICAgIHJldHVybiBzZXNzaW9uLnByb21pc2U7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBDb21wbGV0ZXMgYSBicm93c2VyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluLiBJZiBgb3B0aW9ucy5wb3B1cGAgaXMgYHRydWVgIHRoZSB1c2VyXG4gICAgICogd2lsbCBiZSByZXR1cm5lZCB0byB0aGUgcHJldmlvdXMgd2luZG93LiBPdGhlcndpc2UgYSBuZXcgYFVzZXJTZXNzaW9uYFxuICAgICAqIHdpbGwgYmUgcmV0dXJuZWQuIFlvdSBtdXN0IHBhc3MgdGhlIHNhbWUgdmFsdWVzIGZvciBgb3B0aW9ucy5wb3B1cGAgYW5kXG4gICAgICogYG9wdGlvbnMucG9ydGFsYCBhcyB5b3UgdXNlZCBpbiBgYmVnaW5PQXV0aDIoKWAuXG4gICAgICpcbiAgICAgKiBAYnJvd3Nlck9ubHlcbiAgICAgKi9cbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIFVzZXJTZXNzaW9uLmNvbXBsZXRlT0F1dGgyID0gZnVuY3Rpb24gKG9wdGlvbnMsIHdpbikge1xuICAgICAgICBpZiAod2luID09PSB2b2lkIDApIHsgd2luID0gd2luZG93OyB9XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHsgcG9ydGFsOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsIHBvcHVwOiB0cnVlIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIHBvcHVwID0gX2EucG9wdXA7XG4gICAgICAgIGZ1bmN0aW9uIGNvbXBsZXRlU2lnbkluKGVycm9yLCBvYXV0aEluZm8pIHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgdmFyIGhhbmRsZXJGbiA9IHZvaWQgMDtcbiAgICAgICAgICAgICAgICB2YXIgaGFuZGxlckZuTmFtZSA9IFwiX19FU1JJX1JFU1RfQVVUSF9IQU5ETEVSX1wiICsgY2xpZW50SWQ7XG4gICAgICAgICAgICAgICAgaWYgKHBvcHVwKSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIEd1YXJkIGIvYyBJRSBkb2VzIG5vdCBzdXBwb3J0IHdpbmRvdy5vcGVuZXJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHdpbi5vcGVuZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh3aW4ub3BlbmVyLnBhcmVudCAmJiB3aW4ub3BlbmVyLnBhcmVudFtoYW5kbGVyRm5OYW1lXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbiA9IHdpbi5vcGVuZXIucGFyZW50W2hhbmRsZXJGbk5hbWVdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZiAod2luLm9wZW5lciAmJiB3aW4ub3BlbmVyW2hhbmRsZXJGbk5hbWVdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gc3VwcG9ydCBwb3Atb3V0IG9hdXRoIGZyb20gd2l0aGluIGFuIGlmcmFtZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbiA9IHdpbi5vcGVuZXJbaGFuZGxlckZuTmFtZV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBJRVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHdpbiAhPT0gd2luLnBhcmVudCAmJiB3aW4ucGFyZW50ICYmIHdpbi5wYXJlbnRbaGFuZGxlckZuTmFtZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4gPSB3aW4ucGFyZW50W2hhbmRsZXJGbk5hbWVdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIC8vIGlmIHdlIGhhdmUgYSBoYW5kbGVyIGZuLCBjYWxsIGl0IGFuZCBjbG9zZSB0aGUgd2luZG93XG4gICAgICAgICAgICAgICAgICAgIGlmIChoYW5kbGVyRm4pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbihlcnJvciA/IEpTT04uc3RyaW5naWZ5KGVycm9yKSA6IHVuZGVmaW5lZCwgSlNPTi5zdHJpbmdpZnkob2F1dGhJbmZvKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB3aW4uY2xvc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IoXCJVbmFibGUgdG8gY29tcGxldGUgYXV0aGVudGljYXRpb24uIEl0J3MgcG9zc2libGUgeW91IHNwZWNpZmllZCBwb3B1cCBiYXNlZCBvQXV0aDIgYnV0IG5vIGhhbmRsZXIgZnJvbSBcXFwiYmVnaW5PQXV0aDIoKVxcXCIgcHJlc2VudC4gVGhpcyBnZW5lcmFsbHkgaGFwcGVucyBiZWNhdXNlIHRoZSBcXFwicG9wdXBcXFwiIG9wdGlvbiBkaWZmZXJzIGJldHdlZW4gXFxcImJlZ2luT0F1dGgyKClcXFwiIGFuZCBcXFwiY29tcGxldGVPQXV0aDIoKVxcXCIuXCIpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcihlcnJvci5lcnJvck1lc3NhZ2UsIGVycm9yLmVycm9yKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgICAgIGNsaWVudElkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICBzc2w6IG9hdXRoSW5mby5zc2wsXG4gICAgICAgICAgICAgICAgdG9rZW46IG9hdXRoSW5mby50b2tlbixcbiAgICAgICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG9hdXRoSW5mby5leHBpcmVzLFxuICAgICAgICAgICAgICAgIHVzZXJuYW1lOiBvYXV0aEluZm8udXNlcm5hbWUsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgcGFyYW1zID0gZGVjb2RlUXVlcnlTdHJpbmcod2luLmxvY2F0aW9uLmhhc2gpO1xuICAgICAgICBpZiAoIXBhcmFtcy5hY2Nlc3NfdG9rZW4pIHtcbiAgICAgICAgICAgIHZhciBlcnJvciA9IHZvaWQgMDtcbiAgICAgICAgICAgIHZhciBlcnJvck1lc3NhZ2UgPSBcIlVua25vd24gZXJyb3JcIjtcbiAgICAgICAgICAgIGlmIChwYXJhbXMuZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBlcnJvciA9IHBhcmFtcy5lcnJvcjtcbiAgICAgICAgICAgICAgICBlcnJvck1lc3NhZ2UgPSBwYXJhbXMuZXJyb3JfZGVzY3JpcHRpb247XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gY29tcGxldGVTaWduSW4oeyBlcnJvcjogZXJyb3IsIGVycm9yTWVzc2FnZTogZXJyb3JNZXNzYWdlIH0pO1xuICAgICAgICB9XG4gICAgICAgIHZhciB0b2tlbiA9IHBhcmFtcy5hY2Nlc3NfdG9rZW47XG4gICAgICAgIHZhciBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIHBhcnNlSW50KHBhcmFtcy5leHBpcmVzX2luLCAxMCkgKiAxMDAwIC0gNjAgKiAxMDAwKTtcbiAgICAgICAgdmFyIHVzZXJuYW1lID0gcGFyYW1zLnVzZXJuYW1lO1xuICAgICAgICB2YXIgc3NsID0gcGFyYW1zLnNzbCA9PT0gXCJ0cnVlXCI7XG4gICAgICAgIHJldHVybiBjb21wbGV0ZVNpZ25Jbih1bmRlZmluZWQsIHtcbiAgICAgICAgICAgIHRva2VuOiB0b2tlbixcbiAgICAgICAgICAgIGV4cGlyZXM6IGV4cGlyZXMsXG4gICAgICAgICAgICBzc2w6IHNzbCxcbiAgICAgICAgICAgIHVzZXJuYW1lOiB1c2VybmFtZSxcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXF1ZXN0IHNlc3Npb24gaW5mb3JtYXRpb24gZnJvbSB0aGUgcGFyZW50IGFwcGxpY2F0aW9uXG4gICAgICpcbiAgICAgKiBXaGVuIGFuIGFwcGxpY2F0aW9uIGlzIGVtYmVkZGVkIGludG8gYW5vdGhlciBhcHBsaWNhdGlvbiB2aWEgYW4gSUZyYW1lLCB0aGUgZW1iZWRkZWQgYXBwIGNhblxuICAgICAqIHVzZSBgd2luZG93LnBvc3RNZXNzYWdlYCB0byByZXF1ZXN0IGNyZWRlbnRpYWxzIGZyb20gdGhlIGhvc3QgYXBwbGljYXRpb24uIFRoaXMgZnVuY3Rpb24gd3JhcHNcbiAgICAgKiB0aGF0IGJlaGF2aW9yLlxuICAgICAqXG4gICAgICogVGhlIEFyY0dJUyBBUEkgZm9yIEphdmFzY3JpcHQgaGFzIHRoaXMgYnVpbHQgaW50byB0aGUgSWRlbnRpdHkgTWFuYWdlciBhcyBvZiB0aGUgNC4xOSByZWxlYXNlLlxuICAgICAqXG4gICAgICogTm90ZTogVGhlIHBhcmVudCBhcHBsaWNhdGlvbiB3aWxsIG5vdCByZXNwb25kIGlmIHRoZSBlbWJlZGRlZCBhcHAncyBvcmlnaW4gaXMgbm90OlxuICAgICAqIC0gdGhlIHNhbWUgb3JpZ2luIGFzIHRoZSBwYXJlbnQgb3IgKi5hcmNnaXMuY29tIChKU0FQSSlcbiAgICAgKiAtIGluIHRoZSBsaXN0IG9mIHZhbGlkIGNoaWxkIG9yaWdpbnMgKFJFU1QtSlMpXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSBwYXJlbnRPcmlnaW4gb3JpZ2luIG9mIHRoZSBwYXJlbnQgZnJhbWUuIFBhc3NlZCBpbnRvIHRoZSBlbWJlZGRlZCBhcHBsaWNhdGlvbiBhcyBgcGFyZW50T3JpZ2luYCBxdWVyeSBwYXJhbVxuICAgICAqIEBicm93c2VyT25seVxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmZyb21QYXJlbnQgPSBmdW5jdGlvbiAocGFyZW50T3JpZ2luLCB3aW4pIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQ6IG11c3QgcGFzcyBpbiBhIG1vY2t3aW5kb3cgZm9yIHRlc3RzIHNvIHdlIGNhbid0IGNvdmVyIHRoZSBvdGhlciBicmFuY2ggKi9cbiAgICAgICAgaWYgKCF3aW4gJiYgd2luZG93KSB7XG4gICAgICAgICAgICB3aW4gPSB3aW5kb3c7XG4gICAgICAgIH1cbiAgICAgICAgLy8gRGVjbGFyZSBoYW5kbGVyIG91dHNpZGUgb2YgcHJvbWlzZSBzY29wZSBzbyB3ZSBjYW4gZGV0YWNoIGl0XG4gICAgICAgIHZhciBoYW5kbGVyO1xuICAgICAgICAvLyByZXR1cm4gYSBwcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdoZW4gdGhlIGhhbmRsZXIgcmVjZWl2ZXNcbiAgICAgICAgLy8gc2Vzc2lvbiBpbmZvcm1hdGlvbiBmcm9tIHRoZSBjb3JyZWN0IG9yaWdpblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgLy8gY3JlYXRlIGFuIGV2ZW50IGhhbmRsZXIgdGhhdCBqdXN0IHdyYXBzIHRoZSBwYXJlbnRNZXNzYWdlSGFuZGxlclxuICAgICAgICAgICAgaGFuZGxlciA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICAgICAgICAgIC8vIGVuc3VyZSB3ZSBvbmx5IGxpc3RlbiB0byBldmVudHMgZnJvbSB0aGUgcGFyZW50XG4gICAgICAgICAgICAgICAgaWYgKGV2ZW50LnNvdXJjZSA9PT0gd2luLnBhcmVudCAmJiBldmVudC5kYXRhKSB7XG4gICAgICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzb2x2ZShVc2VyU2Vzc2lvbi5wYXJlbnRNZXNzYWdlSGFuZGxlcihldmVudCkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICAvLyBhZGQgbGlzdGVuZXJcbiAgICAgICAgICAgIHdpbi5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCBoYW5kbGVyLCBmYWxzZSk7XG4gICAgICAgICAgICB3aW4ucGFyZW50LnBvc3RNZXNzYWdlKHsgdHlwZTogXCJhcmNnaXM6YXV0aDpyZXF1ZXN0Q3JlZGVudGlhbFwiIH0sIHBhcmVudE9yaWdpbik7XG4gICAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHNlc3Npb24pIHtcbiAgICAgICAgICAgIHdpbi5yZW1vdmVFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCBoYW5kbGVyLCBmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm4gc2Vzc2lvbjtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBCZWdpbnMgYSBuZXcgc2VydmVyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluLiBUaGlzIHdpbGwgcmVkaXJlY3QgdGhlIHVzZXIgdG9cbiAgICAgKiB0aGUgQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZSBhdXRob3JpemF0aW9uIHBhZ2UuXG4gICAgICpcbiAgICAgKiBAbm9kZU9ubHlcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5hdXRob3JpemUgPSBmdW5jdGlvbiAob3B0aW9ucywgcmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKG9wdGlvbnMuZHVyYXRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiREVQUkVDQVRFRDogJ2R1cmF0aW9uJyBpcyBkZXByZWNhdGVkIC0gdXNlICdleHBpcmF0aW9uJyBpbnN0ZWFkXCIpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHsgcG9ydGFsOiBcImh0dHBzOi8vYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIiwgZXhwaXJhdGlvbjogMjAxNjAgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgZXhwaXJhdGlvbiA9IF9hLmV4cGlyYXRpb24sIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmk7XG4gICAgICAgIHJlc3BvbnNlLndyaXRlSGVhZCgzMDEsIHtcbiAgICAgICAgICAgIExvY2F0aW9uOiBwb3J0YWwgKyBcIi9vYXV0aDIvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImZXhwaXJhdGlvbj1cIiArIChvcHRpb25zLmR1cmF0aW9uIHx8IGV4cGlyYXRpb24pICsgXCImcmVzcG9uc2VfdHlwZT1jb2RlJnJlZGlyZWN0X3VyaT1cIiArIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSksXG4gICAgICAgIH0pO1xuICAgICAgICByZXNwb25zZS5lbmQoKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIENvbXBsZXRlcyB0aGUgc2VydmVyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluIHByb2Nlc3MgYnkgZXhjaGFuZ2luZyB0aGUgYGF1dGhvcml6YXRpb25Db2RlYFxuICAgICAqIGZvciBhIGBhY2Nlc3NfdG9rZW5gLlxuICAgICAqXG4gICAgICogQG5vZGVPbmx5XG4gICAgICovXG4gICAgVXNlclNlc3Npb24uZXhjaGFuZ2VBdXRob3JpemF0aW9uQ29kZSA9IGZ1bmN0aW9uIChvcHRpb25zLCBhdXRob3JpemF0aW9uQ29kZSkge1xuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7XG4gICAgICAgICAgICBwb3J0YWw6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogMjAxNjAsXG4gICAgICAgIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmksIHJlZnJlc2hUb2tlblRUTCA9IF9hLnJlZnJlc2hUb2tlblRUTDtcbiAgICAgICAgcmV0dXJuIGZldGNoVG9rZW4ocG9ydGFsICsgXCIvb2F1dGgyL3Rva2VuXCIsIHtcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGdyYW50X3R5cGU6IFwiYXV0aG9yaXphdGlvbl9jb2RlXCIsXG4gICAgICAgICAgICAgICAgY2xpZW50X2lkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICByZWRpcmVjdF91cmk6IHJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgICAgIGNvZGU6IGF1dGhvcml6YXRpb25Db2RlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgICAgIGNsaWVudElkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICBzc2w6IHJlc3BvbnNlLnNzbCxcbiAgICAgICAgICAgICAgICByZWRpcmVjdFVyaTogcmVkaXJlY3RVcmksXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuOiByZXNwb25zZS5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiByZWZyZXNoVG9rZW5UVEwsXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogbmV3IERhdGUoRGF0ZS5ub3coKSArIChyZWZyZXNoVG9rZW5UVEwgLSAxKSAqIDYwICogMTAwMCksXG4gICAgICAgICAgICAgICAgdG9rZW46IHJlc3BvbnNlLnRva2VuLFxuICAgICAgICAgICAgICAgIHRva2VuRXhwaXJlczogcmVzcG9uc2UuZXhwaXJlcyxcbiAgICAgICAgICAgICAgICB1c2VybmFtZTogcmVzcG9uc2UudXNlcm5hbWUsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBVc2VyU2Vzc2lvbi5kZXNlcmlhbGl6ZSA9IGZ1bmN0aW9uIChzdHIpIHtcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBKU09OLnBhcnNlKHN0cik7XG4gICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgY2xpZW50SWQ6IG9wdGlvbnMuY2xpZW50SWQsXG4gICAgICAgICAgICByZWZyZXNoVG9rZW46IG9wdGlvbnMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogbmV3IERhdGUob3B0aW9ucy5yZWZyZXNoVG9rZW5FeHBpcmVzKSxcbiAgICAgICAgICAgIHVzZXJuYW1lOiBvcHRpb25zLnVzZXJuYW1lLFxuICAgICAgICAgICAgcGFzc3dvcmQ6IG9wdGlvbnMucGFzc3dvcmQsXG4gICAgICAgICAgICB0b2tlbjogb3B0aW9ucy50b2tlbixcbiAgICAgICAgICAgIHRva2VuRXhwaXJlczogbmV3IERhdGUob3B0aW9ucy50b2tlbkV4cGlyZXMpLFxuICAgICAgICAgICAgcG9ydGFsOiBvcHRpb25zLnBvcnRhbCxcbiAgICAgICAgICAgIHNzbDogb3B0aW9ucy5zc2wsXG4gICAgICAgICAgICB0b2tlbkR1cmF0aW9uOiBvcHRpb25zLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICByZWRpcmVjdFVyaTogb3B0aW9ucy5yZWRpcmVjdFVyaSxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogb3B0aW9ucy5yZWZyZXNoVG9rZW5UVEwsXG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogVHJhbnNsYXRlcyBhdXRoZW50aWNhdGlvbiBmcm9tIHRoZSBmb3JtYXQgdXNlZCBpbiB0aGUgW0FyY0dJUyBBUEkgZm9yIEphdmFTY3JpcHRdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL2phdmFzY3JpcHQvKS5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwoe1xuICAgICAqICAgdXNlcklkOiBcImpzbWl0aFwiLFxuICAgICAqICAgdG9rZW46IFwic2VjcmV0XCJcbiAgICAgKiB9KTtcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEByZXR1cm5zIFVzZXJTZXNzaW9uXG4gICAgICovXG4gICAgVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwgPSBmdW5jdGlvbiAoY3JlZGVudGlhbCkge1xuICAgICAgICAvLyBBdCBBcmNHSVMgT25saW5lIDkuMSwgY3JlZGVudGlhbHMgbm8gbG9uZ2VyIGluY2x1ZGUgdGhlIHNzbCBhbmQgZXhwaXJlcyBwcm9wZXJ0aWVzXG4gICAgICAgIC8vIEhlcmUsIHdlIHByb3ZpZGUgZGVmYXVsdCB2YWx1ZXMgZm9yIHRoZW0gdG8gY292ZXIgdGhpcyBjb25kaXRpb25cbiAgICAgICAgdmFyIHNzbCA9IHR5cGVvZiBjcmVkZW50aWFsLnNzbCAhPT0gXCJ1bmRlZmluZWRcIiA/IGNyZWRlbnRpYWwuc3NsIDogdHJ1ZTtcbiAgICAgICAgdmFyIGV4cGlyZXMgPSBjcmVkZW50aWFsLmV4cGlyZXMgfHwgRGF0ZS5ub3coKSArIDcyMDAwMDA7IC8qIDIgaG91cnMgKi9cbiAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICBwb3J0YWw6IGNyZWRlbnRpYWwuc2VydmVyLmluY2x1ZGVzKFwic2hhcmluZy9yZXN0XCIpXG4gICAgICAgICAgICAgICAgPyBjcmVkZW50aWFsLnNlcnZlclxuICAgICAgICAgICAgICAgIDogY3JlZGVudGlhbC5zZXJ2ZXIgKyBcIi9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHNzbDogc3NsLFxuICAgICAgICAgICAgdG9rZW46IGNyZWRlbnRpYWwudG9rZW4sXG4gICAgICAgICAgICB1c2VybmFtZTogY3JlZGVudGlhbC51c2VySWQsXG4gICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG5ldyBEYXRlKGV4cGlyZXMpLFxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEhhbmRsZSB0aGUgcmVzcG9uc2UgZnJvbSB0aGUgcGFyZW50XG4gICAgICogQHBhcmFtIGV2ZW50IERPTSBFdmVudFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnBhcmVudE1lc3NhZ2VIYW5kbGVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIGlmIChldmVudC5kYXRhLnR5cGUgPT09IFwiYXJjZ2lzOmF1dGg6Y3JlZGVudGlhbFwiKSB7XG4gICAgICAgICAgICByZXR1cm4gVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwoZXZlbnQuZGF0YS5jcmVkZW50aWFsKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZXZlbnQuZGF0YS50eXBlID09PSBcImFyY2dpczphdXRoOmVycm9yXCIpIHtcbiAgICAgICAgICAgIHZhciBlcnIgPSBuZXcgRXJyb3IoZXZlbnQuZGF0YS5lcnJvci5tZXNzYWdlKTtcbiAgICAgICAgICAgIGVyci5uYW1lID0gZXZlbnQuZGF0YS5lcnJvci5uYW1lO1xuICAgICAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiVW5rbm93biBtZXNzYWdlIHR5cGUuXCIpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGF1dGhlbnRpY2F0aW9uIGluIGEgZm9ybWF0IHVzZWFibGUgaW4gdGhlIFtBcmNHSVMgQVBJIGZvciBKYXZhU2NyaXB0XShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9qYXZhc2NyaXB0LykuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIGVzcmlJZC5yZWdpc3RlclRva2VuKHNlc3Npb24udG9DcmVkZW50aWFsKCkpO1xuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHJldHVybnMgSUNyZWRlbnRpYWxcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudG9DcmVkZW50aWFsID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgZXhwaXJlczogdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpLFxuICAgICAgICAgICAgc2VydmVyOiB0aGlzLnBvcnRhbCxcbiAgICAgICAgICAgIHNzbDogdGhpcy5zc2wsXG4gICAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICAgIHVzZXJJZDogdGhpcy51c2VybmFtZSxcbiAgICAgICAgfTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgaW5mb3JtYXRpb24gYWJvdXQgdGhlIGN1cnJlbnRseSBsb2dnZWQgaW4gW3VzZXJdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy91c2VyLmh0bSkuIFN1YnNlcXVlbnQgY2FsbHMgd2lsbCAqbm90KiByZXN1bHQgaW4gYWRkaXRpb25hbCB3ZWIgdHJhZmZpYy5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogc2Vzc2lvbi5nZXRVc2VyKClcbiAgICAgKiAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgKiAgICAgY29uc29sZS5sb2cocmVzcG9uc2Uucm9sZSk7IC8vIFwib3JnX2FkbWluXCJcbiAgICAgKiAgIH0pXG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC4gTk9URTogYHJhd1Jlc3BvbnNlYCBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoaXMgb3BlcmF0aW9uLlxuICAgICAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkYXRhIGZyb20gdGhlIHJlc3BvbnNlLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRVc2VyID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3QpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5fdXNlcikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLl91c2VyKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHZhciB1cmwgPSB0aGlzLnBvcnRhbCArIFwiL2NvbW11bml0eS9zZWxmXCI7XG4gICAgICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJHRVRcIiwgYXV0aGVudGljYXRpb246IHRoaXMgfSwgcmVxdWVzdE9wdGlvbnMpLCB7IHJhd1Jlc3BvbnNlOiBmYWxzZSB9KTtcbiAgICAgICAgICAgIHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdCA9IHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIF90aGlzLl91c2VyID0gcmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdCA9IG51bGw7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGluZm9ybWF0aW9uIGFib3V0IHRoZSBjdXJyZW50bHkgbG9nZ2VkIGluIHVzZXIncyBbcG9ydGFsXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvcG9ydGFsLXNlbGYuaHRtKS4gU3Vic2VxdWVudCBjYWxscyB3aWxsICpub3QqIHJlc3VsdCBpbiBhZGRpdGlvbmFsIHdlYiB0cmFmZmljLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBzZXNzaW9uLmdldFBvcnRhbCgpXG4gICAgICogICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICogICAgIGNvbnNvbGUubG9nKHBvcnRhbC5uYW1lKTsgLy8gXCJDaXR5IG9mIC4uLlwiXG4gICAgICogICB9KVxuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuIE5PVEU6IGByYXdSZXNwb25zZWAgaXMgbm90IHN1cHBvcnRlZCBieSB0aGlzIG9wZXJhdGlvbi5cbiAgICAgKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGF0YSBmcm9tIHRoZSByZXNwb25zZS5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0UG9ydGFsID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMuX3BvcnRhbEluZm8pIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy5fcG9ydGFsSW5mbyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB2YXIgdXJsID0gdGhpcy5wb3J0YWwgKyBcIi9wb3J0YWxzL3NlbGZcIjtcbiAgICAgICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIkdFVFwiLCBhdXRoZW50aWNhdGlvbjogdGhpcyB9LCByZXF1ZXN0T3B0aW9ucyksIHsgcmF3UmVzcG9uc2U6IGZhbHNlIH0pO1xuICAgICAgICAgICAgdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3QgPSByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcG9ydGFsSW5mbyA9IHJlc3BvbnNlO1xuICAgICAgICAgICAgICAgIF90aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdCA9IG51bGw7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIHVzZXJuYW1lIGZvciB0aGUgY3VycmVudGx5IGxvZ2dlZCBpbiBbdXNlcl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3VzZXIuaHRtKS4gU3Vic2VxdWVudCBjYWxscyB3aWxsICpub3QqIHJlc3VsdCBpbiBhZGRpdGlvbmFsIHdlYiB0cmFmZmljLiBUaGlzIGlzIGFsc28gdXNlZCBpbnRlcm5hbGx5IHdoZW4gYSB1c2VybmFtZSBpcyByZXF1aXJlZCBmb3Igc29tZSByZXF1ZXN0cyBidXQgaXMgbm90IHByZXNlbnQgaW4gdGhlIG9wdGlvbnMuXG4gICAgICpcbiAgICAgKiAgICAqIGBgYGpzXG4gICAgICogc2Vzc2lvbi5nZXRVc2VybmFtZSgpXG4gICAgICogICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICogICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTsgLy8gXCJjYXNleV9qb25lc1wiXG4gICAgICogICB9KVxuICAgICAqIGBgYFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRVc2VybmFtZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKHRoaXMudXNlcm5hbWUpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy51c2VybmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5fdXNlcikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLl91c2VyLnVzZXJuYW1lKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldFVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHVzZXIudXNlcm5hbWU7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogR2V0cyBhbiBhcHByb3ByaWF0ZSB0b2tlbiBmb3IgdGhlIGdpdmVuIFVSTC4gSWYgYHBvcnRhbGAgaXMgQXJjR0lTIE9ubGluZSBhbmRcbiAgICAgKiB0aGUgcmVxdWVzdCBpcyB0byBhbiBBcmNHSVMgT25saW5lIGRvbWFpbiBgdG9rZW5gIHdpbGwgYmUgdXNlZC4gSWYgdGhlIHJlcXVlc3RcbiAgICAgKiBpcyB0byB0aGUgY3VycmVudCBgcG9ydGFsYCB0aGUgY3VycmVudCBgdG9rZW5gIHdpbGwgYWxzbyBiZSB1c2VkLiBIb3dldmVyIGlmXG4gICAgICogdGhlIHJlcXVlc3QgaXMgdG8gYW4gdW5rbm93biBzZXJ2ZXIgd2Ugd2lsbCB2YWxpZGF0ZSB0aGUgc2VydmVyIHdpdGggYSByZXF1ZXN0XG4gICAgICogdG8gb3VyIGN1cnJlbnQgYHBvcnRhbGAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgaWYgKGNhblVzZU9ubGluZVRva2VuKHRoaXMucG9ydGFsLCB1cmwpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRGcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChuZXcgUmVnRXhwKHRoaXMucG9ydGFsLCBcImlcIikudGVzdCh1cmwpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRGcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldFRva2VuRm9yU2VydmVyKHVybCwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBHZXQgYXBwbGljYXRpb24gYWNjZXNzIGluZm9ybWF0aW9uIGZvciB0aGUgY3VycmVudCB1c2VyXG4gICAgICogc2VlIGB2YWxpZGF0ZUFwcEFjY2Vzc2AgZnVuY3Rpb24gZm9yIGRldGFpbHNcbiAgICAgKlxuICAgICAqIEBwYXJhbSBjbGllbnRJZCBhcHBsaWNhdGlvbiBjbGllbnQgaWRcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudmFsaWRhdGVBcHBBY2Nlc3MgPSBmdW5jdGlvbiAoY2xpZW50SWQpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW4odGhpcy5wb3J0YWwpLnRoZW4oZnVuY3Rpb24gKHRva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gdmFsaWRhdGVBcHBBY2Nlc3ModG9rZW4sIGNsaWVudElkKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudG9KU09OID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgY2xpZW50SWQ6IHRoaXMuY2xpZW50SWQsXG4gICAgICAgICAgICByZWZyZXNoVG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogdGhpcy5yZWZyZXNoVG9rZW5FeHBpcmVzLFxuICAgICAgICAgICAgdXNlcm5hbWU6IHRoaXMudXNlcm5hbWUsXG4gICAgICAgICAgICBwYXNzd29yZDogdGhpcy5wYXNzd29yZCxcbiAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiB0aGlzLnRva2VuRXhwaXJlcyxcbiAgICAgICAgICAgIHBvcnRhbDogdGhpcy5wb3J0YWwsXG4gICAgICAgICAgICBzc2w6IHRoaXMuc3NsLFxuICAgICAgICAgICAgdG9rZW5EdXJhdGlvbjogdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgcmVkaXJlY3RVcmk6IHRoaXMucmVkaXJlY3RVcmksXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IHRoaXMucmVmcmVzaFRva2VuVFRMLFxuICAgICAgICB9O1xuICAgIH07XG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnNlcmlhbGl6ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHRoaXMpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRm9yIGEgXCJIb3N0XCIgYXBwIHRoYXQgZW1iZWRzIG90aGVyIHBsYXRmb3JtIGFwcHMgdmlhIGlmcmFtZXMsIGFmdGVyIGF1dGhlbnRpY2F0aW5nIHRoZSB1c2VyXG4gICAgICogYW5kIGNyZWF0aW5nIGEgVXNlclNlc3Npb24sIHRoZSBhcHAgY2FuIHRoZW4gZW5hYmxlIFwicG9zdCBtZXNzYWdlXCIgc3R5bGUgYXV0aGVudGljYXRpb24gYnkgY2FsbGluZ1xuICAgICAqIHRoaXMgbWV0aG9kLlxuICAgICAqXG4gICAgICogSW50ZXJuYWxseSB0aGlzIGFkZHMgYW4gZXZlbnQgbGlzdGVuZXIgb24gd2luZG93IGZvciB0aGUgYG1lc3NhZ2VgIGV2ZW50XG4gICAgICpcbiAgICAgKiBAcGFyYW0gdmFsaWRDaGlsZE9yaWdpbnMgQXJyYXkgb2Ygb3JpZ2lucyB0aGF0IGFyZSBhbGxvd2VkIHRvIHJlcXVlc3QgYXV0aGVudGljYXRpb24gZnJvbSB0aGUgaG9zdCBhcHBcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZW5hYmxlUG9zdE1lc3NhZ2VBdXRoID0gZnVuY3Rpb24gKHZhbGlkQ2hpbGRPcmlnaW5zLCB3aW4pIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQ6IG11c3QgcGFzcyBpbiBhIG1vY2t3aW5kb3cgZm9yIHRlc3RzIHNvIHdlIGNhbid0IGNvdmVyIHRoZSBvdGhlciBicmFuY2ggKi9cbiAgICAgICAgaWYgKCF3aW4gJiYgd2luZG93KSB7XG4gICAgICAgICAgICB3aW4gPSB3aW5kb3c7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5faG9zdEhhbmRsZXIgPSB0aGlzLmNyZWF0ZVBvc3RNZXNzYWdlSGFuZGxlcih2YWxpZENoaWxkT3JpZ2lucyk7XG4gICAgICAgIHdpbi5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCB0aGlzLl9ob3N0SGFuZGxlciwgZmFsc2UpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRm9yIGEgXCJIb3N0XCIgYXBwIHRoYXQgaGFzIGVtYmVkZGVkIG90aGVyIHBsYXRmb3JtIGFwcHMgdmlhIGlmcmFtZXMsIHdoZW4gdGhlIGhvc3QgbmVlZHNcbiAgICAgKiB0byB0cmFuc2l0aW9uIHJvdXRlcywgaXQgc2hvdWxkIGNhbGwgYFVzZXJTZXNzaW9uLmRpc2FibGVQb3N0TWVzc2FnZUF1dGgoKWAgdG8gcmVtb3ZlXG4gICAgICogdGhlIGV2ZW50IGxpc3RlbmVyIGFuZCBwcmV2ZW50IG1lbW9yeSBsZWFrc1xuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5kaXNhYmxlUG9zdE1lc3NhZ2VBdXRoID0gZnVuY3Rpb24gKHdpbikge1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dDogbXVzdCBwYXNzIGluIGEgbW9ja3dpbmRvdyBmb3IgdGVzdHMgc28gd2UgY2FuJ3QgY292ZXIgdGhlIG90aGVyIGJyYW5jaCAqL1xuICAgICAgICBpZiAoIXdpbiAmJiB3aW5kb3cpIHtcbiAgICAgICAgICAgIHdpbiA9IHdpbmRvdztcbiAgICAgICAgfVxuICAgICAgICB3aW4ucmVtb3ZlRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgdGhpcy5faG9zdEhhbmRsZXIsIGZhbHNlKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIE1hbnVhbGx5IHJlZnJlc2hlcyB0aGUgY3VycmVudCBgdG9rZW5gIGFuZCBgdG9rZW5FeHBpcmVzYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFNlc3Npb24gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgLy8gbWFrZSBzdXJlIHN1YnNlcXVlbnQgY2FsbHMgdG8gZ2V0VXNlcigpIGRvbid0IHJldHVybmVkIGNhY2hlZCBtZXRhZGF0YVxuICAgICAgICB0aGlzLl91c2VyID0gbnVsbDtcbiAgICAgICAgaWYgKHRoaXMudXNlcm5hbWUgJiYgdGhpcy5wYXNzd29yZCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFdpdGhVc2VybmFtZUFuZFBhc3N3b3JkKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5jbGllbnRJZCAmJiB0aGlzLnJlZnJlc2hUb2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFdpdGhSZWZyZXNoVG9rZW4oKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEFyY0dJU0F1dGhFcnJvcihcIlVuYWJsZSB0byByZWZyZXNoIHRva2VuLlwiKSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBEZXRlcm1pbmVzIHRoZSByb290IG9mIHRoZSBBcmNHSVMgU2VydmVyIG9yIFBvcnRhbCBmb3IgYSBnaXZlbiBVUkwuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gdXJsIHRoZSBVUmwgdG8gZGV0ZXJtaW5lIHRoZSByb290IHVybCBmb3IuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFNlcnZlclJvb3RVcmwgPSBmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgIHZhciByb290ID0gY2xlYW5VcmwodXJsKS5zcGxpdCgvXFwvcmVzdChcXC9hZG1pbik/XFwvc2VydmljZXMoPzpcXC98I3xcXD98JCkvKVswXTtcbiAgICAgICAgdmFyIF9hID0gcm9vdC5tYXRjaCgvKGh0dHBzPzpcXC9cXC8pKC4rKS8pLCBtYXRjaCA9IF9hWzBdLCBwcm90b2NvbCA9IF9hWzFdLCBkb21haW5BbmRQYXRoID0gX2FbMl07XG4gICAgICAgIHZhciBfYiA9IGRvbWFpbkFuZFBhdGguc3BsaXQoXCIvXCIpLCBkb21haW4gPSBfYlswXSwgcGF0aCA9IF9iLnNsaWNlKDEpO1xuICAgICAgICAvLyBvbmx5IHRoZSBkb21haW4gaXMgbG93ZXJjYXNlZCBiZWNhdXNlIGluIHNvbWUgY2FzZXMgYW4gb3JnIGlkIG1pZ2h0IGJlXG4gICAgICAgIC8vIGluIHRoZSBwYXRoIHdoaWNoIGNhbm5vdCBiZSBsb3dlcmNhc2VkLlxuICAgICAgICByZXR1cm4gXCJcIiArIHByb3RvY29sICsgZG9tYWluLnRvTG93ZXJDYXNlKCkgKyBcIi9cIiArIHBhdGguam9pbihcIi9cIik7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBwcm9wZXIgW2BjcmVkZW50aWFsc2BdIG9wdGlvbiBmb3IgYGZldGNoYCBmb3IgYSBnaXZlbiBkb21haW4uXG4gICAgICogU2VlIFt0cnVzdGVkIHNlcnZlcl0oaHR0cHM6Ly9lbnRlcnByaXNlLmFyY2dpcy5jb20vZW4vcG9ydGFsL2xhdGVzdC9hZG1pbmlzdGVyL3dpbmRvd3MvY29uZmlndXJlLXNlY3VyaXR5Lmh0bSNFU1JJX1NFQ1RJT04xXzcwQ0MxNTlCMzU0MDQ0MEFCMzI1QkU1RDg5REJFOTRBKS5cbiAgICAgKiBVc2VkIGludGVybmFsbHkgYnkgdW5kZXJseWluZyByZXF1ZXN0IG1ldGhvZHMgdG8gYWRkIHN1cHBvcnQgZm9yIHNwZWNpZmljIHNlY3VyaXR5IGNvbnNpZGVyYXRpb25zLlxuICAgICAqXG4gICAgICogQHBhcmFtIHVybCBUaGUgdXJsIG9mIHRoZSByZXF1ZXN0XG4gICAgICogQHJldHVybnMgXCJpbmNsdWRlXCIgb3IgXCJzYW1lLW9yaWdpblwiXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldERvbWFpbkNyZWRlbnRpYWxzID0gZnVuY3Rpb24gKHVybCkge1xuICAgICAgICBpZiAoIXRoaXMudHJ1c3RlZERvbWFpbnMgfHwgIXRoaXMudHJ1c3RlZERvbWFpbnMubGVuZ3RoKSB7XG4gICAgICAgICAgICByZXR1cm4gXCJzYW1lLW9yaWdpblwiO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLnRydXN0ZWREb21haW5zLnNvbWUoZnVuY3Rpb24gKGRvbWFpbldpdGhQcm90b2NvbCkge1xuICAgICAgICAgICAgcmV0dXJuIHVybC5zdGFydHNXaXRoKGRvbWFpbldpdGhQcm90b2NvbCk7XG4gICAgICAgIH0pXG4gICAgICAgICAgICA/IFwiaW5jbHVkZVwiXG4gICAgICAgICAgICA6IFwic2FtZS1vcmlnaW5cIjtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybiBhIGZ1bmN0aW9uIHRoYXQgY2xvc2VzIG92ZXIgdGhlIHZhbGlkT3JpZ2lucyBhcnJheSBhbmRcbiAgICAgKiBjYW4gYmUgdXNlZCBhcyBhbiBldmVudCBoYW5kbGVyIGZvciB0aGUgYG1lc3NhZ2VgIGV2ZW50XG4gICAgICpcbiAgICAgKiBAcGFyYW0gdmFsaWRPcmlnaW5zIEFycmF5IG9mIHZhbGlkIG9yaWdpbnNcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuY3JlYXRlUG9zdE1lc3NhZ2VIYW5kbGVyID0gZnVuY3Rpb24gKHZhbGlkT3JpZ2lucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAvLyByZXR1cm4gYSBmdW5jdGlvbiB0aGF0IGNsb3NlcyBvdmVyIHRoZSB2YWxpZE9yaWdpbnMgYW5kXG4gICAgICAgIC8vIGhhcyBhY2Nlc3MgdG8gdGhlIGNyZWRlbnRpYWxcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICAgICAgLy8gVmVyaWZ5IHRoYXQgdGhlIG9yaWdpbiBpcyB2YWxpZFxuICAgICAgICAgICAgLy8gTm90ZTogZG8gbm90IHVzZSByZWdleCdzIGhlcmUuIHZhbGlkT3JpZ2lucyBpcyBhbiBhcnJheSBzbyB3ZSdyZSBjaGVja2luZyB0aGF0IHRoZSBldmVudCdzIG9yaWdpblxuICAgICAgICAgICAgLy8gaXMgaW4gdGhlIGFycmF5IHZpYSBleGFjdCBtYXRjaC4gTW9yZSBpbmZvIGFib3V0IGF2b2lkaW5nIHBvc3RNZXNzYWdlIHhzcyBpc3N1ZXMgaGVyZVxuICAgICAgICAgICAgLy8gaHR0cHM6Ly9qbGFqYXJhLmdpdGxhYi5pby93ZWIvMjAyMC8wNy8xNy9Eb21fWFNTX1Bvc3RNZXNzYWdlXzIuaHRtbCN0aXBzYnlwYXNzZXMtaW4tcG9zdG1lc3NhZ2UtdnVsbmVyYWJpbGl0aWVzXG4gICAgICAgICAgICB2YXIgaXNWYWxpZE9yaWdpbiA9IHZhbGlkT3JpZ2lucy5pbmRleE9mKGV2ZW50Lm9yaWdpbikgPiAtMTtcbiAgICAgICAgICAgIC8vIEpTQVBJIGhhbmRsZXMgdGhpcyBzbGlnaHRseSBkaWZmZXJlbnRseSAtIGluc3RlYWQgb2YgY2hlY2tpbmcgYSBsaXN0LCBpdCB3aWxsIHJlc3BvbmQgaWZcbiAgICAgICAgICAgIC8vIGV2ZW50Lm9yaWdpbiA9PT0gd2luZG93LmxvY2F0aW9uLm9yaWdpbiB8fCBldmVudC5vcmlnaW4uZW5kc1dpdGgoJy5hcmNnaXMuY29tJylcbiAgICAgICAgICAgIC8vIEZvciBIdWIsIGFuZCB0byBlbmFibGUgY3Jvc3MgZG9tYWluIGRlYnVnZ2luZyB3aXRoIHBvcnQncyBpbiB1cmxzLCB3ZSBhcmUgb3B0aW5nIHRvXG4gICAgICAgICAgICAvLyB1c2UgYSBsaXN0IG9mIHZhbGlkIG9yaWdpbnNcbiAgICAgICAgICAgIC8vIEVuc3VyZSB0aGUgbWVzc2FnZSB0eXBlIGlzIHNvbWV0aGluZyB3ZSB3YW50IHRvIGhhbmRsZVxuICAgICAgICAgICAgdmFyIGlzVmFsaWRUeXBlID0gZXZlbnQuZGF0YS50eXBlID09PSBcImFyY2dpczphdXRoOnJlcXVlc3RDcmVkZW50aWFsXCI7XG4gICAgICAgICAgICB2YXIgaXNUb2tlblZhbGlkID0gX3RoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCk7XG4gICAgICAgICAgICBpZiAoaXNWYWxpZE9yaWdpbiAmJiBpc1ZhbGlkVHlwZSkge1xuICAgICAgICAgICAgICAgIHZhciBtc2cgPSB7fTtcbiAgICAgICAgICAgICAgICBpZiAoaXNUb2tlblZhbGlkKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjcmVkZW50aWFsID0gX3RoaXMudG9DcmVkZW50aWFsKCk7XG4gICAgICAgICAgICAgICAgICAgIC8vIGFyY2dpczphdXRoOmVycm9yIHdpdGgge25hbWU6IFwiXCIsIG1lc3NhZ2U6IFwiXCJ9XG4gICAgICAgICAgICAgICAgICAgIC8vIHRoZSBmb2xsb3dpbmcgbGluZSBhbGxvd3MgdXMgdG8gY29uZm9ybSB0byBvdXIgc3BlYyB3aXRob3V0IGNoYW5naW5nIG90aGVyIGRlcGVuZGVkLW9uIGZ1bmN0aW9uYWxpdHlcbiAgICAgICAgICAgICAgICAgICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvYmxvYi9tYXN0ZXIvcGFja2FnZXMvYXJjZ2lzLXJlc3QtYXV0aC9wb3N0LW1lc3NhZ2UtYXV0aC1zcGVjLm1kI2FyY2dpc2F1dGhjcmVkZW50aWFsXG4gICAgICAgICAgICAgICAgICAgIGNyZWRlbnRpYWwuc2VydmVyID0gY3JlZGVudGlhbC5zZXJ2ZXIucmVwbGFjZShcIi9zaGFyaW5nL3Jlc3RcIiwgXCJcIik7XG4gICAgICAgICAgICAgICAgICAgIG1zZyA9IHsgdHlwZTogXCJhcmNnaXM6YXV0aDpjcmVkZW50aWFsXCIsIGNyZWRlbnRpYWw6IGNyZWRlbnRpYWwgfTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFJldHVybiBhbiBlcnJvclxuICAgICAgICAgICAgICAgICAgICBtc2cgPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0eXBlOiBcImFyY2dpczphdXRoOmVycm9yXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICBlcnJvcjoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5hbWU6IFwidG9rZW5FeHBpcmVkRXJyb3JcIixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBtZXNzYWdlOiBcIlNlc3Npb24gdG9rZW4gd2FzIGV4cGlyZWQsIGFuZCBub3QgcmV0dXJuZWQgdG8gdGhlIGNoaWxkIGFwcGxpY2F0aW9uXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBldmVudC5zb3VyY2UucG9zdE1lc3NhZ2UobXNnLCBldmVudC5vcmlnaW4pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgIH07XG4gICAgLyoqXG4gICAgICogVmFsaWRhdGVzIHRoYXQgYSBnaXZlbiBVUkwgaXMgcHJvcGVybHkgZmVkZXJhdGVkIHdpdGggb3VyIGN1cnJlbnQgYHBvcnRhbGAuXG4gICAgICogQXR0ZW1wdHMgdG8gdXNlIHRoZSBpbnRlcm5hbCBgZmVkZXJhdGVkU2VydmVyc2AgY2FjaGUgZmlyc3QuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFRva2VuRm9yU2VydmVyID0gZnVuY3Rpb24gKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgLy8gcmVxdWVzdHMgdG8gL3Jlc3Qvc2VydmljZXMvIGFuZCAvcmVzdC9hZG1pbi9zZXJ2aWNlcy8gYXJlIGJvdGggdmFsaWRcbiAgICAgICAgLy8gRmVkZXJhdGVkIHNlcnZlcnMgbWF5IGhhdmUgaW5jb25zaXN0ZW50IGNhc2luZywgc28gbG93ZXJDYXNlIGl0XG4gICAgICAgIHZhciByb290ID0gdGhpcy5nZXRTZXJ2ZXJSb290VXJsKHVybCk7XG4gICAgICAgIHZhciBleGlzdGluZ1Rva2VuID0gdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdO1xuICAgICAgICBpZiAoZXhpc3RpbmdUb2tlbiAmJlxuICAgICAgICAgICAgZXhpc3RpbmdUb2tlbi5leHBpcmVzICYmXG4gICAgICAgICAgICBleGlzdGluZ1Rva2VuLmV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShleGlzdGluZ1Rva2VuLnRva2VuKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF0pIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XSA9IHRoaXMuZmV0Y2hBdXRob3JpemVkRG9tYWlucygpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHJlcXVlc3Qocm9vdCArIFwiL3Jlc3QvaW5mb1wiLCB7XG4gICAgICAgICAgICAgICAgY3JlZGVudGlhbHM6IF90aGlzLmdldERvbWFpbkNyZWRlbnRpYWxzKHVybCksXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZS5vd25pbmdTeXN0ZW1VcmwpIHtcbiAgICAgICAgICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgICAgICAgICAqIGlmIHRoaXMgc2VydmVyIGlzIG5vdCBvd25lZCBieSB0aGlzIHBvcnRhbFxuICAgICAgICAgICAgICAgICAgICAgKiBiYWlsIG91dCB3aXRoIGFuIGVycm9yIHNpbmNlIHdlIGtub3cgd2Ugd29udFxuICAgICAgICAgICAgICAgICAgICAgKiBiZSBhYmxlIHRvIGdlbmVyYXRlIGEgdG9rZW5cbiAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgIGlmICghaXNGZWRlcmF0ZWQocmVzcG9uc2Uub3duaW5nU3lzdGVtVXJsLCBfdGhpcy5wb3J0YWwpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKHVybCArIFwiIGlzIG5vdCBmZWRlcmF0ZWQgd2l0aCBcIiArIF90aGlzLnBvcnRhbCArIFwiLlwiLCBcIk5PVF9GRURFUkFURURcIik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAgICAgICAgICAgICAqIGlmIHRoZSBzZXJ2ZXIgaXMgZmVkZXJhdGVkLCB1c2UgdGhlIHJlbGV2YW50IHRva2VuIGVuZHBvaW50LlxuICAgICAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVxdWVzdChyZXNwb25zZS5vd25pbmdTeXN0ZW1VcmwgKyBcIi9zaGFyaW5nL3Jlc3QvaW5mb1wiLCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAocmVzcG9uc2UuYXV0aEluZm8gJiZcbiAgICAgICAgICAgICAgICAgICAgX3RoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICAgICAgICAgKiBpZiBpdHMgYSBzdGFuZC1hbG9uZSBpbnN0YW5jZSBvZiBBcmNHSVMgU2VydmVyIHRoYXQgZG9lc24ndCBhZHZlcnRpc2VcbiAgICAgICAgICAgICAgICAgICAgICogZmVkZXJhdGlvbiwgYnV0IHRoZSByb290IHNlcnZlciB1cmwgaXMgcmVjb2duaXplZCwgdXNlIGl0cyBidWlsdCBpbiB0b2tlbiBlbmRwb2ludC5cbiAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoe1xuICAgICAgICAgICAgICAgICAgICAgICAgYXV0aEluZm86IHJlc3BvbnNlLmF1dGhJbmZvLFxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IodXJsICsgXCIgaXMgbm90IGZlZGVyYXRlZCB3aXRoIGFueSBwb3J0YWwgYW5kIGlzIG5vdCBleHBsaWNpdGx5IHRydXN0ZWQuXCIsIFwiTk9UX0ZFREVSQVRFRFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5hdXRoSW5mby50b2tlblNlcnZpY2VzVXJsO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAodG9rZW5TZXJ2aWNlc1VybCkge1xuICAgICAgICAgICAgICAgIC8vIGFuIGV4cGlyZWQgdG9rZW4gY2FudCBiZSB1c2VkIHRvIGdlbmVyYXRlIGEgbmV3IHRva2VuXG4gICAgICAgICAgICAgICAgaWYgKF90aGlzLnRva2VuICYmIF90aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBnZW5lcmF0ZVRva2VuKHRva2VuU2VydmljZXNVcmwsIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuOiBfdGhpcy50b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXJ2ZXJVcmw6IHVybCxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBleHBpcmF0aW9uOiBfdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaWVudDogXCJyZWZlcmVyXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgLy8gZ2VuZXJhdGUgYW4gZW50aXJlbHkgZnJlc2ggdG9rZW4gaWYgbmVjZXNzYXJ5XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZ2VuZXJhdGVUb2tlbih0b2tlblNlcnZpY2VzVXJsLCB7XG4gICAgICAgICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1c2VybmFtZTogX3RoaXMudXNlcm5hbWUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzc3dvcmQ6IF90aGlzLnBhc3N3b3JkLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4cGlyYXRpb246IF90aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50OiBcInJlZmVyZXJcIixcbiAgICAgICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdID0ge1xuICAgICAgICAgICAgICAgICAgICBleHBpcmVzOiBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKSxcbiAgICAgICAgICAgICAgICAgICAgdG9rZW46IHJlc3BvbnNlLnRva2VuLFxuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgZGVsZXRlIF90aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgYW4gdW5leHBpcmVkIHRva2VuIGZvciB0aGUgY3VycmVudCBgcG9ydGFsYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0RnJlc2hUb2tlbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy50b2tlbiAmJiAhdGhpcy50b2tlbkV4cGlyZXMpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy50b2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMudG9rZW4gJiZcbiAgICAgICAgICAgIHRoaXMudG9rZW5FeHBpcmVzICYmXG4gICAgICAgICAgICB0aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMudG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbdGhpcy5wb3J0YWxdKSB7XG4gICAgICAgICAgICB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1t0aGlzLnBvcnRhbF0gPSB0aGlzLnJlZnJlc2hTZXNzaW9uKHJlcXVlc3RPcHRpb25zKS50aGVuKGZ1bmN0aW9uIChzZXNzaW9uKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW190aGlzLnBvcnRhbF0gPSBudWxsO1xuICAgICAgICAgICAgICAgIHJldHVybiBzZXNzaW9uLnRva2VuO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3RoaXMucG9ydGFsXTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJlZnJlc2hlcyB0aGUgY3VycmVudCBgdG9rZW5gIGFuZCBgdG9rZW5FeHBpcmVzYCB3aXRoIGB1c2VybmFtZWAgYW5kXG4gICAgICogYHBhc3N3b3JkYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFdpdGhVc2VybmFtZUFuZFBhc3N3b3JkID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICB1c2VybmFtZTogdGhpcy51c2VybmFtZSxcbiAgICAgICAgICAgICAgICBwYXNzd29yZDogdGhpcy5wYXNzd29yZCxcbiAgICAgICAgICAgICAgICBleHBpcmF0aW9uOiB0aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICB9IH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIGdlbmVyYXRlVG9rZW4odGhpcy5wb3J0YWwgKyBcIi9nZW5lcmF0ZVRva2VuXCIsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKTtcbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZWZyZXNoZXMgdGhlIGN1cnJlbnQgYHRva2VuYCBhbmQgYHRva2VuRXhwaXJlc2Agd2l0aCBgcmVmcmVzaFRva2VuYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFdpdGhSZWZyZXNoVG9rZW4gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMucmVmcmVzaFRva2VuICYmXG4gICAgICAgICAgICB0aGlzLnJlZnJlc2hUb2tlbkV4cGlyZXMgJiZcbiAgICAgICAgICAgIHRoaXMucmVmcmVzaFRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPCBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5yZWZyZXNoUmVmcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgY2xpZW50X2lkOiB0aGlzLmNsaWVudElkLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgICAgIGdyYW50X3R5cGU6IFwicmVmcmVzaF90b2tlblwiLFxuICAgICAgICAgICAgfSB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBmZXRjaFRva2VuKHRoaXMucG9ydGFsICsgXCIvb2F1dGgyL3Rva2VuXCIsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSByZXNwb25zZS5leHBpcmVzO1xuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEV4Y2hhbmdlcyBhbiB1bmV4cGlyZWQgYHJlZnJlc2hUb2tlbmAgZm9yIGEgbmV3IG9uZSwgYWxzbyB1cGRhdGVzIGB0b2tlbmAgYW5kXG4gICAgICogYHRva2VuRXhwaXJlc2AuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hSZWZyZXNoVG9rZW4gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGNsaWVudF9pZDogdGhpcy5jbGllbnRJZCxcbiAgICAgICAgICAgICAgICByZWZyZXNoX3Rva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgICAgICByZWRpcmVjdF91cmk6IHRoaXMucmVkaXJlY3RVcmksXG4gICAgICAgICAgICAgICAgZ3JhbnRfdHlwZTogXCJleGNoYW5nZV9yZWZyZXNoX3Rva2VuXCIsXG4gICAgICAgICAgICB9IH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIGZldGNoVG9rZW4odGhpcy5wb3J0YWwgKyBcIi9vYXV0aDIvdG9rZW5cIiwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IHJlc3BvbnNlLmV4cGlyZXM7XG4gICAgICAgICAgICBfdGhpcy5fcmVmcmVzaFRva2VuID0gcmVzcG9uc2UucmVmcmVzaFRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3JlZnJlc2hUb2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgKF90aGlzLnJlZnJlc2hUb2tlblRUTCAtIDEpICogNjAgKiAxMDAwKTtcbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBlbnN1cmVzIHRoYXQgdGhlIGF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnMgYXJlIG9idGFpbmVkIGZyb20gdGhlIHBvcnRhbCBhbmQgY2FjaGVkXG4gICAgICogc28gd2UgY2FuIGNoZWNrIHRoZW0gbGF0ZXIuXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB0aGlzXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmZldGNoQXV0aG9yaXplZERvbWFpbnMgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIC8vIGlmIHRoaXMgdG9rZW4gaXMgZm9yIGEgc3BlY2lmaWMgc2VydmVyIG9yIHdlIGRvbid0IGhhdmUgYSBwb3J0YWxcbiAgICAgICAgLy8gZG9uJ3QgZ2V0IHRoZSBwb3J0YWwgaW5mbyBiZWNhdXNlIHdlIGNhbnQgZ2V0IHRoZSBhdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zXG4gICAgICAgIGlmICh0aGlzLnNlcnZlciB8fCAhdGhpcy5wb3J0YWwpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcyk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0UG9ydGFsKCkudGhlbihmdW5jdGlvbiAocG9ydGFsSW5mbykge1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBTcGVjaWZpYyBkb21haW5zIGNhbiBiZSBjb25maWd1cmVkIGFzIHNlY3VyZS5lc3JpLmNvbSBvciBodHRwczovL3NlY3VyZS5lc3JpLmNvbSB0aGlzXG4gICAgICAgICAgICAgKiBub3JtYWxpemVzIHRvIGh0dHBzOi8vc2VjdXJlLmVzcmkuY29tIHNvIHdlIGNhbiB1c2Ugc3RhcnRzV2l0aCBsYXRlci5cbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgaWYgKHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWlucyAmJlxuICAgICAgICAgICAgICAgIHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWlucy5sZW5ndGgpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy50cnVzdGVkRG9tYWlucyA9IHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWluc1xuICAgICAgICAgICAgICAgICAgICAuZmlsdGVyKGZ1bmN0aW9uIChkKSB7IHJldHVybiAhZC5zdGFydHNXaXRoKFwiaHR0cDovL1wiKTsgfSlcbiAgICAgICAgICAgICAgICAgICAgLm1hcChmdW5jdGlvbiAoZCkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZC5zdGFydHNXaXRoKFwiaHR0cHM6Ly9cIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly9cIiArIGQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICByZXR1cm4gVXNlclNlc3Npb247XG59KCkpO1xuZXhwb3J0IHsgVXNlclNlc3Npb24gfTtcbi8vIyBzb3VyY2VNYXBwaW5nVVJMPVVzZXJTZXNzaW9uLmpzLm1hcCIsImltcG9ydCB7IGNsZWFuVXJsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogVXNlZCB0byB0ZXN0IGlmIGEgVVJMIGlzIGFuIEFyY0dJUyBPbmxpbmUgVVJMXG4gKi9cbnZhciBhcmNnaXNPbmxpbmVVcmxSZWdleCA9IC9eaHR0cHM/OlxcL1xcLyhcXFMrKVxcLmFyY2dpc1xcLmNvbS4rLztcbi8qKlxuICogVXNlZCB0byB0ZXN0IGlmIGEgVVJMIGlzIHByb2R1Y3Rpb24gQXJjR0lTIE9ubGluZSBQb3J0YWxcbiAqL1xudmFyIGFyY2dpc09ubGluZVBvcnRhbFJlZ2V4ID0gL15odHRwcz86XFwvXFwvKGRldnxkZXZleHR8cWF8cWFleHR8d3d3KVxcLmFyY2dpc1xcLmNvbVxcL3NoYXJpbmdcXC9yZXN0Ky87XG4vKipcbiAqIFVzZWQgdG8gdGVzdCBpZiBhIFVSTCBpcyBhbiBBcmNHSVMgT25saW5lIE9yZ2FuaXphdGlvbiBQb3J0YWxcbiAqL1xudmFyIGFyY2dpc09ubGluZU9yZ1BvcnRhbFJlZ2V4ID0gL15odHRwcz86XFwvXFwvKD86W2EtejAtOS1dK1xcLm1hcHMoZGV2fGRldmV4dHxxYXxxYWV4dCk/KT8uYXJjZ2lzXFwuY29tXFwvc2hhcmluZ1xcL3Jlc3QvO1xuZXhwb3J0IGZ1bmN0aW9uIGlzT25saW5lKHVybCkge1xuICAgIHJldHVybiBhcmNnaXNPbmxpbmVVcmxSZWdleC50ZXN0KHVybCk7XG59XG5leHBvcnQgZnVuY3Rpb24gbm9ybWFsaXplT25saW5lUG9ydGFsVXJsKHBvcnRhbFVybCkge1xuICAgIGlmICghYXJjZ2lzT25saW5lVXJsUmVnZXgudGVzdChwb3J0YWxVcmwpKSB7XG4gICAgICAgIHJldHVybiBwb3J0YWxVcmw7XG4gICAgfVxuICAgIHN3aXRjaCAoZ2V0T25saW5lRW52aXJvbm1lbnQocG9ydGFsVXJsKSkge1xuICAgICAgICBjYXNlIFwiZGV2XCI6XG4gICAgICAgICAgICByZXR1cm4gXCJodHRwczovL2RldmV4dC5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgICAgICBjYXNlIFwicWFcIjpcbiAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vcWFleHQuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgfVxufVxuZXhwb3J0IGZ1bmN0aW9uIGdldE9ubGluZUVudmlyb25tZW50KHVybCkge1xuICAgIGlmICghYXJjZ2lzT25saW5lVXJsUmVnZXgudGVzdCh1cmwpKSB7XG4gICAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICB2YXIgbWF0Y2ggPSB1cmwubWF0Y2goYXJjZ2lzT25saW5lVXJsUmVnZXgpO1xuICAgIHZhciBzdWJkb21haW4gPSBtYXRjaFsxXS5zcGxpdChcIi5cIikucG9wKCk7XG4gICAgaWYgKHN1YmRvbWFpbi5pbmNsdWRlcyhcImRldlwiKSkge1xuICAgICAgICByZXR1cm4gXCJkZXZcIjtcbiAgICB9XG4gICAgaWYgKHN1YmRvbWFpbi5pbmNsdWRlcyhcInFhXCIpKSB7XG4gICAgICAgIHJldHVybiBcInFhXCI7XG4gICAgfVxuICAgIHJldHVybiBcInByb2R1Y3Rpb25cIjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBpc0ZlZGVyYXRlZChvd25pbmdTeXN0ZW1VcmwsIHBvcnRhbFVybCkge1xuICAgIHZhciBub3JtYWxpemVkUG9ydGFsVXJsID0gY2xlYW5Vcmwobm9ybWFsaXplT25saW5lUG9ydGFsVXJsKHBvcnRhbFVybCkpLnJlcGxhY2UoL2h0dHBzPzpcXC9cXC8vLCBcIlwiKTtcbiAgICB2YXIgbm9ybWFsaXplZE93bmluZ1N5c3RlbVVybCA9IGNsZWFuVXJsKG93bmluZ1N5c3RlbVVybCkucmVwbGFjZSgvaHR0cHM/OlxcL1xcLy8sIFwiXCIpO1xuICAgIHJldHVybiBuZXcgUmVnRXhwKG5vcm1hbGl6ZWRPd25pbmdTeXN0ZW1VcmwsIFwiaVwiKS50ZXN0KG5vcm1hbGl6ZWRQb3J0YWxVcmwpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGNhblVzZU9ubGluZVRva2VuKHBvcnRhbFVybCwgcmVxdWVzdFVybCkge1xuICAgIHZhciBwb3J0YWxJc09ubGluZSA9IGlzT25saW5lKHBvcnRhbFVybCk7XG4gICAgdmFyIHJlcXVlc3RJc09ubGluZSA9IGlzT25saW5lKHJlcXVlc3RVcmwpO1xuICAgIHZhciBwb3J0YWxFbnYgPSBnZXRPbmxpbmVFbnZpcm9ubWVudChwb3J0YWxVcmwpO1xuICAgIHZhciByZXF1ZXN0RW52ID0gZ2V0T25saW5lRW52aXJvbm1lbnQocmVxdWVzdFVybCk7XG4gICAgaWYgKHBvcnRhbElzT25saW5lICYmIHJlcXVlc3RJc09ubGluZSAmJiBwb3J0YWxFbnYgPT09IHJlcXVlc3RFbnYpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIHJldHVybiBmYWxzZTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWZlZGVyYXRpb24tdXRpbHMuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHJlcXVlc3QgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuZXhwb3J0IGZ1bmN0aW9uIGZldGNoVG9rZW4odXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBvcHRpb25zID0gcmVxdWVzdE9wdGlvbnM7XG4gICAgLy8gd2UgZ2VuZXJhdGUgYSByZXNwb25zZSwgc28gd2UgY2FuJ3QgcmV0dXJuIHRoZSByYXcgcmVzcG9uc2VcbiAgICBvcHRpb25zLnJhd1Jlc3BvbnNlID0gZmFsc2U7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2YXIgciA9IHtcbiAgICAgICAgICAgIHRva2VuOiByZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICB1c2VybmFtZTogcmVzcG9uc2UudXNlcm5hbWUsXG4gICAgICAgICAgICBleHBpcmVzOiBuZXcgRGF0ZShcbiAgICAgICAgICAgIC8vIGNvbnZlcnQgc2Vjb25kcyBpbiByZXNwb25zZSB0byBtaWxsaXNlY29uZHMgYW5kIGFkZCB0aGUgdmFsdWUgdG8gdGhlIGN1cnJlbnQgdGltZSB0byBjYWxjdWxhdGUgYSBzdGF0aWMgZXhwaXJhdGlvbiB0aW1lc3RhbXBcbiAgICAgICAgICAgIERhdGUubm93KCkgKyAocmVzcG9uc2UuZXhwaXJlc19pbiAqIDEwMDAgLSAxMDAwKSksXG4gICAgICAgICAgICBzc2w6IHJlc3BvbnNlLnNzbCA9PT0gdHJ1ZVxuICAgICAgICB9O1xuICAgICAgICBpZiAocmVzcG9uc2UucmVmcmVzaF90b2tlbikge1xuICAgICAgICAgICAgci5yZWZyZXNoVG9rZW4gPSByZXNwb25zZS5yZWZyZXNoX3Rva2VuO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByO1xuICAgIH0pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZmV0Y2gtdG9rZW4uanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcmVxdWVzdCwgTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVIsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbmV4cG9ydCBmdW5jdGlvbiBnZW5lcmF0ZVRva2VuKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgb3B0aW9ucyA9IHJlcXVlc3RPcHRpb25zO1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBlbHNlICovXG4gICAgaWYgKHR5cGVvZiB3aW5kb3cgIT09IFwidW5kZWZpbmVkXCIgJiZcbiAgICAgICAgd2luZG93LmxvY2F0aW9uICYmXG4gICAgICAgIHdpbmRvdy5sb2NhdGlvbi5ob3N0KSB7XG4gICAgICAgIG9wdGlvbnMucGFyYW1zLnJlZmVyZXIgPSB3aW5kb3cubG9jYXRpb24uaG9zdDtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIG9wdGlvbnMucGFyYW1zLnJlZmVyZXIgPSBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUjtcbiAgICB9XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWdlbmVyYXRlLXRva2VuLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxOC0yMDIwIEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHJlcXVlc3QgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBWYWxpZGF0ZXMgdGhhdCB0aGUgdXNlciBoYXMgYWNjZXNzIHRvIHRoZSBhcHBsaWNhdGlvblxuICogYW5kIGlmIHRoZXkgdXNlciBzaG91bGQgYmUgcHJlc2VudGVkIGEgXCJWaWV3IE9ubHlcIiBtb2RlXG4gKlxuICogVGhpcyBpcyBvbmx5IG5lZWRlZC92YWxpZCBmb3IgRXNyaSBhcHBsaWNhdGlvbnMgdGhhdCBhcmUgXCJsaWNlbnNlZFwiXG4gKiBhbmQgc2hpcHBlZCBpbiBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlLiBNb3N0IGN1c3RvbSBhcHBsaWNhdGlvbnNcbiAqIHNob3VsZCBub3QgbmVlZCBvciB1c2UgdGhpcy5cbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgdmFsaWRhdGVBcHBBY2Nlc3MgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1hdXRoJztcbiAqXG4gKiByZXR1cm4gdmFsaWRhdGVBcHBBY2Nlc3MoJ3lvdXItdG9rZW4nLCAndGhlQ2xpZW50SWQnKVxuICogLnRoZW4oKHJlc3VsdCkgPT4ge1xuICogICAgaWYgKCFyZXN1bHQudmFsdWUpIHtcbiAqICAgICAgLy8gcmVkaXJlY3Qgb3Igc2hvdyBzb21lIG90aGVyIHVpXG4gKiAgICB9IGVsc2Uge1xuICogICAgICBpZiAocmVzdWx0LnZpZXdPbmx5VXNlclR5cGVBcHApIHtcbiAqICAgICAgICAvLyB1c2UgdGhpcyB0byBpbmZvcm0geW91ciBhcHAgdG8gc2hvdyBhIFwiVmlldyBPbmx5XCIgbW9kZVxuICogICAgICB9XG4gKiAgICB9XG4gKiB9KVxuICogLmNhdGNoKChlcnIpID0+IHtcbiAqICAvLyB0d28gcG9zc2libGUgZXJyb3JzXG4gKiAgLy8gaW52YWxpZCBjbGllbnRJZDoge1wiZXJyb3JcIjp7XCJjb2RlXCI6NDAwLFwibWVzc2FnZUNvZGVcIjpcIkdXTV8wMDA3XCIsXCJtZXNzYWdlXCI6XCJJbnZhbGlkIHJlcXVlc3RcIixcImRldGFpbHNcIjpbXX19XG4gKiAgLy8gaW52YWxpZCB0b2tlbjoge1wiZXJyb3JcIjp7XCJjb2RlXCI6NDk4LFwibWVzc2FnZVwiOlwiSW52YWxpZCB0b2tlbi5cIixcImRldGFpbHNcIjpbXX19XG4gKiB9KVxuICogYGBgXG4gKlxuICogTm90ZTogVGhpcyBpcyBvbmx5IHVzYWJsZSBieSBFc3JpIGFwcGxpY2F0aW9ucyBob3N0ZWQgb24gKmFyY2dpcy5jb20sICplc3JpLmNvbSBvciB3aXRoaW5cbiAqIGFuIEFyY0dJUyBFbnRlcnByaXNlIGluc3RhbGxhdGlvbi4gQ3VzdG9tIGFwcGxpY2F0aW9ucyBjYW4gbm90IHVzZSB0aGlzLlxuICpcbiAqIEBwYXJhbSB0b2tlbiBwbGF0Zm9ybSB0b2tlblxuICogQHBhcmFtIGNsaWVudElkIGFwcGxpY2F0aW9uIGNsaWVudCBpZFxuICogQHBhcmFtIHBvcnRhbCBPcHRpb25hbFxuICovXG5leHBvcnQgZnVuY3Rpb24gdmFsaWRhdGVBcHBBY2Nlc3ModG9rZW4sIGNsaWVudElkLCBwb3J0YWwpIHtcbiAgICBpZiAocG9ydGFsID09PSB2b2lkIDApIHsgcG9ydGFsID0gXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiOyB9XG4gICAgdmFyIHVybCA9IHBvcnRhbCArIFwiL29hdXRoMi92YWxpZGF0ZUFwcEFjY2Vzc1wiO1xuICAgIHZhciBybyA9IHtcbiAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICBmOiBcImpzb25cIixcbiAgICAgICAgICAgIGNsaWVudF9pZDogY2xpZW50SWQsXG4gICAgICAgICAgICB0b2tlbjogdG9rZW4sXG4gICAgICAgIH0sXG4gICAgfTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIHJvKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXZhbGlkYXRlLWFwcC1hY2Nlc3MuanMubWFwIiwiLyohICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXHJcbkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLlxyXG5cclxuUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XHJcbnB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZC5cclxuXHJcblRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEhcclxuUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZXHJcbkFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1IgQU5ZIFNQRUNJQUwsIERJUkVDVCxcclxuSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NXHJcbkxPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SXHJcbk9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1JcclxuUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cclxuKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogKi9cclxuLyogZ2xvYmFsIFJlZmxlY3QsIFByb21pc2UgKi9cclxuXHJcbnZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24oZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxyXG4gICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcclxuICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcclxuICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXh0ZW5kcyhkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG4gICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XHJcbiAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XHJcbn1cclxuXHJcbmV4cG9ydCB2YXIgX19hc3NpZ24gPSBmdW5jdGlvbigpIHtcclxuICAgIF9fYXNzaWduID0gT2JqZWN0LmFzc2lnbiB8fCBmdW5jdGlvbiBfX2Fzc2lnbih0KSB7XHJcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XHJcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XHJcbiAgICAgICAgICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSkgdFtwXSA9IHNbcF07XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3Jlc3QocywgZSkge1xyXG4gICAgdmFyIHQgPSB7fTtcclxuICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSAmJiBlLmluZGV4T2YocCkgPCAwKVxyXG4gICAgICAgIHRbcF0gPSBzW3BdO1xyXG4gICAgaWYgKHMgIT0gbnVsbCAmJiB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBwID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyhzKTsgaSA8IHAubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgaWYgKGUuaW5kZXhPZihwW2ldKSA8IDAgJiYgT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZS5jYWxsKHMsIHBbaV0pKVxyXG4gICAgICAgICAgICAgICAgdFtwW2ldXSA9IHNbcFtpXV07XHJcbiAgICAgICAgfVxyXG4gICAgcmV0dXJuIHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2RlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKSB7XHJcbiAgICB2YXIgYyA9IGFyZ3VtZW50cy5sZW5ndGgsIHIgPSBjIDwgMyA/IHRhcmdldCA6IGRlc2MgPT09IG51bGwgPyBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0YXJnZXQsIGtleSkgOiBkZXNjLCBkO1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0LmRlY29yYXRlID09PSBcImZ1bmN0aW9uXCIpIHIgPSBSZWZsZWN0LmRlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKTtcclxuICAgIGVsc2UgZm9yICh2YXIgaSA9IGRlY29yYXRvcnMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIGlmIChkID0gZGVjb3JhdG9yc1tpXSkgciA9IChjIDwgMyA/IGQocikgOiBjID4gMyA/IGQodGFyZ2V0LCBrZXksIHIpIDogZCh0YXJnZXQsIGtleSkpIHx8IHI7XHJcbiAgICByZXR1cm4gYyA+IDMgJiYgciAmJiBPYmplY3QuZGVmaW5lUHJvcGVydHkodGFyZ2V0LCBrZXksIHIpLCByO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19wYXJhbShwYXJhbUluZGV4LCBkZWNvcmF0b3IpIHtcclxuICAgIHJldHVybiBmdW5jdGlvbiAodGFyZ2V0LCBrZXkpIHsgZGVjb3JhdG9yKHRhcmdldCwga2V5LCBwYXJhbUluZGV4KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSkge1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0Lm1ldGFkYXRhID09PSBcImZ1bmN0aW9uXCIpIHJldHVybiBSZWZsZWN0Lm1ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXRlcih0aGlzQXJnLCBfYXJndW1lbnRzLCBQLCBnZW5lcmF0b3IpIHtcclxuICAgIGZ1bmN0aW9uIGFkb3B0KHZhbHVlKSB7IHJldHVybiB2YWx1ZSBpbnN0YW5jZW9mIFAgPyB2YWx1ZSA6IG5ldyBQKGZ1bmN0aW9uIChyZXNvbHZlKSB7IHJlc29sdmUodmFsdWUpOyB9KTsgfVxyXG4gICAgcmV0dXJuIG5ldyAoUCB8fCAoUCA9IFByb21pc2UpKShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XHJcbiAgICAgICAgZnVuY3Rpb24gZnVsZmlsbGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yLm5leHQodmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHJlamVjdGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yW1widGhyb3dcIl0odmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHN0ZXAocmVzdWx0KSB7IHJlc3VsdC5kb25lID8gcmVzb2x2ZShyZXN1bHQudmFsdWUpIDogYWRvcHQocmVzdWx0LnZhbHVlKS50aGVuKGZ1bGZpbGxlZCwgcmVqZWN0ZWQpOyB9XHJcbiAgICAgICAgc3RlcCgoZ2VuZXJhdG9yID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pKS5uZXh0KCkpO1xyXG4gICAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2dlbmVyYXRvcih0aGlzQXJnLCBib2R5KSB7XHJcbiAgICB2YXIgXyA9IHsgbGFiZWw6IDAsIHNlbnQ6IGZ1bmN0aW9uKCkgeyBpZiAodFswXSAmIDEpIHRocm93IHRbMV07IHJldHVybiB0WzFdOyB9LCB0cnlzOiBbXSwgb3BzOiBbXSB9LCBmLCB5LCB0LCBnO1xyXG4gICAgcmV0dXJuIGcgPSB7IG5leHQ6IHZlcmIoMCksIFwidGhyb3dcIjogdmVyYigxKSwgXCJyZXR1cm5cIjogdmVyYigyKSB9LCB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgKGdbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhpczsgfSksIGc7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgcmV0dXJuIGZ1bmN0aW9uICh2KSB7IHJldHVybiBzdGVwKFtuLCB2XSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAob3ApIHtcclxuICAgICAgICBpZiAoZikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy5cIik7XHJcbiAgICAgICAgd2hpbGUgKF8pIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChmID0gMSwgeSAmJiAodCA9IG9wWzBdICYgMiA/IHlbXCJyZXR1cm5cIl0gOiBvcFswXSA/IHlbXCJ0aHJvd1wiXSB8fCAoKHQgPSB5W1wicmV0dXJuXCJdKSAmJiB0LmNhbGwoeSksIDApIDogeS5uZXh0KSAmJiAhKHQgPSB0LmNhbGwoeSwgb3BbMV0pKS5kb25lKSByZXR1cm4gdDtcclxuICAgICAgICAgICAgaWYgKHkgPSAwLCB0KSBvcCA9IFtvcFswXSAmIDIsIHQudmFsdWVdO1xyXG4gICAgICAgICAgICBzd2l0Y2ggKG9wWzBdKSB7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDA6IGNhc2UgMTogdCA9IG9wOyBicmVhaztcclxuICAgICAgICAgICAgICAgIGNhc2UgNDogXy5sYWJlbCsrOyByZXR1cm4geyB2YWx1ZTogb3BbMV0sIGRvbmU6IGZhbHNlIH07XHJcbiAgICAgICAgICAgICAgICBjYXNlIDU6IF8ubGFiZWwrKzsgeSA9IG9wWzFdOyBvcCA9IFswXTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDc6IG9wID0gXy5vcHMucG9wKCk7IF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgIGlmICghKHQgPSBfLnRyeXMsIHQgPSB0Lmxlbmd0aCA+IDAgJiYgdFt0Lmxlbmd0aCAtIDFdKSAmJiAob3BbMF0gPT09IDYgfHwgb3BbMF0gPT09IDIpKSB7IF8gPSAwOyBjb250aW51ZTsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gMyAmJiAoIXQgfHwgKG9wWzFdID4gdFswXSAmJiBvcFsxXSA8IHRbM10pKSkgeyBfLmxhYmVsID0gb3BbMV07IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSA2ICYmIF8ubGFiZWwgPCB0WzFdKSB7IF8ubGFiZWwgPSB0WzFdOyB0ID0gb3A7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHQgJiYgXy5sYWJlbCA8IHRbMl0pIHsgXy5sYWJlbCA9IHRbMl07IF8ub3BzLnB1c2gob3ApOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0WzJdKSBfLm9wcy5wb3AoKTtcclxuICAgICAgICAgICAgICAgICAgICBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIG9wID0gYm9keS5jYWxsKHRoaXNBcmcsIF8pO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgb3AgPSBbNiwgZV07IHkgPSAwOyB9IGZpbmFsbHkgeyBmID0gdCA9IDA7IH1cclxuICAgICAgICBpZiAob3BbMF0gJiA1KSB0aHJvdyBvcFsxXTsgcmV0dXJuIHsgdmFsdWU6IG9wWzBdID8gb3BbMV0gOiB2b2lkIDAsIGRvbmU6IHRydWUgfTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY3JlYXRlQmluZGluZyhvLCBtLCBrLCBrMikge1xyXG4gICAgaWYgKGsyID09PSB1bmRlZmluZWQpIGsyID0gaztcclxuICAgIG9bazJdID0gbVtrXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXhwb3J0U3RhcihtLCBleHBvcnRzKSB7XHJcbiAgICBmb3IgKHZhciBwIGluIG0pIGlmIChwICE9PSBcImRlZmF1bHRcIiAmJiAhZXhwb3J0cy5oYXNPd25Qcm9wZXJ0eShwKSkgZXhwb3J0c1twXSA9IG1bcF07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3ZhbHVlcyhvKSB7XHJcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xyXG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XHJcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XHJcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xyXG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xyXG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XHJcbiAgICAgICAgfVxyXG4gICAgfTtcclxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVhZChvLCBuKSB7XHJcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XHJcbiAgICBpZiAoIW0pIHJldHVybiBvO1xyXG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xyXG4gICAgfVxyXG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XHJcbiAgICBmaW5hbGx5IHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZCgpIHtcclxuICAgIGZvciAodmFyIGFyID0gW10sIGkgPSAwOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKVxyXG4gICAgICAgIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkQXJyYXlzKCkge1xyXG4gICAgZm9yICh2YXIgcyA9IDAsIGkgPSAwLCBpbCA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBpbDsgaSsrKSBzICs9IGFyZ3VtZW50c1tpXS5sZW5ndGg7XHJcbiAgICBmb3IgKHZhciByID0gQXJyYXkocyksIGsgPSAwLCBpID0gMDsgaSA8IGlsOyBpKyspXHJcbiAgICAgICAgZm9yICh2YXIgYSA9IGFyZ3VtZW50c1tpXSwgaiA9IDAsIGpsID0gYS5sZW5ndGg7IGogPCBqbDsgaisrLCBrKyspXHJcbiAgICAgICAgICAgIHJba10gPSBhW2pdO1xyXG4gICAgcmV0dXJuIHI7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdCh2KSB7XHJcbiAgICByZXR1cm4gdGhpcyBpbnN0YW5jZW9mIF9fYXdhaXQgPyAodGhpcy52ID0gdiwgdGhpcykgOiBuZXcgX19hd2FpdCh2KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNHZW5lcmF0b3IodGhpc0FyZywgX2FyZ3VtZW50cywgZ2VuZXJhdG9yKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIGcgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSksIGksIHEgPSBbXTtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpZiAoZ1tuXSkgaVtuXSA9IGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAoYSwgYikgeyBxLnB1c2goW24sIHYsIGEsIGJdKSA+IDEgfHwgcmVzdW1lKG4sIHYpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gcmVzdW1lKG4sIHYpIHsgdHJ5IHsgc3RlcChnW25dKHYpKTsgfSBjYXRjaCAoZSkgeyBzZXR0bGUocVswXVszXSwgZSk7IH0gfVxyXG4gICAgZnVuY3Rpb24gc3RlcChyKSB7IHIudmFsdWUgaW5zdGFuY2VvZiBfX2F3YWl0ID8gUHJvbWlzZS5yZXNvbHZlKHIudmFsdWUudikudGhlbihmdWxmaWxsLCByZWplY3QpIDogc2V0dGxlKHFbMF1bMl0sIHIpOyB9XHJcbiAgICBmdW5jdGlvbiBmdWxmaWxsKHZhbHVlKSB7IHJlc3VtZShcIm5leHRcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiByZWplY3QodmFsdWUpIHsgcmVzdW1lKFwidGhyb3dcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUoZiwgdikgeyBpZiAoZih2KSwgcS5zaGlmdCgpLCBxLmxlbmd0aCkgcmVzdW1lKHFbMF1bMF0sIHFbMF1bMV0pOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jRGVsZWdhdG9yKG8pIHtcclxuICAgIHZhciBpLCBwO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiLCBmdW5jdGlvbiAoZSkgeyB0aHJvdyBlOyB9KSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobiwgZikgeyBpW25dID0gb1tuXSA/IGZ1bmN0aW9uICh2KSB7IHJldHVybiAocCA9ICFwKSA/IHsgdmFsdWU6IF9fYXdhaXQob1tuXSh2KSksIGRvbmU6IG4gPT09IFwicmV0dXJuXCIgfSA6IGYgPyBmKHYpIDogdjsgfSA6IGY7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNWYWx1ZXMobykge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBtID0gb1tTeW1ib2wuYXN5bmNJdGVyYXRvcl0sIGk7XHJcbiAgICByZXR1cm4gbSA/IG0uY2FsbChvKSA6IChvID0gdHlwZW9mIF9fdmFsdWVzID09PSBcImZ1bmN0aW9uXCIgPyBfX3ZhbHVlcyhvKSA6IG9bU3ltYm9sLml0ZXJhdG9yXSgpLCBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaSk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaVtuXSA9IG9bbl0gJiYgZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHsgdiA9IG9bbl0odiksIHNldHRsZShyZXNvbHZlLCByZWplY3QsIHYuZG9uZSwgdi52YWx1ZSk7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCBkLCB2KSB7IFByb21pc2UucmVzb2x2ZSh2KS50aGVuKGZ1bmN0aW9uKHYpIHsgcmVzb2x2ZSh7IHZhbHVlOiB2LCBkb25lOiBkIH0pOyB9LCByZWplY3QpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ha2VUZW1wbGF0ZU9iamVjdChjb29rZWQsIHJhdykge1xyXG4gICAgaWYgKE9iamVjdC5kZWZpbmVQcm9wZXJ0eSkgeyBPYmplY3QuZGVmaW5lUHJvcGVydHkoY29va2VkLCBcInJhd1wiLCB7IHZhbHVlOiByYXcgfSk7IH0gZWxzZSB7IGNvb2tlZC5yYXcgPSByYXc7IH1cclxuICAgIHJldHVybiBjb29rZWQ7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnRTdGFyKG1vZCkge1xyXG4gICAgaWYgKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgcmV0dXJuIG1vZDtcclxuICAgIHZhciByZXN1bHQgPSB7fTtcclxuICAgIGlmIChtb2QgIT0gbnVsbCkgZm9yICh2YXIgayBpbiBtb2QpIGlmIChPYmplY3QuaGFzT3duUHJvcGVydHkuY2FsbChtb2QsIGspKSByZXN1bHRba10gPSBtb2Rba107XHJcbiAgICByZXN1bHQuZGVmYXVsdCA9IG1vZDtcclxuICAgIHJldHVybiByZXN1bHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydERlZmF1bHQobW9kKSB7XHJcbiAgICByZXR1cm4gKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgPyBtb2QgOiB7IGRlZmF1bHQ6IG1vZCB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZEdldChyZWNlaXZlciwgcHJpdmF0ZU1hcCkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIGdldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHJldHVybiBwcml2YXRlTWFwLmdldChyZWNlaXZlcik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkU2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwLCB2YWx1ZSkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIHNldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHByaXZhdGVNYXAuc2V0KHJlY2VpdmVyLCB2YWx1ZSk7XHJcbiAgICByZXR1cm4gdmFsdWU7XHJcbn1cclxuIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IGFkZEZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogYWRkRmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cHM6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvU2VydmljZVJlcXVlc3QvRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgIGZlYXR1cmVzOiBbe1xuICogICAgIGdlb21ldHJ5OiB7IHg6IC0xMjAsIHk6IDQ1LCBzcGF0aWFsUmVmZXJlbmNlOiB7IHdraWQ6IDQzMjYgfSB9LFxuICogICAgIGF0dHJpYnV0ZXM6IHsgc3RhdHVzOiBcImFsaXZlXCIgfVxuICogICB9XVxuICogfSlcbiAqICAgLnRoZW4ocmVzcG9uc2UpXG4gKiBgYGBcbiAqIEFkZCBmZWF0dXJlcyByZXF1ZXN0LiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL2FkZC1mZWF0dXJlcy5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGFkZEZlYXR1cmVzIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gYWRkRmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL2FkZEZlYXR1cmVzXCI7XG4gICAgLy8gZWRpdCBvcGVyYXRpb25zIGFyZSBQT1NUIG9ubHlcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1wiZmVhdHVyZXNcIiwgXCJnZGJWZXJzaW9uXCIsIFwicmV0dXJuRWRpdE1vbWVudFwiLCBcInJvbGxiYWNrT25GYWlsdXJlXCJdLCB7IHBhcmFtczogX19hc3NpZ24oe30sIHJlcXVlc3RPcHRpb25zLnBhcmFtcykgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWFkZC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgZGVsZXRlRmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBkZWxldGVGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwczovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9TZXJ2aWNlUmVxdWVzdC9GZWF0dXJlU2VydmVyLzBcIixcbiAqICAgb2JqZWN0SWRzOiBbMSwyLDNdXG4gKiB9KTtcbiAqIGBgYFxuICogRGVsZXRlIGZlYXR1cmVzIHJlcXVlc3QuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvZGVsZXRlLWZlYXR1cmVzLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIGRlbGV0ZUZlYXR1cmVzUmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkZWxldGVGZWF0dXJlcyByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlbGV0ZUZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9kZWxldGVGZWF0dXJlc1wiO1xuICAgIC8vIGVkaXQgb3BlcmF0aW9ucyBQT1NUIG9ubHlcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1xuICAgICAgICBcIndoZXJlXCIsXG4gICAgICAgIFwib2JqZWN0SWRzXCIsXG4gICAgICAgIFwiZ2RiVmVyc2lvblwiLFxuICAgICAgICBcInJldHVybkVkaXRNb21lbnRcIixcbiAgICAgICAgXCJyb2xsYmFja09uRmFpbHVyZVwiXG4gICAgXSwgeyBwYXJhbXM6IF9fYXNzaWduKHt9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1kZWxldGUuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgZ2V0RmVhdHVyZSB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIGNvbnN0IHVybCA9IFwiaHR0cHM6Ly9zZXJ2aWNlcy5hcmNnaXMuY29tL1Y2WkhGcjZ6ZGdOWnVWRzAvYXJjZ2lzL3Jlc3Qvc2VydmljZXMvTGFuZHNjYXBlX1RyZWVzL0ZlYXR1cmVTZXJ2ZXIvMFwiO1xuICogLy9cbiAqIGdldEZlYXR1cmUoe1xuICogICB1cmwsXG4gKiAgIGlkOiA0MlxuICogfSkudGhlbihmZWF0dXJlID0+IHtcbiAqICBjb25zb2xlLmxvZyhmZWF0dXJlLmF0dHJpYnV0ZXMuRklEKTsgLy8gNDJcbiAqIH0pO1xuICogYGBgXG4gKiBHZXQgYSBmZWF0dXJlIGJ5IGlkLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0XG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZmVhdHVyZSBvciB0aGUgW3Jlc3BvbnNlXShodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvUmVzcG9uc2UpIGl0c2VsZiBpZiBgcmF3UmVzcG9uc2U6IHRydWVgIHdhcyBwYXNzZWQgaW4uXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRGZWF0dXJlKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9cIiArIHJlcXVlc3RPcHRpb25zLmlkO1xuICAgIC8vIGRlZmF1bHQgdG8gYSBHRVQgcmVxdWVzdFxuICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIkdFVFwiIH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChvcHRpb25zLnJhd1Jlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmZlYXR1cmU7XG4gICAgfSk7XG59XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBxdWVyeUZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogcXVlcnlGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL0NlbnN1cy9NYXBTZXJ2ZXIvM1wiLFxuICogICB3aGVyZTogXCJTVEFURV9OQU1FID0gJ0FsYXNrYSdcIlxuICogfSlcbiAqICAgLnRoZW4ocmVzdWx0KVxuICogYGBgXG4gKiBRdWVyeSBhIGZlYXR1cmUgc2VydmljZS4gU2VlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL3F1ZXJ5LWZlYXR1cmUtc2VydmljZS1sYXllci0uaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdFxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIHF1ZXJ5IHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcXVlcnlGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBxdWVyeU9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcbiAgICAgICAgXCJ3aGVyZVwiLFxuICAgICAgICBcIm9iamVjdElkc1wiLFxuICAgICAgICBcInJlbGF0aW9uUGFyYW1cIixcbiAgICAgICAgXCJ0aW1lXCIsXG4gICAgICAgIFwiZGlzdGFuY2VcIixcbiAgICAgICAgXCJ1bml0c1wiLFxuICAgICAgICBcIm91dEZpZWxkc1wiLFxuICAgICAgICBcImdlb21ldHJ5XCIsXG4gICAgICAgIFwiZ2VvbWV0cnlUeXBlXCIsXG4gICAgICAgIFwic3BhdGlhbFJlbFwiLFxuICAgICAgICBcInJldHVybkdlb21ldHJ5XCIsXG4gICAgICAgIFwibWF4QWxsb3dhYmxlT2Zmc2V0XCIsXG4gICAgICAgIFwiZ2VvbWV0cnlQcmVjaXNpb25cIixcbiAgICAgICAgXCJpblNSXCIsXG4gICAgICAgIFwib3V0U1JcIixcbiAgICAgICAgXCJnZGJWZXJzaW9uXCIsXG4gICAgICAgIFwicmV0dXJuRGlzdGluY3RWYWx1ZXNcIixcbiAgICAgICAgXCJyZXR1cm5JZHNPbmx5XCIsXG4gICAgICAgIFwicmV0dXJuQ291bnRPbmx5XCIsXG4gICAgICAgIFwicmV0dXJuRXh0ZW50T25seVwiLFxuICAgICAgICBcIm9yZGVyQnlGaWVsZHNcIixcbiAgICAgICAgXCJncm91cEJ5RmllbGRzRm9yU3RhdGlzdGljc1wiLFxuICAgICAgICBcIm91dFN0YXRpc3RpY3NcIixcbiAgICAgICAgXCJyZXR1cm5aXCIsXG4gICAgICAgIFwicmV0dXJuTVwiLFxuICAgICAgICBcIm11bHRpcGF0Y2hPcHRpb25cIixcbiAgICAgICAgXCJyZXN1bHRPZmZzZXRcIixcbiAgICAgICAgXCJyZXN1bHRSZWNvcmRDb3VudFwiLFxuICAgICAgICBcInF1YW50aXphdGlvblBhcmFtZXRlcnNcIixcbiAgICAgICAgXCJyZXR1cm5DZW50cm9pZFwiLFxuICAgICAgICBcInJlc3VsdFR5cGVcIixcbiAgICAgICAgXCJoaXN0b3JpY01vbWVudFwiLFxuICAgICAgICBcInJldHVyblRydWVDdXJ2ZXNcIixcbiAgICAgICAgXCJzcWxGb3JtYXRcIixcbiAgICAgICAgXCJyZXR1cm5FeGNlZWRlZExpbWl0RmVhdHVyZXNcIixcbiAgICAgICAgXCJmXCJcbiAgICBdLCB7XG4gICAgICAgIGh0dHBNZXRob2Q6IFwiR0VUXCIsXG4gICAgICAgIHBhcmFtczogX19hc3NpZ24oeyBcbiAgICAgICAgICAgIC8vIHNldCBkZWZhdWx0IHF1ZXJ5IHBhcmFtZXRlcnNcbiAgICAgICAgICAgIHdoZXJlOiBcIjE9MVwiLCBvdXRGaWVsZHM6IFwiKlwiIH0sIHJlcXVlc3RPcHRpb25zLnBhcmFtcylcbiAgICB9KTtcbiAgICByZXR1cm4gcmVxdWVzdChjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvcXVlcnlcIiwgcXVlcnlPcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXF1ZXJ5LmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgcXVlcnlSZWxhdGVkIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcidcbiAqIC8vXG4gKiBxdWVyeVJlbGF0ZWQoe1xuICogIHVybDogXCJodHRwOi8vc2VydmljZXMubXlzZXJ2ZXIvT3JnSUQvQXJjR0lTL3Jlc3Qvc2VydmljZXMvUGV0cm9sZXVtL0tTUGV0cm8vRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgcmVsYXRpb25zaGlwSWQ6IDEsXG4gKiAgcGFyYW1zOiB7IHJldHVybkNvdW50T25seTogdHJ1ZSB9XG4gKiB9KVxuICogIC50aGVuKHJlc3BvbnNlKSAvLyByZXNwb25zZS5yZWxhdGVkUmVjb3Jkc1xuICogYGBgXG4gKiBRdWVyeSB0aGUgcmVsYXRlZCByZWNvcmRzIGZvciBhIGZlYXR1cmUgc2VydmljZS4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9xdWVyeS1yZWxhdGVkLXJlY29yZHMtZmVhdHVyZS1zZXJ2aWNlLS5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9uc1xuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIHF1ZXJ5IHJlc3BvbnNlXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBxdWVyeVJlbGF0ZWQocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1wib2JqZWN0SWRzXCIsIFwicmVsYXRpb25zaGlwSWRcIiwgXCJkZWZpbml0aW9uRXhwcmVzc2lvblwiLCBcIm91dEZpZWxkc1wiXSwge1xuICAgICAgICBodHRwTWV0aG9kOiBcIkdFVFwiLFxuICAgICAgICBwYXJhbXM6IF9fYXNzaWduKHsgXG4gICAgICAgICAgICAvLyBzZXQgZGVmYXVsdCBxdWVyeSBwYXJhbWV0ZXJzXG4gICAgICAgICAgICBkZWZpbml0aW9uRXhwcmVzc2lvbjogXCIxPTFcIiwgb3V0RmllbGRzOiBcIipcIiwgcmVsYXRpb25zaGlwSWQ6IDAgfSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKVxuICAgIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9xdWVyeVJlbGF0ZWRSZWNvcmRzXCIsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cXVlcnlSZWxhdGVkLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgdXBkYXRlRmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiB1cGRhdGVGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwczovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9TZXJ2aWNlUmVxdWVzdC9GZWF0dXJlU2VydmVyLzBcIixcbiAqICAgZmVhdHVyZXM6IFt7XG4gKiAgICAgZ2VvbWV0cnk6IHsgeDogLTEyMCwgeTogNDUsIHNwYXRpYWxSZWZlcmVuY2U6IHsgd2tpZDogNDMyNiB9IH0sXG4gKiAgICAgYXR0cmlidXRlczogeyBzdGF0dXM6IFwiYWxpdmVcIiB9XG4gKiAgIH1dXG4gKiB9KTtcbiAqIGBgYFxuICogVXBkYXRlIGZlYXR1cmVzIHJlcXVlc3QuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvdXBkYXRlLWZlYXR1cmVzLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgdXBkYXRlRmVhdHVyZXMgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB1cGRhdGVGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvdXBkYXRlRmVhdHVyZXNcIjtcbiAgICAvLyBlZGl0IG9wZXJhdGlvbnMgYXJlIFBPU1Qgb25seVxuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXCJmZWF0dXJlc1wiLCBcImdkYlZlcnNpb25cIiwgXCJyZXR1cm5FZGl0TW9tZW50XCIsIFwicm9sbGJhY2tPbkZhaWx1cmVcIiwgXCJ0cnVlQ3VydmVDbGllbnRcIl0sIHsgcGFyYW1zOiBfX2Fzc2lnbih7fSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSB9KTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9dXBkYXRlLmpzLm1hcCIsIi8qISAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxyXG5Db3B5cmlnaHQgKGMpIE1pY3Jvc29mdCBDb3Jwb3JhdGlvbi5cclxuXHJcblBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxyXG5wdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQuXHJcblxyXG5USEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFUyBXSVRIXHJcblJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWVxyXG5BTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SIEFOWSBTUEVDSUFMLCBESVJFQ1QsXHJcbklORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVMgV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTVxyXG5MT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUlxyXG5PVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SXHJcblBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXHJcbioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqICovXHJcbi8qIGdsb2JhbCBSZWZsZWN0LCBQcm9taXNlICovXHJcblxyXG52YXIgZXh0ZW5kU3RhdGljcyA9IGZ1bmN0aW9uKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MgPSBPYmplY3Quc2V0UHJvdG90eXBlT2YgfHxcclxuICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XHJcbiAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XHJcbiAgICByZXR1cm4gZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4dGVuZHMoZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxuICAgIGZ1bmN0aW9uIF9fKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gZDsgfVxyXG4gICAgZC5wcm90b3R5cGUgPSBiID09PSBudWxsID8gT2JqZWN0LmNyZWF0ZShiKSA6IChfXy5wcm90b3R5cGUgPSBiLnByb3RvdHlwZSwgbmV3IF9fKCkpO1xyXG59XHJcblxyXG5leHBvcnQgdmFyIF9fYXNzaWduID0gZnVuY3Rpb24oKSB7XHJcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24gX19hc3NpZ24odCkge1xyXG4gICAgICAgIGZvciAodmFyIHMsIGkgPSAxLCBuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IG47IGkrKykge1xyXG4gICAgICAgICAgICBzID0gYXJndW1lbnRzW2ldO1xyXG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpIHRbcF0gPSBzW3BdO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdDtcclxuICAgIH1cclxuICAgIHJldHVybiBfX2Fzc2lnbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZXN0KHMsIGUpIHtcclxuICAgIHZhciB0ID0ge307XHJcbiAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkgJiYgZS5pbmRleE9mKHApIDwgMClcclxuICAgICAgICB0W3BdID0gc1twXTtcclxuICAgIGlmIChzICE9IG51bGwgJiYgdHlwZW9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMgPT09IFwiZnVuY3Rpb25cIilcclxuICAgICAgICBmb3IgKHZhciBpID0gMCwgcCA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMocyk7IGkgPCBwLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgICAgIGlmIChlLmluZGV4T2YocFtpXSkgPCAwICYmIE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGUuY2FsbChzLCBwW2ldKSlcclxuICAgICAgICAgICAgICAgIHRbcFtpXV0gPSBzW3BbaV1dO1xyXG4gICAgICAgIH1cclxuICAgIHJldHVybiB0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYykge1xyXG4gICAgdmFyIGMgPSBhcmd1bWVudHMubGVuZ3RoLCByID0gYyA8IDMgPyB0YXJnZXQgOiBkZXNjID09PSBudWxsID8gZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodGFyZ2V0LCBrZXkpIDogZGVzYywgZDtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSA9PT0gXCJmdW5jdGlvblwiKSByID0gUmVmbGVjdC5kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYyk7XHJcbiAgICBlbHNlIGZvciAodmFyIGkgPSBkZWNvcmF0b3JzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSBpZiAoZCA9IGRlY29yYXRvcnNbaV0pIHIgPSAoYyA8IDMgPyBkKHIpIDogYyA+IDMgPyBkKHRhcmdldCwga2V5LCByKSA6IGQodGFyZ2V0LCBrZXkpKSB8fCByO1xyXG4gICAgcmV0dXJuIGMgPiAzICYmIHIgJiYgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRhcmdldCwga2V5LCByKSwgcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcGFyYW0ocGFyYW1JbmRleCwgZGVjb3JhdG9yKSB7XHJcbiAgICByZXR1cm4gZnVuY3Rpb24gKHRhcmdldCwga2V5KSB7IGRlY29yYXRvcih0YXJnZXQsIGtleSwgcGFyYW1JbmRleCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpIHtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5tZXRhZGF0YSA9PT0gXCJmdW5jdGlvblwiKSByZXR1cm4gUmVmbGVjdC5tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0ZXIodGhpc0FyZywgX2FyZ3VtZW50cywgUCwgZ2VuZXJhdG9yKSB7XHJcbiAgICBmdW5jdGlvbiBhZG9wdCh2YWx1ZSkgeyByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBQID8gdmFsdWUgOiBuZXcgUChmdW5jdGlvbiAocmVzb2x2ZSkgeyByZXNvbHZlKHZhbHVlKTsgfSk7IH1cclxuICAgIHJldHVybiBuZXcgKFAgfHwgKFAgPSBQcm9taXNlKSkoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xyXG4gICAgICAgIGZ1bmN0aW9uIGZ1bGZpbGxlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvci5uZXh0KHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiByZWplY3RlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvcltcInRocm93XCJdKHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiBzdGVwKHJlc3VsdCkgeyByZXN1bHQuZG9uZSA/IHJlc29sdmUocmVzdWx0LnZhbHVlKSA6IGFkb3B0KHJlc3VsdC52YWx1ZSkudGhlbihmdWxmaWxsZWQsIHJlamVjdGVkKTsgfVxyXG4gICAgICAgIHN0ZXAoKGdlbmVyYXRvciA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSkubmV4dCgpKTtcclxuICAgIH0pO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19nZW5lcmF0b3IodGhpc0FyZywgYm9keSkge1xyXG4gICAgdmFyIF8gPSB7IGxhYmVsOiAwLCBzZW50OiBmdW5jdGlvbigpIHsgaWYgKHRbMF0gJiAxKSB0aHJvdyB0WzFdOyByZXR1cm4gdFsxXTsgfSwgdHJ5czogW10sIG9wczogW10gfSwgZiwgeSwgdCwgZztcclxuICAgIHJldHVybiBnID0geyBuZXh0OiB2ZXJiKDApLCBcInRocm93XCI6IHZlcmIoMSksIFwicmV0dXJuXCI6IHZlcmIoMikgfSwgdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIChnW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbigpIHsgcmV0dXJuIHRoaXM7IH0pLCBnO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IHJldHVybiBmdW5jdGlvbiAodikgeyByZXR1cm4gc3RlcChbbiwgdl0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKG9wKSB7XHJcbiAgICAgICAgaWYgKGYpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJHZW5lcmF0b3IgaXMgYWxyZWFkeSBleGVjdXRpbmcuXCIpO1xyXG4gICAgICAgIHdoaWxlIChfKSB0cnkge1xyXG4gICAgICAgICAgICBpZiAoZiA9IDEsIHkgJiYgKHQgPSBvcFswXSAmIDIgPyB5W1wicmV0dXJuXCJdIDogb3BbMF0gPyB5W1widGhyb3dcIl0gfHwgKCh0ID0geVtcInJldHVyblwiXSkgJiYgdC5jYWxsKHkpLCAwKSA6IHkubmV4dCkgJiYgISh0ID0gdC5jYWxsKHksIG9wWzFdKSkuZG9uZSkgcmV0dXJuIHQ7XHJcbiAgICAgICAgICAgIGlmICh5ID0gMCwgdCkgb3AgPSBbb3BbMF0gJiAyLCB0LnZhbHVlXTtcclxuICAgICAgICAgICAgc3dpdGNoIChvcFswXSkge1xyXG4gICAgICAgICAgICAgICAgY2FzZSAwOiBjYXNlIDE6IHQgPSBvcDsgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDQ6IF8ubGFiZWwrKzsgcmV0dXJuIHsgdmFsdWU6IG9wWzFdLCBkb25lOiBmYWxzZSB9O1xyXG4gICAgICAgICAgICAgICAgY2FzZSA1OiBfLmxhYmVsKys7IHkgPSBvcFsxXTsgb3AgPSBbMF07IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA3OiBvcCA9IF8ub3BzLnBvcCgpOyBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICBpZiAoISh0ID0gXy50cnlzLCB0ID0gdC5sZW5ndGggPiAwICYmIHRbdC5sZW5ndGggLSAxXSkgJiYgKG9wWzBdID09PSA2IHx8IG9wWzBdID09PSAyKSkgeyBfID0gMDsgY29udGludWU7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDMgJiYgKCF0IHx8IChvcFsxXSA+IHRbMF0gJiYgb3BbMV0gPCB0WzNdKSkpIHsgXy5sYWJlbCA9IG9wWzFdOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gNiAmJiBfLmxhYmVsIDwgdFsxXSkgeyBfLmxhYmVsID0gdFsxXTsgdCA9IG9wOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0ICYmIF8ubGFiZWwgPCB0WzJdKSB7IF8ubGFiZWwgPSB0WzJdOyBfLm9wcy5wdXNoKG9wKTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodFsyXSkgXy5vcHMucG9wKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBvcCA9IGJvZHkuY2FsbCh0aGlzQXJnLCBfKTtcclxuICAgICAgICB9IGNhdGNoIChlKSB7IG9wID0gWzYsIGVdOyB5ID0gMDsgfSBmaW5hbGx5IHsgZiA9IHQgPSAwOyB9XHJcbiAgICAgICAgaWYgKG9wWzBdICYgNSkgdGhyb3cgb3BbMV07IHJldHVybiB7IHZhbHVlOiBvcFswXSA/IG9wWzFdIDogdm9pZCAwLCBkb25lOiB0cnVlIH07XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NyZWF0ZUJpbmRpbmcobywgbSwgaywgazIpIHtcclxuICAgIGlmIChrMiA9PT0gdW5kZWZpbmVkKSBrMiA9IGs7XHJcbiAgICBvW2syXSA9IG1ba107XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4cG9ydFN0YXIobSwgZXhwb3J0cykge1xyXG4gICAgZm9yICh2YXIgcCBpbiBtKSBpZiAocCAhPT0gXCJkZWZhdWx0XCIgJiYgIWV4cG9ydHMuaGFzT3duUHJvcGVydHkocCkpIGV4cG9ydHNbcF0gPSBtW3BdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX192YWx1ZXMobykge1xyXG4gICAgdmFyIHMgPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgU3ltYm9sLml0ZXJhdG9yLCBtID0gcyAmJiBvW3NdLCBpID0gMDtcclxuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xyXG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xyXG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcclxuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcclxuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xyXG4gICAgICAgIH1cclxuICAgIH07XHJcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3JlYWQobywgbikge1xyXG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xyXG4gICAgaWYgKCFtKSByZXR1cm4gbztcclxuICAgIHZhciBpID0gbS5jYWxsKG8pLCByLCBhciA9IFtdLCBlO1xyXG4gICAgdHJ5IHtcclxuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcclxuICAgIH1cclxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxyXG4gICAgZmluYWxseSB7XHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGZpbmFsbHkgeyBpZiAoZSkgdGhyb3cgZS5lcnJvcjsgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWQoKSB7XHJcbiAgICBmb3IgKHZhciBhciA9IFtdLCBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKylcclxuICAgICAgICBhciA9IGFyLmNvbmNhdChfX3JlYWQoYXJndW1lbnRzW2ldKSk7XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZEFycmF5cygpIHtcclxuICAgIGZvciAodmFyIHMgPSAwLCBpID0gMCwgaWwgPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgaWw7IGkrKykgcyArPSBhcmd1bWVudHNbaV0ubGVuZ3RoO1xyXG4gICAgZm9yICh2YXIgciA9IEFycmF5KHMpLCBrID0gMCwgaSA9IDA7IGkgPCBpbDsgaSsrKVxyXG4gICAgICAgIGZvciAodmFyIGEgPSBhcmd1bWVudHNbaV0sIGogPSAwLCBqbCA9IGEubGVuZ3RoOyBqIDwgamw7IGorKywgaysrKVxyXG4gICAgICAgICAgICByW2tdID0gYVtqXTtcclxuICAgIHJldHVybiByO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXQodikge1xyXG4gICAgcmV0dXJuIHRoaXMgaW5zdGFuY2VvZiBfX2F3YWl0ID8gKHRoaXMudiA9IHYsIHRoaXMpIDogbmV3IF9fYXdhaXQodik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jR2VuZXJhdG9yKHRoaXNBcmcsIF9hcmd1bWVudHMsIGdlbmVyYXRvcikge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBnID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pLCBpLCBxID0gW107XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaWYgKGdbbl0pIGlbbl0gPSBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKGEsIGIpIHsgcS5wdXNoKFtuLCB2LCBhLCBiXSkgPiAxIHx8IHJlc3VtZShuLCB2KTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHJlc3VtZShuLCB2KSB7IHRyeSB7IHN0ZXAoZ1tuXSh2KSk7IH0gY2F0Y2ggKGUpIHsgc2V0dGxlKHFbMF1bM10sIGUpOyB9IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAocikgeyByLnZhbHVlIGluc3RhbmNlb2YgX19hd2FpdCA/IFByb21pc2UucmVzb2x2ZShyLnZhbHVlLnYpLnRoZW4oZnVsZmlsbCwgcmVqZWN0KSA6IHNldHRsZShxWzBdWzJdLCByKTsgfVxyXG4gICAgZnVuY3Rpb24gZnVsZmlsbCh2YWx1ZSkgeyByZXN1bWUoXCJuZXh0XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gcmVqZWN0KHZhbHVlKSB7IHJlc3VtZShcInRocm93XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKGYsIHYpIHsgaWYgKGYodiksIHEuc2hpZnQoKSwgcS5sZW5ndGgpIHJlc3VtZShxWzBdWzBdLCBxWzBdWzFdKTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0RlbGVnYXRvcihvKSB7XHJcbiAgICB2YXIgaSwgcDtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiwgZnVuY3Rpb24gKGUpIHsgdGhyb3cgZTsgfSksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4sIGYpIHsgaVtuXSA9IG9bbl0gPyBmdW5jdGlvbiAodikgeyByZXR1cm4gKHAgPSAhcCkgPyB7IHZhbHVlOiBfX2F3YWl0KG9bbl0odikpLCBkb25lOiBuID09PSBcInJldHVyblwiIH0gOiBmID8gZih2KSA6IHY7IH0gOiBmOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jVmFsdWVzKG8pIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgbSA9IG9bU3ltYm9sLmFzeW5jSXRlcmF0b3JdLCBpO1xyXG4gICAgcmV0dXJuIG0gPyBtLmNhbGwobykgOiAobyA9IHR5cGVvZiBfX3ZhbHVlcyA9PT0gXCJmdW5jdGlvblwiID8gX192YWx1ZXMobykgOiBvW1N5bWJvbC5pdGVyYXRvcl0oKSwgaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGkpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlbbl0gPSBvW25dICYmIGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7IHYgPSBvW25dKHYpLCBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCB2LmRvbmUsIHYudmFsdWUpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgZCwgdikgeyBQcm9taXNlLnJlc29sdmUodikudGhlbihmdW5jdGlvbih2KSB7IHJlc29sdmUoeyB2YWx1ZTogdiwgZG9uZTogZCB9KTsgfSwgcmVqZWN0KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tYWtlVGVtcGxhdGVPYmplY3QoY29va2VkLCByYXcpIHtcclxuICAgIGlmIChPYmplY3QuZGVmaW5lUHJvcGVydHkpIHsgT2JqZWN0LmRlZmluZVByb3BlcnR5KGNvb2tlZCwgXCJyYXdcIiwgeyB2YWx1ZTogcmF3IH0pOyB9IGVsc2UgeyBjb29rZWQucmF3ID0gcmF3OyB9XHJcbiAgICByZXR1cm4gY29va2VkO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0U3Rhcihtb2QpIHtcclxuICAgIGlmIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpIHJldHVybiBtb2Q7XHJcbiAgICB2YXIgcmVzdWx0ID0ge307XHJcbiAgICBpZiAobW9kICE9IG51bGwpIGZvciAodmFyIGsgaW4gbW9kKSBpZiAoT2JqZWN0Lmhhc093blByb3BlcnR5LmNhbGwobW9kLCBrKSkgcmVzdWx0W2tdID0gbW9kW2tdO1xyXG4gICAgcmVzdWx0LmRlZmF1bHQgPSBtb2Q7XHJcbiAgICByZXR1cm4gcmVzdWx0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnREZWZhdWx0KG1vZCkge1xyXG4gICAgcmV0dXJuIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpID8gbW9kIDogeyBkZWZhdWx0OiBtb2QgfTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRHZXQocmVjZWl2ZXIsIHByaXZhdGVNYXApIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBnZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcHJpdmF0ZU1hcC5nZXQocmVjZWl2ZXIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZFNldChyZWNlaXZlciwgcHJpdmF0ZU1hcCwgdmFsdWUpIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBzZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICBwcml2YXRlTWFwLnNldChyZWNlaXZlciwgdmFsdWUpO1xyXG4gICAgcmV0dXJuIHZhbHVlO1xyXG59XHJcbiIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduLCBfX2V4dGVuZHMgfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IGVuY29kZUZvcm1EYXRhIH0gZnJvbSBcIi4vdXRpbHMvZW5jb2RlLWZvcm0tZGF0YVwiO1xuaW1wb3J0IHsgZW5jb2RlUXVlcnlTdHJpbmcgfSBmcm9tIFwiLi91dGlscy9lbmNvZGUtcXVlcnktc3RyaW5nXCI7XG5pbXBvcnQgeyByZXF1aXJlc0Zvcm1EYXRhIH0gZnJvbSBcIi4vdXRpbHMvcHJvY2Vzcy1wYXJhbXNcIjtcbmltcG9ydCB7IEFyY0dJU1JlcXVlc3RFcnJvciB9IGZyb20gXCIuL3V0aWxzL0FyY0dJU1JlcXVlc3RFcnJvclwiO1xuaW1wb3J0IHsgd2FybiB9IGZyb20gXCIuL3V0aWxzL3dhcm5cIjtcbmV4cG9ydCB2YXIgTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVIgPSBcIkBlc3JpL2FyY2dpcy1yZXN0LWpzXCI7XG52YXIgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TID0ge1xuICAgIGh0dHBNZXRob2Q6IFwiUE9TVFwiLFxuICAgIHBhcmFtczoge1xuICAgICAgICBmOiBcImpzb25cIixcbiAgICB9LFxufTtcbi8qKlxuICogU2V0cyB0aGUgZGVmYXVsdCBvcHRpb25zIHRoYXQgd2lsbCBiZSBwYXNzZWQgaW4gKiphbGwgcmVxdWVzdHMgYWNyb3NzIGFsbCBgQGVzcmkvYXJjZ2lzLXJlc3QtanNgIG1vZHVsZXMqKi5cbiAqXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHNldERlZmF1bHRSZXF1ZXN0T3B0aW9ucyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4gKiBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnMoe1xuICogICBhdXRoZW50aWNhdGlvbjogdXNlclNlc3Npb24gLy8gYWxsIHJlcXVlc3RzIHdpbGwgdXNlIHRoaXMgc2Vzc2lvbiBieSBkZWZhdWx0XG4gKiB9KVxuICogYGBgXG4gKiBZb3Ugc2hvdWxkICoqbmV2ZXIqKiBzZXQgYSBkZWZhdWx0IGBhdXRoZW50aWNhdGlvbmAgd2hlbiB5b3UgYXJlIGluIGEgc2VydmVyIHNpZGUgZW52aXJvbm1lbnQgd2hlcmUgeW91IG1heSBiZSBoYW5kbGluZyByZXF1ZXN0cyBmb3IgbWFueSBkaWZmZXJlbnQgYXV0aGVudGljYXRlZCB1c2Vycy5cbiAqXG4gKiBAcGFyYW0gb3B0aW9ucyBUaGUgZGVmYXVsdCBvcHRpb25zIHRvIHBhc3Mgd2l0aCBldmVyeSByZXF1ZXN0LiBFeGlzdGluZyBkZWZhdWx0IHdpbGwgYmUgb3ZlcndyaXR0ZW4uXG4gKiBAcGFyYW0gaGlkZVdhcm5pbmdzIFNpbGVuY2Ugd2FybmluZ3MgYWJvdXQgc2V0dGluZyBkZWZhdWx0IGBhdXRoZW50aWNhdGlvbmAgaW4gc2hhcmVkIGVudmlyb25tZW50cy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHNldERlZmF1bHRSZXF1ZXN0T3B0aW9ucyhvcHRpb25zLCBoaWRlV2FybmluZ3MpIHtcbiAgICBpZiAob3B0aW9ucy5hdXRoZW50aWNhdGlvbiAmJiAhaGlkZVdhcm5pbmdzKSB7XG4gICAgICAgIHdhcm4oXCJZb3Ugc2hvdWxkIG5vdCBzZXQgYGF1dGhlbnRpY2F0aW9uYCBhcyBhIGRlZmF1bHQgaW4gYSBzaGFyZWQgZW52aXJvbm1lbnQgc3VjaCBhcyBhIHdlYiBzZXJ2ZXIgd2hpY2ggd2lsbCBwcm9jZXNzIG11bHRpcGxlIHVzZXJzIHJlcXVlc3RzLiBZb3UgY2FuIGNhbGwgYHNldERlZmF1bHRSZXF1ZXN0T3B0aW9uc2Agd2l0aCBgdHJ1ZWAgYXMgYSBzZWNvbmQgYXJndW1lbnQgdG8gZGlzYWJsZSB0aGlzIHdhcm5pbmcuXCIpO1xuICAgIH1cbiAgICBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMgPSBvcHRpb25zO1xufVxudmFyIEFyY0dJU0F1dGhFcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQXJjR0lTQXV0aEVycm9yLCBfc3VwZXIpO1xuICAgIC8qKlxuICAgICAqIENyZWF0ZSBhIG5ldyBgQXJjR0lTQXV0aEVycm9yYCAgb2JqZWN0LlxuICAgICAqXG4gICAgICogQHBhcmFtIG1lc3NhZ2UgLSBUaGUgZXJyb3IgbWVzc2FnZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gY29kZSAtIFRoZSBlcnJvciBjb2RlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSByZXNwb25zZSAtIFRoZSBvcmlnaW5hbCByZXNwb25zZSBmcm9tIHRoZSBBUEkgdGhhdCBjYXVzZWQgdGhlIGVycm9yXG4gICAgICogQHBhcmFtIHVybCAtIFRoZSBvcmlnaW5hbCB1cmwgb2YgdGhlIHJlcXVlc3RcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyAtIFRoZSBvcmlnaW5hbCBvcHRpb25zIG9mIHRoZSByZXF1ZXN0XG4gICAgICovXG4gICAgZnVuY3Rpb24gQXJjR0lTQXV0aEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpIHtcbiAgICAgICAgaWYgKG1lc3NhZ2UgPT09IHZvaWQgMCkgeyBtZXNzYWdlID0gXCJBVVRIRU5USUNBVElPTl9FUlJPUlwiOyB9XG4gICAgICAgIGlmIChjb2RlID09PSB2b2lkIDApIHsgY29kZSA9IFwiQVVUSEVOVElDQVRJT05fRVJST1JfQ09ERVwiOyB9XG4gICAgICAgIHZhciBfdGhpcyA9IF9zdXBlci5jYWxsKHRoaXMsIG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpIHx8IHRoaXM7XG4gICAgICAgIF90aGlzLm5hbWUgPSBcIkFyY0dJU0F1dGhFcnJvclwiO1xuICAgICAgICBfdGhpcy5tZXNzYWdlID1cbiAgICAgICAgICAgIGNvZGUgPT09IFwiQVVUSEVOVElDQVRJT05fRVJST1JfQ09ERVwiID8gbWVzc2FnZSA6IGNvZGUgKyBcIjogXCIgKyBtZXNzYWdlO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIEFyY0dJU0F1dGhFcnJvci5wcm90b3R5cGUucmV0cnkgPSBmdW5jdGlvbiAoZ2V0U2Vzc2lvbiwgcmV0cnlMaW1pdCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAocmV0cnlMaW1pdCA9PT0gdm9pZCAwKSB7IHJldHJ5TGltaXQgPSAzOyB9XG4gICAgICAgIHZhciB0cmllcyA9IDA7XG4gICAgICAgIHZhciByZXRyeVJlcXVlc3QgPSBmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgICBnZXRTZXNzaW9uKF90aGlzLnVybCwgX3RoaXMub3B0aW9ucylcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAoc2Vzc2lvbikge1xuICAgICAgICAgICAgICAgIHZhciBuZXdPcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oe30sIF90aGlzLm9wdGlvbnMpLCB7IGF1dGhlbnRpY2F0aW9uOiBzZXNzaW9uIH0pO1xuICAgICAgICAgICAgICAgIHRyaWVzID0gdHJpZXMgKyAxO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXF1ZXN0KF90aGlzLnVybCwgbmV3T3B0aW9ucyk7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIHJlc29sdmUocmVzcG9uc2UpO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKGUpIHtcbiAgICAgICAgICAgICAgICBpZiAoZS5uYW1lID09PSBcIkFyY0dJU0F1dGhFcnJvclwiICYmIHRyaWVzIDwgcmV0cnlMaW1pdCkge1xuICAgICAgICAgICAgICAgICAgICByZXRyeVJlcXVlc3QocmVzb2x2ZSwgcmVqZWN0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoZS5uYW1lID09PSBcIkFyY0dJU0F1dGhFcnJvclwiICYmIHRyaWVzID49IHJldHJ5TGltaXQpIHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KF90aGlzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgICAgIHJldHJ5UmVxdWVzdChyZXNvbHZlLCByZWplY3QpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBBcmNHSVNBdXRoRXJyb3I7XG59KEFyY0dJU1JlcXVlc3RFcnJvcikpO1xuZXhwb3J0IHsgQXJjR0lTQXV0aEVycm9yIH07XG4vKipcbiAqIENoZWNrcyBmb3IgZXJyb3JzIGluIGEgSlNPTiByZXNwb25zZSBmcm9tIHRoZSBBcmNHSVMgUkVTVCBBUEkuIElmIHRoZXJlIGFyZSBubyBlcnJvcnMsIGl0IHdpbGwgcmV0dXJuIHRoZSBgZGF0YWAgcGFzc2VkIGluLiBJZiB0aGVyZSBpcyBhbiBlcnJvciwgaXQgd2lsbCB0aHJvdyBhbiBgQXJjR0lTUmVxdWVzdEVycm9yYCBvciBgQXJjR0lTQXV0aEVycm9yYC5cbiAqXG4gKiBAcGFyYW0gZGF0YSBUaGUgcmVzcG9uc2UgSlNPTiB0byBjaGVjayBmb3IgZXJyb3JzLlxuICogQHBhcmFtIHVybCBUaGUgdXJsIG9mIHRoZSBvcmlnaW5hbCByZXF1ZXN0XG4gKiBAcGFyYW0gcGFyYW1zIFRoZSBwYXJhbWV0ZXJzIG9mIHRoZSBvcmlnaW5hbCByZXF1ZXN0XG4gKiBAcGFyYW0gb3B0aW9ucyBUaGUgb3B0aW9ucyBvZiB0aGUgb3JpZ2luYWwgcmVxdWVzdFxuICogQHJldHVybnMgVGhlIGRhdGEgdGhhdCB3YXMgcGFzc2VkIGluIHRoZSBgZGF0YWAgcGFyYW1ldGVyXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjaGVja0ZvckVycm9ycyhyZXNwb25zZSwgdXJsLCBwYXJhbXMsIG9wdGlvbnMsIG9yaWdpbmFsQXV0aEVycm9yKSB7XG4gICAgLy8gdGhpcyBpcyBhbiBlcnJvciBtZXNzYWdlIGZyb20gYmlsbGluZy5hcmNnaXMuY29tIGJhY2tlbmRcbiAgICBpZiAocmVzcG9uc2UuY29kZSA+PSA0MDApIHtcbiAgICAgICAgdmFyIG1lc3NhZ2UgPSByZXNwb25zZS5tZXNzYWdlLCBjb2RlID0gcmVzcG9uc2UuY29kZTtcbiAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICB9XG4gICAgLy8gZXJyb3IgZnJvbSBBcmNHSVMgT25saW5lIG9yIGFuIEFyY0dJUyBQb3J0YWwgb3Igc2VydmVyIGluc3RhbmNlLlxuICAgIGlmIChyZXNwb25zZS5lcnJvcikge1xuICAgICAgICB2YXIgX2EgPSByZXNwb25zZS5lcnJvciwgbWVzc2FnZSA9IF9hLm1lc3NhZ2UsIGNvZGUgPSBfYS5jb2RlLCBtZXNzYWdlQ29kZSA9IF9hLm1lc3NhZ2VDb2RlO1xuICAgICAgICB2YXIgZXJyb3JDb2RlID0gbWVzc2FnZUNvZGUgfHwgY29kZSB8fCBcIlVOS05PV05fRVJST1JfQ09ERVwiO1xuICAgICAgICBpZiAoY29kZSA9PT0gNDk4IHx8XG4gICAgICAgICAgICBjb2RlID09PSA0OTkgfHxcbiAgICAgICAgICAgIG1lc3NhZ2VDb2RlID09PSBcIkdXTV8wMDAzXCIgfHxcbiAgICAgICAgICAgIChjb2RlID09PSA0MDAgJiYgbWVzc2FnZSA9PT0gXCJVbmFibGUgdG8gZ2VuZXJhdGUgdG9rZW4uXCIpKSB7XG4gICAgICAgICAgICBpZiAob3JpZ2luYWxBdXRoRXJyb3IpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBvcmlnaW5hbEF1dGhFcnJvcjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IobWVzc2FnZSwgZXJyb3JDb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGVycm9yQ29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgfVxuICAgIC8vIGVycm9yIGZyb20gYSBzdGF0dXMgY2hlY2tcbiAgICBpZiAocmVzcG9uc2Uuc3RhdHVzID09PSBcImZhaWxlZFwiIHx8IHJlc3BvbnNlLnN0YXR1cyA9PT0gXCJmYWlsdXJlXCIpIHtcbiAgICAgICAgdmFyIG1lc3NhZ2UgPSB2b2lkIDA7XG4gICAgICAgIHZhciBjb2RlID0gXCJVTktOT1dOX0VSUk9SX0NPREVcIjtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIG1lc3NhZ2UgPSBKU09OLnBhcnNlKHJlc3BvbnNlLnN0YXR1c01lc3NhZ2UpLm1lc3NhZ2U7XG4gICAgICAgICAgICBjb2RlID0gSlNPTi5wYXJzZShyZXNwb25zZS5zdGF0dXNNZXNzYWdlKS5jb2RlO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICBtZXNzYWdlID0gcmVzcG9uc2Uuc3RhdHVzTWVzc2FnZSB8fCByZXNwb25zZS5tZXNzYWdlO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgfVxuICAgIHJldHVybiByZXNwb25zZTtcbn1cbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IHJlcXVlc3QgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0JztcbiAqIC8vXG4gKiByZXF1ZXN0KCdodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdCcpXG4gKiAgIC50aGVuKHJlc3BvbnNlKSAvLyByZXNwb25zZS5jdXJyZW50VmVyc2lvbiA9PT0gNS4yXG4gKiAvL1xuICogcmVxdWVzdCgnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3QnLCB7XG4gKiAgIGh0dHBNZXRob2Q6IFwiR0VUXCJcbiAqIH0pXG4gKiAvL1xuICogcmVxdWVzdCgnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3Qvc2VhcmNoJywge1xuICogICBwYXJhbXM6IHsgcTogJ3BhcmtzJyB9XG4gKiB9KVxuICogICAudGhlbihyZXNwb25zZSkgLy8gcmVzcG9uc2UudG90YWwgPT4gNzgzNzlcbiAqIGBgYFxuICogR2VuZXJpYyBtZXRob2QgZm9yIG1ha2luZyBIVFRQIHJlcXVlc3RzIHRvIEFyY0dJUyBSRVNUIEFQSSBlbmRwb2ludHMuXG4gKlxuICogQHBhcmFtIHVybCAtIFRoZSBVUkwgb2YgdGhlIEFyY0dJUyBSRVNUIEFQSSBlbmRwb2ludC5cbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LCBpbmNsdWRpbmcgcGFyYW1ldGVycyByZWxldmFudCB0byB0aGUgZW5kcG9pbnQuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGF0YSBmcm9tIHRoZSByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHJlcXVlc3QodXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgIGlmIChyZXF1ZXN0T3B0aW9ucyA9PT0gdm9pZCAwKSB7IHJlcXVlc3RPcHRpb25zID0geyBwYXJhbXM6IHsgZjogXCJqc29uXCIgfSB9OyB9XG4gICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbihfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiUE9TVFwiIH0sIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUyksIHJlcXVlc3RPcHRpb25zKSwge1xuICAgICAgICBwYXJhbXM6IF9fYXNzaWduKF9fYXNzaWduKHt9LCBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMucGFyYW1zKSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSxcbiAgICAgICAgaGVhZGVyczogX19hc3NpZ24oX19hc3NpZ24oe30sIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUy5oZWFkZXJzKSwgcmVxdWVzdE9wdGlvbnMuaGVhZGVycyksXG4gICAgfSk7XG4gICAgdmFyIG1pc3NpbmdHbG9iYWxzID0gW107XG4gICAgdmFyIHJlY29tbWVuZGVkUGFja2FnZXMgPSBbXTtcbiAgICAvLyBkb24ndCBjaGVjayBmb3IgYSBnbG9iYWwgZmV0Y2ggaWYgYSBjdXN0b20gaW1wbGVtZW50YXRpb24gd2FzIHBhc3NlZCB0aHJvdWdoXG4gICAgaWYgKCFvcHRpb25zLmZldGNoICYmIHR5cGVvZiBmZXRjaCAhPT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICBvcHRpb25zLmZldGNoID0gZmV0Y2guYmluZChGdW5jdGlvbihcInJldHVybiB0aGlzXCIpKCkpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgbWlzc2luZ0dsb2JhbHMucHVzaChcImBmZXRjaGBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBub2RlLWZldGNoYFwiKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBQcm9taXNlID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIG1pc3NpbmdHbG9iYWxzLnB1c2goXCJgUHJvbWlzZWBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBlczYtcHJvbWlzZWBcIik7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgRm9ybURhdGEgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgbWlzc2luZ0dsb2JhbHMucHVzaChcImBGb3JtRGF0YWBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBpc29tb3JwaGljLWZvcm0tZGF0YWBcIik7XG4gICAgfVxuICAgIGlmICghb3B0aW9ucy5mZXRjaCB8fFxuICAgICAgICB0eXBlb2YgUHJvbWlzZSA9PT0gXCJ1bmRlZmluZWRcIiB8fFxuICAgICAgICB0eXBlb2YgRm9ybURhdGEgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiYGFyY2dpcy1yZXN0LXJlcXVlc3RgIHJlcXVpcmVzIGEgYGZldGNoYCBpbXBsZW1lbnRhdGlvbiBhbmQgZ2xvYmFsIHZhcmlhYmxlcyBmb3IgYFByb21pc2VgIGFuZCBgRm9ybURhdGFgIHRvIGJlIHByZXNlbnQgaW4gdGhlIGdsb2JhbCBzY29wZS4gWW91IGFyZSBtaXNzaW5nIFwiICsgbWlzc2luZ0dsb2JhbHMuam9pbihcIiwgXCIpICsgXCIuIFdlIHJlY29tbWVuZCBpbnN0YWxsaW5nIHRoZSBcIiArIHJlY29tbWVuZGVkUGFja2FnZXMuam9pbihcIiwgXCIpICsgXCIgbW9kdWxlcyBhdCB0aGUgcm9vdCBvZiB5b3VyIGFwcGxpY2F0aW9uIHRvIGFkZCB0aGVzZSB0byB0aGUgZ2xvYmFsIHNjb3BlLiBTZWUgaHR0cHM6Ly9iaXQubHkvMktOd1dhSiBmb3IgbW9yZSBpbmZvLlwiKTtcbiAgICB9XG4gICAgdmFyIGh0dHBNZXRob2QgPSBvcHRpb25zLmh0dHBNZXRob2QsIGF1dGhlbnRpY2F0aW9uID0gb3B0aW9ucy5hdXRoZW50aWNhdGlvbiwgcmF3UmVzcG9uc2UgPSBvcHRpb25zLnJhd1Jlc3BvbnNlO1xuICAgIHZhciBwYXJhbXMgPSBfX2Fzc2lnbih7IGY6IFwianNvblwiIH0sIG9wdGlvbnMucGFyYW1zKTtcbiAgICB2YXIgb3JpZ2luYWxBdXRoRXJyb3IgPSBudWxsO1xuICAgIHZhciBmZXRjaE9wdGlvbnMgPSB7XG4gICAgICAgIG1ldGhvZDogaHR0cE1ldGhvZCxcbiAgICAgICAgLyogZW5zdXJlcyBiZWhhdmlvciBtaW1pY3MgWE1MSHR0cFJlcXVlc3QuXG4gICAgICAgIG5lZWRlZCB0byBzdXBwb3J0IHNlbmRpbmcgSVdBIGNvb2tpZXMgKi9cbiAgICAgICAgY3JlZGVudGlhbHM6IG9wdGlvbnMuY3JlZGVudGlhbHMgfHwgXCJzYW1lLW9yaWdpblwiLFxuICAgIH07XG4gICAgLy8gdGhlIC9vYXV0aDIvcGxhdGZvcm1TZWxmIHJvdXRlIHdpbGwgYWRkIFgtRXNyaS1BdXRoLUNsaWVudC1JZCBoZWFkZXJcbiAgICAvLyBhbmQgdGhhdCByZXF1ZXN0IG5lZWRzIHRvIHNlbmQgY29va2llcyBjcm9zcyBkb21haW5cbiAgICAvLyBzbyB3ZSBuZWVkIHRvIHNldCB0aGUgY3JlZGVudGlhbHMgdG8gXCJpbmNsdWRlXCJcbiAgICBpZiAob3B0aW9ucy5oZWFkZXJzICYmXG4gICAgICAgIG9wdGlvbnMuaGVhZGVyc1tcIlgtRXNyaS1BdXRoLUNsaWVudC1JZFwiXSAmJlxuICAgICAgICB1cmwuaW5kZXhPZihcIi9vYXV0aDIvcGxhdGZvcm1TZWxmXCIpID4gLTEpIHtcbiAgICAgICAgZmV0Y2hPcHRpb25zLmNyZWRlbnRpYWxzID0gXCJpbmNsdWRlXCI7XG4gICAgfVxuICAgIHJldHVybiAoYXV0aGVudGljYXRpb25cbiAgICAgICAgPyBhdXRoZW50aWNhdGlvbi5nZXRUb2tlbih1cmwsIHsgZmV0Y2g6IG9wdGlvbnMuZmV0Y2ggfSkuY2F0Y2goZnVuY3Rpb24gKGVycikge1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBhcHBlbmQgb3JpZ2luYWwgcmVxdWVzdCB1cmwgYW5kIHJlcXVlc3RPcHRpb25zXG4gICAgICAgICAgICAgKiB0byB0aGUgZXJyb3IgdGhyb3duIGJ5IGdldFRva2VuKClcbiAgICAgICAgICAgICAqIHRvIGFzc2lzdCB3aXRoIHJldHJ5aW5nXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGVyci51cmwgPSB1cmw7XG4gICAgICAgICAgICBlcnIub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIGlmIGFuIGF0dGVtcHQgaXMgbWFkZSB0byB0YWxrIHRvIGFuIHVuZmVkZXJhdGVkIHNlcnZlclxuICAgICAgICAgICAgICogZmlyc3QgdHJ5IHRoZSByZXF1ZXN0IGFub255bW91c2x5LiBpZiBhICd0b2tlbiByZXF1aXJlZCdcbiAgICAgICAgICAgICAqIGVycm9yIGlzIHRocm93biwgdGhyb3cgdGhlIFVORkVERVJBVEVEIGVycm9yIHRoZW4uXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIG9yaWdpbmFsQXV0aEVycm9yID0gZXJyO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShcIlwiKTtcbiAgICAgICAgfSlcbiAgICAgICAgOiBQcm9taXNlLnJlc29sdmUoXCJcIikpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uICh0b2tlbikge1xuICAgICAgICBpZiAodG9rZW4ubGVuZ3RoKSB7XG4gICAgICAgICAgICBwYXJhbXMudG9rZW4gPSB0b2tlbjtcbiAgICAgICAgfVxuICAgICAgICBpZiAoYXV0aGVudGljYXRpb24gJiYgYXV0aGVudGljYXRpb24uZ2V0RG9tYWluQ3JlZGVudGlhbHMpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5jcmVkZW50aWFscyA9IGF1dGhlbnRpY2F0aW9uLmdldERvbWFpbkNyZWRlbnRpYWxzKHVybCk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gQ3VzdG9tIGhlYWRlcnMgdG8gYWRkIHRvIHJlcXVlc3QuIElSZXF1ZXN0T3B0aW9ucy5oZWFkZXJzIHdpdGggbWVyZ2Ugb3ZlciByZXF1ZXN0SGVhZGVycy5cbiAgICAgICAgdmFyIHJlcXVlc3RIZWFkZXJzID0ge307XG4gICAgICAgIGlmIChmZXRjaE9wdGlvbnMubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICAgICAgICAvLyBQcmV2ZW50cyB0b2tlbiBmcm9tIGJlaW5nIHBhc3NlZCBpbiBxdWVyeSBwYXJhbXMgd2hlbiBoaWRlVG9rZW4gb3B0aW9uIGlzIHVzZWQuXG4gICAgICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgaWYgLSB3aW5kb3cgaXMgYWx3YXlzIGRlZmluZWQgaW4gYSBicm93c2VyLiBUZXN0IGNhc2UgaXMgY292ZXJlZCBieSBKYXNtaW5lIGluIG5vZGUgdGVzdCAqL1xuICAgICAgICAgICAgaWYgKHBhcmFtcy50b2tlbiAmJlxuICAgICAgICAgICAgICAgIG9wdGlvbnMuaGlkZVRva2VuICYmXG4gICAgICAgICAgICAgICAgLy8gU2hhcmluZyBBUEkgZG9lcyBub3Qgc3VwcG9ydCBwcmVmbGlnaHQgY2hlY2sgcmVxdWlyZWQgYnkgbW9kZXJuIGJyb3dzZXJzIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvR2xvc3NhcnkvUHJlZmxpZ2h0X3JlcXVlc3RcbiAgICAgICAgICAgICAgICB0eXBlb2Ygd2luZG93ID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgICAgICAgICAgcmVxdWVzdEhlYWRlcnNbXCJYLUVzcmktQXV0aG9yaXphdGlvblwiXSA9IFwiQmVhcmVyIFwiICsgcGFyYW1zLnRva2VuO1xuICAgICAgICAgICAgICAgIGRlbGV0ZSBwYXJhbXMudG9rZW47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBlbmNvZGUgdGhlIHBhcmFtZXRlcnMgaW50byB0aGUgcXVlcnkgc3RyaW5nXG4gICAgICAgICAgICB2YXIgcXVlcnlQYXJhbXMgPSBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgICAgICAgICAgLy8gZG9udCBhcHBlbmQgYSAnPycgdW5sZXNzIHBhcmFtZXRlcnMgYXJlIGFjdHVhbGx5IHByZXNlbnRcbiAgICAgICAgICAgIHZhciB1cmxXaXRoUXVlcnlTdHJpbmcgPSBxdWVyeVBhcmFtcyA9PT0gXCJcIiA/IHVybCA6IHVybCArIFwiP1wiICsgZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgIC8vIFRoaXMgd291bGQgZXhjZWVkIHRoZSBtYXhpbXVtIGxlbmd0aCBmb3IgVVJMcyBzcGVjaWZpZWQgYnkgdGhlIGNvbnN1bWVyIGFuZCByZXF1aXJlcyBQT1NUXG4gICAgICAgICAgICAob3B0aW9ucy5tYXhVcmxMZW5ndGggJiZcbiAgICAgICAgICAgICAgICB1cmxXaXRoUXVlcnlTdHJpbmcubGVuZ3RoID4gb3B0aW9ucy5tYXhVcmxMZW5ndGgpIHx8XG4gICAgICAgICAgICAgICAgLy8gT3IgaWYgdGhlIGN1c3RvbWVyIHJlcXVpcmVzIHRoZSB0b2tlbiB0byBiZSBoaWRkZW4gYW5kIGl0IGhhcyBub3QgYWxyZWFkeSBiZWVuIGhpZGRlbiBpbiB0aGUgaGVhZGVyIChmb3IgYnJvd3NlcnMpXG4gICAgICAgICAgICAgICAgKHBhcmFtcy50b2tlbiAmJiBvcHRpb25zLmhpZGVUb2tlbikpIHtcbiAgICAgICAgICAgICAgICAvLyB0aGUgY29uc3VtZXIgc3BlY2lmaWVkIGEgbWF4aW11bSBsZW5ndGggZm9yIFVSTHNcbiAgICAgICAgICAgICAgICAvLyBhbmQgdGhpcyB3b3VsZCBleGNlZWQgaXQsIHNvIHVzZSBwb3N0IGluc3RlYWRcbiAgICAgICAgICAgICAgICBmZXRjaE9wdGlvbnMubWV0aG9kID0gXCJQT1NUXCI7XG4gICAgICAgICAgICAgICAgLy8gSWYgdGhlIHRva2VuIHdhcyBhbHJlYWR5IGFkZGVkIGFzIGEgQXV0aCBoZWFkZXIsIGFkZCB0aGUgdG9rZW4gYmFjayB0byBib2R5IHdpdGggb3RoZXIgcGFyYW1zIGluc3RlYWQgb2YgaGVhZGVyXG4gICAgICAgICAgICAgICAgaWYgKHRva2VuLmxlbmd0aCAmJiBvcHRpb25zLmhpZGVUb2tlbikge1xuICAgICAgICAgICAgICAgICAgICBwYXJhbXMudG9rZW4gPSB0b2tlbjtcbiAgICAgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIGV4aXN0aW5nIGhlYWRlciB0aGF0IHdhcyBhZGRlZCBiZWZvcmUgdXJsIHF1ZXJ5IGxlbmd0aCB3YXMgY2hlY2tlZFxuICAgICAgICAgICAgICAgICAgICBkZWxldGUgcmVxdWVzdEhlYWRlcnNbXCJYLUVzcmktQXV0aG9yaXphdGlvblwiXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAvLyBqdXN0IHVzZSBHRVRcbiAgICAgICAgICAgICAgICB1cmwgPSB1cmxXaXRoUXVlcnlTdHJpbmc7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgLyogdXBkYXRlUmVzb3VyY2VzIGN1cnJlbnRseSByZXF1aXJlcyBGb3JtRGF0YSBldmVuIHdoZW4gdGhlIGlucHV0IHBhcmFtZXRlcnMgZG9udCB3YXJyYW50IGl0LlxuICAgIGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy91cGRhdGUtcmVzb3VyY2VzLmh0bVxuICAgICAgICBzZWUgaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvcHVsbC81MDAgZm9yIG1vcmUgaW5mby4gKi9cbiAgICAgICAgdmFyIGZvcmNlRm9ybURhdGEgPSBuZXcgUmVnRXhwKFwiL2l0ZW1zLy4rL3VwZGF0ZVJlc291cmNlc1wiKS50ZXN0KHVybCk7XG4gICAgICAgIGlmIChmZXRjaE9wdGlvbnMubWV0aG9kID09PSBcIlBPU1RcIikge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmJvZHkgPSBlbmNvZGVGb3JtRGF0YShwYXJhbXMsIGZvcmNlRm9ybURhdGEpO1xuICAgICAgICB9XG4gICAgICAgIC8vIE1peGluIGhlYWRlcnMgZnJvbSByZXF1ZXN0IG9wdGlvbnNcbiAgICAgICAgZmV0Y2hPcHRpb25zLmhlYWRlcnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgcmVxdWVzdEhlYWRlcnMpLCBvcHRpb25zLmhlYWRlcnMpO1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAtIGthcm1hIHJlcG9ydHMgY292ZXJhZ2Ugb24gYnJvd3NlciB0ZXN0cyBvbmx5ICovXG4gICAgICAgIGlmICh0eXBlb2Ygd2luZG93ID09PSBcInVuZGVmaW5lZFwiICYmICFmZXRjaE9wdGlvbnMuaGVhZGVycy5yZWZlcmVyKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuaGVhZGVycy5yZWZlcmVyID0gTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVI7XG4gICAgICAgIH1cbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIGVsc2UgYmxvYiByZXNwb25zZXMgYXJlIGRpZmZpY3VsdCB0byBtYWtlIGNyb3NzIHBsYXRmb3JtIHdlIHdpbGwganVzdCBoYXZlIHRvIHRydXN0IHRoZSBpc29tb3JwaGljIGZldGNoIHdpbGwgZG8gaXRzIGpvYiAqL1xuICAgICAgICBpZiAoIXJlcXVpcmVzRm9ybURhdGEocGFyYW1zKSAmJiAhZm9yY2VGb3JtRGF0YSkge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmhlYWRlcnNbXCJDb250ZW50LVR5cGVcIl0gPVxuICAgICAgICAgICAgICAgIFwiYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkXCI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIG9wdGlvbnMuZmV0Y2godXJsLCBmZXRjaE9wdGlvbnMpO1xuICAgIH0pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBpZiAoIXJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAvLyBzZXJ2ZXIgcmVzcG9uZGVkIHcvIGFuIGFjdHVhbCBlcnJvciAoNDA0LCA1MDAsIGV0YylcbiAgICAgICAgICAgIHZhciBzdGF0dXNfMSA9IHJlc3BvbnNlLnN0YXR1cywgc3RhdHVzVGV4dCA9IHJlc3BvbnNlLnN0YXR1c1RleHQ7XG4gICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKHN0YXR1c1RleHQsIFwiSFRUUCBcIiArIHN0YXR1c18xLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAocmF3UmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfVxuICAgICAgICBzd2l0Y2ggKHBhcmFtcy5mKSB7XG4gICAgICAgICAgICBjYXNlIFwianNvblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICBjYXNlIFwiZ2VvanNvblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICBjYXNlIFwiaHRtbFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS50ZXh0KCk7XG4gICAgICAgICAgICBjYXNlIFwidGV4dFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS50ZXh0KCk7XG4gICAgICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCBibG9iIHJlc3BvbnNlcyBhcmUgZGlmZmljdWx0IHRvIG1ha2UgY3Jvc3MgcGxhdGZvcm0gd2Ugd2lsbCBqdXN0IGhhdmUgdG8gdHJ1c3QgdGhhdCBpc29tb3JwaGljIGZldGNoIHdpbGwgZG8gaXRzIGpvYiAqL1xuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuYmxvYigpO1xuICAgICAgICB9XG4gICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgaWYgKChwYXJhbXMuZiA9PT0gXCJqc29uXCIgfHwgcGFyYW1zLmYgPT09IFwiZ2VvanNvblwiKSAmJiAhcmF3UmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciByZXNwb25zZSA9IGNoZWNrRm9yRXJyb3JzKGRhdGEsIHVybCwgcGFyYW1zLCBvcHRpb25zLCBvcmlnaW5hbEF1dGhFcnJvcik7XG4gICAgICAgICAgICBpZiAob3JpZ2luYWxBdXRoRXJyb3IpIHtcbiAgICAgICAgICAgICAgICAvKiBJZiB0aGUgcmVxdWVzdCB3YXMgbWFkZSB0byBhbiB1bmZlZGVyYXRlZCBzZXJ2aWNlIHRoYXRcbiAgICAgICAgICAgICAgICBkaWRuJ3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvbiwgYWRkIHRoZSBiYXNlIHVybCBhbmQgYSBkdW1teSB0b2tlblxuICAgICAgICAgICAgICAgIHRvIHRoZSBsaXN0IG9mIHRydXN0ZWQgc2VydmVycyB0byBhdm9pZCBhbm90aGVyIGZlZGVyYXRpb24gY2hlY2tcbiAgICAgICAgICAgICAgICBpbiB0aGUgZXZlbnQgb2YgYSByZXBlYXQgcmVxdWVzdCAqL1xuICAgICAgICAgICAgICAgIHZhciB0cnVuY2F0ZWRVcmwgPSB1cmxcbiAgICAgICAgICAgICAgICAgICAgLnRvTG93ZXJDYXNlKClcbiAgICAgICAgICAgICAgICAgICAgLnNwbGl0KC9cXC9yZXN0KFxcL2FkbWluKT9cXC9zZXJ2aWNlc1xcLy8pWzBdO1xuICAgICAgICAgICAgICAgIG9wdGlvbnMuYXV0aGVudGljYXRpb24uZmVkZXJhdGVkU2VydmVyc1t0cnVuY2F0ZWRVcmxdID0ge1xuICAgICAgICAgICAgICAgICAgICB0b2tlbjogW10sXG4gICAgICAgICAgICAgICAgICAgIC8vIGRlZmF1bHQgdG8gMjQgaG91cnNcbiAgICAgICAgICAgICAgICAgICAgZXhwaXJlczogbmV3IERhdGUoRGF0ZS5ub3coKSArIDg2NDAwICogMTAwMCksXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICBvcmlnaW5hbEF1dGhFcnJvciA9IG51bGw7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gZGF0YTtcbiAgICAgICAgfVxuICAgIH0pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cmVxdWVzdC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLy8gVHlwZVNjcmlwdCAyLjEgbm8gbG9uZ2VyIGFsbG93cyB5b3UgdG8gZXh0ZW5kIGJ1aWx0IGluIHR5cGVzLiBTZWUgaHR0cHM6Ly9naXRodWIuY29tL01pY3Jvc29mdC9UeXBlU2NyaXB0L2lzc3Vlcy8xMjc5MCNpc3N1ZWNvbW1lbnQtMjY1OTgxNDQyXG4vLyBhbmQgaHR0cHM6Ly9naXRodWIuY29tL01pY3Jvc29mdC9UeXBlU2NyaXB0LXdpa2kvYmxvYi9tYXN0ZXIvQnJlYWtpbmctQ2hhbmdlcy5tZCNleHRlbmRpbmctYnVpbHQtaW5zLWxpa2UtZXJyb3ItYXJyYXktYW5kLW1hcC1tYXktbm8tbG9uZ2VyLXdvcmtcbi8vXG4vLyBUaGlzIGNvZGUgaXMgZnJvbSBNRE4gaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvSmF2YVNjcmlwdC9SZWZlcmVuY2UvR2xvYmFsX09iamVjdHMvRXJyb3IjQ3VzdG9tX0Vycm9yX1R5cGVzLlxudmFyIEFyY0dJU1JlcXVlc3RFcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICAvKipcbiAgICAgKiBDcmVhdGUgYSBuZXcgYEFyY0dJU1JlcXVlc3RFcnJvcmAgIG9iamVjdC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBtZXNzYWdlIC0gVGhlIGVycm9yIG1lc3NhZ2UgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIGNvZGUgLSBUaGUgZXJyb3IgY29kZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gcmVzcG9uc2UgLSBUaGUgb3JpZ2luYWwgcmVzcG9uc2UgZnJvbSB0aGUgQVBJIHRoYXQgY2F1c2VkIHRoZSBlcnJvclxuICAgICAqIEBwYXJhbSB1cmwgLSBUaGUgb3JpZ2luYWwgdXJsIG9mIHRoZSByZXF1ZXN0XG4gICAgICogQHBhcmFtIG9wdGlvbnMgLSBUaGUgb3JpZ2luYWwgb3B0aW9ucyBhbmQgcGFyYW1ldGVycyBvZiB0aGUgcmVxdWVzdFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBtZXNzYWdlIHx8IFwiVU5LTk9XTl9FUlJPUlwiO1xuICAgICAgICBjb2RlID0gY29kZSB8fCBcIlVOS05PV05fRVJST1JfQ09ERVwiO1xuICAgICAgICB0aGlzLm5hbWUgPSBcIkFyY0dJU1JlcXVlc3RFcnJvclwiO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPVxuICAgICAgICAgICAgY29kZSA9PT0gXCJVTktOT1dOX0VSUk9SX0NPREVcIiA/IG1lc3NhZ2UgOiBjb2RlICsgXCI6IFwiICsgbWVzc2FnZTtcbiAgICAgICAgdGhpcy5vcmlnaW5hbE1lc3NhZ2UgPSBtZXNzYWdlO1xuICAgICAgICB0aGlzLmNvZGUgPSBjb2RlO1xuICAgICAgICB0aGlzLnJlc3BvbnNlID0gcmVzcG9uc2U7XG4gICAgICAgIHRoaXMudXJsID0gdXJsO1xuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgIH1cbiAgICByZXR1cm4gQXJjR0lTUmVxdWVzdEVycm9yO1xufSgpKTtcbmV4cG9ydCB7IEFyY0dJU1JlcXVlc3RFcnJvciB9O1xuQXJjR0lTUmVxdWVzdEVycm9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUoRXJyb3IucHJvdG90eXBlKTtcbkFyY0dJU1JlcXVlc3RFcnJvci5wcm90b3R5cGUuY29uc3RydWN0b3IgPSBBcmNHSVNSZXF1ZXN0RXJyb3I7XG4vLyMgc291cmNlTWFwcGluZ1VSTD1BcmNHSVNSZXF1ZXN0RXJyb3IuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbi8qKlxuICogSGVscGVyIGZvciBtZXRob2RzIHdpdGggbG90cyBvZiBmaXJzdCBvcmRlciByZXF1ZXN0IG9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIGFzIHJlcXVlc3QgcGFyYW1ldGVycy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFwcGVuZEN1c3RvbVBhcmFtcyhjdXN0b21PcHRpb25zLCBrZXlzLCBiYXNlT3B0aW9ucykge1xuICAgIHZhciByZXF1ZXN0T3B0aW9uc0tleXMgPSBbXG4gICAgICAgIFwicGFyYW1zXCIsXG4gICAgICAgIFwiaHR0cE1ldGhvZFwiLFxuICAgICAgICBcInJhd1Jlc3BvbnNlXCIsXG4gICAgICAgIFwiYXV0aGVudGljYXRpb25cIixcbiAgICAgICAgXCJwb3J0YWxcIixcbiAgICAgICAgXCJmZXRjaFwiLFxuICAgICAgICBcIm1heFVybExlbmd0aFwiLFxuICAgICAgICBcImhlYWRlcnNcIlxuICAgIF07XG4gICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7IHBhcmFtczoge30gfSwgYmFzZU9wdGlvbnMpLCBjdXN0b21PcHRpb25zKTtcbiAgICAvLyBtZXJnZSBhbGwga2V5cyBpbiBjdXN0b21PcHRpb25zIGludG8gb3B0aW9ucy5wYXJhbXNcbiAgICBvcHRpb25zLnBhcmFtcyA9IGtleXMucmVkdWNlKGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICAgIGlmIChjdXN0b21PcHRpb25zW2tleV0gfHwgdHlwZW9mIGN1c3RvbU9wdGlvbnNba2V5XSA9PT0gXCJib29sZWFuXCIpIHtcbiAgICAgICAgICAgIHZhbHVlW2tleV0gPSBjdXN0b21PcHRpb25zW2tleV07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHZhbHVlO1xuICAgIH0sIG9wdGlvbnMucGFyYW1zKTtcbiAgICAvLyBub3cgcmVtb3ZlIGFsbCBwcm9wZXJ0aWVzIGluIG9wdGlvbnMgdGhhdCBkb24ndCBleGlzdCBpbiBJUmVxdWVzdE9wdGlvbnNcbiAgICByZXR1cm4gcmVxdWVzdE9wdGlvbnNLZXlzLnJlZHVjZShmdW5jdGlvbiAodmFsdWUsIGtleSkge1xuICAgICAgICBpZiAob3B0aW9uc1trZXldKSB7XG4gICAgICAgICAgICB2YWx1ZVtrZXldID0gb3B0aW9uc1trZXldO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9LCB7fSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1hcHBlbmQtY3VzdG9tLXBhcmFtcy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLyoqXG4gKiBIZWxwZXIgbWV0aG9kIHRvIGVuc3VyZSB0aGF0IHVzZXIgc3VwcGxpZWQgdXJscyBkb24ndCBpbmNsdWRlIHdoaXRlc3BhY2Ugb3IgYSB0cmFpbGluZyBzbGFzaC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNsZWFuVXJsKHVybCkge1xuICAgIC8vIEd1YXJkIHNvIHdlIGRvbid0IHRyeSB0byB0cmltIHNvbWV0aGluZyB0aGF0J3Mgbm90IGEgc3RyaW5nXG4gICAgaWYgKHR5cGVvZiB1cmwgIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgcmV0dXJuIHVybDtcbiAgICB9XG4gICAgLy8gdHJpbSBsZWFkaW5nIGFuZCB0cmFpbGluZyBzcGFjZXMsIGJ1dCBub3Qgc3BhY2VzIGluc2lkZSB0aGUgdXJsXG4gICAgdXJsID0gdXJsLnRyaW0oKTtcbiAgICAvLyByZW1vdmUgdGhlIHRyYWlsaW5nIHNsYXNoIHRvIHRoZSB1cmwgaWYgb25lIHdhcyBpbmNsdWRlZFxuICAgIGlmICh1cmxbdXJsLmxlbmd0aCAtIDFdID09PSBcIi9cIikge1xuICAgICAgICB1cmwgPSB1cmwuc2xpY2UoMCwgLTEpO1xuICAgIH1cbiAgICByZXR1cm4gdXJsO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9Y2xlYW4tdXJsLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDIwIEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVQYXJhbShwYXJhbSkge1xuICAgIHZhciBfYSA9IHBhcmFtLnNwbGl0KFwiPVwiKSwga2V5ID0gX2FbMF0sIHZhbHVlID0gX2FbMV07XG4gICAgcmV0dXJuIHsga2V5OiBkZWNvZGVVUklDb21wb25lbnQoa2V5KSwgdmFsdWU6IGRlY29kZVVSSUNvbXBvbmVudCh2YWx1ZSkgfTtcbn1cbi8qKlxuICogRGVjb2RlcyB0aGUgcGFzc2VkIHF1ZXJ5IHN0cmluZyBhcyBhbiBvYmplY3QuXG4gKlxuICogQHBhcmFtIHF1ZXJ5IEEgc3RyaW5nIHRvIGJlIGRlY29kZWQuXG4gKiBAcmV0dXJucyBBIGRlY29kZWQgcXVlcnkgcGFyYW0gb2JqZWN0LlxuICovXG5leHBvcnQgZnVuY3Rpb24gZGVjb2RlUXVlcnlTdHJpbmcocXVlcnkpIHtcbiAgICByZXR1cm4gcXVlcnlcbiAgICAgICAgLnJlcGxhY2UoL14jLywgXCJcIilcbiAgICAgICAgLnNwbGl0KFwiJlwiKVxuICAgICAgICAucmVkdWNlKGZ1bmN0aW9uIChhY2MsIGVudHJ5KSB7XG4gICAgICAgIHZhciBfYSA9IGRlY29kZVBhcmFtKGVudHJ5KSwga2V5ID0gX2Eua2V5LCB2YWx1ZSA9IF9hLnZhbHVlO1xuICAgICAgICBhY2Nba2V5XSA9IHZhbHVlO1xuICAgICAgICByZXR1cm4gYWNjO1xuICAgIH0sIHt9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRlY29kZS1xdWVyeS1zdHJpbmcuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHByb2Nlc3NQYXJhbXMsIHJlcXVpcmVzRm9ybURhdGEgfSBmcm9tIFwiLi9wcm9jZXNzLXBhcmFtc1wiO1xuaW1wb3J0IHsgZW5jb2RlUXVlcnlTdHJpbmcgfSBmcm9tIFwiLi9lbmNvZGUtcXVlcnktc3RyaW5nXCI7XG4vKipcbiAqIEVuY29kZXMgcGFyYW1ldGVycyBpbiBhIFtGb3JtRGF0YV0oaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvQVBJL0Zvcm1EYXRhKSBvYmplY3QgaW4gYnJvd3NlcnMgb3IgaW4gYSBbRm9ybURhdGFdKGh0dHBzOi8vZ2l0aHViLmNvbS9mb3JtLWRhdGEvZm9ybS1kYXRhKSBpbiBOb2RlLmpzXG4gKlxuICogQHBhcmFtIHBhcmFtcyBBbiBvYmplY3QgdG8gYmUgZW5jb2RlZC5cbiAqIEByZXR1cm5zIFRoZSBjb21wbGV0ZSBbRm9ybURhdGFdKGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9Gb3JtRGF0YSkgb2JqZWN0LlxuICovXG5leHBvcnQgZnVuY3Rpb24gZW5jb2RlRm9ybURhdGEocGFyYW1zLCBmb3JjZUZvcm1EYXRhKSB7XG4gICAgLy8gc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL2lzc3Vlcy80OTkgZm9yIG1vcmUgaW5mby5cbiAgICB2YXIgdXNlRm9ybURhdGEgPSByZXF1aXJlc0Zvcm1EYXRhKHBhcmFtcykgfHwgZm9yY2VGb3JtRGF0YTtcbiAgICB2YXIgbmV3UGFyYW1zID0gcHJvY2Vzc1BhcmFtcyhwYXJhbXMpO1xuICAgIGlmICh1c2VGb3JtRGF0YSkge1xuICAgICAgICB2YXIgZm9ybURhdGFfMSA9IG5ldyBGb3JtRGF0YSgpO1xuICAgICAgICBPYmplY3Qua2V5cyhuZXdQYXJhbXMpLmZvckVhY2goZnVuY3Rpb24gKGtleSkge1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBCbG9iICE9PSBcInVuZGVmaW5lZFwiICYmIG5ld1BhcmFtc1trZXldIGluc3RhbmNlb2YgQmxvYikge1xuICAgICAgICAgICAgICAgIC8qIFRvIG5hbWUgdGhlIEJsb2I6XG4gICAgICAgICAgICAgICAgIDEuIGxvb2sgdG8gYW4gYWx0ZXJuYXRlIHJlcXVlc3QgcGFyYW1ldGVyIGNhbGxlZCAnZmlsZU5hbWUnXG4gICAgICAgICAgICAgICAgIDIuIHNlZSBpZiAnbmFtZScgaGFzIGJlZW4gdGFja2VkIG9udG8gdGhlIEJsb2IgbWFudWFsbHlcbiAgICAgICAgICAgICAgICAgMy4gaWYgYWxsIGVsc2UgZmFpbHMsIHVzZSB0aGUgcmVxdWVzdCBwYXJhbWV0ZXJcbiAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgIHZhciBmaWxlbmFtZSA9IG5ld1BhcmFtc1tcImZpbGVOYW1lXCJdIHx8IG5ld1BhcmFtc1trZXldLm5hbWUgfHwga2V5O1xuICAgICAgICAgICAgICAgIGZvcm1EYXRhXzEuYXBwZW5kKGtleSwgbmV3UGFyYW1zW2tleV0sIGZpbGVuYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIGZvcm1EYXRhXzEuYXBwZW5kKGtleSwgbmV3UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIGZvcm1EYXRhXzE7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICByZXR1cm4gZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICB9XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1lbmNvZGUtZm9ybS1kYXRhLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBwcm9jZXNzUGFyYW1zIH0gZnJvbSBcIi4vcHJvY2Vzcy1wYXJhbXNcIjtcbi8qKlxuICogRW5jb2RlcyBrZXlzIGFuZCBwYXJhbWV0ZXJzIGZvciB1c2UgaW4gYSBVUkwncyBxdWVyeSBzdHJpbmcuXG4gKlxuICogQHBhcmFtIGtleSBQYXJhbWV0ZXIncyBrZXlcbiAqIEBwYXJhbSB2YWx1ZSBQYXJhbWV0ZXIncyB2YWx1ZVxuICogQHJldHVybnMgUXVlcnkgc3RyaW5nIHdpdGgga2V5IGFuZCB2YWx1ZSBwYWlycyBzZXBhcmF0ZWQgYnkgXCImXCJcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVuY29kZVBhcmFtKGtleSwgdmFsdWUpIHtcbiAgICAvLyBGb3IgYXJyYXkgb2YgYXJyYXlzLCByZXBlYXQga2V5PXZhbHVlIGZvciBlYWNoIGVsZW1lbnQgb2YgY29udGFpbmluZyBhcnJheVxuICAgIGlmIChBcnJheS5pc0FycmF5KHZhbHVlKSAmJiB2YWx1ZVswXSAmJiBBcnJheS5pc0FycmF5KHZhbHVlWzBdKSkge1xuICAgICAgICByZXR1cm4gdmFsdWUubWFwKGZ1bmN0aW9uIChhcnJheUVsZW0pIHsgcmV0dXJuIGVuY29kZVBhcmFtKGtleSwgYXJyYXlFbGVtKTsgfSkuam9pbihcIiZcIik7XG4gICAgfVxuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQoa2V5KSArIFwiPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHZhbHVlKTtcbn1cbi8qKlxuICogRW5jb2RlcyB0aGUgcGFzc2VkIG9iamVjdCBhcyBhIHF1ZXJ5IHN0cmluZy5cbiAqXG4gKiBAcGFyYW0gcGFyYW1zIEFuIG9iamVjdCB0byBiZSBlbmNvZGVkLlxuICogQHJldHVybnMgQW4gZW5jb2RlZCBxdWVyeSBzdHJpbmcuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpIHtcbiAgICB2YXIgbmV3UGFyYW1zID0gcHJvY2Vzc1BhcmFtcyhwYXJhbXMpO1xuICAgIHJldHVybiBPYmplY3Qua2V5cyhuZXdQYXJhbXMpXG4gICAgICAgIC5tYXAoZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gZW5jb2RlUGFyYW0oa2V5LCBuZXdQYXJhbXNba2V5XSk7XG4gICAgfSlcbiAgICAgICAgLmpvaW4oXCImXCIpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZW5jb2RlLXF1ZXJ5LXN0cmluZy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLyoqXG4gKiBDaGVja3MgcGFyYW1ldGVycyB0byBzZWUgaWYgd2Ugc2hvdWxkIHVzZSBGb3JtRGF0YSB0byBzZW5kIHRoZSByZXF1ZXN0XG4gKiBAcGFyYW0gcGFyYW1zIFRoZSBvYmplY3Qgd2hvc2Uga2V5cyB3aWxsIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJuIEEgYm9vbGVhbiBpbmRpY2F0aW5nIGlmIEZvcm1EYXRhIHdpbGwgYmUgcmVxdWlyZWQuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByZXF1aXJlc0Zvcm1EYXRhKHBhcmFtcykge1xuICAgIHJldHVybiBPYmplY3Qua2V5cyhwYXJhbXMpLnNvbWUoZnVuY3Rpb24gKGtleSkge1xuICAgICAgICB2YXIgdmFsdWUgPSBwYXJhbXNba2V5XTtcbiAgICAgICAgaWYgKCF2YWx1ZSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGlmICh2YWx1ZSAmJiB2YWx1ZS50b1BhcmFtKSB7XG4gICAgICAgICAgICB2YWx1ZSA9IHZhbHVlLnRvUGFyYW0oKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgdHlwZSA9IHZhbHVlLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIHN3aXRjaCAodHlwZSkge1xuICAgICAgICAgICAgY2FzZSBcIkFycmF5XCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIk9iamVjdFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJEYXRlXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIkZ1bmN0aW9uXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIkJvb2xlYW5cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiU3RyaW5nXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIk51bWJlclwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICB9KTtcbn1cbi8qKlxuICogQ29udmVydHMgcGFyYW1ldGVycyB0byB0aGUgcHJvcGVyIHJlcHJlc2VudGF0aW9uIHRvIHNlbmQgdG8gdGhlIEFyY0dJUyBSRVNUIEFQSS5cbiAqIEBwYXJhbSBwYXJhbXMgVGhlIG9iamVjdCB3aG9zZSBrZXlzIHdpbGwgYmUgZW5jb2RlZC5cbiAqIEByZXR1cm4gQSBuZXcgb2JqZWN0IHdpdGggcHJvcGVybHkgZW5jb2RlZCB2YWx1ZXMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBwcm9jZXNzUGFyYW1zKHBhcmFtcykge1xuICAgIHZhciBuZXdQYXJhbXMgPSB7fTtcbiAgICBPYmplY3Qua2V5cyhwYXJhbXMpLmZvckVhY2goZnVuY3Rpb24gKGtleSkge1xuICAgICAgICB2YXIgX2EsIF9iO1xuICAgICAgICB2YXIgcGFyYW0gPSBwYXJhbXNba2V5XTtcbiAgICAgICAgaWYgKHBhcmFtICYmIHBhcmFtLnRvUGFyYW0pIHtcbiAgICAgICAgICAgIHBhcmFtID0gcGFyYW0udG9QYXJhbSgpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghcGFyYW0gJiZcbiAgICAgICAgICAgIHBhcmFtICE9PSAwICYmXG4gICAgICAgICAgICB0eXBlb2YgcGFyYW0gIT09IFwiYm9vbGVhblwiICYmXG4gICAgICAgICAgICB0eXBlb2YgcGFyYW0gIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB2YXIgdHlwZSA9IHBhcmFtLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIHZhciB2YWx1ZTtcbiAgICAgICAgLy8gcHJvcGVybHkgZW5jb2RlcyBvYmplY3RzLCBhcnJheXMgYW5kIGRhdGVzIGZvciBhcmNnaXMuY29tIGFuZCBvdGhlciBzZXJ2aWNlcy5cbiAgICAgICAgLy8gcG9ydGVkIGZyb20gaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvZXNyaS1sZWFmbGV0L2Jsb2IvbWFzdGVyL3NyYy9SZXF1ZXN0LmpzI0wyMi1MMzBcbiAgICAgICAgLy8gYWxzbyBzZWUgaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvaXNzdWVzLzE4OlxuICAgICAgICAvLyBudWxsLCB1bmRlZmluZWQsIGZ1bmN0aW9uIGFyZSBleGNsdWRlZC4gSWYgeW91IHdhbnQgdG8gc2VuZCBhbiBlbXB0eSBrZXkgeW91IG5lZWQgdG8gc2VuZCBhbiBlbXB0eSBzdHJpbmcgXCJcIi5cbiAgICAgICAgc3dpdGNoICh0eXBlKSB7XG4gICAgICAgICAgICBjYXNlIFwiQXJyYXlcIjpcbiAgICAgICAgICAgICAgICAvLyBCYXNlZCBvbiB0aGUgZmlyc3QgZWxlbWVudCBvZiB0aGUgYXJyYXksIGNsYXNzaWZ5IGFycmF5IGFzIGFuIGFycmF5IG9mIGFycmF5cywgYW4gYXJyYXkgb2Ygb2JqZWN0c1xuICAgICAgICAgICAgICAgIC8vIHRvIGJlIHN0cmluZ2lmaWVkLCBvciBhbiBhcnJheSBvZiBub24tb2JqZWN0cyB0byBiZSBjb21tYS1zZXBhcmF0ZWRcbiAgICAgICAgICAgICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tY2FzZS1kZWNsYXJhdGlvbnNcbiAgICAgICAgICAgICAgICB2YXIgZmlyc3RFbGVtZW50VHlwZSA9IChfYiA9IChfYSA9IHBhcmFtWzBdKSA9PT0gbnVsbCB8fCBfYSA9PT0gdm9pZCAwID8gdm9pZCAwIDogX2EuY29uc3RydWN0b3IpID09PSBudWxsIHx8IF9iID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYi5uYW1lO1xuICAgICAgICAgICAgICAgIHZhbHVlID1cbiAgICAgICAgICAgICAgICAgICAgZmlyc3RFbGVtZW50VHlwZSA9PT0gXCJBcnJheVwiID8gcGFyYW0gOiAvLyBwYXNzIHRocnUgYXJyYXkgb2YgYXJyYXlzXG4gICAgICAgICAgICAgICAgICAgICAgICBmaXJzdEVsZW1lbnRUeXBlID09PSBcIk9iamVjdFwiID8gSlNPTi5zdHJpbmdpZnkocGFyYW0pIDogLy8gc3RyaW5naWZ5IGFycmF5IG9mIG9iamVjdHNcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXJhbS5qb2luKFwiLFwiKTsgLy8gam9pbiBvdGhlciB0eXBlcyBvZiBhcnJheSBlbGVtZW50c1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIk9iamVjdFwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gSlNPTi5zdHJpbmdpZnkocGFyYW0pO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIkRhdGVcIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IHBhcmFtLnZhbHVlT2YoKTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJGdW5jdGlvblwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gbnVsbDtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJCb29sZWFuXCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBwYXJhbSArIFwiXCI7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgIHZhbHVlID0gcGFyYW07XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHZhbHVlIHx8IHZhbHVlID09PSAwIHx8IHR5cGVvZiB2YWx1ZSA9PT0gXCJzdHJpbmdcIiB8fCBBcnJheS5pc0FycmF5KHZhbHVlKSkge1xuICAgICAgICAgICAgbmV3UGFyYW1zW2tleV0gPSB2YWx1ZTtcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIHJldHVybiBuZXdQYXJhbXM7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1wcm9jZXNzLXBhcmFtcy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vKipcbiAqIE1ldGhvZCB1c2VkIGludGVybmFsbHkgdG8gc3VyZmFjZSBtZXNzYWdlcyB0byBkZXZlbG9wZXJzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gd2FybihtZXNzYWdlKSB7XG4gICAgaWYgKGNvbnNvbGUgJiYgY29uc29sZS53YXJuKSB7XG4gICAgICAgIGNvbnNvbGUud2Fybi5hcHBseShjb25zb2xlLCBbbWVzc2FnZV0pO1xuICAgIH1cbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXdhcm4uanMubWFwIiwiLyohICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXHJcbkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLlxyXG5cclxuUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XHJcbnB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZC5cclxuXHJcblRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEhcclxuUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZXHJcbkFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1IgQU5ZIFNQRUNJQUwsIERJUkVDVCxcclxuSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NXHJcbkxPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SXHJcbk9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1JcclxuUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cclxuKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogKi9cclxuLyogZ2xvYmFsIFJlZmxlY3QsIFByb21pc2UgKi9cclxuXHJcbnZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24oZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxyXG4gICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcclxuICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcclxuICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXh0ZW5kcyhkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG4gICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XHJcbiAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XHJcbn1cclxuXHJcbmV4cG9ydCB2YXIgX19hc3NpZ24gPSBmdW5jdGlvbigpIHtcclxuICAgIF9fYXNzaWduID0gT2JqZWN0LmFzc2lnbiB8fCBmdW5jdGlvbiBfX2Fzc2lnbih0KSB7XHJcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XHJcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XHJcbiAgICAgICAgICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSkgdFtwXSA9IHNbcF07XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3Jlc3QocywgZSkge1xyXG4gICAgdmFyIHQgPSB7fTtcclxuICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSAmJiBlLmluZGV4T2YocCkgPCAwKVxyXG4gICAgICAgIHRbcF0gPSBzW3BdO1xyXG4gICAgaWYgKHMgIT0gbnVsbCAmJiB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBwID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyhzKTsgaSA8IHAubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgaWYgKGUuaW5kZXhPZihwW2ldKSA8IDAgJiYgT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZS5jYWxsKHMsIHBbaV0pKVxyXG4gICAgICAgICAgICAgICAgdFtwW2ldXSA9IHNbcFtpXV07XHJcbiAgICAgICAgfVxyXG4gICAgcmV0dXJuIHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2RlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKSB7XHJcbiAgICB2YXIgYyA9IGFyZ3VtZW50cy5sZW5ndGgsIHIgPSBjIDwgMyA/IHRhcmdldCA6IGRlc2MgPT09IG51bGwgPyBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0YXJnZXQsIGtleSkgOiBkZXNjLCBkO1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0LmRlY29yYXRlID09PSBcImZ1bmN0aW9uXCIpIHIgPSBSZWZsZWN0LmRlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKTtcclxuICAgIGVsc2UgZm9yICh2YXIgaSA9IGRlY29yYXRvcnMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIGlmIChkID0gZGVjb3JhdG9yc1tpXSkgciA9IChjIDwgMyA/IGQocikgOiBjID4gMyA/IGQodGFyZ2V0LCBrZXksIHIpIDogZCh0YXJnZXQsIGtleSkpIHx8IHI7XHJcbiAgICByZXR1cm4gYyA+IDMgJiYgciAmJiBPYmplY3QuZGVmaW5lUHJvcGVydHkodGFyZ2V0LCBrZXksIHIpLCByO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19wYXJhbShwYXJhbUluZGV4LCBkZWNvcmF0b3IpIHtcclxuICAgIHJldHVybiBmdW5jdGlvbiAodGFyZ2V0LCBrZXkpIHsgZGVjb3JhdG9yKHRhcmdldCwga2V5LCBwYXJhbUluZGV4KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSkge1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0Lm1ldGFkYXRhID09PSBcImZ1bmN0aW9uXCIpIHJldHVybiBSZWZsZWN0Lm1ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXRlcih0aGlzQXJnLCBfYXJndW1lbnRzLCBQLCBnZW5lcmF0b3IpIHtcclxuICAgIGZ1bmN0aW9uIGFkb3B0KHZhbHVlKSB7IHJldHVybiB2YWx1ZSBpbnN0YW5jZW9mIFAgPyB2YWx1ZSA6IG5ldyBQKGZ1bmN0aW9uIChyZXNvbHZlKSB7IHJlc29sdmUodmFsdWUpOyB9KTsgfVxyXG4gICAgcmV0dXJuIG5ldyAoUCB8fCAoUCA9IFByb21pc2UpKShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XHJcbiAgICAgICAgZnVuY3Rpb24gZnVsZmlsbGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yLm5leHQodmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHJlamVjdGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yW1widGhyb3dcIl0odmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHN0ZXAocmVzdWx0KSB7IHJlc3VsdC5kb25lID8gcmVzb2x2ZShyZXN1bHQudmFsdWUpIDogYWRvcHQocmVzdWx0LnZhbHVlKS50aGVuKGZ1bGZpbGxlZCwgcmVqZWN0ZWQpOyB9XHJcbiAgICAgICAgc3RlcCgoZ2VuZXJhdG9yID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pKS5uZXh0KCkpO1xyXG4gICAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2dlbmVyYXRvcih0aGlzQXJnLCBib2R5KSB7XHJcbiAgICB2YXIgXyA9IHsgbGFiZWw6IDAsIHNlbnQ6IGZ1bmN0aW9uKCkgeyBpZiAodFswXSAmIDEpIHRocm93IHRbMV07IHJldHVybiB0WzFdOyB9LCB0cnlzOiBbXSwgb3BzOiBbXSB9LCBmLCB5LCB0LCBnO1xyXG4gICAgcmV0dXJuIGcgPSB7IG5leHQ6IHZlcmIoMCksIFwidGhyb3dcIjogdmVyYigxKSwgXCJyZXR1cm5cIjogdmVyYigyKSB9LCB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgKGdbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhpczsgfSksIGc7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgcmV0dXJuIGZ1bmN0aW9uICh2KSB7IHJldHVybiBzdGVwKFtuLCB2XSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAob3ApIHtcclxuICAgICAgICBpZiAoZikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy5cIik7XHJcbiAgICAgICAgd2hpbGUgKF8pIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChmID0gMSwgeSAmJiAodCA9IG9wWzBdICYgMiA/IHlbXCJyZXR1cm5cIl0gOiBvcFswXSA/IHlbXCJ0aHJvd1wiXSB8fCAoKHQgPSB5W1wicmV0dXJuXCJdKSAmJiB0LmNhbGwoeSksIDApIDogeS5uZXh0KSAmJiAhKHQgPSB0LmNhbGwoeSwgb3BbMV0pKS5kb25lKSByZXR1cm4gdDtcclxuICAgICAgICAgICAgaWYgKHkgPSAwLCB0KSBvcCA9IFtvcFswXSAmIDIsIHQudmFsdWVdO1xyXG4gICAgICAgICAgICBzd2l0Y2ggKG9wWzBdKSB7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDA6IGNhc2UgMTogdCA9IG9wOyBicmVhaztcclxuICAgICAgICAgICAgICAgIGNhc2UgNDogXy5sYWJlbCsrOyByZXR1cm4geyB2YWx1ZTogb3BbMV0sIGRvbmU6IGZhbHNlIH07XHJcbiAgICAgICAgICAgICAgICBjYXNlIDU6IF8ubGFiZWwrKzsgeSA9IG9wWzFdOyBvcCA9IFswXTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDc6IG9wID0gXy5vcHMucG9wKCk7IF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgIGlmICghKHQgPSBfLnRyeXMsIHQgPSB0Lmxlbmd0aCA+IDAgJiYgdFt0Lmxlbmd0aCAtIDFdKSAmJiAob3BbMF0gPT09IDYgfHwgb3BbMF0gPT09IDIpKSB7IF8gPSAwOyBjb250aW51ZTsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gMyAmJiAoIXQgfHwgKG9wWzFdID4gdFswXSAmJiBvcFsxXSA8IHRbM10pKSkgeyBfLmxhYmVsID0gb3BbMV07IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSA2ICYmIF8ubGFiZWwgPCB0WzFdKSB7IF8ubGFiZWwgPSB0WzFdOyB0ID0gb3A7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHQgJiYgXy5sYWJlbCA8IHRbMl0pIHsgXy5sYWJlbCA9IHRbMl07IF8ub3BzLnB1c2gob3ApOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0WzJdKSBfLm9wcy5wb3AoKTtcclxuICAgICAgICAgICAgICAgICAgICBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIG9wID0gYm9keS5jYWxsKHRoaXNBcmcsIF8pO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgb3AgPSBbNiwgZV07IHkgPSAwOyB9IGZpbmFsbHkgeyBmID0gdCA9IDA7IH1cclxuICAgICAgICBpZiAob3BbMF0gJiA1KSB0aHJvdyBvcFsxXTsgcmV0dXJuIHsgdmFsdWU6IG9wWzBdID8gb3BbMV0gOiB2b2lkIDAsIGRvbmU6IHRydWUgfTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY3JlYXRlQmluZGluZyhvLCBtLCBrLCBrMikge1xyXG4gICAgaWYgKGsyID09PSB1bmRlZmluZWQpIGsyID0gaztcclxuICAgIG9bazJdID0gbVtrXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXhwb3J0U3RhcihtLCBleHBvcnRzKSB7XHJcbiAgICBmb3IgKHZhciBwIGluIG0pIGlmIChwICE9PSBcImRlZmF1bHRcIiAmJiAhZXhwb3J0cy5oYXNPd25Qcm9wZXJ0eShwKSkgZXhwb3J0c1twXSA9IG1bcF07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3ZhbHVlcyhvKSB7XHJcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xyXG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XHJcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XHJcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xyXG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xyXG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XHJcbiAgICAgICAgfVxyXG4gICAgfTtcclxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVhZChvLCBuKSB7XHJcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XHJcbiAgICBpZiAoIW0pIHJldHVybiBvO1xyXG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xyXG4gICAgfVxyXG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XHJcbiAgICBmaW5hbGx5IHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZCgpIHtcclxuICAgIGZvciAodmFyIGFyID0gW10sIGkgPSAwOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKVxyXG4gICAgICAgIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkQXJyYXlzKCkge1xyXG4gICAgZm9yICh2YXIgcyA9IDAsIGkgPSAwLCBpbCA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBpbDsgaSsrKSBzICs9IGFyZ3VtZW50c1tpXS5sZW5ndGg7XHJcbiAgICBmb3IgKHZhciByID0gQXJyYXkocyksIGsgPSAwLCBpID0gMDsgaSA8IGlsOyBpKyspXHJcbiAgICAgICAgZm9yICh2YXIgYSA9IGFyZ3VtZW50c1tpXSwgaiA9IDAsIGpsID0gYS5sZW5ndGg7IGogPCBqbDsgaisrLCBrKyspXHJcbiAgICAgICAgICAgIHJba10gPSBhW2pdO1xyXG4gICAgcmV0dXJuIHI7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdCh2KSB7XHJcbiAgICByZXR1cm4gdGhpcyBpbnN0YW5jZW9mIF9fYXdhaXQgPyAodGhpcy52ID0gdiwgdGhpcykgOiBuZXcgX19hd2FpdCh2KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNHZW5lcmF0b3IodGhpc0FyZywgX2FyZ3VtZW50cywgZ2VuZXJhdG9yKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIGcgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSksIGksIHEgPSBbXTtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpZiAoZ1tuXSkgaVtuXSA9IGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAoYSwgYikgeyBxLnB1c2goW24sIHYsIGEsIGJdKSA+IDEgfHwgcmVzdW1lKG4sIHYpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gcmVzdW1lKG4sIHYpIHsgdHJ5IHsgc3RlcChnW25dKHYpKTsgfSBjYXRjaCAoZSkgeyBzZXR0bGUocVswXVszXSwgZSk7IH0gfVxyXG4gICAgZnVuY3Rpb24gc3RlcChyKSB7IHIudmFsdWUgaW5zdGFuY2VvZiBfX2F3YWl0ID8gUHJvbWlzZS5yZXNvbHZlKHIudmFsdWUudikudGhlbihmdWxmaWxsLCByZWplY3QpIDogc2V0dGxlKHFbMF1bMl0sIHIpOyB9XHJcbiAgICBmdW5jdGlvbiBmdWxmaWxsKHZhbHVlKSB7IHJlc3VtZShcIm5leHRcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiByZWplY3QodmFsdWUpIHsgcmVzdW1lKFwidGhyb3dcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUoZiwgdikgeyBpZiAoZih2KSwgcS5zaGlmdCgpLCBxLmxlbmd0aCkgcmVzdW1lKHFbMF1bMF0sIHFbMF1bMV0pOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jRGVsZWdhdG9yKG8pIHtcclxuICAgIHZhciBpLCBwO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiLCBmdW5jdGlvbiAoZSkgeyB0aHJvdyBlOyB9KSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobiwgZikgeyBpW25dID0gb1tuXSA/IGZ1bmN0aW9uICh2KSB7IHJldHVybiAocCA9ICFwKSA/IHsgdmFsdWU6IF9fYXdhaXQob1tuXSh2KSksIGRvbmU6IG4gPT09IFwicmV0dXJuXCIgfSA6IGYgPyBmKHYpIDogdjsgfSA6IGY7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNWYWx1ZXMobykge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBtID0gb1tTeW1ib2wuYXN5bmNJdGVyYXRvcl0sIGk7XHJcbiAgICByZXR1cm4gbSA/IG0uY2FsbChvKSA6IChvID0gdHlwZW9mIF9fdmFsdWVzID09PSBcImZ1bmN0aW9uXCIgPyBfX3ZhbHVlcyhvKSA6IG9bU3ltYm9sLml0ZXJhdG9yXSgpLCBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaSk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaVtuXSA9IG9bbl0gJiYgZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHsgdiA9IG9bbl0odiksIHNldHRsZShyZXNvbHZlLCByZWplY3QsIHYuZG9uZSwgdi52YWx1ZSk7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCBkLCB2KSB7IFByb21pc2UucmVzb2x2ZSh2KS50aGVuKGZ1bmN0aW9uKHYpIHsgcmVzb2x2ZSh7IHZhbHVlOiB2LCBkb25lOiBkIH0pOyB9LCByZWplY3QpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ha2VUZW1wbGF0ZU9iamVjdChjb29rZWQsIHJhdykge1xyXG4gICAgaWYgKE9iamVjdC5kZWZpbmVQcm9wZXJ0eSkgeyBPYmplY3QuZGVmaW5lUHJvcGVydHkoY29va2VkLCBcInJhd1wiLCB7IHZhbHVlOiByYXcgfSk7IH0gZWxzZSB7IGNvb2tlZC5yYXcgPSByYXc7IH1cclxuICAgIHJldHVybiBjb29rZWQ7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnRTdGFyKG1vZCkge1xyXG4gICAgaWYgKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgcmV0dXJuIG1vZDtcclxuICAgIHZhciByZXN1bHQgPSB7fTtcclxuICAgIGlmIChtb2QgIT0gbnVsbCkgZm9yICh2YXIgayBpbiBtb2QpIGlmIChPYmplY3QuaGFzT3duUHJvcGVydHkuY2FsbChtb2QsIGspKSByZXN1bHRba10gPSBtb2Rba107XHJcbiAgICByZXN1bHQuZGVmYXVsdCA9IG1vZDtcclxuICAgIHJldHVybiByZXN1bHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydERlZmF1bHQobW9kKSB7XHJcbiAgICByZXR1cm4gKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgPyBtb2QgOiB7IGRlZmF1bHQ6IG1vZCB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZEdldChyZWNlaXZlciwgcHJpdmF0ZU1hcCkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIGdldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHJldHVybiBwcml2YXRlTWFwLmdldChyZWNlaXZlcik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkU2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwLCB2YWx1ZSkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIHNldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHByaXZhdGVNYXAuc2V0KHJlY2VpdmVyLCB2YWx1ZSk7XHJcbiAgICByZXR1cm4gdmFsdWU7XHJcbn1cclxuIiwibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGZpbGwtcnVsZT1cXFwiZXZlbm9kZFxcXCIgY2xpcC1ydWxlPVxcXCJldmVub2RkXFxcIiBkPVxcXCJNMS4zMzMgMGg0Yy43MzcgMCAxLjMzNC41OTcgMS4zMzQgMS4zMzN2MS4zMzRoOEMxNS40MDMgMi42NjcgMTYgMy4yNjQgMTYgNHYxMC42NjdjMCAuNzM2LS41OTcgMS4zMzMtMS4zMzMgMS4zMzNIMS4zMzNBMS4zMzMgMS4zMzMgMCAwIDEgMCAxNC42NjdWMS4zMzNDMCAuNTk3LjU5NyAwIDEuMzMzIDBabTAgNy4zMzN2Ny4zMzRoMTMuMzM0VjcuMzMzSDEuMzM0Wm0wLTEuMzMzaDEzLjMzNFY0SDUuMzM0VjEuMzM1aC00VjZaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk05LjQzOC45OTRjLjIxMyAwIC4zOTcuMTQ2LjQ0LjM1LjE1MS43MjIuMjU3IDEuMzQuMzE2IDEuODUyLjM3NC4xNi43MjUuMzYyIDEuMDQ4LjU5OWwxLjcyOC0uNjc2YS40NTUuNDU1IDAgMCAxIC41NTYuMTg4bDEuNDIgMi4zOTRhLjQzLjQzIDAgMCAxLS4wOTEuNTQ3IDIxLjk4IDIxLjk4IDAgMCAxLTEuNDkgMS4xOTQgNS4xNyA1LjE3IDAgMCAxLS4wMDcgMS4xODNsMS40NjQgMS4xMTlhLjQzLjQzIDAgMCAxIC4xMTEuNTYzbC0xLjQyIDIuMzk0YS40NTQuNDU0IDAgMCAxLS41My4xOTcgMjIuNDQ1IDIyLjQ0NSAwIDAgMS0xLjgwNy0uNjZjLS4zMjUuMjMzLS42NzkuNDMtMS4wNTUuNTg2bC0uMjYzIDEuNzk0YS40NDYuNDQ2IDAgMCAxLS40NDUuMzc2SDYuNTc0YS40NDYuNDQ2IDAgMCAxLS40NC0uMzUgMjEuMDE5IDIxLjAxOSAwIDAgMS0uMzE3LTEuODUzIDUuMzQgNS4zNCAwIDAgMS0xLjA0Ny0uNTk4bC0xLjcyOC42NzVhLjQ1NS40NTUgMCAwIDEtLjU1Ni0uMTg3bC0xLjQyLTIuMzk1YS40My40MyAwIDAgMSAuMDkxLS41NDZjLjU2Ny0uNDkgMS4wNjMtLjg4OCAxLjQ5LTEuMTk0YTUuMTY3IDUuMTY3IDAgMCAxIC4wMDgtMS4xODNMMS4xOSA2LjI0M2EuNDMuNDMgMCAwIDEtLjExMi0uNTYybDEuNDItMi4zOTVhLjQ1NS40NTUgMCAwIDEgLjUzMS0uMTk2Yy43MTkuMjMzIDEuMzIxLjQ1MyAxLjgwNy42Ni4zMjQtLjIzMy42NzktLjQzIDEuMDU2LS41ODdsLjI2Mi0xLjc5NEEuNDQ2LjQ0NiAwIDAgMSA2LjYuOTk0aDIuODM5Wm0tLjM2NSAxSDYuOTg1bC0uMjggMS44NjYtLjQ2Ny4xOWMtLjIzNS4wOTUtLjQ2LjIxLS42NzIuMzRsLS4yMDcuMTM2LS40Mi4yOTMtLjQ3Ni0uMTk3Yy0uMzI4LS4xMzctLjcxOC0uMjgxLTEuMTY5LS40MzNsLS4yMjEtLjA3NC0xLjA0NSAxLjcxOUwzLjU5IDYuOTk5bC0uMDYuNDc5YTQuMTI3IDQuMTI3IDAgMCAwLS4wMjEuODE2bC4wMTQuMTQ0LjA1OC40OTItLjQxOS4yOTRjLS4yODguMjAzLS42MTUuNDUxLS45NzkuNzQ2bC0uMTc3LjE0NSAxLjA0MyAxLjcyIDEuODQ1LS43MDMuNDA2LjI5Yy4yMDQuMTQ2LjQyLjI3NC42NDUuMzg0bC4yMjguMTAzLjQ3NC4xOTkuMDU5LjQ5Yy4wNC4zMzguMTAzLjczMS4xOSAxLjE3N2wuMDQzLjIxOWgyLjA4OGwuMjgyLTEuODY3LjQ2Ni0uMTljLjIzNi0uMDk1LjQ2LS4yMS42NzItLjM0bC4yMDctLjEzNi40MTktLjI5My40NzYuMTk4Yy4zMy4xMzYuNzIuMjggMS4xNy40MzNsLjIyLjA3MiAxLjA0NC0xLjcxOC0xLjU2LTEuMTY1LjA2LS40NzlhNC4xMzEgNC4xMzEgMCAwIDAgLjAyLS44MTVsLS4wMTMtLjE0NC0uMDYtLjQ5Mi40Mi0uMjk1YTE4LjEgMTguMSAwIDAgMCAuOTgtLjc0NmwuMTc2LS4xNDYtMS4wNDMtMS43Mi0xLjg0NC43MDUtLjQwNi0uMjlhNC40OTYgNC40OTYgMCAwIDAtLjY0Ni0uMzg1bC0uMjI4LS4xMDMtLjQ3NC0uMTk5LS4wNTgtLjQ5Yy0uMDMyLS4yNy0uMDgtLjU3Ni0uMTQtLjkxNmwtLjA5NC0uNDhabS0xLjA2NyAzYTMgMyAwIDEgMSAwIDYgMyAzIDAgMCAxIDAtNlptMCAxYTIgMiAwIDEgMCAwIDQgMiAyIDAgMCAwIDAtNFpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBmaWxsLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGNsaXAtcnVsZT1cXFwiZXZlbm9kZFxcXCIgZD1cXFwiTTE0IDhBNiA2IDAgMSAxIDIgOGE2IDYgMCAwIDEgMTIgMFptMSAwQTcgNyAwIDEgMSAxIDhhNyA3IDAgMCAxIDE0IDBaTTcuNSA0LjVhLjUuNSAwIDAgMSAxIDB2M2gzYS41LjUgMCAwIDEgMCAxaC0zdjNhLjUuNSAwIDAgMS0xIDB2LTNoLTNhLjUuNSAwIDAgMSAwLTFoM3YtM1pcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBkPVxcXCJNNiA2LjVhLjUuNSAwIDAgMSAxIDB2NmEuNS41IDAgMCAxLTEgMHYtNlpNOS41IDZhLjUuNSAwIDAgMC0uNS41djZhLjUuNSAwIDAgMCAxIDB2LTZhLjUuNSAwIDAgMC0uNS0uNVpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48cGF0aCBmaWxsLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGNsaXAtcnVsZT1cXFwiZXZlbm9kZFxcXCIgZD1cXFwiTTExIDBINWExIDEgMCAwIDAtMSAxdjJILjVhLjUuNSAwIDAgMCAwIDFoMS42bC44MSAxMS4xYTEgMSAwIDAgMCAuOTk1LjloOC4xOWExIDEgMCAwIDAgLjk5NS0uOUwxMy45IDRoMS42YS41LjUgMCAwIDAgMC0xSDEyVjFhMSAxIDAgMCAwLTEtMVptMCAzVjFINXYyaDZabTEuODk1IDFoLTkuNzlsLjggMTFoOC4xOWwuOC0xMVpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBkPVxcXCJtNyAxMS41IDUuMzU0LTUuMzU0LS43MDgtLjcwN0w3IDEwLjA4NiA0LjM1NCA3LjQzOWwtLjcwOC43MDdMNyAxMS41WlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjxwYXRoIGZpbGwtcnVsZT1cXFwiZXZlbm9kZFxcXCIgY2xpcC1ydWxlPVxcXCJldmVub2RkXFxcIiBkPVxcXCJNMCA4YTggOCAwIDEgMCAxNiAwQTggOCAwIDAgMCAwIDhabTE1IDBBNyA3IDAgMSAxIDEgOGE3IDcgMCAwIDEgMTQgMFpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsImltcG9ydCB7IFJlYWN0LCBjbGFzc05hbWVzIH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyB0eXBlIFNWR0NvbXBvbmVudFByb3BzIH0gZnJvbSAnamltdS11aSdcclxuaW1wb3J0IHNyYyBmcm9tICcuLi8uLi9zdmcvb3V0bGluZWQvYXBwbGljYXRpb24vZm9sZGVyLnN2ZydcclxuXHJcbmV4cG9ydCBjb25zdCBGb2xkZXJPdXRsaW5lZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9vdXRsaW5lZC9hcHBsaWNhdGlvbi9zZXR0aW5nLnN2ZydcclxuXHJcbmV4cG9ydCBjb25zdCBTZXR0aW5nT3V0bGluZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCB7IFJlYWN0LCBjbGFzc05hbWVzIH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyB0eXBlIFNWR0NvbXBvbmVudFByb3BzIH0gZnJvbSAnamltdS11aSdcclxuaW1wb3J0IHNyYyBmcm9tICcuLi8uLi9zdmcvb3V0bGluZWQvZWRpdG9yL3BsdXMtY2lyY2xlLnN2ZydcclxuXHJcbmV4cG9ydCBjb25zdCBQbHVzQ2lyY2xlT3V0bGluZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCB7IFJlYWN0LCBjbGFzc05hbWVzIH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyB0eXBlIFNWR0NvbXBvbmVudFByb3BzIH0gZnJvbSAnamltdS11aSdcclxuaW1wb3J0IHNyYyBmcm9tICcuLi8uLi9zdmcvb3V0bGluZWQvZWRpdG9yL3RyYXNoLnN2ZydcclxuXHJcbmV4cG9ydCBjb25zdCBUcmFzaE91dGxpbmVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL291dGxpbmVkL3N1Z2dlc3RlZC9zdWNjZXNzLnN2ZydcclxuXHJcbmV4cG9ydCBjb25zdCBTdWNjZXNzT3V0bGluZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIjtcclxuaW1wb3J0IHtcclxuICBBcHBXaWRnZXRDb25maWcsIEFzc2Vzc21lbnQsIFxyXG4gIENsc3NSZXNwb25zZSxcclxuICBDTFNTVGVtcGxhdGUsIFxyXG4gIENvbXBvbmVudFRlbXBsYXRlLCBcclxuICBIYXphcmQsXHJcbiAgSW5jaWRlbnQsXHJcbiAgSW5Db21tZW50LFxyXG4gIEluZGljYXRvckFzc2Vzc21lbnQsXHJcbiAgSW5kaWNhdG9yVGVtcGxhdGUsIEluZGljYXRvcldlaWdodCwgTGlmZWxpbmVTdGF0dXMsIExpZmVMaW5lVGVtcGxhdGUsXHJcbiAgT3JnYW5pemF0aW9uLCBTY2FsZUZhY3RvclxyXG59IGZyb20gXCIuL2RhdGEtZGVmaW5pdGlvbnNcIjtcclxuaW1wb3J0IHtcclxuICBBU1NFU1NNRU5UX1VSTF9FUlJPUiwgXHJcbiAgQkFTRUxJTkVfVEVNUExBVEVfTkFNRSwgXHJcbiAgQ09NUE9ORU5UX1VSTF9FUlJPUiwgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OLCBIQVpBUkRfVVJMX0VSUk9SLCBJTkNJREVOVF9TVEFCSUxJWkFUSU9OLCBJTkNJREVOVF9VUkxfRVJST1IsIElORElDQVRPUl9VUkxfRVJST1IsXHJcbiAgTElGRV9TQUZFVFksXHJcbiAgTElGRV9TQUZFVFlfU0NBTEVfRkFDVE9SLFxyXG4gIExJRkVMSU5FX1VSTF9FUlJPUiwgTUFYSU1VTV9XRUlHSFQsIE9SR0FOSVpBVElPTl9VUkxfRVJST1IsIE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SLCBcclxuICBQT1JUQUxfVVJMLCBcclxuICBQUk9QRVJUWV9QUk9URUNUSU9OLCBcclxuICBSQU5LLCBcclxuICBURU1QTEFURV9VUkxfRVJST1J9IGZyb20gXCIuL2NvbnN0YW50c1wiO1xyXG5pbXBvcnQgeyBnZXRBcHBTdG9yZSB9IGZyb20gXCJqaW11LWNvcmVcIjtcclxuaW1wb3J0IHtcclxuICBJRmVhdHVyZSwgSUZlYXR1cmVTZXQsIElGaWVsZH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXJcIjtcclxuaW1wb3J0IHsgcXVlcnlUYWJsZUZlYXR1cmVzLCBcclxuICAgdXBkYXRlVGFibGVGZWF0dXJlLCBkZWxldGVUYWJsZUZlYXR1cmVzLCBcclxuICAgIGFkZFRhYmxlRmVhdHVyZXMsIHVwZGF0ZVRhYmxlRmVhdHVyZXMsIHF1ZXJ5VGFibGVGZWF0dXJlU2V0IH0gZnJvbSBcIi4vZXNyaS1hcGlcIjtcclxuaW1wb3J0IHsgbG9nLCBMb2dUeXBlIH0gZnJvbSBcIi4vbG9nZ2VyXCI7XHJcbmltcG9ydCB7IElDb2RlZFZhbHVlIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXR5cGVzXCI7XHJcbmltcG9ydCB7IGNoZWNrQ3VycmVudFN0YXR1cywgc2lnbkluIH0gZnJvbSBcIi4vYXV0aFwiO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuL2Nsc3Mtc3RvcmVcIjtcclxuaW1wb3J0IHsgSUNyZWRlbnRpYWwgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aFwiO1xyXG5pbXBvcnQgeyBwYXJzZURhdGUgfSBmcm9tIFwiLi91dGlsc1wiO1xyXG5cclxuXHJcbi8vPT09PT09PT09PT09PT09PT09PT09PT09UFVCTElDPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxyXG5cclxuZXhwb3J0IGNvbnN0IGluaXRpYWxpemVBdXRoID0gYXN5bmMoYXBwSWQ6IHN0cmluZykgPT57ICAgXHJcbiAgY29uc29sZS5sb2coJ2luaXRpYWxpemVBdXRoIGNhbGxlZCcpXHJcbiAgbGV0IGNyZWQgPSBhd2FpdCBjaGVja0N1cnJlbnRTdGF0dXMoYXBwSWQsIFBPUlRBTF9VUkwpO1xyXG5cclxuICBpZighY3JlZCl7XHJcbiAgICBjcmVkID0gYXdhaXQgc2lnbkluKGFwcElkLCBQT1JUQUxfVVJMKTsgICAgXHJcbiAgfVxyXG5cclxuICBjb25zdCBjcmVkZW50aWFsID0ge1xyXG4gICAgZXhwaXJlczogY3JlZC5leHBpcmVzLFxyXG4gICAgc2VydmVyOiBjcmVkLnNlcnZlcixcclxuICAgIHNzbDogY3JlZC5zc2wsXHJcbiAgICB0b2tlbjogY3JlZC50b2tlbixcclxuICAgIHVzZXJJZDogY3JlZC51c2VySWRcclxuICB9IGFzIElDcmVkZW50aWFsXHJcblxyXG4gIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLkFVVEhFTlRJQ0FURV9BQ1RJT04sIGNyZWRlbnRpYWwpOyBcclxufVxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlTGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXM6IExpZmVsaW5lU3RhdHVzLCBcclxuICBjb25maWc6IEFwcFdpZGdldENvbmZpZywgYXNzZXNzbWVudE9iamVjdElkOiBudW1iZXIsICB1c2VyOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgXHJcbiAgY29uc29sZS5sb2coJ2NhbGxlZCB1cGRhdGVMaWZlbGluZVN0YXR1cycpXHJcbiAgY2hlY2tQYXJhbShjb25maWcubGlmZWxpbmVTdGF0dXMsICdMaWZlbGluZSBTdGF0dXMgVVJMIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICBjb25zdCBhdHRyaWJ1dGVzID0ge1xyXG4gICAgT0JKRUNUSUQ6IGxpZmVsaW5lU3RhdHVzLm9iamVjdElkLFxyXG4gICAgU2NvcmU6IGxpZmVsaW5lU3RhdHVzLnNjb3JlLCBcclxuICAgIENvbG9yOiBsaWZlbGluZVN0YXR1cy5jb2xvciwgXHJcbiAgICBJc092ZXJyaWRlbjogbGlmZWxpbmVTdGF0dXMuaXNPdmVycmlkZW4sIFxyXG4gICAgT3ZlcnJpZGVuU2NvcmU6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlU2NvcmUsICBcclxuICAgIE92ZXJyaWRlbkNvbG9yOiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZW5Db2xvcixcclxuICAgIE92ZXJyaWRlbkJ5OiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZW5CeSwgIFxyXG4gICAgT3ZlcnJpZGVDb21tZW50OiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZUNvbW1lbnQgXHJcbiAgfVxyXG4gIGxldCByZXNwb25zZSAgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBhdHRyaWJ1dGVzLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG5cclxuICAgIGNvbnN0IGlhRmVhdHVyZXMgPSBsaWZlbGluZVN0YXR1cy5pbmRpY2F0b3JBc3Nlc3NtZW50cy5tYXAoaSA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgT0JKRUNUSUQ6IGkub2JqZWN0SWQsXHJcbiAgICAgICAgICBzdGF0dXM6IGkuc3RhdHVzLFxyXG4gICAgICAgICAgQ29tbWVudHM6IGkuY29tbWVudHMgJiYgaS5jb21tZW50cy5sZW5ndGggPiAwID8gSlNPTi5zdHJpbmdpZnkoaS5jb21tZW50cyk6ICcnXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9KVxyXG5cclxuICAgIHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGlhRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuXHJcbiAgICAgIGNvbnN0IGFzc2Vzc0ZlYXR1cmUgPSB7XHJcbiAgICAgICAgT0JKRUNUSUQ6IGFzc2Vzc21lbnRPYmplY3RJZCxcclxuICAgICAgICBFZGl0ZWREYXRlOiBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcclxuICAgICAgICBFZGl0b3I6IHVzZXJcclxuICAgICAgfVxyXG4gICAgICByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcuYXNzZXNzbWVudHMsIGFzc2Vzc0ZlYXR1cmUsIGNvbmZpZylcclxuICAgICAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0gICAgXHJcbiAgfVxyXG4gIGxvZygnVXBkYXRpbmcgTGlmZWxpbmUgc2NvcmUgZmFpbGVkJywgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZUxpZmVsaW5lU3RhdHVzJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ1VwZGF0aW5nIExpZmVsaW5lIHNjb3JlIGZhaWxlZCdcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wbGV0ZUFzc2Vzc21lbnQoYXNzZXNzbWVudDogQXNzZXNzbWVudCwgXHJcbiAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHVzZXJOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIGNoZWNrUGFyYW0oY29uZmlnLmFzc2Vzc21lbnRzLCAnTm8gQXNzZXNzbWVudCBVcmwgcHJvdmlkZWQnKTtcclxuXHJcbiAgIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcuYXNzZXNzbWVudHMsIHtcclxuICAgICAgT0JKRUNUSUQ6IGFzc2Vzc21lbnQub2JqZWN0SWQsXHJcbiAgICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICAgIEVkaXRlZERhdGU6IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxyXG4gICAgICBJc0NvbXBsZXRlZDogMVxyXG4gICB9LCBjb25maWcpO1xyXG4gICBjb25zb2xlLmxvZyhyZXNwb25zZSk7XHJcbiAgIHJldHVybntcclxuICAgICBkYXRhOiByZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpXHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IHBhc3NEYXRhSW50ZWdyaXR5ID0gYXN5bmMgKHNlcnZpY2VVcmw6IHN0cmluZywgZmllbGRzOiBJRmllbGRbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpID0+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShzZXJ2aWNlVXJsLCAnU2VydmljZSBVUkwgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIC8vIHNlcnZpY2VVcmwgPSBgJHtzZXJ2aWNlVXJsfT9mPWpzb24mdG9rZW49JHt0b2tlbn1gO1xyXG4gIC8vIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goc2VydmljZVVybCwge1xyXG4gIC8vICAgbWV0aG9kOiBcIkdFVFwiLFxyXG4gIC8vICAgaGVhZGVyczoge1xyXG4gIC8vICAgICAnY29udGVudC10eXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAvLyAgIH1cclxuICAvLyB9XHJcbiAgLy8gKTtcclxuICAvLyBjb25zdCBqc29uID0gYXdhaXQgcmVzcG9uc2UuanNvbigpO1xyXG5cclxuICAvLyBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhzZXJ2aWNlVXJsLCAnMT0xJywgY29uZmlnKTtcclxuXHJcbiAgLy8gY29uc3QgZGF0YUZpZWxkcyA9IGZlYXR1cmVzWzBdLiBhcyBJRmllbGRbXTtcclxuXHJcbiAgLy8gZGVidWdnZXI7XHJcbiAgLy8gaWYgKGZpZWxkcy5sZW5ndGggPiBkYXRhRmllbGRzLmxlbmd0aCkge1xyXG4gIC8vICAgdGhyb3cgbmV3IEVycm9yKCdOdW1iZXIgb2YgZmllbGRzIGRvIG5vdCBtYXRjaCBmb3IgJyArIHNlcnZpY2VVcmwpO1xyXG4gIC8vIH1cclxuXHJcbiAgLy8gY29uc3QgYWxsRmllbGRzR29vZCA9IGZpZWxkcy5ldmVyeShmID0+IHtcclxuICAvLyAgIGNvbnN0IGZvdW5kID0gZGF0YUZpZWxkcy5maW5kKGYxID0+IGYxLm5hbWUgPT09IGYubmFtZSAmJiBmMS50eXBlLnRvU3RyaW5nKCkgPT09IGYudHlwZS50b1N0cmluZygpICYmIGYxLmRvbWFpbiA9PSBmLmRvbWFpbik7XHJcbiAgLy8gICByZXR1cm4gZm91bmQ7XHJcbiAgLy8gfSk7XHJcblxyXG4gIC8vIGlmICghYWxsRmllbGRzR29vZCkge1xyXG4gIC8vICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGZpZWxkcyBpbiB0aGUgZmVhdHVyZSBzZXJ2aWNlICcgKyBzZXJ2aWNlVXJsKVxyXG4gIC8vIH1cclxuICByZXR1cm4gdHJ1ZTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0SW5kaWNhdG9yRmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgSW5kaWNhdG9ycyBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0V2VpZ2h0c0ZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IFdlaWdodHMgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldExpZmVsaW5lRmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgTGlmZWxpbmUgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0Q29tcG9uZW50RmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgQ29tcG9uZW50cyBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5jb21wb25lbnRzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0VGVtcGxhdGVGZWF0dXJlU2V0KHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVNldD57XHJcbiAgY29uc29sZS5sb2coJ2dldCBUZW1wbGF0ZSBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVTZXQoY29uZmlnLnRlbXBsYXRlcywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRUZW1wbGF0ZXMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlSWQ/OiBzdHJpbmcsIHF1ZXJ5U3RyaW5nPzpzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxDTFNTVGVtcGxhdGVbXT4+IHtcclxuXHJcbiAgY29uc3QgdGVtcGxhdGVVcmwgPSBjb25maWcudGVtcGxhdGVzO1xyXG4gIGNvbnN0IGxpZmVsaW5lVXJsID0gY29uZmlnLmxpZmVsaW5lcztcclxuICBjb25zdCBjb21wb25lbnRVcmwgPSBjb25maWcuY29tcG9uZW50cztcclxuXHJcbiAgdHJ5e1xyXG4gICAgY2hlY2tQYXJhbSh0ZW1wbGF0ZVVybCwgVEVNUExBVEVfVVJMX0VSUk9SKTtcclxuICAgIGNoZWNrUGFyYW0obGlmZWxpbmVVcmwsIExJRkVMSU5FX1VSTF9FUlJPUik7XHJcbiAgICBjaGVja1BhcmFtKGNvbXBvbmVudFVybCwgQ09NUE9ORU5UX1VSTF9FUlJPUik7XHJcblxyXG4gICAgY29uc3QgdGVtcFF1ZXJ5ID0gdGVtcGxhdGVJZCA/IGBHbG9iYWxJRD0nJHt0ZW1wbGF0ZUlkfWAgOihxdWVyeVN0cmluZyA/IHF1ZXJ5U3RyaW5nIDogJzE9MScgKTtcclxuXHJcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IFByb21pc2UuYWxsKFtcclxuICAgICAgZ2V0VGVtcGxhdGVGZWF0dXJlU2V0KHRlbXBRdWVyeSwgY29uZmlnKSxcclxuICAgICAgZ2V0TGlmZWxpbmVGZWF0dXJlcygnMT0xJywgY29uZmlnKSwgXHJcbiAgICAgIGdldENvbXBvbmVudEZlYXR1cmVzKCcxPTEnLCBjb25maWcpXSk7XHJcbiAgICBcclxuICAgIGNvbnN0IHRlbXBsYXRlRmVhdHVyZVNldCA9IHJlc3BvbnNlWzBdO1xyXG4gICAgY29uc3QgbGlmZWxpbmVGZWF0dXJlcyA9IHJlc3BvbnNlWzFdO1xyXG4gICAgY29uc3QgY29tcG9uZW50RmVhdHVyZXMgPSByZXNwb25zZVsyXTtcclxuXHJcbiAgICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlcyA9IGF3YWl0IGdldEluZGljYXRvckZlYXR1cmVzKCcxPTEnLCBjb25maWcpO1xyXG4gICAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSBhd2FpdCBnZXRXZWlnaHRzRmVhdHVyZXMoJzE9MScsIGNvbmZpZyk7XHJcblxyXG4gICAgY29uc3QgdGVtcGxhdGVzID0gYXdhaXQgUHJvbWlzZS5hbGwodGVtcGxhdGVGZWF0dXJlU2V0LmZlYXR1cmVzLm1hcChhc3luYyAodGVtcGxhdGVGZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgICBjb25zdCB0ZW1wbGF0ZUluZGljYXRvckZlYXR1cmVzID0gaW5kaWNhdG9yRmVhdHVyZXMuZmlsdGVyKGkgPT5pLmF0dHJpYnV0ZXMuVGVtcGxhdGVJRCA9PSB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgICAgICBcclxuICAgICAgcmV0dXJuIGF3YWl0IGdldFRlbXBsYXRlKHRlbXBsYXRlRmVhdHVyZSwgbGlmZWxpbmVGZWF0dXJlcywgY29tcG9uZW50RmVhdHVyZXMsIFxyXG4gICAgICAgIHRlbXBsYXRlSW5kaWNhdG9yRmVhdHVyZXMsIHdlaWdodEZlYXR1cmVzLCBcclxuICAgICAgICB0ZW1wbGF0ZUZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdTdGF0dXMnKS5kb21haW4uY29kZWRWYWx1ZXMpXHJcbiAgICB9KSk7XHJcblxyXG4gICAgaWYodGVtcGxhdGVzLmZpbHRlcih0ID0+IHQuaXNTZWxlY3RlZCkubGVuZ3RoID4gMSB8fCB0ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5pc1NlbGVjdGVkKS5sZW5ndGggPT0gMCl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdGVtcGxhdGVzLm1hcCh0ID0+IHtcclxuICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLnQsXHJcbiAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IHQubmFtZSA9PT0gQkFTRUxJTkVfVEVNUExBVEVfTkFNRVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBpZih0ZW1wbGF0ZXMubGVuZ3RoID09PSAxKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0ZW1wbGF0ZXMubWFwKHQgPT4ge1xyXG4gICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgaXNTZWxlY3RlZDogdHJ1ZVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRlbXBsYXRlc1xyXG4gICAgfVxyXG4gIH1cclxuICBjYXRjaChlKXsgXHJcbiAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2dldFRlbXBsYXRlcycpO1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiAnVGVtcGxhdGVzIHJlcXVlc3QgZmFpbGVkLidcclxuICAgIH1cclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiB1c2VGZXRjaERhdGE8VD4odXJsOiBzdHJpbmcsIGNhbGxiYWNrQWRhcHRlcj86IEZ1bmN0aW9uKTogW1QsIEZ1bmN0aW9uLCBib29sZWFuLCBzdHJpbmddIHtcclxuICBjb25zdCBbZGF0YSwgc2V0RGF0YV0gPSBSZWFjdC51c2VTdGF0ZShudWxsKTtcclxuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSBSZWFjdC51c2VTdGF0ZSh0cnVlKTtcclxuICBjb25zdCBbZXJyb3IsIHNldEVycm9yXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTtcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgIGNvbnN0IGNvbnRyb2xsZXIgPSBuZXcgQWJvcnRDb250cm9sbGVyKCk7XHJcbiAgICByZXF1ZXN0RGF0YSh1cmwsIGNvbnRyb2xsZXIpXHJcbiAgICAgIC50aGVuKChkYXRhKSA9PiB7XHJcbiAgICAgICAgaWYgKGNhbGxiYWNrQWRhcHRlcikge1xyXG4gICAgICAgICAgc2V0RGF0YShjYWxsYmFja0FkYXB0ZXIoZGF0YSkpO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICBzZXREYXRhKGRhdGEpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgfSlcclxuICAgICAgLmNhdGNoKChlcnIpID0+IHtcclxuICAgICAgICBjb25zb2xlLmxvZyhlcnIpO1xyXG4gICAgICAgIHNldEVycm9yKGVycik7XHJcbiAgICAgIH0pXHJcbiAgICByZXR1cm4gKCkgPT4gY29udHJvbGxlci5hYm9ydCgpO1xyXG4gIH0sIFt1cmxdKVxyXG5cclxuICByZXR1cm4gW2RhdGEsIHNldERhdGEsIGxvYWRpbmcsIGVycm9yXVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gZGlzcGF0Y2hBY3Rpb24odHlwZTogYW55LCB2YWw6IGFueSkge1xyXG4gIGdldEFwcFN0b3JlKCkuZGlzcGF0Y2goe1xyXG4gICAgdHlwZSxcclxuICAgIHZhbFxyXG4gIH0pO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0SW5jaWRlbnRzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJbmNpZGVudFtdPiB7XHJcbiAgIFxyXG4gIGNvbnNvbGUubG9nKCdnZXQgaW5jaWRlbnRzIGNhbGxlZC4nKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluY2lkZW50cywgSU5DSURFTlRfVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluY2lkZW50cywgJzE9MScsIGNvbmZpZyk7XHJcblxyXG4gIGNvbnN0IHF1ZXJ5ID0gYEdsb2JhbElEIElOICgke2ZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5IYXphcmRJRCkubWFwKGlkID0+IGAnJHtpZH0nYCkuam9pbignLCcpfSlgO1xyXG4gIFxyXG4gIGNvbnN0IGhhemFyZEZlYXR1cmVzZXQgPSBhd2FpdCBnZXRIYXphcmRGZWF0dXJlcyhjb25maWcsIHF1ZXJ5LCAnZ2V0SW5jaWRlbnRzJyk7XHJcblxyXG4gIHJldHVybiBmZWF0dXJlcy5tYXAoKGY6IElGZWF0dXJlKSA9PntcclxuICAgICAgY29uc3QgaGYgPSBoYXphcmRGZWF0dXJlc2V0LmZlYXR1cmVzLmZpbmQoaCA9PiBoLmF0dHJpYnV0ZXMuR2xvYmFsSUQgPT0gZi5hdHRyaWJ1dGVzLkhhemFyZElEKVxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG9iamVjdElkOiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICBoYXphcmQ6IGhmID8ge1xyXG4gICAgICAgICAgb2JqZWN0SWQ6IGhmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgICBpZDogaGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICAgIG5hbWU6IGhmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICAgIHRpdGxlOiBoZi5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSB8fCBoZi5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGhmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICAgIHR5cGU6IGhmLmF0dHJpYnV0ZXMuVHlwZSxcclxuICAgICAgICAgIGRlc2NyaXB0aW9uOiBoZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgICAgZG9tYWluczogaGF6YXJkRmVhdHVyZXNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1R5cGUnKS5kb21haW4uY29kZWRWYWx1ZXNcclxuICAgICAgICB9IDogbnVsbCxcclxuICAgICAgICBkZXNjcmlwdGlvbjogZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgIHN0YXJ0RGF0ZTogTnVtYmVyKGYuYXR0cmlidXRlcy5TdGFydERhdGUpLFxyXG4gICAgICAgIGVuZERhdGU6IE51bWJlcihmLmF0dHJpYnV0ZXMuRW5kRGF0ZSlcclxuICAgICAgfSBhcyBJbmNpZGVudDtcclxuICB9KTtcclxuICByZXR1cm4gW107XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEhhemFyZEZlYXR1cmVzIChjb25maWc6IEFwcFdpZGdldENvbmZpZywgcXVlcnk6IHN0cmluZywgY2FsbGVyOiBzdHJpbmcpOiBQcm9taXNlPElGZWF0dXJlU2V0PiB7XHJcbiAgY29uc29sZS5sb2coJ2dldCBIYXphcmRzIGNhbGxlZCBieSAnK2NhbGxlcilcclxuICBjaGVja1BhcmFtKGNvbmZpZy5oYXphcmRzLCBIQVpBUkRfVVJMX0VSUk9SKTsgIFxyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZVNldChjb25maWcuaGF6YXJkcywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRIYXphcmRzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBxdWVyeVN0cmluZzogc3RyaW5nLCBjYWxsZXI6IHN0cmluZyk6IFByb21pc2U8SGF6YXJkW10+IHtcclxuICBcclxuICBjb25zdCBmZWF0dXJlU2V0ID0gYXdhaXQgZ2V0SGF6YXJkRmVhdHVyZXMoY29uZmlnLCBxdWVyeVN0cmluZywgY2FsbGVyKTtcclxuICBpZighZmVhdHVyZVNldCB8fCBmZWF0dXJlU2V0LmZlYXR1cmVzLmxlbmd0aCA9PSAwKXtcclxuICAgIHJldHVybiBbXTtcclxuICB9XHJcbiAgcmV0dXJuIGZlYXR1cmVTZXQuZmVhdHVyZXMubWFwKChmOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgb2JqZWN0SWQ6IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIHRpdGxlOiBmLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlIHx8IGYuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgdHlwZTogZi5hdHRyaWJ1dGVzLlR5cGUsXHJcbiAgICAgIGRlc2NyaXB0aW9uOiBmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgIGRvbWFpbnM6IGZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdUeXBlJykuZG9tYWluLmNvZGVkVmFsdWVzXHJcbiAgICB9IGFzIEhhemFyZFxyXG4gIH0pXHJcbiAgcmV0dXJuIFtdO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0T3JnYW5pemF0aW9ucyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgcXVlcnlTdHJpbmc6IHN0cmluZyk6IFByb21pc2U8T3JnYW5pemF0aW9uW10+IHtcclxuICBjb25zb2xlLmxvZygnZ2V0IE9yZ2FuaXphdGlvbnMgY2FsbGVkJylcclxuICBjaGVja1BhcmFtKGNvbmZpZy5vcmdhbml6YXRpb25zLCBPUkdBTklaQVRJT05fVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgZmVhdHVyZVNldCA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlU2V0KGNvbmZpZy5vcmdhbml6YXRpb25zLCBxdWVyeVN0cmluZywgY29uZmlnKTtcclxuIFxyXG4gIGlmKGZlYXR1cmVTZXQgJiYgZmVhdHVyZVNldC5mZWF0dXJlcyAmJiBmZWF0dXJlU2V0LmZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgcmV0dXJuIGZlYXR1cmVTZXQuZmVhdHVyZXMubWFwKChmOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG9iamVjdElkOiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICB0aXRsZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgdHlwZTogZi5hdHRyaWJ1dGVzLlR5cGUsXHJcbiAgICAgICAgcGFyZW50SWQ6IGYuYXR0cmlidXRlcy5QYXJlbnRJRCxcclxuICAgICAgICBkZXNjcmlwdGlvbjogZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgIGRvbWFpbnM6IGZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdUeXBlJykuZG9tYWluLmNvZGVkVmFsdWVzXHJcbiAgICAgIH0gYXMgT3JnYW5pemF0aW9uXHJcbiAgICB9KVxyXG4gIH1cclxuICByZXR1cm4gW107XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcmVhdGVOZXdUZW1wbGF0ZShjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgXHJcbiB1c2VyTmFtZTogc3RyaW5nLCBvcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbiwgaGF6YXJkOiBIYXphcmQpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG4gXHJcbiAgY2hlY2tQYXJhbShjb25maWcudGVtcGxhdGVzLCBURU1QTEFURV9VUkxfRVJST1IpO1xyXG4gIGNoZWNrUGFyYW0odGVtcGxhdGUsICdUZW1wbGF0ZSBkYXRhIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICBjb25zdCBjcmVhdGVEYXRlID0gbmV3IERhdGUoKS5nZXRUaW1lKCk7XHJcbiAgY29uc3QgdGVtcGxhdGVOYW1lID0gdGVtcGxhdGUubmFtZVswXS50b0xvY2FsZVVwcGVyQ2FzZSgpK3RlbXBsYXRlLm5hbWUuc3Vic3RyaW5nKDEpO1xyXG4gXHJcbiAgbGV0IGZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIE9yZ2FuaXphdGlvbklEOiBvcmdhbml6YXRpb24gPyBvcmdhbml6YXRpb24uaWQgOiAgbnVsbCxcclxuICAgICAgT3JnYW5pemF0aW9uTmFtZTogb3JnYW5pemF0aW9uID8gb3JnYW5pemF0aW9uLm5hbWU6IG51bGwsXHJcbiAgICAgIE9yZ2FuaXphdGlvblR5cGU6IG9yZ2FuaXphdGlvbiA/IChvcmdhbml6YXRpb24udHlwZS5jb2RlID8gb3JnYW5pemF0aW9uLnR5cGUuY29kZTogb3JnYW5pemF0aW9uLnR5cGUgKTogbnVsbCxcclxuICAgICAgSGF6YXJkSUQ6ICBoYXphcmQgPyBoYXphcmQuaWQgOiBudWxsLFxyXG4gICAgICBIYXphcmROYW1lOiAgaGF6YXJkID8gaGF6YXJkLm5hbWUgOiBudWxsLFxyXG4gICAgICBIYXphcmRUeXBlOiAgaGF6YXJkID8gKGhhemFyZC50eXBlLmNvZGUgPyBoYXphcmQudHlwZS5jb2RlIDogaGF6YXJkLnR5cGUpIDogbnVsbCxcclxuICAgICAgTmFtZTogdGVtcGxhdGVOYW1lICxcclxuICAgICAgQ3JlYXRvcjogdXNlck5hbWUsXHJcbiAgICAgIENyZWF0ZWREYXRlOiBjcmVhdGVEYXRlLCAgICAgIFxyXG4gICAgICBTdGF0dXM6IDEsXHJcbiAgICAgIElzU2VsZWN0ZWQ6IDAsXHJcbiAgICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICAgIEVkaXRlZERhdGU6IGNyZWF0ZURhdGUgICAgIFxyXG4gICAgfVxyXG4gIH1cclxuICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy50ZW1wbGF0ZXMsIFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgIFxyXG4gICAgY29uc3QgdGVtcGxhdGVJZCA9IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWQ7XHJcbiAgICAvL2NyZWF0ZSBuZXcgaW5kaWNhdG9ycyAgIFxyXG4gICAgY29uc3QgaW5kaWNhdG9ycyA9IGdldFRlbXBsYXRlSW5kaWNhdG9ycyh0ZW1wbGF0ZSk7XHJcbiAgICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlcyA9IGluZGljYXRvcnMubWFwKGluZGljYXRvciA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgVGVtcGxhdGVJRDogdGVtcGxhdGVJZCwgIFxyXG4gICAgICAgICAgQ29tcG9uZW50SUQ6IGluZGljYXRvci5jb21wb25lbnRJZCxcclxuICAgICAgICAgIENvbXBvbmVudE5hbWU6IGluZGljYXRvci5jb21wb25lbnROYW1lLCAgXHJcbiAgICAgICAgICBOYW1lOiBpbmRpY2F0b3IubmFtZSwgICBcclxuICAgICAgICAgIFRlbXBsYXRlTmFtZTogdGVtcGxhdGVOYW1lLCBcclxuICAgICAgICAgIExpZmVsaW5lTmFtZTogaW5kaWNhdG9yLmxpZmVsaW5lTmFtZSAgICAgIFxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSlcclxuICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgaW5kaWNhdG9yRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuXHJcbiAgICAgIGNvbnN0IGdsb2JhbElkcyA9IGAoJHtyZXNwb25zZS5hZGRSZXN1bHRzLm1hcChyID0+IGAnJHtyLmdsb2JhbElkfSdgKS5qb2luKCcsJyl9KWA7XHJcbiAgICAgIGNvbnN0IHF1ZXJ5ID0gJ0dsb2JhbElEIElOICcrZ2xvYmFsSWRzOyAgICAgXHJcbiAgICAgIGNvbnN0IGFkZGVkSW5kaWNhdG9yRmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMscXVlcnkgLCBjb25maWcpO1xyXG5cclxuICAgICAgIGxldCB3ZWlnaHRzRmVhdHVyZXMgPSBbXTtcclxuICAgICAgIGZvcihsZXQgZmVhdHVyZSBvZiBhZGRlZEluZGljYXRvckZlYXR1cmVzKXsgICBcclxuICAgICAgICAgY29uc3QgaW5jb21pbmdJbmRpY2F0b3IgPSBpbmRpY2F0b3JzLmZpbmQoaSA9PiBpLm5hbWUgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lKTtcclxuICAgICAgICAgaWYoaW5jb21pbmdJbmRpY2F0b3Ipe1xyXG4gICAgICAgICAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSBpbmNvbWluZ0luZGljYXRvci53ZWlnaHRzLm1hcCh3ID0+IHsgICAgICAgIFxyXG4gICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgICAgICAgIEluZGljYXRvcklEOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsICBcclxuICAgICAgICAgICAgICAgIE5hbWU6IHcubmFtZSAsXHJcbiAgICAgICAgICAgICAgICBXZWlnaHQ6IHcud2VpZ2h0LCBcclxuICAgICAgICAgICAgICAgIFNjYWxlRmFjdG9yOiAwLCAgXHJcbiAgICAgICAgICAgICAgICBBZGp1c3RlZFdlaWdodCA6IDAsXHJcbiAgICAgICAgICAgICAgICBNYXhBZGp1c3RlZFdlaWdodDowXHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICAgIHdlaWdodHNGZWF0dXJlcyA9IHdlaWdodHNGZWF0dXJlcy5jb25jYXQod2VpZ2h0RmVhdHVyZXMpXHJcbiAgICAgICAgIH0gICAgICAgICAgICBcclxuICAgICAgIH1cclxuXHJcbiAgICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHdlaWdodHNGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgICAgfVxyXG4gICAgICAgfVxyXG4gICAgfVxyXG4gICAgLy8gY29uc3QgcHJvbWlzZXMgPSBpbmRpY2F0b3JzLm1hcChpbmRpY2F0b3IgPT4gY3JlYXRlTmV3SW5kaWNhdG9yKGluZGljYXRvciwgY29uZmlnLCB0ZW1wbGF0ZUlkLCB0ZW1wbGF0ZU5hbWUpKTtcclxuXHJcbiAgICAvLyBjb25zdCBwcm9taXNlUmVzcG9uc2UgPSBhd2FpdCBQcm9taXNlLmFsbChwcm9taXNlcyk7XHJcbiAgICAvLyBpZihwcm9taXNlUmVzcG9uc2UuZXZlcnkocCA9PiBwLmRhdGEpKXtcclxuICAgIC8vICAgcmV0dXJuIHtcclxuICAgIC8vICAgICBkYXRhOiB0cnVlXHJcbiAgICAvLyAgIH1cclxuICAgIC8vIH1cclxuICB9IFxyXG5cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnY3JlYXRlTmV3VGVtcGxhdGUnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBjcmVhdGluZyB0aGUgbmV3IHRlbXBsYXRlJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZVRlbXBsYXRlT3JnYW5pemF0aW9uQW5kSGF6YXJkKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBcclxuICB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCB1c2VyTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbSh0ZW1wbGF0ZSwgJ1RlbXBsYXRlIG5vdCBwcm92aWRlZCcpO1xyXG4gIGNoZWNrUGFyYW0oY29uZmlnLnRlbXBsYXRlcywgVEVNUExBVEVfVVJMX0VSUk9SKTsgXHJcblxyXG4gIGNvbnN0IGF0dHJpYnV0ZXMgPSB7XHJcbiAgICBPQkpFQ1RJRDogdGVtcGxhdGUub2JqZWN0SWQsXHJcbiAgICBPcmdhbml6YXRpb25JRDogdGVtcGxhdGUub3JnYW5pemF0aW9uSWQsXHJcbiAgICBIYXphcmRJRDogdGVtcGxhdGUuaGF6YXJkSWQsXHJcbiAgICBPcmdhbml6YXRpb25OYW1lOiB0ZW1wbGF0ZS5vcmdhbml6YXRpb25OYW1lLFxyXG4gICAgT3JnYW5pemF0aW9uVHlwZTogdGVtcGxhdGUub3JnYW5pemF0aW9uVHlwZSxcclxuICAgIEhhemFyZE5hbWU6IHRlbXBsYXRlLmhhemFyZE5hbWUsXHJcbiAgICBIYXphcmRUeXBlOiB0ZW1wbGF0ZS5oYXphcmRUeXBlLFxyXG4gICAgTmFtZTogdGVtcGxhdGUubmFtZSxcclxuICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICBFZGl0ZWREYXRlOiBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcclxuICAgIFN0YXR1czogdGVtcGxhdGUuc3RhdHVzLmNvZGUsXHJcbiAgICBJc1NlbGVjdGVkOiB0ZW1wbGF0ZS5pc1NlbGVjdGVkID8gMTogMFxyXG4gIH0gXHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy50ZW1wbGF0ZXMsIGF0dHJpYnV0ZXMsIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICB9XHJcbiAgfVxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICd1cGRhdGVUZW1wbGF0ZU9yZ2FuaXphdGlvbkFuZEhhemFyZCcpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHVwZGF0aW5nIHRlbXBsYXRlLidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzZWxlY3RUZW1wbGF0ZShvYmplY3RJZDogbnVtYmVyLCBvYmplY3RJZHM6IG51bWJlcltdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPFN0cmluZz4+IHtcclxuICBcclxuICAgIGNvbnNvbGUubG9nKCdzZWxlY3QgVGVtcGxhdGUgY2FsbGVkJylcclxuICAgIHRyeXtcclxuICAgICAgY2hlY2tQYXJhbShjb25maWcudGVtcGxhdGVzLCBURU1QTEFURV9VUkxfRVJST1IpO1xyXG5cclxuICAgICAgLy9sZXQgZmVhdHVyZXMgPSBhd2FpdCBnZXRUZW1wbGF0ZUZlYXR1cmVzKCcxPTEnLCBjb25maWcpLy8gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy50ZW1wbGF0ZXMsICcxPTEnLCBjb25maWcpXHJcbiAgICBcclxuICAgICAgY29uc3QgZmVhdHVyZXMgPSAgb2JqZWN0SWRzLm1hcChvaWQgPT4ge1xyXG4gICAgICAgIHJldHVybiB7ICAgICAgICAgIFxyXG4gICAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgICBPQkpFQ1RJRDogb2lkLFxyXG4gICAgICAgICAgICBJc1NlbGVjdGVkOiBvaWQgPT09IG9iamVjdElkID8gMSA6IDBcclxuICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgIH0pXHJcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlcyhjb25maWcudGVtcGxhdGVzLCBmZWF0dXJlcywgY29uZmlnKVxyXG4gICAgICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGE6IHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHNbMF0uZ2xvYmFsSWRcclxuICAgICAgICAgfSBhcyBDbHNzUmVzcG9uc2U8U3RyaW5nPjtcclxuICAgICAgfVxyXG4gICAgfWNhdGNoKGUpIHtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdzZWxlY3RUZW1wbGF0ZScpO1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGVycm9yczogZVxyXG4gICAgICB9XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBsb2FkU2NhbGVGYWN0b3JzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8U2NhbGVGYWN0b3JbXT4+e1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5jb25zdGFudHMsICdSYXRpbmcgU2NhbGVzIHVybCBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgdHJ5e1xyXG5cclxuICAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmNvbnN0YW50cywgJzE9MScsIGNvbmZpZyk7XHJcbiAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgIGNvbnN0IHNjYWxlcyA9ICBmZWF0dXJlcy5tYXAoZiA9PntcclxuICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgICB2YWx1ZTogZi5hdHRyaWJ1dGVzLlZhbHVlXHJcbiAgICAgICB9IGFzIFNjYWxlRmFjdG9yOyAgICAgICBcclxuICAgICB9KVxyXG5cclxuICAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiBzY2FsZXNcclxuICAgIH0gYXMgQ2xzc1Jlc3BvbnNlPFNjYWxlRmFjdG9yW10+XHJcbiAgIH1cclxuXHJcbiAgIGxvZygnRXJyb3Igb2NjdXJyZWQgd2hpbGUgcmVxdWVzdGluZyByYXRpbmcgc2NhbGVzJywgTG9nVHlwZS5FUlJPUiwgJ2xvYWRSYXRpbmdTY2FsZXMnKVxyXG4gICByZXR1cm4ge1xyXG4gICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHJlcXVlc3RpbmcgcmF0aW5nIHNjYWxlcydcclxuICAgfVxyXG4gIH0gY2F0Y2goZSl7XHJcbiAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdsb2FkUmF0aW5nU2NhbGVzJyk7ICAgIFxyXG4gIH0gIFxyXG4gICBcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZU5ld0luZGljYXRvcihpbmRpY2F0b3I6IEluZGljYXRvclRlbXBsYXRlLCBjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGVJZDogc3RyaW5nLCB0ZW1wbGF0ZU5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElORElDQVRPUl9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBUZW1wbGF0ZUlEOiB0ZW1wbGF0ZUlkLCAgXHJcbiAgICAgIENvbXBvbmVudElEOiBpbmRpY2F0b3IuY29tcG9uZW50SWQsXHJcbiAgICAgIENvbXBvbmVudE5hbWU6IGluZGljYXRvci5jb21wb25lbnROYW1lLCAgXHJcbiAgICAgIE5hbWU6IGluZGljYXRvci5uYW1lLCAgIFxyXG4gICAgICBUZW1wbGF0ZU5hbWU6IHRlbXBsYXRlTmFtZSwgXHJcbiAgICAgIExpZmVsaW5lTmFtZTogaW5kaWNhdG9yLmxpZmVsaW5lTmFtZSAgICAgIFxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgW2luZGljYXRvckZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG5cclxuICAgIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gaW5kaWNhdG9yLndlaWdodHMubWFwKHcgPT4ge1xyXG4gICAgICAgXHJcbiAgICAgICByZXR1cm4ge1xyXG4gICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIEluZGljYXRvcklEOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkLCAgXHJcbiAgICAgICAgICBOYW1lOiB3Lm5hbWUgLFxyXG4gICAgICAgICAgV2VpZ2h0OiB3LndlaWdodCwgXHJcbiAgICAgICAgICBTY2FsZUZhY3RvcjogMCwgIFxyXG4gICAgICAgICAgQWRqdXN0ZWRXZWlnaHQgOiAwLFxyXG4gICAgICAgICAgTWF4QWRqdXN0ZWRXZWlnaHQ6MFxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSk7XHJcblxyXG4gICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCB3ZWlnaHRGZWF0dXJlcywgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgICB9XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnY3JlYXRlTmV3SW5kaWNhdG9yJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHNhdmluZyB0aGUgaW5kaWNhdG9yLidcclxuICB9XHJcblxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlSW5kaWNhdG9yTmFtZShjb25maWc6IEFwcFdpZGdldENvbmZpZywgaW5kaWNhdG9yVGVtcDpJbmRpY2F0b3JUZW1wbGF0ZSk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5ESUNBVE9SX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGF0dHJpYnV0ZXMgPSB7XHJcbiAgICBPQkpFQ1RJRDogaW5kaWNhdG9yVGVtcC5vYmplY3RJZCxcclxuICAgIE5hbWU6IGluZGljYXRvclRlbXAubmFtZSxcclxuICAgIERpc3BsYXlUaXRsZTogaW5kaWNhdG9yVGVtcC5uYW1lLFxyXG4gICAgSXNBY3RpdmU6IDFcclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5pbmRpY2F0b3JzLCBhdHRyaWJ1dGVzLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgfVxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICd1cGRhdGVJbmRpY2F0b3JOYW1lJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgdXBkYXRpbmcgaW5kaWNhdG9yJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZUluZGljYXRvcihpbmRpY2F0b3I6IEluZGljYXRvclRlbXBsYXRlLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5DSURFTlRfVVJMX0VSUk9SKTtcclxuXHJcbiAgbGV0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBgTmFtZT0nJHtpbmRpY2F0b3IubmFtZX0nIEFORCBUZW1wbGF0ZU5hbWU9JyR7aW5kaWNhdG9yLnRlbXBsYXRlTmFtZX0nYCwgY29uZmlnKVxyXG4gXHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6ICdBbiBpbmRpY2F0b3Igd2l0aCB0aGUgc2FtZSBuYW1lIGFscmVhZHkgZXhpc3RzJ1xyXG4gICAgfVxyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZUluZGljYXRvck5hbWUoY29uZmlnLCBpbmRpY2F0b3IpO1xyXG5cclxuICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiByZXNwb25zZS5lcnJvcnNcclxuICAgIH1cclxuICB9XHJcbiBcclxuICAgZmVhdHVyZXMgPSBpbmRpY2F0b3Iud2VpZ2h0cy5tYXAodyA9PiB7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIE9CSkVDVElEOiB3Lm9iamVjdElkLFxyXG4gICAgICAgICAgV2VpZ2h0OiBOdW1iZXIody53ZWlnaHQpLCBcclxuICAgICAgICAgIEFkanVzdGVkV2VpZ2h0OiBOdW1iZXIody53ZWlnaHQpICogdy5zY2FsZUZhY3RvclxyXG4gICAgICAgfVxyXG4gICAgIH1cclxuICAgfSk7XHJcblxyXG4gICBjb25zdCB1cGRhdGVSZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIGZlYXR1cmVzLCBjb25maWcpO1xyXG4gICBpZih1cGRhdGVSZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHVwZGF0ZVJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gICB9XHJcblxyXG4gICBsb2coSlNPTi5zdHJpbmdpZnkodXBkYXRlUmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlSW5kaWNhdG9yJyk7XHJcbiAgIHJldHVybiB7XHJcbiAgICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgdXBkYXRpbmcgaW5kaWNhdG9yLidcclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlSW5kaWNhdG9yKGluZGljYXRvclRlbXBsYXRlOiBJbmRpY2F0b3JUZW1wbGF0ZSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkRJQ0FUT1JfVVJMX0VSUk9SKTtcclxuICBjaGVja1BhcmFtKGNvbmZpZy53ZWlnaHRzLCAnV2VpZ2h0cyBVUkwgbm90IHByb3ZpZGVkJyk7XHJcbiAgXHJcbiAgbGV0IHJlc3AgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBbaW5kaWNhdG9yVGVtcGxhdGUub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gIGlmKHJlc3AuZGVsZXRlUmVzdWx0cyAmJiByZXNwLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICBjb25zdCB3ZWlnaHRzT2JqZWN0SWRzID0gaW5kaWNhdG9yVGVtcGxhdGUud2VpZ2h0cy5tYXAodyA9PiB3Lm9iamVjdElkKTtcclxuICAgICByZXNwID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgd2VpZ2h0c09iamVjdElkcywgY29uZmlnKTtcclxuICAgICBpZihyZXNwLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcC5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICB9XHJcbiAgICAgfVxyXG4gIH1cclxuXHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3ApLCBMb2dUeXBlLkVSUk9SLCAnZGVsZXRlSW5kaWNhdG9yJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgZGVsZXRpbmcgdGhlIGluZGljYXRvcidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBhcmNoaXZlVGVtcGxhdGUob2JqZWN0SWQ6IG51bWJlciwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG4gXHJcbiAgY29uc3QgcmVzcG9uc2UgID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy50ZW1wbGF0ZXMsIHtcclxuICAgIE9CSkVDVElEOiBvYmplY3RJZCxcclxuICAgIElzU2VsZWN0ZWQ6IDAsXHJcbiAgICBJc0FjdGl2ZTogMFxyXG4gIH0sIGNvbmZpZyk7XHJcbiAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeShlID0+IGUuc3VjY2Vzcykpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgfVxyXG4gIH1cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnYXJjaGl2ZVRlbXBsYXRlJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ1RoZSB0ZW1wbGF0ZSBjYW5ub3QgYmUgYXJjaGl2ZWQuJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNhdmVPcmdhbml6YXRpb24oY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8T3JnYW5pemF0aW9uPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5vcmdhbml6YXRpb25zLCBPUkdBTklaQVRJT05fVVJMX0VSUk9SKTtcclxuICBjaGVja1BhcmFtKG9yZ2FuaXphdGlvbiwgJ09yZ2FuaXphdGlvbiBvYmplY3Qgbm90IHByb3ZpZGVkJyk7XHJcbiBcclxuICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBOYW1lOiBvcmdhbml6YXRpb24ubmFtZSxcclxuICAgICAgVHlwZTogb3JnYW5pemF0aW9uLnR5cGU/LmNvZGUsXHJcbiAgICAgIERpc3BsYXlUaXRsZTogb3JnYW5pemF0aW9uLm5hbWUsXHJcbiAgICAgIFBhcmVudElEOiBvcmdhbml6YXRpb24/LnBhcmVudElkXHJcbiAgICB9XHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLm9yZ2FuaXphdGlvbnMsIFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXsgXHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB7XHJcbiAgICAgICAgLi4ub3JnYW5pemF0aW9uXHJcbiAgICAgIH0gYXMgT3JnYW5pemF0aW9uIC8vIChhd2FpdCBnZXRPcmdhbml6YXRpb25zKGNvbmZpZywgYEdsb2JhbElEPScke3Jlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWR9J2ApKVswXVxyXG4gICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzYXZlSGF6YXJkKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBoYXphcmQ6IEhhemFyZCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPEhhemFyZD4+IHtcclxuICBcclxuICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBOYW1lOiBoYXphcmQubmFtZSxcclxuICAgICAgRGlzcGxheVRpdGxlOiBoYXphcmQubmFtZSxcclxuICAgICAgVHlwZTogaGF6YXJkLnR5cGUuY29kZSxcclxuICAgICAgRGVzY3JpcHRpb246IGhhemFyZC5kZXNjcmlwdGlvblxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaGF6YXJkcywgW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2VzcykpeyAgIFxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHtcclxuICAgICAgICAgIC4uLmhhemFyZCxcclxuICAgICAgICAgIG9iamVjdElkOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLm9iamVjdElkLFxyXG4gICAgICAgICAgaWQ6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWRcclxuICAgICAgICB9IGFzIEhhemFyZCAgXHJcbiAgICAgIH1cclxuICB9XHJcblxyXG4gIGxvZyhgRXJyb3Igb2NjdXJyZWQgd2hpbGUgc2F2aW5nIGhhemFyZC4gUmVzdGFydGluZyB0aGUgYXBwbGljYXRpb24gbWF5IGZpeCB0aGlzIGlzc3VlLmAsIExvZ1R5cGUuRVJST1IsICdzYXZlSGF6YXJkJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgc2F2aW5nIGhhemFyZC4gUmVzdGFydGluZyB0aGUgYXBwbGljYXRpb24gbWF5IGZpeCB0aGlzIGlzc3VlLidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVJbmNpZGVudChpbmNpZGVudDogSW5jaWRlbnQsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5jaWRlbnRzLCBbaW5jaWRlbnQub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcG9uc2UuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUhhemFyZChoYXphcmQ6IEhhemFyZCwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaGF6YXJkcywgW2hhemFyZC5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgIGlmKHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcG9uc2UuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgfVxyXG4gICB9XHJcbiAgIHJldHVybiB7XHJcbiAgICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVPcmdhbml6YXRpb24ob3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb24sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcub3JnYW5pemF0aW9ucywgW29yZ2FuaXphdGlvbi5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuZGVsZXRlUmVzdWx0cyAmJiByZXNwb25zZS5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY2hlY2tQYXJhbShwYXJhbTogYW55LCBlcnJvcjogc3RyaW5nKSB7XHJcbiAgaWYgKCFwYXJhbSB8fCBwYXJhbSA9PSBudWxsIHx8IHBhcmFtID09PSAnJyB8fCBwYXJhbSA9PSB1bmRlZmluZWQpIHtcclxuICAgIHRocm93IG5ldyBFcnJvcihlcnJvcilcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB0ZW1wbENsZWFuVXAoaW5kVXJsOiBzdHJpbmcsIGFsaWdVcmw6IHN0cmluZywgdG9rZW46IHN0cmluZykge1xyXG5cclxuXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzYXZlTmV3QXNzZXNzbWVudChuZXdBc3Nlc3NtZW50OiBBc3Nlc3NtZW50LCB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCBcclxuICAgICAgICAgICAgICAgICAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHByZXZBc3Nlc3NtZW50PzogQXNzZXNzbWVudCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHN0cmluZz4+eyAgICBcclxuICAgICAgXHJcbiAgICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBzYXZlQXNzZXNzbWVudChuZXdBc3Nlc3NtZW50LCBjb25maWcpO1xyXG4gICAgICBpZihyZXNwLmVycm9ycyl7XHJcbiAgICAgICAgbG9nKCdVbmFibGUgdG8gY3JlYXRlIHRoZSBhc3Nlc3NtZW50LicsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpO1xyXG5cclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZXJyb3JzOiAnVW5hYmxlIHRvIGNyZWF0ZSB0aGUgYXNzZXNzbWVudC4nXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICAgXHJcbiAgICAgIHRyeXtcclxuXHJcbiAgICAgICAgY29uc3QgaW5kaWNhdG9ycyA9IGdldFRlbXBsYXRlSW5kaWNhdG9ycyh0ZW1wbGF0ZSk7XHJcbiAgICAgICAgaWYoIWluZGljYXRvcnMgfHwgaW5kaWNhdG9ycy5sZW5ndGggPT09IDApe1xyXG4gICAgICAgICAgbG9nKCdUZW1wbGF0ZSBpbmRpY2F0b3JzIG5vdCBmb3VuZCcsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpOyAgXHJcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1RlbXBsYXRlIGluZGljYXRvcnMgbm90IGZvdW5kLicpXHJcbiAgICAgICAgfSAgICAgIFxyXG4gIFxyXG4gICAgICAgIGNvbnN0IGxpZmVsaW5lU3RhdHVzRmVhdHVyZXMgPSB0ZW1wbGF0ZS5saWZlbGluZVRlbXBsYXRlcy5tYXAobHQgPT4ge1xyXG4gICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIGF0dHJpYnV0ZXM6IHsgXHJcbiAgICAgICAgICAgICAgQXNzZXNzbWVudElEIDogcmVzcC5kYXRhLFxyXG4gICAgICAgICAgICAgIFNjb3JlOiBudWxsLCBcclxuICAgICAgICAgICAgICBDb2xvcjogbnVsbCwgXHJcbiAgICAgICAgICAgICAgTGlmZWxpbmVJRDogbHQuaWQsIFxyXG4gICAgICAgICAgICAgIElzT3ZlcnJpZGVuOiAwLCBcclxuICAgICAgICAgICAgICBPdmVycmlkZW5TY29yZTogbnVsbCwgXHJcbiAgICAgICAgICAgICAgT3ZlcnJpZGVuQnk6IG51bGwsIFxyXG4gICAgICAgICAgICAgIE92ZXJyaWRlQ29tbWVudDogbnVsbCwgXHJcbiAgICAgICAgICAgICAgTGlmZWxpbmVOYW1lOiBsdC50aXRsZSwgXHJcbiAgICAgICAgICAgICAgVGVtcGxhdGVOYW1lOiB0ZW1wbGF0ZS5uYW1lXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH1cclxuICAgICAgICB9KVxyXG4gICAgICAgIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBsaWZlbGluZVN0YXR1c0ZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgICAgIGlmKHJlc3BvbnNlICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgICAgIGNvbnN0IHF1ZXJ5ID0gJ0dsb2JhbElEIElOICgnKyByZXNwb25zZS5hZGRSZXN1bHRzLm1hcChyID0+IGAnJHtyLmdsb2JhbElkfSdgKS5qb2luKCcsJykrXCIpXCI7XHJcbiAgICAgICAgICAgY29uc3QgbHNGZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIHF1ZXJ5LCBjb25maWcpO1xyXG4gICAgICAgICAgIFxyXG4gICAgICAgICAgIGNvbnN0IGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcyA9IGluZGljYXRvcnMubWFwKGkgPT4ge1xyXG4gICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgY29uc3QgbGlmZWxpbmVTdGF0dXNGZWF0dXJlID0gbHNGZWF0dXJlcy5maW5kKGxzID0+IFxyXG4gICAgICAgICAgICAgICAgbHMuYXR0cmlidXRlcy5MaWZlbGluZU5hbWUuc3BsaXQoL1snICcmXyxdKy8pLmpvaW4oJ18nKSAgPT09IGkubGlmZWxpbmVOYW1lKTtcclxuICAgICAgICAgICAgaWYoIWxpZmVsaW5lU3RhdHVzRmVhdHVyZSl7XHJcbiAgICAgICAgICAgICAgY29uc29sZS5sb2coYCR7aS5saWZlbGluZU5hbWV9IG5vdCBmb3VuZGApO1xyXG4gICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgJHtpLmxpZmVsaW5lTmFtZX0gbm90IGZvdW5kYCk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICAgICAgICBMaWZlbGluZVN0YXR1c0lEIDogbGlmZWxpbmVTdGF0dXNGZWF0dXJlPyBsaWZlbGluZVN0YXR1c0ZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCA6ICcnLFxyXG4gICAgICAgICAgICAgICAgSW5kaWNhdG9ySUQ6IGkuaWQsICBcclxuICAgICAgICAgICAgICAgIFRlbXBsYXRlTmFtZTogaS50ZW1wbGF0ZU5hbWUsICBcclxuICAgICAgICAgICAgICAgIExpZmVsaW5lTmFtZTogaS5saWZlbGluZU5hbWUsICBcclxuICAgICAgICAgICAgICAgIENvbXBvbmVudE5hbWU6IGkuY29tcG9uZW50TmFtZSwgIFxyXG4gICAgICAgICAgICAgICAgSW5kaWNhdG9yTmFtZTogaS5uYW1lLFxyXG4gICAgICAgICAgICAgICAgQ29tbWVudHM6IFwiXCIsXHJcbiAgICAgICAgICAgICAgICBSYW5rOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gUkFOSyk/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIExpZmVTYWZldHk6IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBMSUZFX1NBRkVUWSk/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIFByb3BlcnR5UHJvdGVjdGlvbjogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IFBST1BFUlRZX1BST1RFQ1RJT04pPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBJbmNpZGVudFN0YWJpbGl6YXRpb246IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBJTkNJREVOVF9TVEFCSUxJWkFUSU9OKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgRW52aXJvbm1lbnRQcmVzZXJ2YXRpb246IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04pPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBTdGF0dXM6IDQgLy91bmtub3duXHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgfSlcclxuICBcclxuICAgICAgICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgICAgICAgaWYocmVzcG9uc2UgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgZGF0YTogcmVzcC5kYXRhXHJcbiAgICAgICAgICAgIH0gXHJcbiAgICAgICAgICAgfWVsc2V7XHJcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignRmFpbGVkIHRvIGFkZCBpbmRpY2F0b3IgYXNzZXNzbWVudCBmZWF0dXJlcycpO1xyXG4gICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgICAgZWxzZXtcclxuICAgICAgICAgIHRocm93IG5ldyBFcnJvcignRmFpbGVkIHRvIGFkZCBMaWZlbGluZSBTdGF0dXMgRmVhdHVyZXMnKTtcclxuICAgICAgICB9IFxyXG5cclxuICAgICAgfWNhdGNoKGUpe1xyXG4gICAgICAgIGF3YWl0IGNsZWFuVXBBc3Nlc3NtZW50RmFpbGVkRGF0YShyZXNwLmRhdGEsIGNvbmZpZyk7XHJcbiAgICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpXHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGVycm9yczonRXJyb3Igb2NjdXJyZWQgd2hpbGUgY3JlYXRpbmcgQXNzZXNzbWVudC4nXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBjbGVhblVwQXNzZXNzbWVudEZhaWxlZERhdGEoYXNzZXNzbWVudEdsb2JhbElkOiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKXtcclxuICAgXHJcbiAgIGxldCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGBHbG9iYWxJRD0nJHthc3Nlc3NtZW50R2xvYmFsSWR9J2AsIGNvbmZpZyk7XHJcbiAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgIGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQpLCBjb25maWcpO1xyXG4gICB9XHJcblxyXG4gICBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIGBBc3Nlc3NtZW50SUQ9JyR7YXNzZXNzbWVudEdsb2JhbElkfSdgLCBjb25maWcpO1xyXG4gICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgIGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQpLCBjb25maWcpO1xyXG5cclxuICAgIGNvbnN0IHF1ZXJ5ID0gYExpZmVsaW5lU3RhdHVzSUQgSU4gKCR7ZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLkdsb2JhbElEKS5qb2luKCcsJyl9KWA7XHJcbiAgICBjb25zb2xlLmxvZygnZGVsZXRlIHF1ZXJpZXMnLCBxdWVyeSlcclxuICAgIGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgcXVlcnksIGNvbmZpZyk7XHJcbiAgICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICAgYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCksIGNvbmZpZyk7XHJcbiAgICB9XHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFzc2Vzc21lbnROYW1lcyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGVOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTx7bmFtZTogc3RyaW5nLCBkYXRlOiBzdHJpbmd9W10+PntcclxuICBcclxuICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGBUZW1wbGF0ZT0nJHt0ZW1wbGF0ZU5hbWV9J2AsIGNvbmZpZyk7XHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID09PSAwKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IFtdXHJcbiAgICB9XHJcbiAgfVxyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICBcclxuICAgICBjb25zdCBhc3Nlc3MgPSAgZmVhdHVyZXMubWFwKGYgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIGRhdGU6IHBhcnNlRGF0ZShOdW1iZXIoZi5hdHRyaWJ1dGVzLkNyZWF0ZWREYXRlKSlcclxuICAgICAgfVxyXG4gICAgIH0pO1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBkYXRhOiBhc3Nlc3NcclxuICAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdSZXF1ZXN0IGZvciBhc3Nlc3NtZW50IG5hbWVzIGZhaWxlZC4nXHJcbiAgfVxyXG5cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0QXNzZXNzbWVudEZlYXR1cmVzKGNvbmZpZykge1xyXG4gICBjb25zb2xlLmxvZygnZ2V0IEFzc2Vzc21lbnQgRmVhdHVyZXMgY2FsbGVkLicpO1xyXG4gICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgYDE9MWAsIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBsb2FkQWxsQXNzZXNzbWVudHMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxBc3Nlc3NtZW50W10+PntcclxuXHJcbiAgIHRyeXtcclxuICAgIGNvbnN0IGFzc2Vzc21lbnRGZWF0dXJlcyA9IGF3YWl0IGdldEFzc2Vzc21lbnRGZWF0dXJlcyhjb25maWcpO1xyXG4gICAgaWYoIWFzc2Vzc21lbnRGZWF0dXJlcyB8fCBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID09IDApe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IFtdXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIFxyXG4gICAgY29uc3QgbHNGZWF0dXJlcyA9IGF3YWl0IGdldExpZmVsaW5lU3RhdHVzRmVhdHVyZXMoY29uZmlnLCBgMT0xYCk7XHJcblxyXG4gICAgY29uc3QgcXVlcnkgPSBgTGlmZWxpbmVTdGF0dXNJRCBJTiAoJHtsc0ZlYXR1cmVzLm1hcChmID0+IGAnJHtmLmF0dHJpYnV0ZXMuR2xvYmFsSUR9J2ApLmpvaW4oJywnKX0pYFxyXG4gICAgXHJcbiAgICBjb25zdCBpbmRpY2F0b3JBc3Nlc3NtZW50cyA9IGF3YWl0IGdldEluZGljYXRvckFzc2Vzc21lbnRzKHF1ZXJ5LCBjb25maWcpO1xyXG5cclxuICAgIGlmKGFzc2Vzc21lbnRGZWF0dXJlcyAmJiBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID4gMCl7ICAgXHJcbiAgICAgIGNvbnN0IGFzc2Vzc21lbnRzID0gYXNzZXNzbWVudEZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgICAgICBjb25zdCBhc3Nlc3NtZW50THNGZWF0dXJlcyA9IGxzRmVhdHVyZXMuZmlsdGVyKGwgPT5sLmF0dHJpYnV0ZXMuQXNzZXNzbWVudElEID09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgICAgICAgIFxyXG4gICAgICAgIHJldHVybiBsb2FkQXNzZXNzbWVudChmZWF0dXJlLCBhc3Nlc3NtZW50THNGZWF0dXJlcywgaW5kaWNhdG9yQXNzZXNzbWVudHMpO1xyXG4gICAgICB9KTtcclxuXHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogYXNzZXNzbWVudHNcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmKGFzc2Vzc21lbnRGZWF0dXJlcyAmJiBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID09IDApe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IFtdXHJcbiAgICAgIH0gIFxyXG4gICAgfVxyXG4gICB9Y2F0Y2goZSl7XHJcbiAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2xvYWRBbGxBc3Nlc3NtZW50cycpO1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiBlXHJcbiAgICB9XHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZUluY2lkZW50KGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBpbmNpZGVudDogSW5jaWRlbnQpOiBQcm9taXNlPENsc3NSZXNwb25zZTx2b2lkPj57XHJcbiAgIFxyXG4gICAgdHJ5e1xyXG4gICAgICBjaGVja1BhcmFtKGNvbmZpZy5pbmNpZGVudHMsIElOQ0lERU5UX1VSTF9FUlJPUik7XHJcbiAgICAgIGNoZWNrUGFyYW0oaW5jaWRlbnQsICdJbmNpZGVudCBkYXRhIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICAgICAgY29uc3QgZmVhdHVyZXMgPSBbe1xyXG4gICAgICAgIGF0dHJpYnV0ZXMgOiB7XHJcbiAgICAgICAgICBIYXphcmRJRDogaW5jaWRlbnQuaGF6YXJkLmlkLFxyXG4gICAgICAgICAgTmFtZSA6IGluY2lkZW50Lm5hbWUsXHJcbiAgICAgICAgICBEZXNjcmlwdGlvbjogaW5jaWRlbnQuZGVzY3JpcHRpb24sXHJcbiAgICAgICAgICBTdGFydERhdGUgOiBTdHJpbmcoaW5jaWRlbnQuc3RhcnREYXRlKSxcclxuICAgICAgICAgIEVuZERhdGUgOiBTdHJpbmcoaW5jaWRlbnQuZW5kRGF0ZSlcclxuICAgICAgICB9XHJcbiAgICAgIH1dXHJcblxyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluY2lkZW50cywgZmVhdHVyZXMsIGNvbmZpZyk7XHJcblxyXG4gICAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgcmV0dXJue30gXHJcbiAgICAgIH1cclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBlcnJvcnM6ICdJbmNpZGVudCBjb3VsZCBub3QgYmUgc2F2ZWQuJ1xyXG4gICAgICB9XHJcbiAgICB9Y2F0Y2goZSkge1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2NyZWF0ZUluY2lkZW50Jyk7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZXJyb3JzOiAnSW5jaWRlbnQgY291bGQgbm90IGJlIHNhdmVkLidcclxuICAgICAgfVxyXG4gICAgfVxyXG59XHJcblxyXG4vLz09PT09PT09PT09PT09PT09PT09UFJJVkFURT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XHJcblxyXG5jb25zdCByZXF1ZXN0RGF0YSA9IGFzeW5jICh1cmw6IHN0cmluZywgY29udHJvbGxlcj86IGFueSk6IFByb21pc2U8SUZlYXR1cmVTZXQ+ID0+IHtcclxuICBpZiAoIWNvbnRyb2xsZXIpIHtcclxuICAgIGNvbnRyb2xsZXIgPSBuZXcgQWJvcnRDb250cm9sbGVyKCk7XHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2godXJsLCB7XHJcbiAgICBtZXRob2Q6IFwiR0VUXCIsXHJcbiAgICBoZWFkZXJzOiB7XHJcbiAgICAgICdjb250ZW50LXR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG4gICAgfSxcclxuICAgIHNpZ25hbDogY29udHJvbGxlci5zaWduYWxcclxuICB9XHJcbiAgKTtcclxuICByZXR1cm4gcmVzcG9uc2UuanNvbigpO1xyXG59XHJcblxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0VGVtcGxhdGUoXHJcbiAgdGVtcGxhdGVGZWF0dXJlOiBJRmVhdHVyZSwgXHJcbiAgbGlmZWxpbmVGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgY29tcG9uZW50RmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIGluZGljYXRvcnNGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgd2VpZ2h0c0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICB0ZW1wbGF0ZURvbWFpbnM6IElDb2RlZFZhbHVlW10pOiBQcm9taXNlPENMU1NUZW1wbGF0ZT57XHJcblxyXG4gIGNvbnN0IGluZGljYXRvckZlYXR1cmVzID0gaW5kaWNhdG9yc0ZlYXR1cmVzLmZpbHRlcihpID0+IGkuYXR0cmlidXRlcy5UZW1wbGF0ZUlEID0gYCcke3RlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEfSdgKS8vICBhd2FpdCBnZXRJbmRpY2F0b3JGZWF0dXJlcyhgVGVtcGxhdGVJRD0nJHt0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRH0nYCwgY29uZmlnKTtcclxuICBcclxuICAvL2NvbnN0IHF1ZXJ5ID0gaW5kaWNhdG9yRmVhdHVyZXMubWFwKGkgPT4gYEluZGljYXRvcklEPScke2kuYXR0cmlidXRlcy5HbG9iYWxJRC50b1VwcGVyQ2FzZSgpfSdgKS5qb2luKCcgT1IgJylcclxuICBcclxuICBjb25zdCBpbmRpY2F0b3JJZHMgPSBpbmRpY2F0b3JGZWF0dXJlcy5tYXAoaSA9PiBpLmF0dHJpYnV0ZXMuR2xvYmFsSUQpO1xyXG4gIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gd2VpZ2h0c0ZlYXR1cmVzLmZpbHRlcih3ID0+IGluZGljYXRvcklkcy5pbmRleE9mKHcuYXR0cmlidXRlcy5JbmRpY2F0b3JJRCkpIC8vYXdhaXQgZ2V0V2VpZ2h0c0ZlYXR1cmVzKHF1ZXJ5LCBjb25maWcpO1xyXG4gIFxyXG4gIGNvbnN0IGluZGljYXRvclRlbXBsYXRlcyA9IGluZGljYXRvckZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuXHJcbiAgICAgY29uc3Qgd2VpZ2h0cyA9IHdlaWdodHNGZWF0dXJlc1xyXG4gICAgICAuZmlsdGVyKHcgPT4gdy5hdHRyaWJ1dGVzLkluZGljYXRvcklEPT09ZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKVxyXG4gICAgICAubWFwKHcgPT4ge1xyXG4gICAgICAgcmV0dXJuIHsgXHJcbiAgICAgICAgb2JqZWN0SWQ6IHcuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICBuYW1lOiB3LmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICB3ZWlnaHQ6IHcuYXR0cmlidXRlcy5XZWlnaHQsXHJcbiAgICAgICAgc2NhbGVGYWN0b3IgOiB3LmF0dHJpYnV0ZXMuU2NhbGVGYWN0b3IsIFxyXG4gICAgICAgIGFkanVzdGVkV2VpZ2h0OiB3LmF0dHJpYnV0ZXMuQWRqdXN0ZWRXZWlnaHQsXHJcbiAgICAgICAgbWF4QWRqdXN0ZWRXZWlnaHQ6IHcuYXR0cmlidXRlcy5NYXhBZGp1c3RlZFdlaWdodFxyXG4gICAgICAgfSBhcyBJbmRpY2F0b3JXZWlnaHRcclxuICAgICB9KVxyXG5cclxuICAgICByZXR1cm4ge1xyXG4gICAgICBvYmplY3RJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELCBcclxuICAgICAgbmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIHRlbXBsYXRlTmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlTmFtZSxcclxuICAgICAgd2VpZ2h0cyxcclxuICAgICAgY29tcG9uZW50SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5Db21wb25lbnRJRCxcclxuICAgICAgdGVtcGxhdGVJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlSUQsICBcclxuICAgICAgY29tcG9uZW50TmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbXBvbmVudE5hbWUsXHJcbiAgICAgIGxpZmVsaW5lTmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZVxyXG4gICAgIH0gYXMgSW5kaWNhdG9yVGVtcGxhdGVcclxuICB9KTtcclxuXHJcbiAgY29uc3QgY29tcG9uZW50VGVtcGxhdGVzID0gY29tcG9uZW50RmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICB0aXRsZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUsXHJcbiAgICAgICAgbmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgbGlmZWxpbmVJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lSUQsXHJcbiAgICAgICAgaW5kaWNhdG9yczogKGluZGljYXRvclRlbXBsYXRlcy5maWx0ZXIoaSA9PiBpLmNvbXBvbmVudElkID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpIGFzIGFueSkub3JkZXJCeSgnbmFtZScpXHJcbiAgICAgfVxyXG4gIH0pO1xyXG5cclxuICBjb25zdCBsaWZlbGluZVRlbXBsYXRlcyA9IGxpZmVsaW5lRmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgdGl0bGU6IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlLFxyXG4gICAgICBuYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSwgICAgICBcclxuICAgICAgY29tcG9uZW50VGVtcGxhdGVzOiAoY29tcG9uZW50VGVtcGxhdGVzLmZpbHRlcihjID0+IGMubGlmZWxpbmVJZCA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSBhcyBhbnkpLm9yZGVyQnkoJ3RpdGxlJylcclxuICAgIH0gYXMgTGlmZUxpbmVUZW1wbGF0ZTtcclxuICB9KTtcclxuXHJcbiAgY29uc3QgdGVtcGxhdGUgPSB7XHJcbiAgICAgIG9iamVjdElkOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICBpc1NlbGVjdGVkOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5Jc1NlbGVjdGVkID09IDEsXHJcbiAgICAgIHN0YXR1czoge1xyXG4gICAgICAgIGNvZGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLlN0YXR1cyxcclxuICAgICAgICBuYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5TdGF0dXMgPT09IDEgPyBcIkFjdGl2ZVwiOiAnQXJjaGl2ZWQnXHJcbiAgICAgIH0gYXMgSUNvZGVkVmFsdWUsXHJcbiAgICAgIG5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIGhhemFyZE5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZE5hbWUsXHJcbiAgICAgIGhhemFyZFR5cGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZFR5cGUsXHJcbiAgICAgIG9yZ2FuaXphdGlvbk5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvbk5hbWUsXHJcbiAgICAgIG9yZ2FuaXphdGlvblR5cGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvblR5cGUsIFxyXG4gICAgICBjcmVhdG9yOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdG9yLFxyXG4gICAgICBjcmVhdGVkRGF0ZTogTnVtYmVyKHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0ZWREYXRlKSxcclxuICAgICAgZWRpdG9yOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5FZGl0b3IsXHJcbiAgICAgIGVkaXRlZERhdGU6IE51bWJlcih0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5FZGl0ZWREYXRlKSxcclxuICAgICAgbGlmZWxpbmVUZW1wbGF0ZXM6ICAobGlmZWxpbmVUZW1wbGF0ZXMgYXMgYW55KS5vcmRlckJ5KCd0aXRsZScpLFxyXG4gICAgICBkb21haW5zOiB0ZW1wbGF0ZURvbWFpbnNcclxuICB9IGFzIENMU1NUZW1wbGF0ZTtcclxuXHJcbiAgcmV0dXJuIHRlbXBsYXRlO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBzYXZlQXNzZXNzbWVudChhc3Nlc3NtZW50OiBBc3Nlc3NtZW50LCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHN0cmluZz4+e1xyXG5cclxuICB0cnl7XHJcbiAgICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgTmFtZSA6YXNzZXNzbWVudC5uYW1lLFxyXG4gICAgICAgIERlc2NyaXB0aW9uOiBhc3Nlc3NtZW50LmRlc2NyaXB0aW9uLFxyXG4gICAgICAgIEFzc2Vzc21lbnRUeXBlOiBhc3Nlc3NtZW50LmFzc2Vzc21lbnRUeXBlLCBcclxuICAgICAgICBPcmdhbml6YXRpb246IGFzc2Vzc21lbnQub3JnYW5pemF0aW9uLCBcclxuICAgICAgICBJbmNpZGVudDogYXNzZXNzbWVudC5pbmNpZGVudCwgXHJcbiAgICAgICAgSGF6YXJkOiBhc3Nlc3NtZW50LmhhemFyZCwgXHJcbiAgICAgICAgQ3JlYXRvcjogYXNzZXNzbWVudC5jcmVhdG9yLCBcclxuICAgICAgICBDcmVhdGVkRGF0ZTogYXNzZXNzbWVudC5jcmVhdGVkRGF0ZSwgXHJcbiAgICAgICAgRWRpdG9yOiBhc3Nlc3NtZW50LmVkaXRvciwgXHJcbiAgICAgICAgRWRpdGVkRGF0ZTogYXNzZXNzbWVudC5lZGl0ZWREYXRlLCBcclxuICAgICAgICBJc0NvbXBsZXRlZDogYXNzZXNzbWVudC5pc0NvbXBsZXRlZCwgXHJcbiAgICAgICAgSGF6YXJkVHlwZTogYXNzZXNzbWVudC5oYXphcmRUeXBlLFxyXG4gICAgICAgIE9yZ2FuaXphdGlvblR5cGU6YXNzZXNzbWVudC5vcmdhbml6YXRpb25UeXBlLFxyXG4gICAgICAgIFRlbXBsYXRlOiBhc3Nlc3NtZW50LnRlbXBsYXRlXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgIHJldHVybnsgZGF0YTogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZH1cclxuICAgIH1cclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogIEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSAgICBcclxuICAgIH1cclxuXHJcbiAgfWNhdGNoKGUpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiBlXHJcbiAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRJbmRpY2F0b3JBc3Nlc3NtZW50cyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SW5kaWNhdG9yQXNzZXNzbWVudFtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IEluZGljYXRvciBBc3Nlc3NtZW50cyBjYWxsZWQuJylcclxuXHJcbiAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBxdWVyeSwgY29uZmlnKTtcclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICByZXR1cm4gZmVhdHVyZXMubWFwKGZlYXR1cmUgPT4geyAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIG9iamVjdElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgICAgaW5kaWNhdG9ySWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5JbmRpY2F0b3JJRCxcclxuICAgICAgICAgIGluZGljYXRvcjogZmVhdHVyZS5hdHRyaWJ1dGVzLkluZGljYXRvck5hbWUsXHJcbiAgICAgICAgICB0ZW1wbGF0ZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlTmFtZSxcclxuICAgICAgICAgIGxpZmVsaW5lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lLFxyXG4gICAgICAgICAgY29tcG9uZW50OiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tcG9uZW50TmFtZSwgICAgICAgICAgXHJcbiAgICAgICAgICBjb21tZW50czogcGFyc2VDb21tZW50KGZlYXR1cmUuYXR0cmlidXRlcy5Db21tZW50cyksICAgICAgICAgIFxyXG4gICAgICAgICAgbGlmZWxpbmVTdGF0dXNJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lU3RhdHVzSUQsXHJcbiAgICAgICAgICBlbnZpcm9ubWVudFByZXNlcnZhdGlvbjogZmVhdHVyZS5hdHRyaWJ1dGVzLkVudmlyb25tZW50UHJlc2VydmF0aW9uLFxyXG4gICAgICAgICAgaW5jaWRlbnRTdGFiaWxpemF0aW9uOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSW5jaWRlbnRTdGFiaWxpemF0aW9uLFxyXG4gICAgICAgICAgcmFuazogZmVhdHVyZS5hdHRyaWJ1dGVzLlJhbmssXHJcbiAgICAgICAgICBsaWZlU2FmZXR5OiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZVNhZmV0eSxcclxuICAgICAgICAgIHByb3BlcnR5UHJvdGVjdGlvbjogZmVhdHVyZS5hdHRyaWJ1dGVzLlByb3BlcnR5UHJvdGVjdGlvbixcclxuICAgICAgICAgIHN0YXR1czogZmVhdHVyZS5hdHRyaWJ1dGVzLlN0YXR1c1xyXG4gICAgICAgIH0gYXMgSW5kaWNhdG9yQXNzZXNzbWVudDtcclxuICAgICB9KVxyXG4gIH1cclxuXHJcbn1cclxuXHJcbmZ1bmN0aW9uIHBhcnNlQ29tbWVudChjb21tZW50czogc3RyaW5nKXtcclxuICBpZighY29tbWVudHMgfHwgY29tbWVudHMgPT09IFwiXCIpe1xyXG4gICAgcmV0dXJuIFtdO1xyXG4gIH1cclxuICBsZXQgcGFyc2VkQ29tbWVudHMgPSBKU09OLnBhcnNlKGNvbW1lbnRzKSBhcyBJbkNvbW1lbnRbXTtcclxuICBcclxuICBpZihwYXJzZWRDb21tZW50cyAmJiBwYXJzZWRDb21tZW50cy5sZW5ndGggPiAwKXtcclxuICAgIHBhcnNlZENvbW1lbnRzLm1hcCgoY29tbWVudERhdGE6IEluQ29tbWVudCkgPT4ge1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLmNvbW1lbnREYXRhLFxyXG4gICAgICAgICAgICBkYXRldGltZTogTnVtYmVyKGNvbW1lbnREYXRhLmRhdGV0aW1lKVxyXG4gICAgICAgIH0gYXMgSW5Db21tZW50XHJcbiAgICB9KTtcclxuICAgIHBhcnNlZENvbW1lbnRzID0gKHBhcnNlZENvbW1lbnRzIGFzIGFueSkub3JkZXJCeSgnZGF0ZXRpbWUnLCB0cnVlKTtcclxuICB9ZWxzZXtcclxuICAgIHBhcnNlZENvbW1lbnRzID0gW107XHJcbiAgfVxyXG4gIFxyXG4gIHJldHVybiBwYXJzZWRDb21tZW50cztcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0TGlmZWxpbmVTdGF0dXNGZWF0dXJlcyhjb25maWcsIHF1ZXJ5KSB7XHJcbiAgY29uc29sZS5sb2coJ2dldCBMaWZlbGluZSBTdGF0dXMgY2FsbGVkJylcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGxvYWRBc3Nlc3NtZW50KGFzc2Vzc21lbnRGZWF0dXJlOiBJRmVhdHVyZSwgbHNGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgaW5kaWNhdG9yQXNzZXNzbWVudHM6IEluZGljYXRvckFzc2Vzc21lbnRbXSk6IEFzc2Vzc21lbnR7ICAgXHJcblxyXG4gIGNvbnN0IGxpZmVsaW5lU3RhdHVzZXMgPSBsc0ZlYXR1cmVzLm1hcCgoZmVhdHVyZSkgPT4geyBcclxuICAgIHJldHVybiB7XHJcbiAgICAgIG9iamVjdElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIGFzc2Vzc21lbnRJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkFzc2Vzc21lbnRJRCxcclxuICAgICAgbGlmZWxpbmVOYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lLFxyXG4gICAgICBpbmRpY2F0b3JBc3Nlc3NtZW50czogaW5kaWNhdG9yQXNzZXNzbWVudHMuZmlsdGVyKGkgPT4gaS5saWZlbGluZVN0YXR1c0lkID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpLCAgICAgIFxyXG4gICAgICBzY29yZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlNjb3JlLFxyXG4gICAgICBjb2xvcjogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbG9yLFxyXG4gICAgICBpc092ZXJyaWRlbjogZmVhdHVyZS5hdHRyaWJ1dGVzLklzT3ZlcnJpZGVuLFxyXG4gICAgICBvdmVycmlkZVNjb3JlOmZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5TY29yZSxcclxuICAgICAgb3ZlcnJpZGVuQnk6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5CeSxcclxuICAgICAgb3ZlcnJpZGVuQ29sb3I6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5Db2xvciwgICAgIFxyXG4gICAgICBvdmVycmlkZUNvbW1lbnQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZUNvbW1lbnQgICAgICBcclxuICAgIH0gYXMgTGlmZWxpbmVTdGF0dXM7XHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IGFzc2Vzc21lbnQgPSB7XHJcbiAgICBvYmplY3RJZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgIGlkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgbmFtZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgYXNzZXNzbWVudFR5cGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuQXNzZXNzbWVudFR5cGUsXHJcbiAgICBsaWZlbGluZVN0YXR1c2VzOiBsaWZlbGluZVN0YXR1c2VzLFxyXG4gICAgZGVzY3JpcHRpb246IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICB0ZW1wbGF0ZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZSxcclxuICAgIG9yZ2FuaXphdGlvbjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb24sXHJcbiAgICBvcmdhbml6YXRpb25UeXBlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvblR5cGUsXHJcbiAgICBpbmNpZGVudDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5JbmNpZGVudCxcclxuICAgIGhhemFyZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmQsXHJcbiAgICBoYXphcmRUeXBlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZFR5cGUsXHJcbiAgICBjcmVhdG9yOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0b3IsXHJcbiAgICBjcmVhdGVkRGF0ZTogTnVtYmVyKGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRlZERhdGUpLFxyXG4gICAgZWRpdG9yOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRvcixcclxuICAgIGVkaXRlZERhdGU6IE51bWJlcihhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRlZERhdGUpLFxyXG4gICAgaXNTZWxlY3RlZDogZmFsc2UsXHJcbiAgICBpc0NvbXBsZXRlZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Jc0NvbXBsZXRlZCxcclxuICB9IGFzIEFzc2Vzc21lbnRcclxuXHJcbiAgcmV0dXJuIGFzc2Vzc21lbnQ7ICBcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gc2F2ZUxpZmVsaW5lU3RhdHVzKGxpZmVsaW5lU3RhdHVzRmVhdHVyZTogSUZlYXR1cmUsIGxzSW5kQXNzZXNzRmVhdHVyZXM6IElGZWF0dXJlW10sIGNvbmZpZyk6IFByb21pc2U8Ym9vbGVhbj57XHJcbiAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIFtsaWZlbGluZVN0YXR1c0ZlYXR1cmVdLCBjb25maWcpXHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KGUgPT4gZS5zdWNjZXNzKSl7XHJcbiAgICAgY29uc3QgZ2xvYmFsSWQgPSByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkO1xyXG5cclxuICAgICBjb25zdCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMgPSBsc0luZEFzc2Vzc0ZlYXR1cmVzLm1hcChpbmQgPT4ge1xyXG4gICAgICAgIGluZC5hdHRyaWJ1dGVzLkxpZmVsaW5lU3RhdHVzSUQgPSBnbG9iYWxJZFxyXG4gICAgICAgIHJldHVybiBpbmQ7XHJcbiAgICAgfSlcclxuICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KGUgPT4gZS5zdWNjZXNzKSl7XHJcbiAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5mdW5jdGlvbiBnZXRUZW1wbGF0ZUluZGljYXRvcnModGVtcGxhdGU6IENMU1NUZW1wbGF0ZSk6IEluZGljYXRvclRlbXBsYXRlW10ge1xyXG4gIHJldHVybiBbXS5jb25jYXQuYXBwbHkoW10sIChbXS5jb25jYXQuYXBwbHkoW10sIFxyXG4gICB0ZW1wbGF0ZS5saWZlbGluZVRlbXBsYXRlcy5tYXAobCA9PiBsLmNvbXBvbmVudFRlbXBsYXRlcykpKVxyXG4gICAubWFwKChjOiBDb21wb25lbnRUZW1wbGF0ZSkgPT4gYy5pbmRpY2F0b3JzKSk7XHJcbn0iLCIvL0FkYXB0ZWQgZnJvbSAvL2h0dHBzOi8vZ2l0aHViLmNvbS9vZG9lL21hcC12dWUvYmxvYi9tYXN0ZXIvc3JjL2RhdGEvYXV0aC50c1xyXG5cclxuaW1wb3J0IHsgbG9hZEFyY0dJU0pTQVBJTW9kdWxlcyB9IGZyb20gXCJqaW11LWFyY2dpc1wiO1xyXG5cclxuLyoqXHJcbiAqIEF0dGVtcHQgdG8gc2lnbiBpbixcclxuICogZmlyc3QgY2hlY2sgY3VycmVudCBzdGF0dXNcclxuICogaWYgbm90IHNpZ25lZCBpbiwgdGhlbiBnbyB0aHJvdWdoXHJcbiAqIHN0ZXBzIHRvIGdldCBjcmVkZW50aWFsc1xyXG4gKi9cclxuZXhwb3J0IGNvbnN0IHNpZ25JbiA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgdHJ5IHtcclxuICAgICAgICByZXR1cm4gYXdhaXQgY2hlY2tDdXJyZW50U3RhdHVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcclxuICAgICAgICBjb25zb2xlLmxvZyhlcnJvcik7XHJcbiAgICAgICAgcmV0dXJuIGF3YWl0IGZldGNoQ3JlZGVudGlhbHMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICB9XHJcbn07XHJcblxyXG4vKipcclxuICogU2lnbiB0aGUgdXNlciBvdXQsIGJ1dCBpZiB3ZSBjaGVja2VkIGNyZWRlbnRpYWxzXHJcbiAqIG1hbnVhbGx5LCBtYWtlIHN1cmUgdGhleSBhcmUgcmVnaXN0ZXJlZCB3aXRoXHJcbiAqIElkZW50aXR5TWFuYWdlciwgc28gaXQgY2FuIGRlc3Ryb3kgdGhlbSBwcm9wZXJseVxyXG4gKi9cclxuZXhwb3J0IGNvbnN0IHNpZ25PdXQgPSBhc3luYyAoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpID0+IHtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgYXdhaXQgc2lnbkluKGFwcElkLCBwb3J0YWxVcmwpO1xyXG5cclxuICAgIGRlbGV0ZSB3aW5kb3dbJ0lkZW50aXR5TWFuYWdlciddO1xyXG4gICAgZGVsZXRlIHdpbmRvd1snT0F1dGhJbmZvJ107XHJcbiAgICBJZGVudGl0eU1hbmFnZXIuZGVzdHJveUNyZWRlbnRpYWxzKCk7XHJcbiAgICBcclxufTtcclxuXHJcbi8qKlxyXG4gKiBHZXQgdGhlIGNyZWRlbnRpYWxzIGZvciB0aGUgcHJvdmlkZWQgcG9ydGFsXHJcbiAqL1xyXG5hc3luYyBmdW5jdGlvbiBmZXRjaENyZWRlbnRpYWxzKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKXtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgY29uc3QgY3JlZGVudGlhbCA9IGF3YWl0IElkZW50aXR5TWFuYWdlci5nZXRDcmVkZW50aWFsKGAke3BvcnRhbFVybH0vc2hhcmluZ2AsIHtcclxuICAgICAgICBlcnJvcjogbnVsbCBhcyBhbnksXHJcbiAgICAgICAgb0F1dGhQb3B1cENvbmZpcm1hdGlvbjogZmFsc2UsXHJcbiAgICAgICAgdG9rZW46IG51bGwgYXMgYW55XHJcbiAgICB9KTtcclxuICAgIHJldHVybiBjcmVkZW50aWFsO1xyXG59O1xyXG5cclxuLyoqXHJcbiAqIEltcG9ydCBJZGVudGl0eSBNYW5hZ2VyLCBhbmQgT0F1dGhJbmZvXHJcbiAqL1xyXG5hc3luYyBmdW5jdGlvbiBsb2FkTW9kdWxlcyhhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykge1xyXG4gICAgbGV0IElkZW50aXR5TWFuYWdlciA9IHdpbmRvd1snSWRlbnRpdHlNYW5hZ2VyJ11cclxuICAgIGlmKCFJZGVudGl0eU1hbmFnZXIpe1xyXG4gICAgICAgIGNvbnN0IG1vZHVsZXMgPSBhd2FpdCBsb2FkQXJjR0lTSlNBUElNb2R1bGVzKFtcclxuICAgICAgICAgICAgJ2VzcmkvaWRlbnRpdHkvSWRlbnRpdHlNYW5hZ2VyJyxcclxuICAgICAgICAgICAgJ2VzcmkvaWRlbnRpdHkvT0F1dGhJbmZvJ10pO1xyXG5cclxuICAgICAgICAgICAgd2luZG93WydJZGVudGl0eU1hbmFnZXInXSA9IG1vZHVsZXNbMF07XHJcbiAgICAgICAgICAgIHdpbmRvd1snT0F1dGhJbmZvJ10gPSBtb2R1bGVzWzFdO1xyXG4gICAgICAgICAgICBcclxuICAgICAgICBJZGVudGl0eU1hbmFnZXIgPSBtb2R1bGVzWzBdO1xyXG4gICAgICAgIGNvbnN0IE9BdXRoSW5mbyA9IG1vZHVsZXNbMV07XHJcblxyXG4gICAgICAgIGNvbnN0IG9hdXRoSW5mbyA9IG5ldyBPQXV0aEluZm8oe1xyXG4gICAgICAgICAgICBhcHBJZCxcclxuICAgICAgICAgICAgcG9ydGFsVXJsLFxyXG4gICAgICAgICAgICBwb3B1cDogZmFsc2VcclxuICAgICAgICB9KTtcclxuICAgICAgICBJZGVudGl0eU1hbmFnZXIucmVnaXN0ZXJPQXV0aEluZm9zKFtvYXV0aEluZm9dKTsgICAgICAgIFxyXG4gICAgfVxyXG4gICAgcmV0dXJuIElkZW50aXR5TWFuYWdlcjtcclxufVxyXG5cclxuLyoqXHJcbiAqIENoZWNrIGN1cnJlbnQgbG9nZ2VkIGluIHN0YXR1cyBmb3IgY3VycmVudCBwb3J0YWxcclxuICovXHJcbmV4cG9ydCBjb25zdCBjaGVja0N1cnJlbnRTdGF0dXMgPSBhc3luYyAoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpID0+IHtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgcmV0dXJuIElkZW50aXR5TWFuYWdlci5jaGVja1NpZ25JblN0YXR1cyhgJHtwb3J0YWxVcmx9L3NoYXJpbmdgKTtcclxufTsiLCJpbXBvcnQgeyBleHRlbnNpb25TcGVjLCBJbW11dGFibGVPYmplY3QsIElNU3RhdGUgfSBmcm9tICdqaW11LWNvcmUnO1xyXG5pbXBvcnQgeyBBc3Nlc3NtZW50LCBDTFNTX1N0YXRlLCBcclxuICBDTFNTVGVtcGxhdGUsIENsc3NVc2VyLCBIYXphcmQsIFxyXG4gIExpZmVsaW5lU3RhdHVzLCBPcmdhbml6YXRpb24sIFxyXG4gIFJhdGluZ1NjYWxlLCBTY2FsZUZhY3RvciB9IGZyb20gJy4vZGF0YS1kZWZpbml0aW9ucyc7XHJcbmltcG9ydCB7IElDb2RlZFZhbHVlIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXMnO1xyXG5pbXBvcnQgeyBJQ3JlZGVudGlhbCB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgnO1xyXG5cclxuXHJcbmV4cG9ydCBlbnVtIENMU1NBY3Rpb25LZXlzIHtcclxuICBBVVRIRU5USUNBVEVfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBhdXRoZW5pY2F0ZSBjcmVkZW50aWFscycsXHJcbiAgTE9BRF9IQVpBUkRTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBoYXphcmRzJyxcclxuICBMT0FEX0hBWkFSRF9UWVBFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgaGF6YXJkIHR5cGVzJyxcclxuICBMT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIG9yZ2FuaXphdGlvbnMnLFxyXG4gIExPQURfT1JHQU5JWkFUSU9OX1RZUEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBvcmdhbml6YXRpb24gdHlwZXMnLFxyXG4gIExPQURfVEVNUExBVEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCB0ZW1wbGF0ZXMnLFxyXG4gIExPQURfUFJJT1JJVElFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgcHJpb3JpdGllcycsXHJcbiAgU0VMRUNUX1RFTVBMQVRFX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gc2VsZWN0IHRlbXBsYXRlJyxcclxuICBTRUFSQ0hfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBzZWFyY2ggZm9yIHRlbXBsYXRlJyxcclxuICBTSUdOX0lOX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2lnbiBpbicsXHJcbiAgU0lHTl9PVVRfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTaWduIG91dCcsXHJcbiAgU0VUX1VTRVJfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZXQgQ0xTUyBVc2VyJyxcclxuICBTRVRfSURFTlRJVFlfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZXQgSWRlbnRpdHknLFxyXG4gIFNFVF9FUlJPUlMgPSAnW0NMU1MtQVBQTElDQVRJT05dIFNldCBnbG9iYWwgZXJyb3JzJyxcclxuICBUT0dHTEVfSU5ESUNBVE9SX0VESVRJTkcgPSAnW0NMU1MtQVBQTElDQVRJT05dIFRvZ2dsZSBpbmRpY2F0b3IgZWRpdGluZycsICBcclxuICBTRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZWxlY3QgYSBsaWZlbGluZSBzdGF0dXMnLFxyXG4gIExPQURfQVNTRVNTTUVOVFNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBMb2FkIGFzc2Vzc21lbnRzJyxcclxuICBTRUxFQ1RfQVNTRVNTTUVOVF9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNlbGVjdCBhc3Nlc3NtZW50JyxcclxuICBMT0FEX1JBVElOR1NDQUxFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIExvYWQgcmF0aW5nIHNjYWxlcycsXHJcbiAgTE9BRF9TQ0FMRUZBQ1RPUlNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBMb2FkIGNvbnN0YW50cydcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1NjYWxlRmFjdG9yc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1NDQUxFRkFDVE9SU19BQ1RJT04sXHJcbiAgdmFsOiBTY2FsZUZhY3RvcltdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9SYXRpbmdfU2NhbGVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfUkFUSU5HU0NBTEVTX0FDVElPTixcclxuICB2YWw6IFJhdGluZ1NjYWxlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWxlY3RfQXNzZXNzbWVudF9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfQVNTRVNTTUVOVF9BQ1RJT04sXHJcbiAgdmFsOiBBc3Nlc3NtZW50XHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Bc3Nlc3NtZW50c19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0FTU0VTU01FTlRTX0FDVElPTixcclxuICB2YWw6IEFzc2Vzc21lbnRbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfUHJpb3JpdGllc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1BSSU9SSVRJRVNfQUNUSU9OLFxyXG4gIHZhbDogYW55W11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX0hhemFyZF9UeXBlc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRF9UWVBFU19BQ1RJT04sXHJcbiAgdmFsOiBJQ29kZWRWYWx1ZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Pcmdhbml6YXRpb25fVHlwZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05fVFlQRVNfQUNUSU9OLFxyXG4gIHZhbDogSUNvZGVkVmFsdWVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlbGVjdF9MaWZlbGluZVN0YXR1c19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OLFxyXG4gIHZhbDogTGlmZWxpbmVTdGF0dXNcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRfVG9nZ2xlX0luZGljYXRvcl9FZGl0aW5nX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlRPR0dMRV9JTkRJQ0FUT1JfRURJVElORyxcclxuICB2YWw6IHN0cmluZ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldF9FcnJvcnNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUyxcclxuICB2YWw6IHN0cmluZ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfSGF6YXJkc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRFNfQUNUSU9OLFxyXG4gIHZhbDogSGF6YXJkW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX09yZ2FuaXphdGlvbnNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTixcclxuICB2YWw6IE9yZ2FuaXphdGlvbltdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0SWRlbnRpdHlfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX0lERU5USVRZX0FDVElPTixcclxuICB2YWw6IENsc3NVc2VyXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0VXNlcl9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRVRfVVNFUl9BQ1RJT04sXHJcbiAgdmFsOiBDbHNzVXNlclxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNpZ25pbl9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TSUdOX0lOX0FDVElPTlxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNpZ25vdXRfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0lHTl9PVVRfQUNUSU9OXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VsZWN0X1RlbXBsYXRlX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFTEVDVF9URU1QTEFURV9BQ1RJT04sXHJcbiAgdmFsOiBzdHJpbmdcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9URU1QTEFURVNfQUNUSU9OLFxyXG4gIHZhbDogQ0xTU1RlbXBsYXRlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWFyY2hfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUFSQ0hfQUNUSU9OLFxyXG4gIHZhbDogc3RyaW5nXHJcbn0gIFxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBBdXRoZW50aWNhdGVfQWN0aW9uX1R5cGUge1xyXG4gICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5BVVRIRU5USUNBVEVfQUNUSU9OLFxyXG4gICB2YWw6IElDcmVkZW50aWFsO1xyXG59XHJcblxyXG5cclxudHlwZSBBY3Rpb25UeXBlcyA9IFxyXG4gU2VsZWN0X1RlbXBsYXRlX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHwgXHJcbiBTZWFyY2hfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHwgXHJcbiBTaWduaW5fQWN0aW9uX1R5cGUgfFxyXG4gU2lnbm91dF9BY3Rpb25fVHlwZSB8XHJcbiBTZXRVc2VyX0FjdGlvbl9UeXBlIHwgXHJcbiBTZXRJZGVudGl0eV9BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX0hhemFyZHNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Pcmdhbml6YXRpb25zX0FjdGlvbl9UeXBlIHxcclxuIFNldF9FcnJvcnNfQWN0aW9uX1R5cGUgfFxyXG4gU2V0X1RvZ2dsZV9JbmRpY2F0b3JfRWRpdGluZ19BY3Rpb25fVHlwZSB8XHJcbiBTZWxlY3RfTGlmZWxpbmVTdGF0dXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9IYXphcmRfVHlwZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Pcmdhbml6YXRpb25fVHlwZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Qcmlvcml0aWVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfQXNzZXNzbWVudHNfQWN0aW9uX1R5cGUgfFxyXG4gU2VsZWN0X0Fzc2Vzc21lbnRfQWN0aW9uX1R5cGV8IFxyXG4gTG9hZF9SYXRpbmdfU2NhbGVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfU2NhbGVGYWN0b3JzX0FjdGlvbl9UeXBlIHxcclxuIEF1dGhlbnRpY2F0ZV9BY3Rpb25fVHlwZSA7XHJcblxyXG50eXBlIElNTXlTdGF0ZSA9IEltbXV0YWJsZU9iamVjdDxDTFNTX1N0YXRlPjtcclxuXHJcbmRlY2xhcmUgbW9kdWxlICdqaW11LWNvcmUvbGliL3R5cGVzL3N0YXRlJ3tcclxuICBpbnRlcmZhY2UgU3RhdGV7XHJcbiAgICBjbHNzU3RhdGU/OiBJTU15U3RhdGVcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIE15UmVkdXhTdG9yZUV4dGVuc2lvbiBpbXBsZW1lbnRzIGV4dGVuc2lvblNwZWMuUmVkdXhTdG9yZUV4dGVuc2lvbiB7XHJcbiAgaWQgPSAnY2xzcy1yZWR1eC1zdG9yZS1leHRlbnNpb24nO1xyXG4gXHJcbiAgZ2V0QWN0aW9ucygpIHtcclxuICAgIHJldHVybiBPYmplY3Qua2V5cyhDTFNTQWN0aW9uS2V5cykubWFwKGsgPT4gQ0xTU0FjdGlvbktleXNba10pO1xyXG4gIH1cclxuXHJcbiAgZ2V0SW5pdExvY2FsU3RhdGUoKSB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICAgc2VsZWN0ZWRUZW1wbGF0ZTogbnVsbCxcclxuICAgICAgIHRlbXBsYXRlczogW10sXHJcbiAgICAgICBzZWFyY2hSZXN1bHRzOiBbXSxcclxuICAgICAgIHVzZXI6IG51bGwsXHJcbiAgICAgICBhdXRoOiBudWxsLFxyXG4gICAgICAgaWRlbnRpdHk6IG51bGwsICAgICAgIFxyXG4gICAgICAgbmV3VGVtcGxhdGVNb2RhbFZpc2libGU6IGZhbHNlLFxyXG4gICAgICAgaGF6YXJkczogW10sXHJcbiAgICAgICBvcmdhbml6YXRpb25zOiBbXSxcclxuICAgICAgIGVycm9yczogJycsXHJcbiAgICAgICBpc0luZGljYXRvckVkaXRpbmc6IGZhbHNlLFxyXG4gICAgICAgc2VsZWN0ZWRMaWZlbGluZVN0YXR1czogbnVsbCxcclxuICAgICAgIG9yZ2FuaXphdGlvblR5cGVzOiBbXSxcclxuICAgICAgIGhhemFyZFR5cGVzOiBbXSxcclxuICAgICAgIHByaW9yaXRpZXM6IFtdLFxyXG4gICAgICAgYXNzZXNzbWVudHM6IFtdLFxyXG4gICAgICAgcmF0aW5nU2NhbGVzOiBbXSxcclxuICAgICAgIHNjYWxlRmFjdG9yczogW10sXHJcbiAgICAgICBhdXRoZW50aWNhdGU6IG51bGxcclxuICAgIH0gYXMgQ0xTU19TdGF0ZTtcclxuICB9XHJcblxyXG4gIGdldFJlZHVjZXIoKSB7XHJcbiAgICByZXR1cm4gKGxvY2FsU3RhdGU6IElNTXlTdGF0ZSwgYWN0aW9uOiBBY3Rpb25UeXBlcywgYXBwU3RhdGU6IElNU3RhdGUpOiBJTU15U3RhdGUgPT4geyAgICAgIFxyXG4gICAgICBcclxuICAgICAgc3dpdGNoIChhY3Rpb24udHlwZSkge1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkFVVEhFTlRJQ0FURV9BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2F1dGhlbnRpY2F0ZScsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfU0NBTEVGQUNUT1JTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnc2NhbGVGYWN0b3JzJywgYWN0aW9uLnZhbCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1JBVElOR1NDQUxFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3JhdGluZ1NjYWxlcycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFTEVDVF9BU1NFU1NNRU5UX0FDVElPTjpcclxuICAgICAgICAgIGNvbnN0IGFzc2Vzc21lbnRzID0gbG9jYWxTdGF0ZS5hc3Nlc3NtZW50cy5tYXAoYXNzZXNzID0+IHtcclxuICAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgLi4uYXNzZXNzLFxyXG4gICAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IGFzc2Vzcy5pZCA9PT0gYWN0aW9uLnZhbC5pZC50b0xvd2VyQ2FzZSgpXHJcbiAgICAgICAgICAgICB9XHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdhc3Nlc3NtZW50cycsIGFzc2Vzc21lbnRzKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX0FTU0VTU01FTlRTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnYXNzZXNzbWVudHMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1BSSU9SSVRJRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdwcmlvcml0aWVzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VMRUNUX0xJRkVMSU5FU1RBVFVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnc2VsZWN0ZWRMaWZlbGluZVN0YXR1cycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlRPR0dMRV9JTkRJQ0FUT1JfRURJVElORzpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaXNJbmRpY2F0b3JFZGl0aW5nJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUzpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnZXJyb3JzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRTX0FDVElPTjogIFxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdoYXphcmRzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRF9UWVBFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2hhemFyZFR5cGVzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTl9UWVBFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ29yZ2FuaXphdGlvblR5cGVzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OOlxyXG4gICAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ29yZ2FuaXphdGlvbnMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFVF9JREVOVElUWV9BQ1RJT046ICBcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaWRlbnRpdHknLCBhY3Rpb24udmFsKTtcclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFVF9VU0VSX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgndXNlcicsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfVEVNUExBVEVTX0FDVElPTjogICAgICAgICAgXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3RlbXBsYXRlcycsIGFjdGlvbi52YWwpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VMRUNUX1RFTVBMQVRFX0FDVElPTjpcclxuICAgICAgICAgIGxldCB0ZW1wbGF0ZXMgPSBbLi4ubG9jYWxTdGF0ZS50ZW1wbGF0ZXNdLm1hcCh0ID0+IHtcclxuICAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgICBpc1NlbGVjdGVkOiB0LmlkID09PSBhY3Rpb24udmFsXHJcbiAgICAgICAgICAgICB9IFxyXG4gICAgICAgICAgfSlcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgndGVtcGxhdGVzJywgdGVtcGxhdGVzKSAgICAgICAgICAgIFxyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgZ2V0U3RvcmVLZXkoKSB7XHJcbiAgICByZXR1cm4gJ2Nsc3NTdGF0ZSc7XHJcbiAgfVxyXG59IiwiZXhwb3J0IGNvbnN0IENMU1NfQURNSU4gPSAnQ0xTU19BZG1pbic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX0VESVRPUiA9ICdDTFNTX0VkaXRvcic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX0FTU0VTU09SID0gJ0NMU1NfQXNzZXNzb3InO1xyXG5leHBvcnQgY29uc3QgQ0xTU19WSUVXRVIgPSAnQ0xTU19WaWV3ZXInO1xyXG5leHBvcnQgY29uc3QgQ0xTU19GT0xMT1dFUlMgPSAnQ0xTUyBGb2xsb3dlcnMnO1xyXG5cclxuZXhwb3J0IGNvbnN0IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUgPSAnQmFzZWxpbmUnO1xyXG5leHBvcnQgY29uc3QgVE9LRU5fRVJST1IgPSAnVG9rZW4gbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IFRFTVBMQVRFX1VSTF9FUlJPUiA9ICdUZW1wbGF0ZSBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBBU1NFU1NNRU5UX1VSTF9FUlJPUiA9ICdBc3Nlc3NtZW50IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IE9SR0FOSVpBVElPTl9VUkxfRVJST1IgPSAnT3JnYW5pemF0aW9uIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IEhBWkFSRF9VUkxfRVJST1IgPSAnSGF6YXJkIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9VUkxfRVJST1IgPSAnSW5kaWNhdG9yIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IEFMSUdOTUVOVF9VUkxfRVJST1IgPSAnQWxpZ25tZW50cyBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBMSUZFTElORV9VUkxfRVJST1IgPSAnTGlmZWxpbmUgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgQ09NUE9ORU5UX1VSTF9FUlJPUiA9ICdDb21wb25lbnQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgUFJJT1JJVFlfVVJMX0VSUk9SID0gJ1ByaW9yaXR5IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IElOQ0lERU5UX1VSTF9FUlJPUiA9ICdJbmNpZGVudCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBTQVZJTkdfU0FNRV9BU19CQVNFTElORV9FUlJPUiA9ICdCYXNlbGluZSB0ZW1wbGF0ZSBjYW5ub3QgYmUgdXBkYXRlZC4gQ2hhbmdlIHRoZSB0ZW1wbGF0ZSBuYW1lIHRvIGNyZWF0ZSBhIG5ldyBvbmUuJ1xyXG5cclxuZXhwb3J0IGNvbnN0IFNUQUJJTElaSU5HX1NDQUxFX0ZBQ1RPUiA9ICdTdGFiaWxpemluZ19TY2FsZV9GYWN0b3InO1xyXG5leHBvcnQgY29uc3QgREVTVEFCSUxJWklOR19TQ0FMRV9GQUNUT1IgPSAnRGVzdGFiaWxpemluZ19TY2FsZV9GYWN0b3InO1xyXG5leHBvcnQgY29uc3QgVU5DSEFOR0VEX1NDQUxFX0ZBQ1RPUiA9ICdVbmNoYW5nZWRfSW5kaWNhdG9ycyc7XHJcbmV4cG9ydCBjb25zdCBERUZBVUxUX1BSSU9SSVRZX0xFVkVMUyA9IFwiRGVmYXVsdF9Qcmlvcml0eV9MZXZlbHNcIjtcclxuZXhwb3J0IGNvbnN0IFJBTksgPSAnSW1wb3J0YW5jZSBvZiBJbmRpY2F0b3InO1xyXG5leHBvcnQgY29uc3QgTElGRV9TQUZFVFkgPSAnTGlmZSBTYWZldHknO1xyXG5leHBvcnQgY29uc3QgSU5DSURFTlRfU1RBQklMSVpBVElPTiA9ICdJbmNpZGVudCBTdGFiaWxpemF0aW9uJztcclxuZXhwb3J0IGNvbnN0IFBST1BFUlRZX1BST1RFQ1RJT04gPSAnUHJvcGVydHkgUHJvdGVjdGlvbic7XHJcbmV4cG9ydCBjb25zdCBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04gPSAnRW52aXJvbm1lbnQgUHJlc2VydmF0aW9uJztcclxuXHJcbmV4cG9ydCBjb25zdCBMSUZFX1NBRkVUWV9TQ0FMRV9GQUNUT1IgPSAyMDA7XHJcbmV4cG9ydCBjb25zdCBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUiA9IDEwMDtcclxuZXhwb3J0IGNvbnN0IE1BWElNVU1fV0VJR0hUID0gNTtcclxuXHJcbmV4cG9ydCBlbnVtIFVwZGF0ZUFjdGlvbiB7XHJcbiAgICBIRUFERVIgPSAnaGVhZGVyJyxcclxuICAgIElORElDQVRPUl9OQU1FID0gJ0luZGljYXRvciBOYW1lJyxcclxuICAgIFBSSU9SSVRJRVMgPSAnSW5kaWNhdG9yIFByaW9yaXRpZXMnLFxyXG4gICAgTkVXX0lORElDQVRPUiA9ICdDcmVhdGUgTmV3IEluZGljYXRvcicsXHJcbiAgICBERUxFVEVfSU5ESUNBVE9SID0gJ0RlbGV0ZSBJbmRpY2F0b3InXHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBJTkNMVURFX0lORElDQVRPUiA9ICdJbXBhY3RlZCAtIFllcyBvciBObyc7XHJcbmV4cG9ydCBjb25zdCBJTkNMVURFX0lORElDQVRPUl9IRUxQID0gJ1llczogVGhlIGluZGljYXRvciB3aWxsIGJlIGNvbnNpZGVyZWQgaW4gdGhlIGFzc2Vzc21lbnQuXFxuTm86IFRoZSBpbmRpY2F0b3Igd2lsbCBub3QgYmUgY29uc2lkZXJlZC5cXG5Vbmtub3duOiBOb3Qgc3VyZSB0byBpbmNsdWRlIHRoZSBpbmRpY2F0b3IgaW4gYXNzZXNzbWVudC4nO1xyXG5cclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9TVEFUVVMgPSAnSW5kaWNhdG9yIEltcGFjdCBTdGF0dXMnO1xyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX1NUQVRVU19IRUxQID0gJ1N0YWJpbGl6aW5nOiBIYXMgdGhlIGluZGljYXRvciBiZWVuIGltcHJvdmVkIG9yIGltcHJvdmluZy5cXG5EZXN0YWJpbGl6aW5nOiBJcyB0aGUgaW5kaWNhdG9yIGRlZ3JhZGluZy5cXG5VbmNoYW5nZWQ6IE5vIHNpZ25pZmljYW50IGltcHJvdmVtZW50IHNpbmNlIHRoZSBsYXN0IGFzc2Vzc21lbnQuJztcclxuXHJcbmV4cG9ydCBjb25zdCBDT01NRU5UID0gJ0NvbW1lbnQnO1xyXG5leHBvcnQgY29uc3QgQ09NTUVOVF9IRUxQID0gJ1Byb3ZpZGUganVzdGlmaWNhdGlvbiBmb3IgdGhlIHNlbGVjdGVkIGluZGljYXRvciBzdGF0dXMuJztcclxuXHJcbmV4cG9ydCBjb25zdCBERUxFVEVfSU5ESUNBVE9SX0NPTkZJUk1BVElPTiA9ICdBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gZGVsZXRlIGluZGljYXRvcj8nO1xyXG5cclxuLy9DZWxsIFdlaWdodCA9ICBUcmVuZCAqICggKC0xKlJhbmspICsgNlxyXG5leHBvcnQgY29uc3QgQ1JJVElDQUwgPSAyNTtcclxuZXhwb3J0IGNvbnN0IENSSVRJQ0FMX0xPV0VSX0JPVU5EQVJZID0gMTIuNTtcclxuZXhwb3J0IGNvbnN0IE1PREVSQVRFX0xPV0VSX0JPVU5EQVJZID0gNS41O1xyXG5leHBvcnQgY29uc3QgTk9EQVRBX0NPTE9SID0gJyM5MTkzOTUnO1xyXG5leHBvcnQgY29uc3QgTk9EQVRBX1ZBTFVFID0gOTk5OTk5O1xyXG5leHBvcnQgY29uc3QgUkVEX0NPTE9SID0gJyNDNTIwMzgnO1xyXG5leHBvcnQgY29uc3QgWUVMTE9XX0NPTE9SID0gJyNGQkJBMTYnO1xyXG5leHBvcnQgY29uc3QgR1JFRU5fQ09MT1IgPSAnIzVFOUM0Mic7XHJcbmV4cG9ydCBjb25zdCBTQVZJTkdfVElNRVIgPSAxNTAwO1xyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX0NPTU1FTlRfTEVOR1RIID0gMzAwO1xyXG5cclxuZXhwb3J0IGNvbnN0IFBPUlRBTF9VUkwgPSAnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbSc7XHJcblxyXG5leHBvcnQgY29uc3QgREVGQVVMVF9MSVNUSVRFTSA9IHtpZDogJzAwMCcsIG5hbWU6ICctTm9uZS0nLCB0aXRsZTogJy1Ob25lLSd9IGFzIGFueTtcclxuXHJcbmV4cG9ydCBjb25zdCBSQU5LX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIHlvdXIganVyaXNkaWN0aW9uIG9yIGhhemFyZD8nO1xyXG5leHBvcnQgY29uc3QgTElGRV9TQUZFVFlfTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gTGlmZSBTYWZldHk/JztcclxuZXhwb3J0IGNvbnN0IFBST1BFUlRZX1BST1RFQ1RJT05fTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gUHJvcGVydHkgUHJvdGVjdGlvbj8nO1xyXG5leHBvcnQgY29uc3QgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIEVudmlyb25tZW50IFByZXNlcnZhdGlvbj8nO1xyXG5leHBvcnQgY29uc3QgSU5DSURFTlRfU1RBQklMSVpBVElPTl9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBJbmNpZGVudCBTdGFiaWxpemF0aW9uPyc7XHJcblxyXG5leHBvcnQgY29uc3QgT1ZFUldSSVRFX1NDT1JFX01FU1NBR0UgPSAnQSBjb21wbGV0ZWQgYXNzZXNzbWVudCBjYW5ub3QgYmUgZWRpdGVkLiBBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gY29tcGxldGUgdGhpcyBhc3Nlc3NtZW50Pyc7XHJcblxyXG5leHBvcnQgY29uc3QgVVNFUl9CT1hfRUxFTUVOVF9JRCA9ICd1c2VyQm94RWxlbWVudCc7XHJcblxyXG5leHBvcnQgY29uc3QgREFUQV9MSUJSQVJZX1RJVExFID0gJ0RhdGEgTGlicmFyeSc7XHJcbmV4cG9ydCBjb25zdCBBTkFMWVNJU19SRVBPUlRJTkdfVElUTEUgPSAnQW5hbHlzaXMgJiBSZXBvcnRpbmcnO1xyXG5cclxuIiwiaW1wb3J0IHsgVXNlclNlc3Npb24gfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aFwiO1xyXG5pbXBvcnQgeyBxdWVyeUZlYXR1cmVzLCBJUXVlcnlGZWF0dXJlc1Jlc3BvbnNlLCBcclxuICAgIElSZWxhdGVkUmVjb3JkR3JvdXAsIHF1ZXJ5UmVsYXRlZCwgdXBkYXRlRmVhdHVyZXMsIFxyXG4gICAgYWRkRmVhdHVyZXMsIGRlbGV0ZUZlYXR1cmVzIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXJcIjtcclxuaW1wb3J0IHsgSUZlYXR1cmVTZXQsIElGZWF0dXJlIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXR5cGVzXCI7XHJcbmltcG9ydCB7IEFwcFdpZGdldENvbmZpZyB9IGZyb20gXCIuL2RhdGEtZGVmaW5pdGlvbnNcIjtcclxuaW1wb3J0IHsgbG9nLCBMb2dUeXBlIH0gZnJvbSBcIi4vbG9nZ2VyXCI7XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRBdXRoZW50aWNhdGlvbihjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG4gIHJldHVybiBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbChjb25maWcuY3JlZGVudGlhbCk7XHJcbn1cclxuICBcclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHF1ZXJ5VGFibGVGZWF0dXJlU2V0KHVybDogc3RyaW5nLCB3aGVyZTogc3RyaW5nLCBcclxuICBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVTZXQ+IHtcclxuICBcclxuICAgIHRyeXtcclxuXHJcbiAgICAgIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuICAgICAgcmV0dXJuIHF1ZXJ5RmVhdHVyZXMoeyB1cmwsIHdoZXJlLCBhdXRoZW50aWNhdGlvbiwgaGlkZVRva2VuOiB0cnVlIH0pXHJcbiAgICAgIC50aGVuKChyZXNwb25zZTogSVF1ZXJ5RmVhdHVyZXNSZXNwb25zZSkgPT4ge1xyXG4gICAgICAgIHJldHVybiByZXNwb25zZVxyXG4gICAgICB9KVxyXG5cclxuICAgIH1jYXRjaChlKXtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdxdWVyeVRhYmxlRmVhdHVyZVNldCcpXHJcbiAgICB9ICAgIFxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcXVlcnlUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCB3aGVyZTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT4ge1xyXG5cclxuIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbiAgdHJ5e1xyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHF1ZXJ5RmVhdHVyZXMoeyB1cmwsIHdoZXJlLCBhdXRoZW50aWNhdGlvbiwgIGh0dHBNZXRob2Q6J1BPU1QnLCBoaWRlVG9rZW46IHRydWUgfSlcclxuICAgICAgcmV0dXJuIChyZXNwb25zZSBhcyBJUXVlcnlGZWF0dXJlc1Jlc3BvbnNlKS5mZWF0dXJlcztcclxuICB9Y2F0Y2goZSl7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAncXVlcnlUYWJsZUZlYXR1cmVzJylcclxuICAgICAgbG9nKHVybCwgTG9nVHlwZS5XUk4sIHdoZXJlKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gcXVlcnlSZWxhdGVkVGFibGVGZWF0dXJlcyhvYmplY3RJZHM6IG51bWJlcltdLFxyXG51cmw6IHN0cmluZywgcmVsYXRpb25zaGlwSWQ6IG51bWJlciwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElSZWxhdGVkUmVjb3JkR3JvdXBbXT4ge1xyXG5cclxuY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBxdWVyeVJlbGF0ZWQoe1xyXG4gICAgb2JqZWN0SWRzLFxyXG4gICAgdXJsLCByZWxhdGlvbnNoaXBJZCxcclxuICAgIGF1dGhlbnRpY2F0aW9uLFxyXG4gICAgaGlkZVRva2VuOiB0cnVlXHJcbn0pO1xyXG5yZXR1cm4gcmVzcG9uc2UucmVsYXRlZFJlY29yZEdyb3VwcztcclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiB1cGRhdGVUYWJsZUZlYXR1cmUodXJsOiBzdHJpbmcsIGF0dHJpYnV0ZXM6IGFueSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG4gIHJldHVybiB1cGRhdGVGZWF0dXJlcyh7XHJcbiAgICAgIHVybCxcclxuICAgICAgYXV0aGVudGljYXRpb24sXHJcbiAgICAgIGZlYXR1cmVzOiBbe1xyXG4gICAgICBhdHRyaWJ1dGVzXHJcbiAgICAgIH1dLFxyXG4gICAgICByb2xsYmFja09uRmFpbHVyZTogdHJ1ZVxyXG4gIH0pXHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gdXBkYXRlVGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgZmVhdHVyZXM6IElGZWF0dXJlW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcbiAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpOyAgXHJcbiAgcmV0dXJuIHVwZGF0ZUZlYXR1cmVzKHtcclxuICAgICAgdXJsLFxyXG4gICAgICBhdXRoZW50aWNhdGlvbixcclxuICAgICAgZmVhdHVyZXNcclxuICB9KVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIGFkZFRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIGZlYXR1cmVzOiBhbnlbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuXHJcbiAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuICB0cnl7XHJcbiAgICByZXR1cm4gYWRkRmVhdHVyZXMoeyB1cmwsIGZlYXR1cmVzLCBhdXRoZW50aWNhdGlvbiwgcm9sbGJhY2tPbkZhaWx1cmU6IHRydWUgfSk7XHJcbiAgfWNhdGNoKGUpe1xyXG4gICAgY29uc29sZS5sb2coZSk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIG9iamVjdElkczogbnVtYmVyW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcblxyXG4gICAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG4gICAgcmV0dXJuIGRlbGV0ZUZlYXR1cmVzKHsgdXJsLCBvYmplY3RJZHMsIGF1dGhlbnRpY2F0aW9uLCByb2xsYmFja09uRmFpbHVyZTogdHJ1ZSB9KTtcclxufSIsImV4cG9ydCBlbnVtIExvZ1R5cGUge1xyXG4gICAgSU5GTyA9ICdJbmZvcm1hdGlvbicsXHJcbiAgICBXUk4gPSAnV2FybmluZycsXHJcbiAgICBFUlJPUiA9ICdFcnJvcidcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGxvZyhtZXNzYWdlOiBzdHJpbmcsIHR5cGU/OiBMb2dUeXBlLCBmdW5jPzogc3RyaW5nKXtcclxuICAgIGlmKCF0eXBlKXtcclxuICAgICAgICB0eXBlID0gTG9nVHlwZS5JTkZPXHJcbiAgICB9XHJcblxyXG4gICAgaWYoZnVuYyl7XHJcbiAgICAgICAgZnVuYyA9IGAoJHtmdW5jfSlgO1xyXG4gICAgfVxyXG5cclxuICAgIG1lc3NhZ2UgPSBgWyR7bmV3IERhdGUoKS50b0xvY2FsZVN0cmluZygpfV06ICR7bWVzc2FnZX0gJHtmdW5jfWA7XHJcblxyXG4gICAgc3dpdGNoKHR5cGUpe1xyXG4gICAgICAgIGNhc2UgTG9nVHlwZS5JTkZPOlxyXG4gICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcclxuICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgY2FzZSBMb2dUeXBlLldSTjpcclxuICAgICAgICAgICAgY29uc29sZS53YXJuKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlIExvZ1R5cGUuRVJST1I6XHJcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IobWVzc2FnZSk7XHJcbiAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xyXG4gICAgfVxyXG59IiwiXHJcbmV4cG9ydCBjb25zdCBzb3J0T2JqZWN0ID0gPFQ+KG9iajogVFtdLCBwcm9wOiBzdHJpbmcsIHJldmVyc2U/OmJvb2xlYW4pOiBUW10gPT4ge1xyXG4gICByZXR1cm4gb2JqLnNvcnQoKGE6VCwgYjpUKSA9PiB7XHJcbiAgICAgIGlmKGFbcHJvcF0gPiBiW3Byb3BdKXtcclxuICAgICAgICByZXR1cm4gcmV2ZXJzZSA/IC0xIDogMVxyXG4gICAgICB9XHJcbiAgICAgIGlmKGFbcHJvcF0gPCBiW3Byb3BdKXtcclxuICAgICAgICByZXR1cm4gcmV2ZXJzZSA/IDEgOiAtMVxyXG4gICAgICB9XHJcbiAgICAgIHJldHVybiAwO1xyXG4gIH0pO1xyXG59XHJcblxyXG5leHBvcnQgY29uc3QgY3JlYXRlR3VpZCA9ICgpID0+e1xyXG4gIHJldHVybiAneHh4eHh4eHgteHh4eC00eHh4LXl4eHgteHh4eHh4eHh4eHh4Jy5yZXBsYWNlKC9beHldL2csIGZ1bmN0aW9uKGMpIHtcclxuICAgIHZhciByID0gTWF0aC5yYW5kb20oKSAqIDE2IHwgMCwgdiA9IGMgPT0gJ3gnID8gciA6IChyICYgMHgzIHwgMHg4KTtcclxuICAgIHJldHVybiB2LnRvU3RyaW5nKDE2KTtcclxuICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IHBhcnNlRGF0ZSA9IChtaWxsaXNlY29uZHM6IG51bWJlcik6IHN0cmluZyA9PiB7XHJcbiAgaWYoIW1pbGxpc2Vjb25kcyl7XHJcbiAgICByZXR1cm5cclxuICB9XHJcbiAgIHJldHVybiBuZXcgRGF0ZShtaWxsaXNlY29uZHMpLnRvTG9jYWxlU3RyaW5nKCk7XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBzYXZlRGF0ZSA9IChkYXRlOiBzdHJpbmcpOiBudW1iZXIgPT4ge1xyXG4gICByZXR1cm4gbmV3IERhdGUoZGF0ZSkuZ2V0TWlsbGlzZWNvbmRzKCk7XHJcbn1cclxuXHJcblxyXG4vL1JlZmVyZW5jZTogaHR0cHM6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvNjE5NTMzNS9saW5lYXItcmVncmVzc2lvbi1pbi1qYXZhc2NyaXB0XHJcbi8vIGV4cG9ydCBjb25zdCBsaW5lYXJSZWdyZXNzaW9uID0gKHlWYWx1ZXM6IG51bWJlcltdLCB4VmFsdWVzOiBudW1iZXJbXSkgPT57XHJcbi8vICAgZGVidWdnZXI7XHJcbi8vICAgY29uc3QgeSA9IHlWYWx1ZXM7XHJcbi8vICAgY29uc3QgeCA9IHhWYWx1ZXM7XHJcblxyXG4vLyAgIHZhciBsciA9IHtzbG9wZTogTmFOLCBpbnRlcmNlcHQ6IE5hTiwgcjI6IE5hTn07XHJcbi8vICAgdmFyIG4gPSB5Lmxlbmd0aDtcclxuLy8gICB2YXIgc3VtX3ggPSAwO1xyXG4vLyAgIHZhciBzdW1feSA9IDA7XHJcbi8vICAgdmFyIHN1bV94eSA9IDA7XHJcbi8vICAgdmFyIHN1bV94eCA9IDA7XHJcbi8vICAgdmFyIHN1bV95eSA9IDA7XHJcblxyXG4vLyAgIGZvciAodmFyIGkgPSAwOyBpIDwgeS5sZW5ndGg7IGkrKykge1xyXG5cclxuLy8gICAgICAgc3VtX3ggKz0geFtpXTtcclxuLy8gICAgICAgc3VtX3kgKz0geVtpXTtcclxuLy8gICAgICAgc3VtX3h5ICs9ICh4W2ldKnlbaV0pO1xyXG4vLyAgICAgICBzdW1feHggKz0gKHhbaV0qeFtpXSk7XHJcbi8vICAgICAgIHN1bV95eSArPSAoeVtpXSp5W2ldKTtcclxuLy8gICB9IFxyXG5cclxuLy8gICBsci5zbG9wZSA9IChuICogc3VtX3h5IC0gc3VtX3ggKiBzdW1feSkgLyAobipzdW1feHggLSBzdW1feCAqIHN1bV94KTtcclxuLy8gICBsci5pbnRlcmNlcHQgPSAoc3VtX3kgLSBsci5zbG9wZSAqIHN1bV94KS9uO1xyXG4vLyAgIGxyLnIyID0gTWF0aC5wb3coKG4qc3VtX3h5IC0gc3VtX3gqc3VtX3kpL01hdGguc3FydCgobipzdW1feHgtc3VtX3gqc3VtX3gpKihuKnN1bV95eS1zdW1feSpzdW1feSkpLDIpO1xyXG4vLyAgIHJldHVybiBscjtcclxuLy8gfVxyXG5cclxuU3RyaW5nLnByb3RvdHlwZS50b1RpdGxlQ2FzZSA9IGZ1bmN0aW9uICgpIHtcclxuICByZXR1cm4gdGhpcy5yZXBsYWNlKC9cXHdcXFMqL2csIGZ1bmN0aW9uKHR4dCl7cmV0dXJuIHR4dC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIHR4dC5zdWJzdHIoMSkudG9Mb3dlckNhc2UoKTt9KTtcclxufTtcclxuXHJcbkFycmF5LnByb3RvdHlwZS5vcmRlckJ5ID0gZnVuY3Rpb248VD4ocHJvcCwgcmV2ZXJzZSkge1xyXG4gIHJldHVybiB0aGlzLnNvcnQoKGE6VCwgYjpUKSA9PiB7XHJcbiAgICBpZihhW3Byb3BdID4gYltwcm9wXSl7XHJcbiAgICAgIHJldHVybiByZXZlcnNlID8gLTEgOiAxXHJcbiAgICB9XHJcbiAgICBpZihhW3Byb3BdIDwgYltwcm9wXSl7XHJcbiAgICAgIHJldHVybiByZXZlcnNlID8gMSA6IC0xXHJcbiAgICB9XHJcbiAgICByZXR1cm4gMDtcclxuICB9KTtcclxufVxyXG5cclxuQXJyYXkucHJvdG90eXBlLmdyb3VwQnkgPSBmdW5jdGlvbihrZXkpIHtcclxuICByZXR1cm4gdGhpcy5yZWR1Y2UoZnVuY3Rpb24ocnYsIHgpIHtcclxuICAgIChydlt4W2tleV1dID0gcnZbeFtrZXldXSB8fCBbXSkucHVzaCh4KTtcclxuICAgIHJldHVybiBydjtcclxuICB9LCB7fSk7XHJcbn07XHJcbiIsImltcG9ydCB7IFRleHRJbnB1dCwgVGV4dEFyZWEgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBMYWJlbFxyXG4gICAgICB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIlxyXG5pbXBvcnQgeyBkaXNwYXRjaEFjdGlvbiwgIHNhdmVIYXphcmQgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGlcIlxyXG5pbXBvcnQgeyBIYXphcmQgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zXCJcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlXCJcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1kcm9wZG93blwiXHJcbmltcG9ydCB7IENsc3NNb2RhbCB9IGZyb20gXCIuL2Nsc3MtbW9kYWxcIjtcclxuaW1wb3J0IHsgUmVhY3RSZWR1eCB9IGZyb20gXCJqaW11LWNvcmVcIlxyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuZXhwb3J0IGNvbnN0IEFkZEhhemFyZFdpZGdldD0oe3Byb3BzLCB2aXNpYmxlLCB0b2dnbGUsIHNldEhhemFyZH06XHJcbiAgICB7cHJvcHM6IGFueSwgdmlzaWJsZTogYm9vbGVhbiwgdG9nZ2xlOiBhbnksIHNldEhhemFyZD86IGFueX0pID0+e1xyXG5cclxuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTsgICAgXHJcbiAgICBjb25zdCBbaXNWaXNpYmxlLCBzZXRWaXNpYmxlXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTsgXHJcbiAgICBjb25zdCBbbmFtZSwgc2V0TmFtZV0gPSBSZWFjdC51c2VTdGF0ZSgnJyk7ICAgXHJcbiAgICBjb25zdCBbZGVzY3JpcHRpb24sIHNldERlc2NyaXB0aW9uXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTsgXHJcbiAgICBjb25zdCBbaGF6YXJkVHlwZXMsIHNldEhhemFyZFR5cGVzXSA9IFJlYWN0LnVzZVN0YXRlPElDb2RlZFZhbHVlW10+KFtdKTtcclxuICAgIGNvbnN0IFtzZWxlY3RlZEhhemFyZFR5cGUsIHNldFNlbGVjdGVkSGF6YXJkVHlwZV0gPSBSZWFjdC51c2VTdGF0ZTxJQ29kZWRWYWx1ZT4obnVsbCk7XHJcbiAgICBjb25zdCBbY29uZmlnLCBzZXRDb25maWddID0gUmVhY3QudXNlU3RhdGUobnVsbClcclxuXHJcbiAgICBjb25zdCBjcmVkZW50aWFsID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5hdXRoZW50aWNhdGU7XHJcbiAgICB9KVxyXG5cclxuICAgIGNvbnN0IGhhemFyZHMgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmhhemFyZHMgYXMgSGF6YXJkW107XHJcbiAgICAgfSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgICAgIGlmKGNyZWRlbnRpYWwpe1xyXG4gICAgICAgICAgIHNldENvbmZpZyh7Li4uIHByb3BzLmNvbmZpZywgY3JlZGVudGlhbDpjcmVkZW50aWFsfSk7ICAgICAgICAgICAgXHJcbiAgICAgICAgfVxyXG4gICAgfSwgW2NyZWRlbnRpYWxdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgaWYoaGF6YXJkcyAmJiBoYXphcmRzLmxlbmd0aCA+IDApe1xyXG4gICAgICAgICAgICBjb25zdCB0eXBlcyA9IGhhemFyZHNbMV0uZG9tYWlucztcclxuICAgICAgICAgICAgKHR5cGVzIGFzIGFueSkub3JkZXJCeSgnbmFtZScpO1xyXG4gICAgICAgICAgICAgc2V0SGF6YXJkVHlwZXModHlwZXMpXHJcbjsgICAgICAgIH1cclxuICAgIH0sIFtoYXphcmRzXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgICBzZXRWaXNpYmxlKHZpc2libGUpO1xyXG4gICAgICAgIHNldE5hbWUoJycpO1xyXG4gICAgICAgIHNldERlc2NyaXB0aW9uKCcnKTtcclxuICAgICAgICBzZXRTZWxlY3RlZEhhemFyZFR5cGUobnVsbCk7XHJcbiAgICB9LCBbdmlzaWJsZV0pICAgXHJcblxyXG4gICAgY29uc3Qgc2F2ZU5ld0hhemFyZD1hc3luYyAoKT0+e1xyXG5cclxuICAgICAgICBjb25zdCBleGlzdCA9IGhhemFyZHMuZmluZChoID0+IGgubmFtZS50b0xvd2VyQ2FzZSgpID09PSBuYW1lLnRvTG93ZXJDYXNlKCkudHJpbSgpKTtcclxuICAgICAgICBpZihleGlzdCl7XHJcbiAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIGBIYXphcmQ6ICR7bmFtZX0gYWxyZWFkeSBleGlzdHNgKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgc2V0TG9hZGluZyh0cnVlKTtcclxuXHJcbiAgICAgICAgdHJ5e1xyXG4gICAgICAgICAgICBsZXQgbmV3SGF6YXJkID0ge1xyXG4gICAgICAgICAgICAgICAgbmFtZSxcclxuICAgICAgICAgICAgICAgIHRpdGxlOiBuYW1lLFxyXG4gICAgICAgICAgICAgICAgdHlwZTogc2VsZWN0ZWRIYXphcmRUeXBlLFxyXG4gICAgICAgICAgICAgICAgZGVzY3JpcHRpb25cclxuICAgICAgICAgICAgfSBhcyBIYXphcmQ7XHJcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgc2F2ZUhhemFyZChjb25maWcsIG5ld0hhemFyZCk7XHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcclxuICAgICAgICAgICAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFN0cmluZyhyZXNwb25zZS5lcnJvcnMpKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBcclxuICAgICAgICAgICAgbmV3SGF6YXJkID0gcmVzcG9uc2UuZGF0YTtcclxuICAgICAgICAgICAgbmV3SGF6YXJkLmRvbWFpbnMgPSBoYXphcmRzWzFdLmRvbWFpbnM7XHJcblxyXG4gICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRFNfQUNUSU9OLFxyXG4gICAgICAgICAgICAgICBbLi4uaGF6YXJkcywgbmV3SGF6YXJkXSlcclxuXHJcbiAgICAgICAgICAgIHNldEhhemFyZChuZXdIYXphcmQpO1xyXG4gICAgICAgICAgICB0b2dnbGUoZmFsc2UpO1xyXG4gICAgICAgIH1jYXRjaChlcnIpe1xyXG4gICAgICAgICAgIGNvbnNvbGUubG9nKGVycik7XHJcbiAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgZXJyLm1lc3NhZ2UpO1xyXG4gICAgICAgIH1maW5hbGx5e1xyXG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8Q2xzc01vZGFsIHRpdGxlPVwiQWRkIE5ldyBIYXphcmRcIlxyXG4gICAgICAgICAgICBkaXNhYmxlPXshKG5hbWUgJiYgc2VsZWN0ZWRIYXphcmRUeXBlKX0gIHNhdmU9e3NhdmVOZXdIYXphcmR9IFxyXG4gICAgICAgICAgICB0b2dnbGVWaXNpYmlsaXR5PXt0b2dnbGV9IHZpc2libGU9e2lzVmlzaWJsZX1cclxuICAgICAgICAgICAgbG9hZGluZz17bG9hZGluZ30+XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImhhemFyZHNcIj5cclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5IYXphcmQgTmFtZTxzcGFuIHN0eWxlPXt7Y29sb3I6ICdyZWQnfX0+Kjwvc3Bhbj48L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgICAgIDxUZXh0SW5wdXQgb25DaGFuZ2U9eyhlKT0+IHNldE5hbWUoZS50YXJnZXQudmFsdWUpfSBcclxuICAgICAgICAgICAgICAgICAgICB2YWx1ZT17bmFtZX0+PC9UZXh0SW5wdXQ+XHJcbiAgICAgICAgICAgICAgICA8L2Rpdj5cclxuXHJcbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+SGF6YXJkIFR5cGU8c3BhbiBzdHlsZT17e2NvbG9yOiAncmVkJ319Pio8L3NwYW4+PC9MYWJlbD5cclxuICAgICAgICAgICAgICAgICAgICA8Q2xzc0Ryb3Bkb3duIGl0ZW1zPXtoYXphcmRUeXBlc31cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGl0ZW09e3NlbGVjdGVkSGF6YXJkVHlwZX0gXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxldGFibGU9e2ZhbHNlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc2V0SXRlbT17c2V0U2VsZWN0ZWRIYXphcmRUeXBlfSAvPiBcclxuICAgICAgICAgICAgICAgIDwvZGl2PiAgICAgICBcclxuXHJcbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+RGVzY3JpcHRpb24gb2YgSGF6YXJkIChPcHRpb25hbCk8L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgICAgIDxUZXh0QXJlYVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZT17ZGVzY3JpcHRpb259XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSkgPT4gc2V0RGVzY3JpcHRpb24oZS50YXJnZXQudmFsdWUpfVxyXG4gICAgICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAgPC9kaXY+ICBcclxuICAgICAgICA8L0Nsc3NNb2RhbD5cclxuICAgIClcclxufSIsImltcG9ydCB7IFRleHRJbnB1dCwgQnV0dG9uLCBNb2RhbCwgTW9kYWxCb2R5LCBNb2RhbEZvb3RlciwgTW9kYWxIZWFkZXIgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBMYWJlbCB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IHsgT3JnYW5pemF0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9uc1wiXHJcbmltcG9ydCB7IGRpc3BhdGNoQWN0aW9uLCBzYXZlT3JnYW5pemF0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpXCJcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlXCJcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIlxyXG5pbXBvcnQgQ2xzc0xvYWRpbmcgZnJvbSBcIi4vY2xzcy1sb2FkaW5nXCJcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1kcm9wZG93blwiO1xyXG5pbXBvcnQgeyBSZWFjdFJlZHV4IH0gZnJvbSBcImppbXUtY29yZVwiXHJcbmltcG9ydCB7IENsc3NNb2RhbCB9IGZyb20gXCIuL2Nsc3MtbW9kYWxcIlxyXG5pbXBvcnQgeyBPcmdhbml6YXRpb25zRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLW9yZ2FuaXphdGlvbnMtZHJvcGRvd25cIlxyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuZXhwb3J0IGNvbnN0IEFkZE9yZ2FuaXphdG9uV2lkZ2V0PSh7cHJvcHNDb25maWcsIHZpc2libGUsIHRvZ2dsZSwgc2V0T3JnYW5pemF0aW9ufSkgPT57XHJcblxyXG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpOyAgICBcclxuICAgIGNvbnN0IFtpc1Zpc2libGUsIHNldFZpc2libGVdID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpOyBcclxuICAgIGNvbnN0IFtvcmdhbml6YXRpb25OYW1lLCBzZXRPcmdhbml6YXRpb25OYW1lXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTsgICAgXHJcbiAgICBjb25zdCBbb3JnYW5pemF0aW9uVHlwZXMsIHNldE9yZ2FuaXphdGlvblR5cGVzXSA9IFJlYWN0LnVzZVN0YXRlPElDb2RlZFZhbHVlW10+KFtdKTtcclxuICAgIGNvbnN0IFtzZWxlY3RlZE9yZ2FuaXphdGlvblR5cGUsIHNldFNlbGVjdGVkT3JnYW5pemF0aW9uVHlwZV0gPSBSZWFjdC51c2VTdGF0ZTxJQ29kZWRWYWx1ZT4obnVsbCk7XHJcbiAgICBjb25zdCBbc2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb24sIHNldFNlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9uXSA9IFJlYWN0LnVzZVN0YXRlPE9yZ2FuaXphdGlvbj4obnVsbCk7XHJcbiAgICBjb25zdCBbY29uZmlnLCBzZXRDb25maWddID0gUmVhY3QudXNlU3RhdGUobnVsbCk7XHJcblxyXG4gICAgY29uc3Qgb3JnYW5pemF0aW9ucyA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8ub3JnYW5pemF0aW9ucyBhcyBPcmdhbml6YXRpb25bXTtcclxuICAgICB9KVxyXG5cclxuICAgICBjb25zdCBjcmVkZW50aWFsID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5hdXRoZW50aWNhdGU7XHJcbiAgICB9KVxyXG4gICAgIFxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57IFxyXG4gICAgICAgIHNldFZpc2libGUodmlzaWJsZSk7XHJcbiAgICAgICAgc2V0T3JnYW5pemF0aW9uTmFtZSgnJyk7XHJcbiAgICAgICAgc2V0U2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlKG51bGwpO1xyXG4gICAgfSwgW3Zpc2libGVdKSAgIFxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgaWYoY3JlZGVudGlhbCl7XHJcbiAgICAgICAgICAgc2V0Q29uZmlnKHsuLi5wcm9wc0NvbmZpZywgY3JlZGVudGlhbH0pOyAgICAgICAgICAgIFxyXG4gICAgICAgIH1cclxuICAgIH0sIFtjcmVkZW50aWFsXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgICBpZihvcmdhbml6YXRpb25zICYmIG9yZ2FuaXphdGlvbnMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgY29uc3QgdHlwZXMgPSBvcmdhbml6YXRpb25zWzFdLmRvbWFpbnM7XHJcbiAgICAgICAgKHR5cGVzIGFzIGFueSk/Lm9yZGVyQnkoJ25hbWUnKTtcclxuICAgICAgICBzZXRPcmdhbml6YXRpb25UeXBlcyh0eXBlcyk7XHJcbiAgICAgIH1cclxuICAgIH0sIFtvcmdhbml6YXRpb25zXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgICBzZXRTZWxlY3RlZFBhcmVudE9yZ2FuaXphdGlvbihvcmdhbml6YXRpb25zWzBdKTtcclxuICAgIH0sIFtvcmdhbml6YXRpb25zXSlcclxuXHJcbiAgICBjb25zdCBzYXZlID0gYXN5bmMgKCkgPT4ge1xyXG4gICAgICAgIGNvbnN0IGV4aXN0cyA9IG9yZ2FuaXphdGlvbnMuZmluZChvID0+IG8ubmFtZSA9PT0gb3JnYW5pemF0aW9uTmFtZSk7XHJcbiAgICAgICAgaWYoZXhpc3RzKXtcclxuICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgYE9yZ2FuaXphdGlvbjogJHtvcmdhbml6YXRpb25OYW1lfSBhbHJlYWR5IGV4aXN0c2ApO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHNldExvYWRpbmcodHJ1ZSk7XHJcbiAgICAgICAgdHJ5e1xyXG4gICAgICAgICAgICBsZXQgbmV3T3JnYW5pemF0aW9uID0ge1xyXG4gICAgICAgICAgICAgICAgbmFtZTogb3JnYW5pemF0aW9uTmFtZSxcclxuICAgICAgICAgICAgICAgIHRpdGxlOiBvcmdhbml6YXRpb25OYW1lLFxyXG4gICAgICAgICAgICAgICAgdHlwZTogc2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlLFxyXG4gICAgICAgICAgICAgICAgcGFyZW50SWQ6IHNlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9uLmlkICE9PSAnMDAwJyA/IHNlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9uLmlkIDogbnVsbFxyXG4gICAgICAgICAgICB9IGFzIE9yZ2FuaXphdGlvblxyXG5cclxuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBzYXZlT3JnYW5pemF0aW9uKGNvbmZpZywgbmV3T3JnYW5pemF0aW9uKTsgICAgICAgICAgICBcclxuICAgICAgICAgICAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xyXG4gICAgICAgICAgICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFN0cmluZyhyZXNwb25zZS5lcnJvcnMpKVxyXG4gICAgICAgICAgICB9ICAgICAgICAgICAgXHJcblxyXG4gICAgICAgICAgICBuZXdPcmdhbml6YXRpb24gPSByZXNwb25zZS5kYXRhO1xyXG4gICAgICAgICAgICBuZXdPcmdhbml6YXRpb24uZG9tYWlucyA9IG9yZ2FuaXphdGlvbnNbMV0uZG9tYWlucztcclxuXHJcbiAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKFxyXG4gICAgICAgICAgICAgICAgQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTixcclxuICAgICAgICAgICAgICAgWy4uLm9yZ2FuaXphdGlvbnMsIG5ld09yZ2FuaXphdGlvbl0pO1xyXG4gICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgc2V0T3JnYW5pemF0aW9uKHJlc3BvbnNlLmRhdGEpXHJcbiAgICAgICAgICAgIHRvZ2dsZShmYWxzZSk7XHJcbiAgICAgICAgfWNhdGNoKGVycil7XHJcbiAgICAgICAgICAgY29uc29sZS5sb2coZXJyKTtcclxuICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCBlcnIubWVzc2FnZSk7XHJcbiAgICAgICAgfWZpbmFsbHl7XHJcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4oICAgICAgICAgICBcclxuICAgICAgPENsc3NNb2RhbCB0aXRsZT1cIkFkZCBOZXcgT3JnYW5pemF0aW9uXCJcclxuICAgICAgICBkaXNhYmxlPXshKG9yZ2FuaXphdGlvbk5hbWUgJiYgc2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlKX0gIFxyXG4gICAgICAgIHNhdmU9e3NhdmV9IFxyXG4gICAgICAgIGxvYWRpbmc9e2xvYWRpbmd9XHJcbiAgICAgICAgdG9nZ2xlVmlzaWJpbGl0eT17dG9nZ2xlfSB2aXNpYmxlPXtpc1Zpc2libGV9PlxyXG4gICAgICAgICBcclxuICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJhZGQtb3JnYW5pemF0aW9uXCI+IFxyXG4gICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuYWRkLW9yZ2FuaXphdGlvbntcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj4gICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPk9yZ2FuaXphdGlvbiBOYW1lPHNwYW4gc3R5bGU9e3tjb2xvcjogJ3JlZCd9fT4qPC9zcGFuPjwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICA8VGV4dElucHV0IGRhdGEtdGVzdGlkPVwidHh0T3JnYW5pemF0aW9uTmFtZVwiIHNpemU9XCJkZWZhdWx0XCJcclxuICAgICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpPT4gc2V0T3JnYW5pemF0aW9uTmFtZShlLnRhcmdldC52YWx1ZSl9IFxyXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlPXtvcmdhbml6YXRpb25OYW1lfT5cclxuICAgICAgICAgICAgICAgIDwvVGV4dElucHV0PlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuXHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPk9yZ2FuaXphdGlvbiBUeXBlPHNwYW4gc3R5bGU9e3tjb2xvcjogJ3JlZCd9fT4qPC9zcGFuPjwvTGFiZWw+ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICA8Q2xzc0Ryb3Bkb3duIGl0ZW1zPXtvcmdhbml6YXRpb25UeXBlc30gXHJcbiAgICAgICAgICAgICAgICAgICAgaXRlbT17c2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlfSBcclxuICAgICAgICAgICAgICAgICAgICBkZWxldGFibGU9e2ZhbHNlfVxyXG4gICAgICAgICAgICAgICAgICAgIHNldEl0ZW09e3NldFNlbGVjdGVkT3JnYW5pemF0aW9uVHlwZX0vPlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuXHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPk9yZ2FuaXphdGlvbidzIFBhcmVudCAoT3B0aW9uYWwpPC9MYWJlbD5cclxuICAgICAgICAgICAgICAgIDxPcmdhbml6YXRpb25zRHJvcGRvd24gXHJcbiAgICAgICAgICAgICAgICAgICAgY29uZmlnPXtjb25maWd9XHJcbiAgICAgICAgICAgICAgICAgICAgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWw9e251bGx9ICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICBvcmdhbml6YXRpb25zPXtvcmdhbml6YXRpb25zfSBcclxuICAgICAgICAgICAgICAgICAgICBzZWxlY3RlZE9yZ2FuaXphdGlvbj17c2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb259IFxyXG4gICAgICAgICAgICAgICAgICAgIHNldE9yZ2FuaXphdGlvbj17c2V0U2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb259XHJcbiAgICAgICAgICAgICAgICAgICAgdmVydGljYWw9e2ZhbHNlfS8+ICBcclxuICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgIDwvZGl2PiAgICAgICAgICAgICAgICBcclxuICAgIFxyXG4gICAgICA8L0Nsc3NNb2RhbD5cclxuICAgIClcclxufSIsImltcG9ydCB7IFRleHRJbnB1dCB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcbmltcG9ydCB7IExhYmVsXHJcbiAgICAgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCB7IENMU1NUZW1wbGF0ZSwgQ2xzc1VzZXIsIEhhemFyZCwgT3JnYW5pemF0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9uc1wiXHJcbmltcG9ydCB7IFJlYWN0UmVkdXggfSBmcm9tIFwiamltdS1jb3JlXCJcclxuaW1wb3J0IHsgY3JlYXRlTmV3VGVtcGxhdGUsIGRpc3BhdGNoQWN0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpXCJcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlXCJcclxuaW1wb3J0IHsgVGVtcGxhdGVzRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLXRlbXBsYXRlcy1kcm9wZG93blwiXHJcbmltcG9ydCB7IEhhemFyZHNEcm9wZG93biB9IGZyb20gXCIuL2Nsc3MtaGF6YXJkcy1kcm9wZG93blwiXHJcbmltcG9ydCB7IE9yZ2FuaXphdGlvbnNEcm9wZG93biB9IGZyb20gXCIuL2Nsc3Mtb3JnYW5pemF0aW9ucy1kcm9wZG93blwiXHJcbmltcG9ydCB7IENsc3NNb2RhbCB9IGZyb20gXCIuL2Nsc3MtbW9kYWxcIlxyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuZXhwb3J0IGludGVyZmFjZSBUZW1wbGF0ZUFyZ3Mge1xyXG4gICAgY29uZmlnOiBhbnk7XHJcbiAgICB2aXNpYmxlOiBib29sZWFuO1xyXG4gICAgdG9nZ2xlVmlzaWJpbGl0eTogRnVuY3Rpb247XHJcbiAgICB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbDogRnVuY3Rpb247XHJcbiAgICB0b2dnbGVOZXdIYXphcmRNb2RhbDogRnVuY3Rpb247XHJcbiAgICBzYXZlVGVtcGxhdGVDb21wbGV0ZUNhbGxiYWNrOiBGdW5jdGlvbjtcclxuICAgIHNlbGVjdGVkSGF6YXJkOiBIYXphcmQ7XHJcbiAgICBzZXRIYXphcmQ6IEZ1bmN0aW9uOyAgIFxyXG4gICAgc2VsZWN0ZWRPcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbjtcclxuICAgIHNldE9yZ2FuaXphdGlvbjogRnVuY3Rpb247XHJcbiAgICBoYXphcmRzOiBIYXphcmRbXTtcclxuICAgIG9yZ2FuaXphdGlvbnM6IE9yZ2FuaXphdGlvbltdO1xyXG4gICAgdXNlcjogQ2xzc1VzZXI7XHJcbiAgICB0ZW1wbGF0ZXM6IENMU1NUZW1wbGF0ZVtdO1xyXG59XHJcblxyXG5leHBvcnQgY29uc3QgQWRkVGVtcGxhdGVXaWRnZXQ9KHByb3BzOiBUZW1wbGF0ZUFyZ3MpID0+e1xyXG5cclxuICAgIGNvbnN0IFtlcnJvciwgc2V0RXJyb3JdID0gUmVhY3QudXNlU3RhdGUoJycpO1xyXG4gICAgY29uc3RbbG9hZGluZywgc2V0TG9hZGluZ10gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7XHJcbiAgICBjb25zdCBbaXNWaXNpYmxlLCBzZXRWaXNpYmlsaXR5XSA9IFJlYWN0LnVzZVN0YXRlKHByb3BzLnZpc2libGUpO1xyXG4gICAgY29uc3QgW3RlbXBsYXRlTmFtZSwgc2V0VGVtcGxhdGVOYW1lXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTsgICAgIFxyXG4gICAgY29uc3QgW3NlbGVjdGVkQmFzZWRPblRlbXBsYXRlLCBzZXRTZWxlY3RlZEJhc2VkT25UZW1wbGF0ZV0gPSBSZWFjdC51c2VTdGF0ZTxDTFNTVGVtcGxhdGU+KG51bGwpOyAgICBcclxuICAgIFxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICAgICAgc2V0VmlzaWJpbGl0eShwcm9wcy52aXNpYmxlKVxyXG4gICAgfSxbcHJvcHNdKSAgIFxyXG4gICBcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PiB7XHJcbiAgICAgICAgaWYocHJvcHMudGVtcGxhdGVzICYmIHByb3BzLnRlbXBsYXRlcy5sZW5ndGggPT09IDEpe1xyXG4gICAgICAgICAgIHNldFNlbGVjdGVkQmFzZWRPblRlbXBsYXRlKHByb3BzLnRlbXBsYXRlc1swXSk7XHJcbiAgICAgICAgfVxyXG4gICAgIH0sIFtwcm9wc10pXHJcbiAgIFxyXG4gICAgY29uc3Qgc2F2ZU5ld1RlbXBsYXRlPWFzeW5jICgpPT4ge1xyXG4gICAgICAgIGNvbnN0IGV4aXN0ID0gcHJvcHMudGVtcGxhdGVzLmZpbmQodCA9PiB0Lm5hbWUudG9Mb3dlckNhc2UoKS50cmltKCkgPT09IHRlbXBsYXRlTmFtZS50b0xvd2VyQ2FzZSgpLnRyaW0oKSk7XHJcbiAgICAgICAgaWYoZXhpc3Qpe1xyXG4gICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCBgVGVtcGxhdGU6ICR7dGVtcGxhdGVOYW1lfSBhbHJlYWR5IGV4aXN0c2ApO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHNldExvYWRpbmcodHJ1ZSk7XHJcblxyXG4gICAgICAgIGxldCBuZXdUZW1wbGF0ZSA9IHtcclxuICAgICAgICAgICAgLi4uc2VsZWN0ZWRCYXNlZE9uVGVtcGxhdGUsICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIG5hbWU6IHRlbXBsYXRlTmFtZSxcclxuICAgICAgICAgICAgdGl0bGU6IHRlbXBsYXRlTmFtZSAgICAgIFxyXG4gICAgICAgIH0gYXMgQ0xTU1RlbXBsYXRlO1xyXG5cclxuICAgICAgICBsZXQgb3JnYW5pemF0aW9uID0gbnVsbDtcclxuICAgICAgICBpZihwcm9wcy5zZWxlY3RlZE9yZ2FuaXphdGlvbiAmJiBcclxuICAgICAgICAgICAgcHJvcHMuc2VsZWN0ZWRPcmdhbml6YXRpb24udGl0bGUgIT09ICctTm9uZS0nKXtcclxuICAgICAgICAgICAgICAgIG9yZ2FuaXphdGlvbiA9IHByb3BzLnNlbGVjdGVkT3JnYW5pemF0aW9uO1xyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgIGxldCBoYXphcmQgPSBudWxsO1xyXG4gICAgICAgIGlmKHByb3BzLnNlbGVjdGVkSGF6YXJkICYmIHByb3BzLnNlbGVjdGVkSGF6YXJkLnRpdGxlICE9PSAnLU5vbmUtJyl7XHJcbiAgICAgICAgICAgIGhhemFyZCA9IHByb3BzLnNlbGVjdGVkSGF6YXJkO1xyXG4gICAgICAgIH1cclxuICAgICAgXHJcbiAgICAgICAgY29uc3Qgc3RhcnQgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKTtcclxuICAgICAgICBjb25zdCByZXNwID0gYXdhaXQgY3JlYXRlTmV3VGVtcGxhdGUocHJvcHMuY29uZmlnLCBuZXdUZW1wbGF0ZSwgcHJvcHMudXNlcj8udXNlck5hbWUsIFxyXG4gICAgICAgICAgICBvcmdhbml6YXRpb24sIGhhemFyZCk7XHJcblxyXG4gICAgICAgIGNvbnNvbGUubG9nKCdDcmVhdGUgVGVtcGxhdGUgVG9vaycsIG5ldyBEYXRlKCkuZ2V0VGltZSgpIC0gc3RhcnQpO1xyXG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICAgIGlmKHJlc3AuZXJyb3JzKXtcclxuICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgcmVzcC5lcnJvcnMpO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfSAgICAgICBcclxuICAgICAgICBwcm9wcy5zYXZlVGVtcGxhdGVDb21wbGV0ZUNhbGxiYWNrKCk7XHJcbiAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7IFxyXG4gICAgICAgIHByb3BzLnRvZ2dsZVZpc2liaWxpdHkoZmFsc2UpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuKFxyXG4gICAgICAgIDxDbHNzTW9kYWwgdGl0bGU9XCJBZGQgTmV3IFRlbXBsYXRlXCJcclxuICAgICAgICAgICAgZGlzYWJsZT17ISh0ZW1wbGF0ZU5hbWUgJiYgc2VsZWN0ZWRCYXNlZE9uVGVtcGxhdGUgJiYgIWVycm9yKX0gIFxyXG4gICAgICAgICAgICBzYXZlPXtzYXZlTmV3VGVtcGxhdGV9IFxyXG4gICAgICAgICAgICBsb2FkaW5nPXtsb2FkaW5nfVxyXG4gICAgICAgICAgICB0b2dnbGVWaXNpYmlsaXR5PXtwcm9wcy50b2dnbGVWaXNpYmlsaXR5fSBcclxuICAgICAgICAgICAgdmlzaWJsZT17aXNWaXNpYmxlfT5cclxuICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJuZXctdGVtcGxhdGVcIj5cclxuICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgLm5ldy10ZW1wbGF0ZXtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjtcclxuICAgICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAubmV3LXRlbXBsYXRlIC5hZGQtbGluayB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAyMDdweDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgbWFyZ2luLWxlZnQ6IC0xNnB4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC9zdHlsZT5cclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5UZW1wbGF0ZSBOYW1lPHNwYW4gc3R5bGU9e3tjb2xvcjogJ3JlZCd9fT4qPC9zcGFuPjwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgPFRleHRJbnB1dCBkYXRhLXRlc3RpZD1cInR4dFRlbXBsYXRlTmFtZVwiIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICBjbGFzc05hbWU9XCJ0ZW1wbGF0ZS1pbnB1dFwiIHNpemU9XCJkZWZhdWx0XCJcclxuICAgICAgICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKT0+IHNldFRlbXBsYXRlTmFtZShlLnRhcmdldC52YWx1ZSl9IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZT17dGVtcGxhdGVOYW1lfT48L1RleHRJbnB1dD5cclxuICAgICAgICAgICAgICAgIDwvZGl2PlxyXG5cclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5CYXNlIFRlbXBsYXRlIE9uPHNwYW4gc3R5bGU9e3tjb2xvcjogJ3JlZCd9fT4qPC9zcGFuPjwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgPFRlbXBsYXRlc0Ryb3Bkb3duIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICB0ZW1wbGF0ZXM9e3Byb3BzLnRlbXBsYXRlc31cclxuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0ZWRUZW1wbGF0ZT17c2VsZWN0ZWRCYXNlZE9uVGVtcGxhdGV9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHNldFRlbXBsYXRlPXtzZXRTZWxlY3RlZEJhc2VkT25UZW1wbGF0ZX0vPiAgICBcclxuICAgICAgICAgICAgICAgIDwvZGl2PiAgICAgICAgXHJcblxyXG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJtb2RhbC1pdGVtXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPlRlbXBsYXRlIEhhemFyZCAoT3B0aW9uYWwpPC9MYWJlbD5cclxuICAgICAgICAgICAgICAgICAgICA8SGF6YXJkc0Ryb3Bkb3duXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICBjb25maWc9e3Byb3BzLmNvbmZpZ31cclxuICAgICAgICAgICAgICAgICAgICAgICAgaGF6YXJkcz17cHJvcHMuaGF6YXJkc31cclxuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0ZWRIYXphcmQ9e3Byb3BzLnNlbGVjdGVkSGF6YXJkfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRIYXphcmQ9e3Byb3BzLnNldEhhemFyZH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgdmVydGljYWw9e3RydWV9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRvZ2dsZU5ld0hhemFyZE1vZGFsPXtwcm9wcy50b2dnbGVOZXdIYXphcmRNb2RhbH0vPiAgIFxyXG4gICAgICAgICAgICAgICAgPC9kaXY+ICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJtb2RhbC1pdGVtXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPlRlbXBsYXRlIE9yZ2FuaXphdGlvbiAoT3B0aW9uYWwpPC9MYWJlbD5cclxuICAgICAgICAgICAgICAgICAgICA8T3JnYW5pemF0aW9uc0Ryb3Bkb3duXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbmZpZz17cHJvcHMuY29uZmlnfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB2ZXJ0aWNhbD17dHJ1ZX0gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgb3JnYW5pemF0aW9ucz17cHJvcHMub3JnYW5pemF0aW9uc31cclxuICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0ZWRPcmdhbml6YXRpb249e3Byb3BzLnNlbGVjdGVkT3JnYW5pemF0aW9ufVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBzZXRPcmdhbml6YXRpb249e3Byb3BzLnNldE9yZ2FuaXphdGlvbn1cclxuICAgICAgICAgICAgICAgICAgICAgICAgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWw9e3Byb3BzLnRvZ2dsZU5ld09yZ2FuaXphdGlvbk1vZGFsfS8+XHJcbiAgICAgICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAgPC9kaXY+IFxyXG4gICAgICAgIDwvQ2xzc01vZGFsPiAgICAgICBcclxuICAgIClcclxufSIsImltcG9ydCB7IERyb3Bkb3duLCBEcm9wZG93bkJ1dHRvbiwgRHJvcGRvd25NZW51LCBMYWJlbCB9IGZyb20gXCJqaW11LXVpXCI7XHJcbmltcG9ydCB7IFRyYXNoT3V0bGluZWQgfSBmcm9tICdqaW11LWljb25zL291dGxpbmVkL2VkaXRvci90cmFzaCc7XHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5cclxuZXhwb3J0IGNvbnN0IENsc3NEcm9wZG93biA9ICh7aXRlbXMsIGl0ZW0sIGRlbGV0YWJsZSwgc2V0SXRlbSwgZGVsZXRlSXRlbSwgbWVudVdpZHRofTpcclxuICAgIHtpdGVtczogYW55W10sIGl0ZW06IGFueSwgZGVsZXRhYmxlOiBib29sZWFuLCBzZXRJdGVtOiBGdW5jdGlvbiwgXHJcbiAgICAgIGRlbGV0ZUl0ZW0/OiBGdW5jdGlvbiwgbWVudVdpZHRoPzogc3RyaW5nfSk9PiB7XHJcblxyXG4gICAgY29uc3QgYnV0dG9uRWxlbWVudCA9IFJlYWN0LnVzZVJlZjxIVE1MRWxlbWVudD4oKTtcclxuICAgIFxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+e1xyXG4gICAgICAgaWYoaXRlbXMgJiYgaXRlbXMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgICBpZighaXRlbSl7XHJcbiAgICAgICAgICAgIHNldEl0ZW0oaXRlbXNbMF0pIFxyXG4gICAgICAgICAgfWVsc2V7XHJcbiAgICAgICAgICAgIHNldEl0ZW0oaXRlbSk7XHJcbiAgICAgICAgICB9ICAgICAgXHJcbiAgICAgICB9XHJcbiAgICB9LCBbaXRlbXNdKVxyXG5cclxuICAgIGNvbnN0IGl0ZW1DbGljayA9IChpdGVtKT0+eyAgICAgXHJcbiAgICAgICAgc2V0SXRlbShpdGVtKTsgICAgICAgIFxyXG4gICAgICAgIGlmKGJ1dHRvbkVsZW1lbnQgJiYgYnV0dG9uRWxlbWVudC5jdXJyZW50KXtcclxuICAgICAgICAgICAgYnV0dG9uRWxlbWVudC5jdXJyZW50LmNsaWNrKCk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHJlbW92ZUl0ZW0gPShpdGVtKSA9PntcclxuICAgICAgICBpZihjb25maXJtKCdSZW1vdmUgJysoaXRlbS50aXRsZSB8fCBpdGVtLm5hbWUpKSl7XHJcbiAgICAgICAgICAgIGRlbGV0ZUl0ZW0oaXRlbSk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJjbHNzLWRyb3Bkb3duLWNvbnRhaW5lclwiIHN0eWxlPXt7d2lkdGg6ICcxMDAlJ319PlxyXG4gICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAuZHJvcGRvd24taXRlbS1jb250YWluZXJ7XHJcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA0NXB4O1xyXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlci1ib3R0b206IDFweCBzb2xpZCByZ2IoMjI3LCAyMjcsIDIyNyk7XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZHJvcGRvd24taXRlbS1jb250YWluZXI6aG92ZXJ7XHJcbiAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogcmdiKDIyNywgMjI3LCAyMjcpO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5qaW11LWRyb3Bkb3duLW1lbnV7XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDM1JTtcclxuICAgICAgICAgICAgICAgICAgICBtYXgtaGVpZ2h0OiA1MDBweDtcclxuICAgICAgICAgICAgICAgICAgICBvdmVyZmxvdzogYXV0bztcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuamltdS1kcm9wZG93bi1tZW51IC5kcm9wZG93bi1pdGVtLWNvbnRhaW5lcjpsYXN0LWNoaWxke1xyXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlci1ib3R0b206IG5vbmU7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLm1vZGFsLWNvbnRlbnQgLmNsc3MtZHJvcGRvd24tY29udGFpbmVyIGJ1dHRvbntcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuY2xzcy1kcm9wZG93bi1jb250YWluZXIgLmppbXUtZHJvcGRvd257XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmNsb3NlLWJ1dHRvbntcclxuICAgICAgICAgICAgICAgICAgICBtYXJnaW46IDEwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6IGdyYXk7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgIC5tb2RhbC1jb250ZW50IC5jbHNzLWRyb3Bkb3duLWNvbnRhaW5lciBidXR0b24gc3BhbntcclxuICAgICAgICAgICAgICAgICAgICAgbGluZS1oZWlnaHQ6IDMwcHggIWltcG9ydGFudDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAuZHJvcGRvd24taXRlbS1jb250YWluZXIgbGFiZWx7XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMDAlO1xyXG4gICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDEuMmVtO1xyXG4gICAgICAgICAgICAgICAgICAgIG1hcmdpbi1sZWZ0OiAxZW07XHJcbiAgICAgICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3N0eWxlPlxyXG4gICAgICAgICAgICA8RHJvcGRvd24gIGFjdGl2ZUljb249XCJ0cnVlXCIgc2l6ZT1cImxnXCI+XHJcbiAgICAgICAgICAgICAgICA8RHJvcGRvd25CdXR0b24gY2xhc3NOYW1lPVwiZHJvcGRvd25CdXR0b25cIiByZWY9e2J1dHRvbkVsZW1lbnR9ICBzaXplPVwibGdcIiBzdHlsZT17e3RleHRBbGlnbjogJ2xlZnQnfX0+XHJcbiAgICAgICAgICAgICAgICAgICAge2l0ZW0/LnRpdGxlIHx8IGl0ZW0/Lm5hbWV9XHJcbiAgICAgICAgICAgICAgICA8L0Ryb3Bkb3duQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgPERyb3Bkb3duTWVudSBzdHlsZT17e3dpZHRoOiBtZW51V2lkdGggfHwgXCIzMCVcIn19PlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGl0ZW1zPy5tYXAoKGl0ZW0sIGlkeCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBpZD17aXRlbT8ubmFtZSB8fCBpdGVtPy50aXRsZX0gY2xhc3NOYW1lPVwiZHJvcGRvd24taXRlbS1jb250YWluZXJcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2sgb25DbGljaz17KCkgPT4gaXRlbUNsaWNrKGl0ZW0pfT57aXRlbT8udGl0bGUgfHwgaXRlbT8ubmFtZX08L0xhYmVsPiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICgoaXRlbT8udGl0bGUgfHwgaXRlbT8ubmFtZSkgIT09ICctTm9uZS0nKSAmJiBkZWxldGFibGUgPyBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKDxUcmFzaE91dGxpbmVkIHRpdGxlPSdSZW1vdmUnIGNsYXNzTmFtZT1cImNsb3NlLWJ1dHRvblwiIHNpemU9ezIwfSBvbkNsaWNrPXsoKSA9PiByZW1vdmVJdGVtKGl0ZW0pfS8+KVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IG51bGxcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4gIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIDwvRHJvcGRvd25NZW51PlxyXG4gICAgICAgICAgICA8L0Ryb3Bkb3duPlxyXG4gICAgICAgIDwvZGl2PlxyXG4gICAgKVxyXG59IiwiaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcbmltcG9ydCB7IENsc3NEcm9wZG93biB9IGZyb20gXCIuL2Nsc3MtZHJvcGRvd25cIlxyXG5pbXBvcnQgeyBIYXphcmQgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zXCJcclxuaW1wb3J0IHsgQnV0dG9uIH0gZnJvbSBcImppbXUtdWlcIjtcclxuaW1wb3J0IHsgUGx1c0NpcmNsZU91dGxpbmVkIH0gZnJvbSBcImppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL3BsdXMtY2lyY2xlXCI7XHJcbmltcG9ydCB7IGRlbGV0ZUhhemFyZCwgZGlzcGF0Y2hBY3Rpb24gfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGlcIjtcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlXCI7XHJcblxyXG5cclxuZXhwb3J0IGNvbnN0IEhhemFyZHNEcm9wZG93biA9KHtjb25maWcsIGhhemFyZHMsIHNlbGVjdGVkSGF6YXJkLCBzZXRIYXphcmQsIHZlcnRpY2FsLCB0b2dnbGVOZXdIYXphcmRNb2RhbH0pPT57XHJcblxyXG4gICAgY29uc3QgW2xvY2FsSGF6YXJkcywgc2V0TG9jYWxIYXphcmRzXSA9IFJlYWN0LnVzZVN0YXRlPEhhemFyZFtdPihbXSk7XHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICAgICAgaWYoaGF6YXJkcyl7ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIHNldExvY2FsSGF6YXJkcyhbLi4uaGF6YXJkc10gYXMgSGF6YXJkW10pXHJcbiAgICAgICAgfVxyXG4gICAgfSwgW2hhemFyZHNdKVxyXG5cclxuICAgIGNvbnN0IHJlbW92ZUhhemFyZCA9YXN5bmMgKGhhemFyZDogSGF6YXJkKT0+eyAgICAgICBcclxuICAgICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZUhhemFyZChoYXphcmQsIGNvbmZpZyk7XHJcbiAgICAgICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlLmVycm9ycyk7XHJcbiAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgcmVzcG9uc2UuZXJyb3JzKTtcclxuICAgICAgICByZXR1cm47XHJcbiAgICAgICB9XHJcbiAgICAgICBjb25zb2xlLmxvZyhgJHtoYXphcmQudGl0bGV9IGRlbGV0ZWRgKTtcclxuICAgICAgIHNldExvY2FsSGF6YXJkcyhbLi4ubG9jYWxIYXphcmRzLmZpbHRlcihoID0+IGguaWQgIT09IGhhemFyZC5pZCldKTtcclxuICAgIH1cclxuICAgIFxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8ZGl2IHN0eWxlPXt7ZGlzcGxheTogdmVydGljYWwgPyAnYmxvY2snOiAnZmxleCcsXHJcbiAgICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInfX0+XHJcbiAgICAgICAgICAgIDxzdHlsZT5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICAgICAgIC5hY3Rpb24taWNvbiB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiBncmF5O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3N0eWxlPlxyXG4gICAgICAgICAgICA8Q2xzc0Ryb3Bkb3duIGl0ZW1zPXtsb2NhbEhhemFyZHN9XHJcbiAgICAgICAgICAgICAgICBpdGVtPXtzZWxlY3RlZEhhemFyZH0gXHJcbiAgICAgICAgICAgICAgICBkZWxldGFibGU9e3RydWV9XHJcbiAgICAgICAgICAgICAgICBzZXRJdGVtPXtzZXRIYXphcmR9IFxyXG4gICAgICAgICAgICAgICAgZGVsZXRlSXRlbT17cmVtb3ZlSGF6YXJkfS8+IFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgIHZlcnRpY2FsPyAoXHJcbiAgICAgICAgICAgICAgICA8QnV0dG9uIGRhdGEtdGVzdGlkPVwiYnRuU2hvd0FkZE9yZ2FuaXphdGlvblwiICBjbGFzc05hbWU9XCIgYWRkLWxpbmtcIlxyXG4gICAgICAgICAgICAgICAgICAgICB0eXBlPVwibGlua1wiIHN0eWxlPXt7dGV4dEFsaWduOiAnbGVmdCd9fVxyXG4gICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpPT4gdG9nZ2xlTmV3SGF6YXJkTW9kYWwodHJ1ZSl9PlxyXG4gICAgICAgICAgICAgICAgICAgIEFkZCBOZXcgSGF6YXJkXHJcbiAgICAgICAgICAgICAgICA8L0J1dHRvbj5cclxuICAgICAgICAgICAgICAgKTooXHJcbiAgICAgICAgICAgICAgICA8UGx1c0NpcmNsZU91dGxpbmVkIGNsYXNzTmFtZT1cImFjdGlvbi1pY29uXCIgXHJcbiAgICAgICAgICAgICAgICAgICAgZGF0YS10ZXN0aWQ9XCJidG5BZGROZXdIYXphcmRcIiBcclxuICAgICAgICAgICAgICAgICAgICB0aXRsZT1cIkFkZCBOZXcgSGF6YXJkXCIgc2l6ZT17MzB9IGNvbG9yPXsnZ3JheSd9XHJcbiAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCk9PiB0b2dnbGVOZXdIYXphcmRNb2RhbCh0cnVlKX0vPiBcclxuICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgfSAgIFxyXG4gICAgICAgICAgICB7LyogPHA+e3NlbGVjdGVkSGF6YXJkPy5kZXNjcmlwdGlvbn08L3A+ICovfVxyXG4gICAgICAgIDwvZGl2PlxyXG4gICAgKVxyXG59IiwiaW1wb3J0IHsgTG9hZGluZyB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcblxyXG5jb25zdCBDbHNzTG9hZGluZyA9KHttZXNzYWdlfTp7bWVzc2FnZT86c3RyaW5nfSkgPT57XHJcbiAgICByZXR1cm4oICAgICAgICBcclxuICAgICAgICA8ZGl2XHJcbiAgICAgICAgICAgIHN0eWxlPXt7XHJcbiAgICAgICAgICAgICAgICBoZWlnaHQ6ICcxMDAlJyxcclxuICAgICAgICAgICAgICAgIHdpZHRoOiAnMTAwJScsXHJcbiAgICAgICAgICAgICAgICBwb3NpdGlvbjogJ2Fic29sdXRlJyxcclxuICAgICAgICAgICAgICAgIGJhY2tncm91bmQ6ICdyZ2IoMCAwIDAgLyAxMyUpJyxcclxuICAgICAgICAgICAgICAgIHRvcDogMCwgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgbGVmdDogMCxcclxuICAgICAgICAgICAgICAgIHpJbmRleDogOTk5OTk5LFxyXG4gICAgICAgICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLFxyXG4gICAgICAgICAgICAgICAganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLFxyXG4gICAgICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcidcclxuICAgICAgICAgICAgfX1cclxuICAgICAgICAgICAgPlxyXG4gICAgICAgICAgICA8TG9hZGluZ1xyXG4gICAgICAgICAgICAgICAgY2xhc3NOYW1lPVwiXCJcclxuICAgICAgICAgICAgICAgIHR5cGU9XCJTRUNPTkRBUllcIlxyXG4gICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICA8aDM+e21lc3NhZ2V9PC9oMz5cclxuICAgICAgICA8L2Rpdj5cclxuICAgIClcclxufVxyXG5leHBvcnQgZGVmYXVsdCBDbHNzTG9hZGluZzsiLCJcclxuaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcbmltcG9ydCB7IE1vZGFsLCBNb2RhbEhlYWRlciwgTW9kYWxCb2R5LCBNb2RhbEZvb3RlciwgQnV0dG9uIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgQ2xzc0xvYWRpbmcgZnJvbSBcIi4vY2xzcy1sb2FkaW5nXCJcclxuXHJcbi8vIGV4cG9ydCBpbnRlcmZhY2UgTW9kYWxQcm9wcyB7XHJcbi8vICAgICB0aXRsZTogc3RyaW5nO1xyXG4vLyAgICAgdmlzaWJsZTogYm9vbGVhbjtcclxuLy8gICAgIGRpc2FibGU6IGJvb2xlYW47XHJcbi8vICAgICBjaGlsZHJlbjogYW55O1xyXG4vLyAgICAgdG9nZ2xlVmlzaWJpbGl0eTogRnVuY3Rpb247XHJcbi8vICAgICBzYXZlOiBGdW5jdGlvbjtcclxuLy8gICAgIGNhbmNlbDogRnVuY3Rpb247XHJcbi8vIH1cclxuXHJcbmV4cG9ydCBjb25zdCBDbHNzTW9kYWwgPShwcm9wcyk9PntcclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPE1vZGFsIGlzT3Blbj17cHJvcHMudmlzaWJsZX0gY2VudGVyZWQ9e3RydWV9IGNsYXNzTmFtZT1cImNsc3MtbW9kYWxcIj5cclxuICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLm1vZGFsLWNvbnRlbnR7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAxLjNyZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCAubW9kYWwtdGl0bGV7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDEuMWVtO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIGlucHV0e1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFkZGluZy1sZWZ0OiAwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIC5qaW11LWlucHV0IHNwYW57XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IC45ZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIGxhYmVse1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IGdyYXk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIC5qaW11LWRyb3Bkb3duLWJ1dHRvbntcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMWVtO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCAubW9kYWwtaXRlbXtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1hcmdpbjogMTBweCAwO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIHRleHRhcmVhe1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAwLjhlbTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIC5zcGFjZXJ7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMWVtO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3N0eWxlPlxyXG4gICAgICAgICAgICA8TW9kYWxIZWFkZXIgdG9nZ2xlPXsoKT0+cHJvcHMudG9nZ2xlVmlzaWJpbGl0eShmYWxzZSl9PlxyXG4gICAgICAgICAgICAgICAge3Byb3BzLnRpdGxlfVxyXG4gICAgICAgICAgICA8L01vZGFsSGVhZGVyPlxyXG4gICAgICAgICAgICA8TW9kYWxCb2R5PlxyXG4gICAgICAgICAgICAgICAge3Byb3BzLmNoaWxkcmVufSAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIDwvTW9kYWxCb2R5PlxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBwcm9wcy5oaWRlRm9vdGVyICYmIHByb3BzLmhpZGVGb290ZXIgPT0gdHJ1ZSA/IG51bGwgOlxyXG4gICAgICAgICAgICAgICAgKFxyXG4gICAgICAgICAgICAgICAgICAgIDxNb2RhbEZvb3RlciA+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDxCdXR0b24gb25DbGljaz17KCkgPT4gKHByb3BzLmNhbmNlbCA/IHByb3BzLmNhbmNlbCgpIDogcHJvcHMudG9nZ2xlVmlzaWJpbGl0eShmYWxzZSkpfT5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtwcm9wcy5ub0J1dHRvblRpdGxlIHx8ICdDYW5jZWwnfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJzcGFjZXJcIi8+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDxCdXR0b24gZGF0YS10ZXN0aWQ9XCJidG5TYXZlXCIgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNhYmxlZD17cHJvcHMuZGlzYWJsZX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpID0+IHByb3BzLnNhdmUoKX0+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB7cHJvcHMueWVzQnV0dG9uVGl0bGUgfHwgJ1NhdmUnfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cclxuICAgICAgICAgICAgICAgICAgICA8L01vZGFsRm9vdGVyPlxyXG4gICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICB9ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgIChwcm9wcy5sb2FkaW5nKSA/IDxDbHNzTG9hZGluZy8+IDogbnVsbCAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIDwvTW9kYWw+IFxyXG4gICAgKVxyXG59IiwiaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiXHJcbmltcG9ydCB7IENsc3NEcm9wZG93biB9IGZyb20gXCIuL2Nsc3MtZHJvcGRvd25cIlxyXG5pbXBvcnQgeyBCdXR0b24gfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCB7IFBsdXNDaXJjbGVPdXRsaW5lZCB9IGZyb20gXCJqaW11LWljb25zL291dGxpbmVkL2VkaXRvci9wbHVzLWNpcmNsZVwiXHJcbmltcG9ydCB7IGRlbGV0ZU9yZ2FuaXphdGlvbiwgZGlzcGF0Y2hBY3Rpb24gfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGlcIlxyXG5pbXBvcnQgeyBPcmdhbml6YXRpb24gfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zXCJcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlXCJcclxuXHJcblxyXG5leHBvcnQgY29uc3QgT3JnYW5pemF0aW9uc0Ryb3Bkb3duID0oe2NvbmZpZywgb3JnYW5pemF0aW9ucywgc2VsZWN0ZWRPcmdhbml6YXRpb24sIFxyXG4gICAgc2V0T3JnYW5pemF0aW9uLCB2ZXJ0aWNhbCwgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWx9KT0+e1xyXG5cclxuICAgIGNvbnN0IFtsb2NhbE9yZ2FuaXphdGlvbnMsIHNldExvY2FsT3JnYW5pemF0aW9uc10gPSBSZWFjdC51c2VTdGF0ZTxPcmdhbml6YXRpb25bXT4oW10pO1xyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICAgIGlmKG9yZ2FuaXphdGlvbnMpeyBcclxuICAgICAgICAgICAgc2V0TG9jYWxPcmdhbml6YXRpb25zKFsuLi5vcmdhbml6YXRpb25zXSBhcyBPcmdhbml6YXRpb25bXSlcclxuICAgICAgICB9XHJcbiAgICB9LCBbb3JnYW5pemF0aW9uc10pXHJcbiAgICBcclxuICAgIGNvbnN0IHJlbW92ZU9yZ2FuaXphdGlvbiA9YXN5bmMgKG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uKT0+e1xyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZU9yZ2FuaXphdGlvbihvcmdhbml6YXRpb24sIGNvbmZpZyk7XHJcbiAgICAgIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICAgICBjb25zb2xlLmxvZyhyZXNwb25zZS5lcnJvcnMpO1xyXG4gICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgcmVzcG9uc2UuZXJyb3JzKTtcclxuICAgICAgIHJldHVybjtcclxuICAgICAgfVxyXG4gICAgICBjb25zb2xlLmxvZyhgJHtvcmdhbml6YXRpb24udGl0bGV9IGRlbGV0ZWRgKVxyXG4gICAgICBzZXRMb2NhbE9yZ2FuaXphdGlvbnMoWy4uLmxvY2FsT3JnYW5pemF0aW9ucy5maWx0ZXIobyA9PiBvLmlkICE9PSBvcmdhbml6YXRpb24uaWQpXSk7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxkaXYgc3R5bGU9e3tkaXNwbGF5OiB2ZXJ0aWNhbCA/ICdibG9jayc6ICdmbGV4JyxcclxuICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcid9fT5cclxuICAgICAgICAgICAgIDxDbHNzRHJvcGRvd24gaXRlbXM9e2xvY2FsT3JnYW5pemF0aW9uc31cclxuICAgICAgICAgICAgICAgIGl0ZW09e3NlbGVjdGVkT3JnYW5pemF0aW9ufSBcclxuICAgICAgICAgICAgICAgIGRlbGV0YWJsZT17dHJ1ZX1cclxuICAgICAgICAgICAgICAgIHNldEl0ZW09e3NldE9yZ2FuaXphdGlvbn0gXHJcbiAgICAgICAgICAgICAgICBkZWxldGVJdGVtPXtyZW1vdmVPcmdhbml6YXRpb259Lz5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICB0b2dnbGVOZXdPcmdhbml6YXRpb25Nb2RhbCA/IChcclxuICAgICAgICAgICAgICAgIHZlcnRpY2FsPyAoXHJcbiAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBkYXRhLXRlc3RpZD1cImJ0blNob3dBZGRPcmdhbml6YXRpb25cIiAgY2xhc3NOYW1lPVwiIGFkZC1saW5rXCJcclxuICAgICAgICAgICAgICAgICAgICAgICAgIHR5cGU9XCJsaW5rXCIgc3R5bGU9e3t0ZXh0QWxpZ246ICdsZWZ0J319XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpPT4gdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWwodHJ1ZSl9PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICBBZGQgTmV3IE9yZ2FuaXphdGlvblxyXG4gICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgICAgKTooXHJcbiAgICAgICAgICAgICAgICAgICAgPFBsdXNDaXJjbGVPdXRsaW5lZCBjbGFzc05hbWU9XCJhY3Rpb24taWNvblwiIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICBkYXRhLXRlc3RpZD1cImJ0bkFkZE5ld09yZ2FuaXphdGlvblwiIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICB0aXRsZT1cIkFkZCBOZXcgT3JnYW5pemF0aW9uXCIgc2l6ZT17MzB9IGNvbG9yPXsnZ3JheSd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2xpY2s9eygpPT4gdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWwodHJ1ZSl9Lz4gICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICk6IG51bGxcclxuICAgICAgICAgICAgfSAgIFxyXG4gICAgICAgIDwvZGl2PlxyXG4gICAgKVxyXG59IiwiaW1wb3J0IHsgVGV4dElucHV0IH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuXHJcbmV4cG9ydCBjb25zdCBDTFNTU2VhcmNoSW5wdXQgPSAoe3RpdGxlLCBvbkNoYW5nZSwgZGVmYXVsdFZhbHVlLCBwcm9wc306XHJcbiAgICB7dGl0bGU6IHN0cmluZywgb25DaGFuZ2U6IEZ1bmN0aW9uLCBkZWZhdWx0VmFsdWU/OiBzdHJpbmcsIHByb3BzOiBhbnl9KSA9PiB7ICAgXHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxoNCBzdHlsZT17e1xyXG4gICAgICAgICAgICB3aWR0aDogJzEwMCUnICAgIFxyXG4gICAgICAgICAgfX0+XHJcbiAgICAgICAge3RpdGxlfTpcclxuICAgICAgICA8VGV4dElucHV0IHN0eWxlPXt7Zm9udFNpemU6IHByb3BzLnRoZW1lLnR5cG9ncmFwaHkuc2l6ZXMuZGlzcGxheTR9fSAgXHJcbiAgICAgICAgICAgIGRhdGEtdGVzdGlkPSd0ZW1wbGF0ZVNlYXJjaElucHV0JyAgICAgICAgIFxyXG4gICAgICAgICAgICBwbGFjZWhvbGRlcj0nU2VhcmNoLi4uJ1xyXG4gICAgICAgICAgICBzaXplPSdsZydcclxuICAgICAgICAgICAgYWxsb3dDbGVhclxyXG4gICAgICAgICAgICB0eXBlPVwidGV4dFwiXHJcbiAgICAgICAgICAgIHZhbHVlPXtkZWZhdWx0VmFsdWV9XHJcbiAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSkgPT4gb25DaGFuZ2UoZS50YXJnZXQudmFsdWUpfSAgICAgICAgICBcclxuICAgICAgICAgICAgey4uLnByb3BzfS8+XHJcbiAgICAgICAgPC9oND5cclxuICAgIClcclxufSIsImltcG9ydCB7IFNldHRpbmdPdXRsaW5lZCB9IGZyb20gJ2ppbXUtaWNvbnMvb3V0bGluZWQvYXBwbGljYXRpb24vc2V0dGluZyc7XHJcbmltcG9ydCB7IFN1Y2Nlc3NPdXRsaW5lZCB9IGZyb20gJ2ppbXUtaWNvbnMvb3V0bGluZWQvc3VnZ2VzdGVkL3N1Y2Nlc3MnO1xyXG5pbXBvcnQgeyBMYWJlbCB9IGZyb20gJ2ppbXUtdWknO1xyXG5pbXBvcnQgUmVhY3QgZnJvbSAncmVhY3QnO1xyXG5pbXBvcnQgeyBCQVNFTElORV9URU1QTEFURV9OQU1FLCBDTFNTX0FETUlOIH0gZnJvbSAnLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jb25zdGFudHMnO1xyXG5pbXBvcnQgeyBDTFNTVGVtcGxhdGUgfSBmcm9tICcuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnMnO1xyXG5pbXBvcnQgeyBGb2xkZXJPdXRsaW5lZCB9IGZyb20gJ2ppbXUtaWNvbnMvb3V0bGluZWQvYXBwbGljYXRpb24vZm9sZGVyJ1xyXG5cclxuZXhwb3J0IGNvbnN0IFRlbXBsYXRlQnV0dG9uID0oe3RlbXBsYXRlLCBvbkNsaWNrLCBvbkRibENsaWNrLCBwcm9wc306XHJcbiAgICB7dGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgb25DbGljazogYW55LCBvbkRibENsaWNrOiBhbnksIHByb3BzOiBhbnl9KT0+IHsgIFxyXG5cclxuICAgIGNvbnN0IG9uRG91YmxlQ2xpY2s9KCk9PntcclxuICAgICAgICAvLyBpZihwcm9wcy51c2VyLmdyb3Vwcy5maW5kKGcgPT4gZy50aXRsZSA9PT0gQ0xTU19BRE1JTikgJiZcclxuICAgICAgICAvLyB0ZW1wbGF0ZS5uYW1lICE9PSBCQVNFTElORV9URU1QTEFURV9OQU1FKXtcclxuXHJcbiAgICAgICAgLy8gICAgIGlmKGNvbmZpcm0oJ0FyY2hpdmUgdGhlIHRlbXBsYXRlPycpID09IHRydWUpe1xyXG4gICAgICAgIC8vICAgICAgICAgb25EYmxDbGljayh0ZW1wbGF0ZS5vYmplY3RJZCk7XHJcbiAgICAgICAgLy8gICAgIH1cclxuICAgICAgICAvLyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxkaXYgZGF0YS10ZXN0aWQ9XCJ0ZW1wbGF0ZUJ1dHRvblwiIGNsYXNzTmFtZT1cImJ1dHRvbi13cmFwcGVyXCIgXHJcbiAgICAgICAgb25Eb3VibGVDbGljaz17b25Eb3VibGVDbGlja30gb25DbGljaz17KCkgPT4gb25DbGljayh0ZW1wbGF0ZS5vYmplY3RJZCl9XHJcbiAgICAgICAgICAgIHN0eWxlPXt7XHJcbiAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZENvbG9yOih0ZW1wbGF0ZS5pc1NlbGVjdGVkIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA/IHByb3BzLmNvbmZpZy5zZWxlY3RlZEJ1dHRvbkJhY2tncm91bmRDb2xvclxyXG4gICAgICAgICAgICAgICAgICAgICAgICA6IHByb3BzLmNvbmZpZy5kZWZhdWx0QnV0dG9uQmFja2dyb3VuZENvbG9yKVxyXG4gICAgICAgICAgICAgICAgICAgfX0+XHJcbiAgICAgICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICAgIHtgXHJcbiAgICAgICAgICAgICAgICAgICAgLmJ1dHRvbi13cmFwcGVye1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBib3JkZXItcmFkaXVzOiAxMHB4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAxNXB4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBwYWRkaW5nOiAxMHB4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjtcclxuICAgICAgICAgICAgICAgICAgICAgICAgbWFyZ2luOiA1cHggMDtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgLmJ1dHRvbi13cmFwcGVyOmhvdmVye1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBvcGFjaXR5OiAwLjU7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIC5idXR0b24tY29udGVudHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICAgICAganVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgIC5idXR0b24tbGFiZWx7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjsgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDE4MHB4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB3aGl0ZS1zcGFjZTogbm93cmFwO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBvdmVyZmxvdzogaGlkZGVuO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpcztcclxuICAgICAgICAgICAgICAgICAgICAgICAgbWFyZ2luLWJvdHRvbTogMCAhaW1wb3J0YW50O1xyXG4gICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAucHJlLWljb257XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG1hcmdpbi1yaWdodDogMTBweDtcclxuICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICBgfVxyXG4gICAgICAgICAgICAgICAgPC9zdHlsZT5cclxuICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJidXR0b24tY29udGVudFwiPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIHRlbXBsYXRlPy5zdGF0dXM/LmNvZGUgPT09IDEgPyAoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDxTZXR0aW5nT3V0bGluZWQgY2xhc3NOYW1lPSdwcmUtaWNvbicgc2l6ZT17MjB9IGNvbG9yPXtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRlbXBsYXRlLmlzU2VsZWN0ZWQgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA/IHByb3BzLmNvbmZpZy5zZWxlY3RlZEJ1dHRvbkNvbG9yXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA6ICdncmF5J30gLz5cclxuICAgICAgICAgICAgICAgICAgICApOiBcclxuICAgICAgICAgICAgICAgICAgICAoXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDxGb2xkZXJPdXRsaW5lZCBjbGFzc05hbWU9J3ByZS1pY29uJyBzaXplPXsxNX0gY29sb3I9e1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGVtcGxhdGUuaXNTZWxlY3RlZCBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgID8gcHJvcHMuY29uZmlnLnNlbGVjdGVkQnV0dG9uQ29sb3JcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogJ2dyYXknfSAvPlxyXG4gICAgICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPExhYmVsIHN0eWxlPXt7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbG9yOiB0ZW1wbGF0ZS5pc1NlbGVjdGVkIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA/IHByb3BzLmNvbmZpZy5zZWxlY3RlZEJ1dHRvbkNvbG9yIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA6IHByb3BzLmNvbmZpZy5kZWZhdWx0VGVtcGxhdGVCdXR0b25Db2xvclxyXG4gICAgICAgICAgICAgICAgICAgIH19IGNsYXNzTmFtZT0nYnV0dG9uLWxhYmVsJz57dGVtcGxhdGUubmFtZX08L0xhYmVsPlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdGVtcGxhdGUuaXNTZWxlY3RlZCA/ICA8U3VjY2Vzc091dGxpbmVkIGNsYXNzTmFtZT0ncG9zdC1pY29uJyBzaXplPXsyMH0gY29sb3I9e3Byb3BzLmNvbmZpZy5zZWxlY3RlZEJ1dHRvbkNvbG9yfS8+IDogbnVsbFxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1kcm9wZG93blwiXHJcblxyXG5cclxuZXhwb3J0IGNvbnN0IFRlbXBsYXRlc0Ryb3Bkb3duID0oe3RlbXBsYXRlcywgc2VsZWN0ZWRUZW1wbGF0ZSwgc2V0VGVtcGxhdGV9KT0+e1xyXG4gICAgXHJcbiAgICBjb25zdCBkZWxldGVUZW1wbGF0ZSA9KCk9PntcclxuICAgICAgICBcclxuICAgIH1cclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPENsc3NEcm9wZG93biBpdGVtcz17dGVtcGxhdGVzfVxyXG4gICAgICAgICAgICBpdGVtPXtzZWxlY3RlZFRlbXBsYXRlfSBcclxuICAgICAgICAgICAgZGVsZXRhYmxlPXt0cnVlfVxyXG4gICAgICAgICAgICBzZXRJdGVtPXtzZXRUZW1wbGF0ZX0gXHJcbiAgICAgICAgICAgIGRlbGV0ZUl0ZW09e2RlbGV0ZVRlbXBsYXRlfS8+XHJcbiAgICApXHJcbn0iLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV9hcmNnaXNfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV9jb3JlX187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX3JlYWN0X187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX2ppbXVfdWlfXzsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdKG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiLy8gZ2V0RGVmYXVsdEV4cG9ydCBmdW5jdGlvbiBmb3IgY29tcGF0aWJpbGl0eSB3aXRoIG5vbi1oYXJtb255IG1vZHVsZXNcbl9fd2VicGFja19yZXF1aXJlX18ubiA9IChtb2R1bGUpID0+IHtcblx0dmFyIGdldHRlciA9IG1vZHVsZSAmJiBtb2R1bGUuX19lc01vZHVsZSA/XG5cdFx0KCkgPT4gKG1vZHVsZVsnZGVmYXVsdCddKSA6XG5cdFx0KCkgPT4gKG1vZHVsZSk7XG5cdF9fd2VicGFja19yZXF1aXJlX18uZChnZXR0ZXIsIHsgYTogZ2V0dGVyIH0pO1xuXHRyZXR1cm4gZ2V0dGVyO1xufTsiLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5wID0gXCJcIjsiLCIvKipcclxuICogV2VicGFjayB3aWxsIHJlcGxhY2UgX193ZWJwYWNrX3B1YmxpY19wYXRoX18gd2l0aCBfX3dlYnBhY2tfcmVxdWlyZV9fLnAgdG8gc2V0IHRoZSBwdWJsaWMgcGF0aCBkeW5hbWljYWxseS5cclxuICogVGhlIHJlYXNvbiB3aHkgd2UgY2FuJ3Qgc2V0IHRoZSBwdWJsaWNQYXRoIGluIHdlYnBhY2sgY29uZmlnIGlzOiB3ZSBjaGFuZ2UgdGhlIHB1YmxpY1BhdGggd2hlbiBkb3dubG9hZC5cclxuICogKi9cclxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lXHJcbi8vIEB0cy1pZ25vcmVcclxuX193ZWJwYWNrX3B1YmxpY19wYXRoX18gPSB3aW5kb3cuamltdUNvbmZpZy5iYXNlVXJsXHJcbiIsIlxyXG5pbXBvcnQgeyBSZWFjdCwgQWxsV2lkZ2V0UHJvcHMsIFJlYWN0UmVkdXggIH0gZnJvbSAnamltdS1jb3JlJztcclxuaW1wb3J0IHsgQnV0dG9uLCBcclxuICBDaGVja2JveCwgXHJcbiAgTGFiZWwgfSBmcm9tICdqaW11LXVpJztcclxuaW1wb3J0IHtDTFNTU2VhcmNoSW5wdXR9IGZyb20gJy4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1zZWFyY2gtdGVtcGxhdGUnO1xyXG5pbXBvcnQgeyBUZW1wbGF0ZUJ1dHRvbiB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy10ZW1wbGF0ZS1idXR0b24nO1xyXG5pbXBvcnQgQ2xzc0xvYWRpbmcgZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWxvYWRpbmcnO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZSc7XHJcbmltcG9ydCB7IGRpc3BhdGNoQWN0aW9uLCBcclxuICBnZXRIYXphcmRzLCBcclxuICBnZXRPcmdhbml6YXRpb25zLCBcclxuICBnZXRUZW1wbGF0ZXMsIFxyXG4gIGluaXRpYWxpemVBdXRofSBmcm9tICcuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaSc7XHJcbmltcG9ydCB7IENMU1NUZW1wbGF0ZSwgQ0xTU19TdGF0ZSwgQ2xzc1VzZXIsIEhhemFyZCwgT3JnYW5pemF0aW9uIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zJztcclxuaW1wb3J0IHsgQ0xTU19BRE1JTiwgQ0xTU19FRElUT1IsIENMU1NfRk9MTE9XRVJTLCBERUZBVUxUX0xJU1RJVEVNIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jb25zdGFudHMnO1xyXG5pbXBvcnQgeyBBZGRUZW1wbGF0ZVdpZGdldCB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1hZGQtdGVtcGxhdGUnO1xyXG5pbXBvcnQgeyBBZGRPcmdhbml6YXRvbldpZGdldCB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1hZGQtb3JnYW5pemF0aW9uJztcclxuaW1wb3J0IHsgQWRkSGF6YXJkV2lkZ2V0IH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFkZC1oYXphcmQnO1xyXG5pbXBvcnQgeyBJTUNvbmZpZyB9IGZyb20gJy4uL2NvbmZpZyc7XHJcbmltcG9ydCB7IHBhcnNlRGF0ZSwgc29ydE9iamVjdCB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvdXRpbHMnO1xyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuY29uc3QgV2lkZ2V0ID0gKHByb3BzOiBBbGxXaWRnZXRQcm9wczxJTUNvbmZpZz4pID0+IHtcclxuICBcclxuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7XHJcbiAgY29uc3QgW2lzQWRkVGVtcGxhdGVNb2RhbFZpc2libGUsIHNldEFkZFRlbXBsYXRlTW9kYWxWaXNpYmlsaXR5XSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICBjb25zdCBbaXNBZGRPcmdhbml6YXRpb25Nb2RhbFZpc2libGUsIHNldEFkZE9yZ2FuaXphdGlvbk1vZGFsVmlzaWJpbGl0eV0gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7XHJcbiAgY29uc3QgW2lzQWRkSGF6YXJkTW9kYWxWaXNpYmxlLCBzZXRBZGRIYXphcmRNb2RhbFZpc2liaWxpdHldID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gIGNvbnN0IFtzZWxlY3RlZEhhemFyZCwgc2V0U2VsZWN0ZWRIYXphcmRdPVJlYWN0LnVzZVN0YXRlPEhhemFyZD4obnVsbCk7XHJcbiAgY29uc3QgW3NlbGVjdGVkT3JnYW5pemF0aW9uLCBzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbl09UmVhY3QudXNlU3RhdGU8T3JnYW5pemF0aW9uPihudWxsKTtcclxuICBjb25zdCBbc2VhcmNoUmVzdWx0LCBzZXRTZWFyY2hSZXN1bHRzXSA9IFJlYWN0LnVzZVN0YXRlPENMU1NUZW1wbGF0ZVtdPihbXSlcclxuICBjb25zdCBbY29uZmlnLCBzZXRDb25maWddID0gUmVhY3QudXNlU3RhdGUobnVsbClcclxuICBjb25zdFtzZWxlY3RlZEZpbHRlciwgc2V0U2VsZWN0ZWRGaWx0ZXJdID0gUmVhY3QudXNlU3RhdGUoJ0FsbCcpXHJcbiAgY29uc3Rbc2VhcmNoVGV4dCwgc2V0U2VhcmNoVGV4dF0gPSBSZWFjdC51c2VTdGF0ZSgnJylcclxuXHJcbiAgY29uc3Qgc3RhdGUgPSAgdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGUgYXMgQ0xTU19TdGF0ZTtcclxuICB9KVxyXG5cclxuICBjb25zdCB1c2VyID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy51c2VyIGFzIENsc3NVc2VyO1xyXG4gIH0pXHJcblxyXG4gIGNvbnN0IGNyZWRlbnRpYWwgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8uYXV0aGVudGljYXRlO1xyXG4gIH0pXHJcblxyXG4gIGNvbnN0IGVycm9ycyA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5lcnJvcnM7XHJcbiAgfSlcclxuICBcclxuICBjb25zdCB0ZW1wbGF0ZXMgPSAgdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LnRlbXBsYXRlcyBhcyBDTFNTVGVtcGxhdGVbXTtcclxuICB9KVxyXG5cclxuICBjb25zdCBoYXphcmRzID0gIHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5oYXphcmRzIGFzIEhhemFyZFtdO1xyXG4gIH0pXHJcblxyXG4gIGNvbnN0IG9yZ2FuaXphdGlvbnMgPSAgdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/Lm9yZ2FuaXphdGlvbnMgYXMgT3JnYW5pemF0aW9uW107XHJcbiAgfSlcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICBpbml0aWFsaXplQXV0aChwcm9wcy5jb25maWcuYXBwSWQpO1xyXG4gIH0sIFtdKTtcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICBpZihjb25maWcpeyAgICAgIFxyXG4gICAgICBpZighaGF6YXJkcyB8fCBoYXphcmRzLmxlbmd0aCA9PT0gMCl7XHJcbiAgICAgICAgY29uc3Qgc3RhcnQgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKTsgICAgICBcclxuICAgICAgICBnZXRIYXphcmRzKGNvbmZpZywgJzE9MScsICdjbHNzLXRlbXBsYXRlcycpXHJcbiAgICAgICAgLnRoZW4oKGhhemFyZHM6IEhhemFyZFtdKSA9PiB7ICBcclxuICAgICAgICAgICAgaWYoaGF6YXJkcyAmJiBoYXphcmRzLmxlbmd0aCA+IDApe1xyXG4gICAgICAgICAgICAgIChoYXphcmRzIGFzIGFueSkub3JkZXJCeSgnbmFtZScpXHJcbiAgICAgICAgICAgICAgaGF6YXJkcy51bnNoaWZ0KERFRkFVTFRfTElTVElURU0pXHJcbiAgICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRTX0FDVElPTiwgaGF6YXJkcyk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgY29uc29sZS5sb2coJ0hhemFyZHMgdG9vazogJyArIChuZXcgRGF0ZSgpLmdldFRpbWUoKSAtIHN0YXJ0KSArXCIgbXNcIilcclxuICAgICAgICB9KTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH0sIFtjb25maWddKVxyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgIGlmKGNvbmZpZyl7ICAgIFxyXG4gICAgICBpZighb3JnYW5pemF0aW9ucyB8fCBvcmdhbml6YXRpb25zLmxlbmd0aCA9PT0gMCkgeyAgXHJcbiAgICAgICAgY29uc3Qgc3RhcnQgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKTtcclxuICAgICAgICAgZ2V0T3JnYW5pemF0aW9ucyhjb25maWcsICcxPTEnKVxyXG4gICAgICAgICAgLnRoZW4oKG9yZ2FuaXphdGlvbnM6IE9yZ2FuaXphdGlvbltdKSA9PiB7XHJcbiAgICAgICAgICAgIGlmKG9yZ2FuaXphdGlvbnMgJiYgb3JnYW5pemF0aW9ucy5sZW5ndGggPiAwKXtcclxuICAgICAgICAgICAgICAob3JnYW5pemF0aW9ucyBhcyBhbnkpLm9yZGVyQnkoJ25hbWUnKTtcclxuICAgICAgICAgICAgICBvcmdhbml6YXRpb25zLnVuc2hpZnQoREVGQVVMVF9MSVNUSVRFTSk7XHJcbiAgICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTiwgb3JnYW5pemF0aW9ucyk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgY29uc29sZS5sb2coJ09yZ2FuaXphdGlvbnMgdG9vazogJysobmV3IERhdGUoKS5nZXRUaW1lKCkgLSBzdGFydCkrXCIgbXNcIilcclxuICAgICAgICAgIH0pXHJcbiAgICAgIH1cclxuICAgIH1cclxuICB9LCBbY29uZmlnXSlcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICBpZihjcmVkZW50aWFsKXsgXHJcbiAgICAgICBzZXRDb25maWcoey4uLiBwcm9wcy5jb25maWcsIGNyZWRlbnRpYWw6Y3JlZGVudGlhbH0pICAgICAgIFxyXG4gICAgfVxyXG4gIH0sIFtjcmVkZW50aWFsXSkgXHJcbiAgXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgIGlmKGNvbmZpZyl7ICAgICBcclxuICAgICAgbG9hZFRlbXBsYXRlcygpO1xyXG4gICB9XHJcbiAgfSwgW2NvbmZpZ10pIFxyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgaWYoZXJyb3JzKXtcclxuICAgICAgYWxlcnQoZXJyb3JzKTtcclxuICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgJycpXHJcbiAgICB9XHJcbiAgfSwgW2Vycm9yc10pXHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKT0+IHtcclxuICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9VU0VSX0FDVElPTixcclxuICAgICAge1xyXG4gICAgICAgIHVzZXJOYW1lOiBwcm9wcy51c2VyPy51c2VybmFtZSxcclxuICAgICAgICBmaXJzdE5hbWU6IHByb3BzLnVzZXI/LmZpcnN0TmFtZSxcclxuICAgICAgICBsYXN0TmFtZTpwcm9wcy51c2VyPy5sYXN0TmFtZSxcclxuICAgICAgICBncm91cHM6IHByb3BzLnVzZXI/Lmdyb3Vwcz8ubWFwKGcgPT4gZy50aXRsZSlcclxuICAgICAgfSBcclxuICAgIClcclxuICB9LCBbcHJvcHMudXNlcl0pO1xyXG4gIFxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKSA9PntcclxuICAgIGlmKHRlbXBsYXRlcyAmJiB0ZW1wbGF0ZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgIGZpbHRlclNlbGVjdGlvbkNoYW5nZShzZWxlY3RlZEZpbHRlciwgdGVtcGxhdGVzKTtcclxuICAgIH0gICAgICAgXHJcbiAgfSxbdGVtcGxhdGVzXSlcclxuIFxyXG4gIGNvbnN0IGxvYWRUZW1wbGF0ZXM9YXN5bmMgKCk9PnsgICAgIFxyXG4gICAgc2V0TG9hZGluZyh0cnVlKTsgICBcclxuICAgIFxyXG4gICAgY29uc3Qgc3RhcnQgPSBuZXcgRGF0ZSgpLmdldFRpbWUoKTtcclxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZ2V0VGVtcGxhdGVzKGNvbmZpZywgbnVsbCwgbnVsbCk7ICAgICBcclxuICAgIGNvbnNvbGUubG9nKCdUZW1wbGF0ZXMgVG9vaycsIG5ldyBEYXRlKCkuZ2V0VGltZSgpIC0gc3RhcnQpO1xyXG4gICAgc2V0TG9hZGluZyhmYWxzZSlcclxuXHJcbiAgICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCByZXNwb25zZS5lcnJvcnMpO1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9ICAgICAgXHJcbiAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5MT0FEX1RFTVBMQVRFU19BQ1RJT04sIHJlc3BvbnNlLmRhdGEpO1xyXG4gICAgYXdhaXQgZmlsdGVyU2VsZWN0aW9uQ2hhbmdlKHNlbGVjdGVkRmlsdGVyLCByZXNwb25zZS5kYXRhKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IHBlcmZvcm1TZWFyY2ggPSh0ZXh0OiBzdHJpbmcpPT57XHJcblxyXG4gICAgc2V0U2VhcmNoVGV4dCh0ZXh0KTtcclxuXHJcbiAgICBsZXQgY29waWVkVGVtcGxhdGVzID0gWy4uLnRlbXBsYXRlc107XHJcblxyXG4gICAgaWYoIXRleHQgfHwgdGV4dCA9PT0gJycgfHwgdGV4dCA9PT0gbnVsbCl7XHJcbiAgICAgIHJldHVybiBzb3J0T2JqZWN0KGNvcGllZFRlbXBsYXRlcywgJ2NyZWF0ZWREYXRlJyk7XHJcbiAgICB9ICAgIFxyXG4gICAgbGV0IHNlYXJjaFJlc3VsdHMgPSBjb3BpZWRUZW1wbGF0ZXMuZmlsdGVyKHQgPT4gXHJcbiAgICAgIHQubmFtZT8udG9Mb2NhbGVMb3dlckNhc2UoKS5pbmNsdWRlcyh0ZXh0LnRvTG9jYWxlTG93ZXJDYXNlKCkpIHx8XHJcbiAgICAgIHQub3JnYW5pemF0aW9uTmFtZT8udG9Mb2NhbGVMb3dlckNhc2UoKS5pbmNsdWRlcyh0ZXh0LnRvTG9jYWxlTG93ZXJDYXNlKCkpIHx8XHJcbiAgICAgIHQuaGF6YXJkTmFtZT8udG9Mb2NhbGVMb3dlckNhc2UoKS5pbmNsdWRlcyh0ZXh0LnRvTG9jYWxlTG93ZXJDYXNlKCkpIHx8XHJcbiAgICAgIHQuaGF6YXJkVHlwZT8udG9Mb2NhbGVMb3dlckNhc2UoKS5pbmNsdWRlcyh0ZXh0LnRvTG9jYWxlTG93ZXJDYXNlKCkpIHx8XHJcbiAgICAgIHBhcnNlRGF0ZSh0LmNyZWF0ZWREYXRlKT8uc3BsaXQoJywnKVswXS50cmltKCkgPT0gdGV4dCB8fFxyXG4gICAgICBwYXJzZURhdGUodC5jcmVhdGVkRGF0ZSk/LmluY2x1ZGVzKHRleHQpIHx8IFxyXG4gICAgICBwYXJzZURhdGUodC5lZGl0ZWREYXRlKT8uaW5jbHVkZXModGV4dCkgfHxcclxuICAgICAgcGFyc2VEYXRlKHQuZWRpdGVkRGF0ZSk/LnNwbGl0KCcsJylbMF0udHJpbSgpID09IHRleHQpO1xyXG5cclxuICAgICAgcmV0dXJuIHNvcnRPYmplY3Qoc2VhcmNoUmVzdWx0cywgJ2NyZWF0ZWREYXRlJyk7XHJcbiAgfVxyXG5cclxuICBjb25zdCBvblNlYXJjaFRlbXBsYXRlcz0odGV4dDogc3RyaW5nKT0+eyAgICAgXHJcbiAgICBmaWx0ZXJTZWxlY3Rpb25DaGFuZ2Uoc2VsZWN0ZWRGaWx0ZXIsIHBlcmZvcm1TZWFyY2godGV4dCkpO1xyXG4gIH1cclxuXHJcbiAgY29uc3Qgb25TZWxlY3RUZW1wbGF0ZT1hc3luYyAob2JqZWN0SWQ6IG51bWJlcik9PnsgXHJcbiAgICBcclxuICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLkxPQURfVEVNUExBVEVTX0FDVElPTiwgdGVtcGxhdGVzLm1hcCh0ID0+IHtcclxuICAgICAgcmV0dXJue1xyXG4gICAgICAgIC4uLnQsIFxyXG4gICAgICAgIGlzU2VsZWN0ZWQ6IHQub2JqZWN0SWQgPT09IG9iamVjdElkXHJcbiAgICAgIH1cclxuICAgIH0pKSAgICBcclxuXHJcbiAgICBpZih0ZW1wbGF0ZXMuZmluZCh0ID0+IHQub2JqZWN0SWQgPT09IG9iamVjdElkKS5zdGF0dXMuY29kZSAhPT0gMSl7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuICAgIC8vYXdhaXQgc2VsZWN0VGVtcGxhdGUob2JqZWN0SWQsIHRlbXBsYXRlcy5tYXAodCA9PiB0Lm9iamVjdElkKSwgY29uZmlnKTsgXHJcbiAgfSBcclxuXHJcbiAgY29uc3Qgb25BcmNoaXZlVGVtcGxhdGU9YXN5bmMgKG9iamVjdElkOiBudW1iZXIpPT57XHJcbiAgICAvLyBzZXRMb2FkaW5nKHRydWUpO1xyXG5cclxuICAgIC8vIGNvbnN0IHJlcyA9IGF3YWl0IGFyY2hpdmVUZW1wbGF0ZShvYmplY3RJZCwgcHJvcHMuY29uZmlnKTtcclxuICAgIC8vIGlmKCFyZXMuZXJyb3JzICYmIHJlcy5kYXRhKXtcclxuICAgIC8vICAgYXdhaXQgbG9hZFRlbXBsYXRlcygpO1xyXG4gICAgLy8gfSAgXHJcbiAgICAvLyBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IHNhdmVUZW1wbGF0ZSA9YXN5bmMgKCk9PntcclxuICAgIGF3YWl0IGxvYWRUZW1wbGF0ZXMoKTtcclxuICAgIHNldEFkZFRlbXBsYXRlTW9kYWxWaXNpYmlsaXR5KGZhbHNlKTtcclxuICB9XHJcblxyXG4gIGNvbnN0IHNlbGVjdEZpbHRlciA9KGlkOiBzdHJpbmcpPT4geyAgICBcclxuICAgIGZpbHRlclNlbGVjdGlvbkNoYW5nZShpZCwgIHBlcmZvcm1TZWFyY2goc2VhcmNoVGV4dCkpO1xyXG4gIH1cclxuXHJcbiAgY29uc3QgZmlsdGVyU2VsZWN0aW9uQ2hhbmdlID1hc3luYyAoaWQsIF90ZW1wbGF0ZXMpPT57XHJcbiAgICAgaWYoX3RlbXBsYXRlcyA9PSBudWxsKXtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgIH0gICAgIFxyXG5cclxuICAgICBzZXRTZWxlY3RlZEZpbHRlcihpZCk7XHJcblxyXG4gICAgIHN3aXRjaChpZCl7XHJcbiAgICAgIGNhc2UgJ0FsbCc6XHJcbiAgICAgICAgc2V0U2VhcmNoUmVzdWx0cyhbLi4uX3RlbXBsYXRlc10pXHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICAgIGNhc2UgJ1NlbGVjdGVkJzpcclxuICAgICAgICBzZXRTZWFyY2hSZXN1bHRzKF90ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5pc1NlbGVjdGVkKSlcclxuICAgICAgICBicmVhaztcclxuICAgICAgY2FzZSAnQWN0aXZlJzogICAgIFxyXG4gICAgICBzZXRTZWFyY2hSZXN1bHRzKF90ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5zdGF0dXMuY29kZSA9PT0gMSkpXHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICAgIGNhc2UgJ0FyY2hpdmVkJzpcclxuICAgICAgICBzZXRTZWFyY2hSZXN1bHRzKF90ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5zdGF0dXMuY29kZSA9PT0gMCkpXHJcbiAgICAgICAgYnJlYWs7XHJcbiAgICAgfVxyXG4gIH1cclxuIFxyXG4gIHJldHVybiAoXHJcbiAgICA8ZGl2IGNsYXNzTmFtZT1cIndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgamltdS13aWRnZXRcIlxyXG4gICAgICBzdHlsZT17e1xyXG4gICAgICAgIGJhY2tncm91bmRDb2xvcjogcHJvcHMudGhlbWUuc3VyZmFjZXNbMl0uYmdcclxuICAgICAgfX0+XHJcbiAgICAgIDxzdHlsZT5cclxuICAgICAgICB7YFxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXJ7ICAgICAgIFxyXG4gICAgICAgICAgICBvdmVyZmxvdzogaGlkZGVuOyBcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC5zZWFyY2gtdGVtcGxhdGVze1xyXG4gICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgIGZsZXg6IDE7XHJcbiAgICAgICAgICAgICAgcGFkZGluZy1ib3R0b206IDEwcHg7XHJcbiAgICAgICAgICAgICAgb3ZlcmZsb3cteTogYXV0bztcclxuICAgICAgICAgICAgICBvdmVyZmxvdy14OiBoaWRkZW47XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAuY2xzcy10ZW1wbGF0ZXMtaGVhZGVye1xyXG4gICAgICAgICAgICBoZWlnaHQ6IDUwcHg7XHJcbiAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgIGp1c3RpZnktY29udGVudDogY2VudGVyO1xyXG4gICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyOyAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLnRlbXBsYXRlLWJ1dHRvbnMtY29udGVudHtcclxuICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjtcclxuICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuO1xyXG4gICAgICAgICAgICBwYWRkaW5nOiAyMHB4IDEwcHg7XHJcbiAgICAgICAgICAgIGhlaWdodDogY2FsYygxMDAlIC0gNTBweCk7XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmNyZWF0ZS1hc3Nlc3NtZW50LWJ1dHRvbnsgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgaGVpZ2h0OiA2NXB4O1xyXG4gICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgZm9udC13ZWlnaHQ6IGJvbGQ7XHJcbiAgICAgICAgICAgIGZvbnQtc2l6ZTogMS41ZW07XHJcbiAgICAgICAgICAgIGJvcmRlci1yYWRpdXM6IDVweDtcclxuICAgICAgICAgICAgbGluZS1oZWlnaHQ6IDEuNWVtO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmNyZWF0ZS1hc3Nlc3NtZW50LWJ1dHRvbjpob3ZlcntcclxuICAgICAgICAgICAgICBvcGFjaXR5OiAwLjhcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC5jcmVhdGUtbmV3LXRlbXBsYXRle1xyXG4gICAgICAgICAgICBoZWlnaHQ6IDUwcHg7XHJcbiAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmNyZWF0ZS1uZXctdGVtcGxhdGU6aG92ZXJ7XHJcbiAgICAgICAgICAgIG9wYWNpdHk6IC44XHJcbiAgICAgICAgICB9ICAgICAgICAgIFxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgLmVkaXRvci1pY29ueyAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIGNvbG9yOiAjNTM0YzRjO1xyXG4gICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgIG1hcmdpbjogMTBweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5lZGl0b3ItaWNvbjpob3ZlcntcclxuICAgICAgICAgICAgb3BhY2l0eTogLjhcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5zYXZlLWNhbmNlbCwgXHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuc2F2ZS1pY29ue1xyXG4gICAgICAgICAgICBwb3NpdGlvbjogYWJzb2x1dGU7XHJcbiAgICAgICAgICAgIHJpZ2h0OiAxMHB4O1xyXG4gICAgICAgICAgICB0b3A6IDEwcHg7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuZGF0YS1kcm9wZG93biwgXHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuZGF0YS1pbnB1dHtcclxuICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuZGF0YS1kcm9wZG93biBcclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5qaW11LWRyb3Bkb3due1xyXG4gICAgICAgICAgICB3aWR0aDogMzAwcHg7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuZGF0YS1kcm9wZG93bi1tZW51e1xyXG4gICAgICAgICAgICB3aWR0aDogMzAwcHg7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuZXJyb3J7XHJcbiAgICAgICAgICAgIGNvbG9yOiByZWQ7XHJcbiAgICAgICAgICAgIGZvbnQtc2l6ZTogMTVweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIC5kcm9wZG93bi1pdGVte1xyXG4gICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS4zZW07XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAub3JnYW5pemF0aW9ue1xyXG4gICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgLmVuZC13aWRnZXR7XHJcbiAgICAgICAgICAgIG1hcmdpbi1ib3R0b206IDE1cHg7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAuZGF0YS1pbnB1dHtcclxuICAgICAgICAgICAgd2lkdGg6IDMwLjclXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciAudGl0bGUudGVtcGxhdGV7XHJcbiAgICAgICAgICAgIHdpZHRoOiAxNDJweDtcclxuICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciB0ZCBsYWJlbCwgXHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciB0ZCBpbnB1dHsgXHJcbiAgICAgICAgICAgIGZvbnQtc2l6ZTogMS41ZW07XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAud2lkZ2V0LWNsc3MtdGVtcGxhdGVzLWNvbnRhaW5lciB0ZCBsYWJlbHtcclxuICAgICAgICAgICAgd2lkdGg6IDEyOHB4O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgdGQgbGFiZWwudmFsdWV7XHJcbiAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkO1xyXG4gICAgICAgICAgICB3aWR0aDogYXV0bztcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyIHRyLnRkLXVuZGVyPnRke1xyXG4gICAgICAgICAgICBwYWRkaW5nLWJvdHRvbTogMWVtO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLndpZGdldC1jbHNzLXRlbXBsYXRlcy1jb250YWluZXIgIC50ZW1wbGF0ZS1pbnB1dCBpbnB1dHtcclxuICAgICAgICAgICAgcGFkZGluZy1sZWZ0OiAyMHB4O1xyXG4gICAgICAgICAgICBoZWlnaHQ6IDQwcHg7XHJcbiAgICAgICAgICAgIGZvbnQtc2l6ZTogMTZweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC53aWRnZXQtY2xzcy10ZW1wbGF0ZXMtY29udGFpbmVyICAudGVtcGxhdGUtaW5wdXQgc3BhbntcclxuICAgICAgICAgICAgaGVpZ2h0OiA0MHB4ICFpbXBvcnRhbnQ7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAudGVtcGxhdGUtZmlsdGVyLWFjdGlvbnMgLmFjdGlvbnN7XHJcbiAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgIGp1c3RpZnktY29udGVudDogc3BhY2UtYXJvdW5kO1xyXG4gICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLnRlbXBsYXRlLWZpbHRlci1hY3Rpb25zIC5qaW11LWNoZWNrYm94e1xyXG4gICAgICAgICAgICBtYXJnaW4tcmlnaHQ6IDEwcHg7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgYH1cclxuICAgICAgPC9zdHlsZT4gICAgICAgXHJcbiAgICAgIDxkaXYgY2xhc3NOYW1lPVwiY2xzcy10ZW1wbGF0ZXMtaGVhZGVyXCIgc3R5bGU9e3tcclxuICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogcHJvcHMuY29uZmlnLmhlYWRlckJhY2tncm91bmRDb2xvciB8fCBwcm9wcy50aGVtZS5jb2xvcnMuc2Vjb25kYXJ5LFxyXG4gICAgICAgICAgY29sb3I6IHByb3BzLmNvbmZpZy5oZWFkZXJUZXh0Q29sb3IgfHwgcHJvcHMudGhlbWUuY29sb3JzLnBhbGV0dGUucHJpbWFyeVs5MDBdLFxyXG4gICAgICAgICAgYm94U2hhZG93OiBwcm9wcy50aGVtZS5ib3hTaGFkb3dzLmRlZmF1bHQsXHJcbiAgICAgICAgICBmb250U2l6ZTogcHJvcHMudGhlbWUudHlwb2dyYXBoeS5zaXplcy5kaXNwbGF5MyxcclxuICAgICAgICAgIGZvbnRXZWlnaHQ6IHByb3BzLnRoZW1lLnR5cG9ncmFwaHkud2VpZ2h0cy5ib2xkXHJcbiAgICAgICAgfX0+XHJcbiAgICAgICAgPExhYmVsIGNoZWNrPlxyXG4gICAgICAgICAgICBUZW1wbGF0ZXNcclxuICAgICAgICA8L0xhYmVsPlxyXG4gICAgICA8L2Rpdj5cclxuICAgICAgPGRpdiBjbGFzc05hbWU9J3RlbXBsYXRlLWJ1dHRvbnMtY29udGVudCc+IFxyXG4gICAgICAgIDxkaXYgY2xhc3NOYW1lPVwidGVtcGxhdGUtZmlsdGVyLWFjdGlvbnNcIj5cclxuICAgICAgICAgICAgPGg0PlxyXG4gICAgICAgICAgICAgIEZpbHRlciB0ZW1wbGF0ZXMgYnk6XHJcbiAgICAgICAgICAgIDwvaDQ+XHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiYWN0aW9uc1wiIGFyaWEtbGFiZWw9XCJGaWx0ZXIgdGVtcGxhdGVzIGJ5XCIgIHJvbGU9XCJncm91cFwiPlxyXG4gICAgICAgICAgICAgIHsvKiA8TGFiZWwgY2VudHJpYyA+XHJcbiAgICAgICAgICAgICAgICA8Q2hlY2tib3hcclxuICAgICAgICAgICAgICAgICAgaWQ9ICdTZWxlY3RlZCdcclxuICAgICAgICAgICAgICAgICAgYXJpYS1sYWJlbD1cIkNoZWNrYm94XCJcclxuICAgICAgICAgICAgICAgICAgY2hlY2tlZD17c2VsZWN0ZWRGaWx0ZXIgPT09ICdTZWxlY3RlZCd9XHJcbiAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSk9PiBmaWx0ZXJTZWxlY3Rpb25DaGFuZ2UoZS50YXJnZXQuaWQsIHRlbXBsYXRlcyl9XHJcbiAgICAgICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICAgICAgU2VsZWN0ZWRcclxuICAgICAgICAgICAgICA8L0xhYmVsPiAqL31cclxuXHJcbiAgICAgICAgICAgICAgPExhYmVsIGNlbnRyaWMgPlxyXG4gICAgICAgICAgICAgICAgPENoZWNrYm94XHJcbiAgICAgICAgICAgICAgICAgIGlkPSAnQWxsJ1xyXG4gICAgICAgICAgICAgICAgICBhcmlhLWxhYmVsPVwiQ2hlY2tib3hcIlxyXG4gICAgICAgICAgICAgICAgICBjaGVja2VkPXtzZWxlY3RlZEZpbHRlciA9PT0gJ0FsbCd9XHJcbiAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSk9PiBzZWxlY3RGaWx0ZXIoZS50YXJnZXQuaWQpfVxyXG4gICAgICAgICAgICAgICAgLz5cclxuICAgICAgICAgICAgICAgIEFsbFxyXG4gICAgICAgICAgICAgIDwvTGFiZWw+XHJcblxyXG4gICAgICAgICAgICAgIDxMYWJlbCBjZW50cmljPlxyXG4gICAgICAgICAgICAgICAgPENoZWNrYm94XHJcbiAgICAgICAgICAgICAgICAgIGlkPSdBY3RpdmUnXHJcbiAgICAgICAgICAgICAgICAgIGFyaWEtbGFiZWw9XCJDaGVja2JveFwiXHJcbiAgICAgICAgICAgICAgICAgIGNoZWNrZWQ9e3NlbGVjdGVkRmlsdGVyID09PSAnQWN0aXZlJ31cclxuICAgICAgICAgICAgICAgICAgb25DaGFuZ2U9eyhlKT0+IHNlbGVjdEZpbHRlcihlLnRhcmdldC5pZCl9XHJcbiAgICAgICAgICAgICAgICAvPlxyXG4gICAgICAgICAgICAgICAgQWN0aXZlXHJcbiAgICAgICAgICAgICAgPC9MYWJlbD5cclxuICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICA8TGFiZWwgY2VudHJpYyBjaGVjaz5cclxuICAgICAgICAgICAgICAgIDxDaGVja2JveFxyXG4gICAgICAgICAgICAgICAgICBpZD0nQXJjaGl2ZWQnXHJcbiAgICAgICAgICAgICAgICAgIGFyaWEtbGFiZWw9XCJDaGVja2JveFwiXHJcbiAgICAgICAgICAgICAgICAgIGNoZWNrZWQ9e3NlbGVjdGVkRmlsdGVyID09PSAnQXJjaGl2ZWQnfVxyXG4gICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpPT4gc2VsZWN0RmlsdGVyKGUudGFyZ2V0LmlkKX1cclxuICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgICAgICBBcmNoaXZlZFxyXG4gICAgICAgICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgIDwvZGl2PiAgIFxyXG4gICAgICAgIDxkaXYgY2xhc3NOYW1lPSdzZWFyY2gtdGVtcGxhdGVzJz5cclxuICAgICAgICAgIDxDTFNTU2VhcmNoSW5wdXQgdGl0bGU9eydTZWFyY2ggVGVtcGxhdGVzJ30gXHJcbiAgICAgICAgICAgIG9uQ2hhbmdlPXtvblNlYXJjaFRlbXBsYXRlc30gcHJvcHM9e3Byb3BzfS8+ICAgIFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgc2VhcmNoUmVzdWx0Py5tYXAoKHRlbXA6IENMU1NUZW1wbGF0ZSkgPT4ge1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIChcclxuICAgICAgICAgICAgICAgICAgPFRlbXBsYXRlQnV0dG9uIGtleT17dGVtcC5pZH0gcHJvcHM9e3Byb3BzfVxyXG4gICAgICAgICAgICAgICAgICAgIHRlbXBsYXRlPXt0ZW1wfSBcclxuICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBvblNlbGVjdFRlbXBsYXRlKHRlbXAub2JqZWN0SWQpfSBcclxuICAgICAgICAgICAgICAgICAgICBvbkRibENsaWNrPXtvbkFyY2hpdmVUZW1wbGF0ZX0vPlxyXG4gICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgIH0gIFxyXG4gICAgICAgIDwvZGl2PiAgICAgICAgICAgXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgKHVzZXIgJiYgdXNlci5ncm91cHM/LmluY2x1ZGVzKENMU1NfQURNSU4pIHx8XHJcbiAgICAgICAgICAgIHVzZXIgJiYgdXNlci5ncm91cHM/LmluY2x1ZGVzKENMU1NfRURJVE9SKSB8fFxyXG4gICAgICAgICAgICB1c2VyICYmIHVzZXIuZ3JvdXBzPy5pbmNsdWRlcyhDTFNTX0ZPTExPV0VSUykpID9cclxuICAgICAgICAgICggPEJ1dHRvbiBkYXRhLXRlc3RpZD1cImJ0bkNyZWF0ZU5ld1RlbXBsYXRlXCIgXHJcbiAgICAgICAgICBjbGFzc05hbWU9J2NyZWF0ZS1uZXctdGVtcGxhdGUnIFxyXG4gICAgICAgICAgc3R5bGU9e3tiYWNrZ3JvdW5kOiBwcm9wcy5jb25maWcuaGVhZGVyQmFja2dyb3VuZENvbG9yfX0gXHJcbiAgICAgICAgICBzaXplPSdsZycgb25DbGljaz17KCkgPT4gc2V0QWRkVGVtcGxhdGVNb2RhbFZpc2liaWxpdHkodHJ1ZSl9PkNyZWF0ZSBUZW1wbGF0ZTwvQnV0dG9uPlxyXG4gICAgICAgICAgKTogbnVsbFxyXG4gICAgICAgIH0gIFxyXG4gICAgICAgIDxBZGRUZW1wbGF0ZVdpZGdldCAgICAgICAgICBcclxuICAgICAgICAgIGNvbmZpZz17Y29uZmlnfVxyXG4gICAgICAgICAgaGF6YXJkcz17aGF6YXJkc31cclxuICAgICAgICAgIHNlbGVjdGVkSGF6YXJkPXtzZWxlY3RlZEhhemFyZH1cclxuICAgICAgICAgIHNldEhhemFyZD17c2V0U2VsZWN0ZWRIYXphcmR9XHJcbiAgICAgICAgICBzZWxlY3RlZE9yZ2FuaXphdGlvbj17c2VsZWN0ZWRPcmdhbml6YXRpb259XHJcbiAgICAgICAgICBvcmdhbml6YXRpb25zPXtvcmdhbml6YXRpb25zfVxyXG4gICAgICAgICAgc2V0T3JnYW5pemF0aW9uPXtzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbn1cclxuICAgICAgICAgIHRlbXBsYXRlcz17dGVtcGxhdGVzfVxyXG4gICAgICAgICAgdXNlcj17dXNlcn0gICAgICAgICAgXHJcbiAgICAgICAgICB2aXNpYmxlPXtpc0FkZFRlbXBsYXRlTW9kYWxWaXNpYmxlfVxyXG4gICAgICAgICAgdG9nZ2xlVmlzaWJpbGl0eT17c2V0QWRkVGVtcGxhdGVNb2RhbFZpc2liaWxpdHl9XHJcbiAgICAgICAgICBzYXZlVGVtcGxhdGVDb21wbGV0ZUNhbGxiYWNrPXtzYXZlVGVtcGxhdGV9XHJcbiAgICAgICAgICB0b2dnbGVOZXdIYXphcmRNb2RhbD17c2V0QWRkSGF6YXJkTW9kYWxWaXNpYmlsaXR5fVxyXG4gICAgICAgICAgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWw9e3NldEFkZE9yZ2FuaXphdGlvbk1vZGFsVmlzaWJpbGl0eX0vPiBcclxuXHJcbiAgICAgICAgPEFkZE9yZ2FuaXphdG9uV2lkZ2V0IFxyXG4gICAgICAgICAgcHJvcHNDb25maWc9e3Byb3BzPy5jb25maWd9XHJcbiAgICAgICAgICB2aXNpYmxlPXtpc0FkZE9yZ2FuaXphdGlvbk1vZGFsVmlzaWJsZX1cclxuICAgICAgICAgIHNldE9yZ2FuaXphdGlvbj17c2V0U2VsZWN0ZWRPcmdhbml6YXRpb259XHJcbiAgICAgICAgICB0b2dnbGU9e3NldEFkZE9yZ2FuaXphdGlvbk1vZGFsVmlzaWJpbGl0eX0vPiBcclxuXHJcbiAgICAgICAgPEFkZEhhemFyZFdpZGdldCBcclxuICAgICAgICAgIHByb3BzPXtwcm9wc31cclxuICAgICAgICAgIHZpc2libGU9e2lzQWRkSGF6YXJkTW9kYWxWaXNpYmxlfVxyXG4gICAgICAgICAgc2V0SGF6YXJkPXtzZXRTZWxlY3RlZEhhemFyZH1cclxuICAgICAgICAgIHRvZ2dsZT17c2V0QWRkSGF6YXJkTW9kYWxWaXNpYmlsaXR5fS8+XHJcbiAgICAgIDwvZGl2PiBcclxuICAgICAge1xyXG4gICAgICAgIGxvYWRpbmcgPyA8Q2xzc0xvYWRpbmcvPjogbnVsbFxyXG4gICAgICB9ICAgIFxyXG4gICAgPC9kaXY+XHJcbiAgKVxyXG59XHJcbmV4cG9ydCBkZWZhdWx0IFdpZGdldFxyXG5cclxuXHJcbiJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==