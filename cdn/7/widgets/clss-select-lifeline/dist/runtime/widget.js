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
/*!*****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-select-lifeline/src/runtime/widget.tsx ***!
  \*****************************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");




const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_0__.ReactRedux;
function useWindowSize() {
    const [size, setSize] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState([0, 0]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useLayoutEffect(() => {
        function updateSize() {
            setSize([window.innerWidth, window.innerHeight]);
        }
        window.addEventListener('resize', updateSize);
        updateSize();
        return () => window.removeEventListener('resize', updateSize);
    }, []);
    return size;
}
const Widget = (props) => {
    // const [width, height] = useWindowSize();
    const [lifelineStatuses, setLifelineStatuses] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState([]);
    const [selectedLifelineStatus, setSelectedLifelineStatus] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const selectedAssessment = useSelector((state) => {
        var _a, _b, _c, _d;
        if (((_a = state.clssState) === null || _a === void 0 ? void 0 : _a.assessments) && ((_b = state.clssState) === null || _b === void 0 ? void 0 : _b.assessments.length) > 0) {
            return (_d = (_c = state.clssState) === null || _c === void 0 ? void 0 : _c.assessments) === null || _d === void 0 ? void 0 : _d.find(a => a.isSelected);
        }
    });
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (selectedAssessment) {
            setLifelineStatuses((selectedAssessment === null || selectedAssessment === void 0 ? void 0 : selectedAssessment.lifelineStatuses).orderBy('lifelineName'));
        }
    }, [selectedAssessment]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (lifelineStatuses) {
            selectLifelineStatus(lifelineStatuses[0]);
        }
    }, [lifelineStatuses]);
    const selectLifelineStatus = (lifelineStatus) => {
        setSelectedLifelineStatus(lifelineStatus);
        (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__.CLSSActionKeys.SELECT_LIFELINESTATUS_ACTION, lifelineStatus);
    };
    if (!lifelineStatuses || lifelineStatuses.length == 0) {
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h5", { style: { position: 'absolute', left: '40%', top: '50%' } }, "No Data");
    }
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-select-lifelines jimu-widget" },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
            .widget-select-lifelines{
              width: 100%;
              height: 100%;
              padding: 10px;
            }
            .select-lifeline-container{
               width: 100%;
               height: 100%;
               display: flex;
               flex-direction: column;
               align-items: center;
               border-radius: 10px;
               overflow-y: auto;
               overflow-x: hidden;
            }
            .lifelines-header{
              width: 100%;
              display: flex;
              justify-content: center;
              align-items: center;
              padding: 10px 0;
              font-size: 1.2rem;
              font-weight: bold;              
              border-radius: 10px 10px 0 0;
            }
            .lifeline{
              width: 100%;
              cursor: pointer;            
              text-align: center;
              font-size: 2.5em;
              padding: 0.2em 0
            }
            .lifeline:hover{
              opacity: 0.5;
            }
            .lifeline label{
              cursor: pointer;
            }
            .back-templates-button{    
              position: absolute;
              bottom: 10px;
              left: 0;           
              height: 65px;
              width: 85%;
              font-weight: bold;
              font-size: 1.5em;
              border-radius: 5px;
              line-height: 1.5em;
              margin: 10px 18px 10px 18px;
            }
            .back-templates-button:hover{
               opacity: 0.8
            }
            .selected-assessment{
              display: flex;
              flex-direction: column;
              width: 100%;
              align-items: center;
              margin-top: 5em;
              color: #9a9a9a;
              border-top: 1px solid;
              padding-top: 20px;
            }
            .selected-assessment h2,
            .selected-assessment h3,
            .selected-assessment-top h2,
            .selected-assessment-top h3 {
              color: #9a9a9a;
              margin: 0;
            }
            .selected-assessment-top{
              color: #9a9a9a;
              margin: 0;
              display: flex;
              flex-direction: column;
              width: 100%;
              align-items: center;   
              border-bottom: 1px solid;
              padding-top: 20px;
            }
           `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "select-lifeline-container", style: {
                backgroundColor: props.config.backgroundColor
            } },
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { check: true, className: 'lifelines-header', style: { backgroundColor: props.config.backgroundColor,
                    color: props.config.fontColor } }, "Assessment"),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("h2", { style: {
                    color: 'rgb(139, 139, 139)',
                    marginTop: '-15px',
                    fontSize: '21px'
                } }, selectedAssessment === null || selectedAssessment === void 0 ? void 0 : selectedAssessment.name),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { check: true, className: 'lifelines-header', style: { backgroundColor: props.config.backgroundColor,
                    color: props.config.fontColor, borderTop: '1px solid white' } }, "Lifelines"), lifelineStatuses === null || lifelineStatuses === void 0 ? void 0 :
            lifelineStatuses.map((lifelineStatus) => {
                return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'lifeline', key: lifelineStatus.id, style: {
                        backgroundColor: (selectedLifelineStatus === null || selectedLifelineStatus === void 0 ? void 0 : selectedLifelineStatus.id) === lifelineStatus.id ? props.config.selectedBackgroundColor : 'transparent'
                    }, onClick: () => selectLifelineStatus(lifelineStatus) },
                    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { size: 'lg', style: { color: props.config.fontColor } }, lifelineStatus.lifelineName)));
            }))));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Widget);

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXNlbGVjdC1saWZlbGluZS9kaXN0L3J1bnRpbWUvd2lkZ2V0LmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQ0E7QUFDaUM7QUFDcUY7QUFDckU7QUFDTjtBQUN5QjtBQUNWO0FBQzFEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVksY0FBYztBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGNBQWMsbUVBQVE7QUFDdEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQixlQUFlO0FBQ2pDO0FBQ0E7QUFDQTtB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QUMsdUJBQXVCLENBQUMsQ0FBQyxDQUFDLGFBQWE7cUJBQ3ZILEVBQUUsT0FBTyxFQUFFLEdBQUcsRUFBRSxDQUFDLG9CQUFvQixDQUFDLGNBQWMsQ0FBQztvQkFDbEQsMkRBQUMsMENBQUssSUFBQyxJQUFJLEVBQUMsSUFBSSxFQUFDLEtBQUssRUFBRSxFQUFDLEtBQUssRUFBRSxLQUFLLENBQUMsTUFBTSxDQUFDLFNBQVMsRUFBQyxJQUNwRCxjQUFjLENBQUMsWUFBWSxDQUN0QixDQUNOLENBQ1Q7WUFDSCxDQUFDLENBQUMsQ0FFQSxDQUNGLENBQ1A7QUFDSCxDQUFDO0FBQ0QsaUVBQWUsTUFBTSIsInNvdXJjZXMiOlsid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9Vc2VyU2Vzc2lvbi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vZmVkZXJhdGlvbi11dGlscy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vZmV0Y2gtdG9rZW4uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL2dlbmVyYXRlLXRva2VuLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS92YWxpZGF0ZS1hcHAtYWNjZXNzLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9ub2RlX21vZHVsZXMvdHNsaWIvdHNsaWIuZXM2LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9hZGQuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL2RlbGV0ZS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vcXVlcnkuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL3F1ZXJ5UmVsYXRlZC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vdXBkYXRlLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9ub2RlX21vZHVsZXMvdHNsaWIvdHNsaWIuZXM2LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS9yZXF1ZXN0LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9BcmNHSVNSZXF1ZXN0RXJyb3IuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2FwcGVuZC1jdXN0b20tcGFyYW1zLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy9jbGVhbi11cmwuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2RlY29kZS1xdWVyeS1zdHJpbmcuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2VuY29kZS1mb3JtLWRhdGEuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2VuY29kZS1xdWVyeS1zdHJpbmcuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL3Byb2Nlc3MtcGFyYW1zLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9kaXN0L2VzbS91dGlscy93YXJuLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdC9ub2RlX21vZHVsZXMvdHNsaWIvdHNsaWIuZXM2LmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaS50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hdXRoLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmUudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY29uc3RhbnRzLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2VzcmktYXBpLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2xvZ2dlci50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy91dGlscy50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtYXJjZ2lzXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LWNvcmVcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtY29yZS9yZWFjdFwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS11aVwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvZGVmaW5lIHByb3BlcnR5IGdldHRlcnMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvaGFzT3duUHJvcGVydHkgc2hvcnRoYW5kIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL21ha2UgbmFtZXNwYWNlIG9iamVjdCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9wdWJsaWNQYXRoIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWNvcmUvbGliL3NldC1wdWJsaWMtcGF0aC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1zZWxlY3QtbGlmZWxpbmUvc3JjL3J1bnRpbWUvd2lkZ2V0LnRzeCJdLCJzb3VyY2VzQ29udGVudCI6WyIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOSBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgQXJjR0lTQXV0aEVycm9yLCBjbGVhblVybCwgZW5jb2RlUXVlcnlTdHJpbmcsIGRlY29kZVF1ZXJ5U3RyaW5nLCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG5pbXBvcnQgeyBnZW5lcmF0ZVRva2VuIH0gZnJvbSBcIi4vZ2VuZXJhdGUtdG9rZW5cIjtcbmltcG9ydCB7IGZldGNoVG9rZW4gfSBmcm9tIFwiLi9mZXRjaC10b2tlblwiO1xuaW1wb3J0IHsgY2FuVXNlT25saW5lVG9rZW4sIGlzRmVkZXJhdGVkIH0gZnJvbSBcIi4vZmVkZXJhdGlvbi11dGlsc1wiO1xuaW1wb3J0IHsgdmFsaWRhdGVBcHBBY2Nlc3MgfSBmcm9tIFwiLi92YWxpZGF0ZS1hcHAtYWNjZXNzXCI7XG5mdW5jdGlvbiBkZWZlcigpIHtcbiAgICB2YXIgZGVmZXJyZWQgPSB7XG4gICAgICAgIHByb21pc2U6IG51bGwsXG4gICAgICAgIHJlc29sdmU6IG51bGwsXG4gICAgICAgIHJlamVjdDogbnVsbCxcbiAgICB9O1xuICAgIGRlZmVycmVkLnByb21pc2UgPSBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgIGRlZmVycmVkLnJlc29sdmUgPSByZXNvbHZlO1xuICAgICAgICBkZWZlcnJlZC5yZWplY3QgPSByZWplY3Q7XG4gICAgfSk7XG4gICAgcmV0dXJuIGRlZmVycmVkO1xufVxuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgVXNlclNlc3Npb24gfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1hdXRoJztcbiAqIFVzZXJTZXNzaW9uLmJlZ2luT0F1dGgyKHtcbiAqICAgLy8gcmVnaXN0ZXIgYW4gYXBwIG9mIHlvdXIgb3duIHRvIGNyZWF0ZSBhIHVuaXF1ZSBjbGllbnRJZFxuICogICBjbGllbnRJZDogXCJhYmMxMjNcIixcbiAqICAgcmVkaXJlY3RVcmk6ICdodHRwczovL3lvdXJhcHAuY29tL2F1dGhlbnRpY2F0ZS5odG1sJ1xuICogfSlcbiAqICAgLnRoZW4oc2Vzc2lvbilcbiAqIC8vIG9yXG4gKiBuZXcgVXNlclNlc3Npb24oe1xuICogICB1c2VybmFtZTogXCJqc21pdGhcIixcbiAqICAgcGFzc3dvcmQ6IFwiMTIzNDU2XCJcbiAqIH0pXG4gKiAvLyBvclxuICogVXNlclNlc3Npb24uZGVzZXJpYWxpemUoY2FjaGUpXG4gKiBgYGBcbiAqIFVzZWQgdG8gYXV0aGVudGljYXRlIGJvdGggQXJjR0lTIE9ubGluZSBhbmQgQXJjR0lTIEVudGVycHJpc2UgdXNlcnMuIGBVc2VyU2Vzc2lvbmAgaW5jbHVkZXMgaGVscGVyIG1ldGhvZHMgZm9yIFtPQXV0aCAyLjBdKC9hcmNnaXMtcmVzdC1qcy9ndWlkZXMvYnJvd3Nlci1hdXRoZW50aWNhdGlvbi8pIGluIGJvdGggYnJvd3NlciBhbmQgc2VydmVyIGFwcGxpY2F0aW9ucy5cbiAqL1xudmFyIFVzZXJTZXNzaW9uID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFVzZXJTZXNzaW9uKG9wdGlvbnMpIHtcbiAgICAgICAgdGhpcy5jbGllbnRJZCA9IG9wdGlvbnMuY2xpZW50SWQ7XG4gICAgICAgIHRoaXMuX3JlZnJlc2hUb2tlbiA9IG9wdGlvbnMucmVmcmVzaFRva2VuO1xuICAgICAgICB0aGlzLl9yZWZyZXNoVG9rZW5FeHBpcmVzID0gb3B0aW9ucy5yZWZyZXNoVG9rZW5FeHBpcmVzO1xuICAgICAgICB0aGlzLnVzZXJuYW1lID0gb3B0aW9ucy51c2VybmFtZTtcbiAgICAgICAgdGhpcy5wYXNzd29yZCA9IG9wdGlvbnMucGFzc3dvcmQ7XG4gICAgICAgIHRoaXMuX3Rva2VuID0gb3B0aW9ucy50b2tlbjtcbiAgICAgICAgdGhpcy5fdG9rZW5FeHBpcmVzID0gb3B0aW9ucy50b2tlbkV4cGlyZXM7XG4gICAgICAgIHRoaXMucG9ydGFsID0gb3B0aW9ucy5wb3J0YWxcbiAgICAgICAgICAgID8gY2xlYW5Vcmwob3B0aW9ucy5wb3J0YWwpXG4gICAgICAgICAgICA6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICAgICAgdGhpcy5zc2wgPSBvcHRpb25zLnNzbDtcbiAgICAgICAgdGhpcy5wcm92aWRlciA9IG9wdGlvbnMucHJvdmlkZXIgfHwgXCJhcmNnaXNcIjtcbiAgICAgICAgdGhpcy50b2tlbkR1cmF0aW9uID0gb3B0aW9ucy50b2tlbkR1cmF0aW9uIHx8IDIwMTYwO1xuICAgICAgICB0aGlzLnJlZGlyZWN0VXJpID0gb3B0aW9ucy5yZWRpcmVjdFVyaTtcbiAgICAgICAgdGhpcy5yZWZyZXNoVG9rZW5UVEwgPSBvcHRpb25zLnJlZnJlc2hUb2tlblRUTCB8fCAyMDE2MDtcbiAgICAgICAgdGhpcy5zZXJ2ZXIgPSBvcHRpb25zLnNlcnZlcjtcbiAgICAgICAgdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzID0ge307XG4gICAgICAgIHRoaXMudHJ1c3RlZERvbWFpbnMgPSBbXTtcbiAgICAgICAgLy8gaWYgYSBub24tZmVkZXJhdGVkIHNlcnZlciB3YXMgcGFzc2VkIGV4cGxpY2l0bHksIGl0IHNob3VsZCBiZSB0cnVzdGVkLlxuICAgICAgICBpZiAob3B0aW9ucy5zZXJ2ZXIpIHtcbiAgICAgICAgICAgIC8vIGlmIHRoZSB1cmwgaW5jbHVkZXMgbW9yZSB0aGFuICcvYXJjZ2lzLycsIHRyaW0gdGhlIHJlc3RcbiAgICAgICAgICAgIHZhciByb290ID0gdGhpcy5nZXRTZXJ2ZXJSb290VXJsKG9wdGlvbnMuc2VydmVyKTtcbiAgICAgICAgICAgIHRoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XSA9IHtcbiAgICAgICAgICAgICAgICB0b2tlbjogb3B0aW9ucy50b2tlbixcbiAgICAgICAgICAgICAgICBleHBpcmVzOiBvcHRpb25zLnRva2VuRXhwaXJlcyxcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHMgPSB7fTtcbiAgICB9XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJ0b2tlblwiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgY3VycmVudCBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlIGB0b2tlbmAuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl90b2tlbjtcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwidG9rZW5FeHBpcmVzXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBleHBpcmF0aW9uIHRpbWUgb2YgdGhlIGN1cnJlbnQgYHRva2VuYC5cbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3Rva2VuRXhwaXJlcztcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwicmVmcmVzaFRva2VuXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBjdXJyZW50IHRva2VuIHRvIEFyY0dJUyBPbmxpbmUgb3IgQXJjR0lTIEVudGVycHJpc2UuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9yZWZyZXNoVG9rZW47XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInJlZnJlc2hUb2tlbkV4cGlyZXNcIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGV4cGlyYXRpb24gdGltZSBvZiB0aGUgY3VycmVudCBgcmVmcmVzaFRva2VuYC5cbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3JlZnJlc2hUb2tlbkV4cGlyZXM7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInRydXN0ZWRTZXJ2ZXJzXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIERlcHJlY2F0ZWQsIHVzZSBgZmVkZXJhdGVkU2VydmVyc2AgaW5zdGVhZC5cbiAgICAgICAgICpcbiAgICAgICAgICogQGRlcHJlY2F0ZWRcbiAgICAgICAgICovXG4gICAgICAgIGdldDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJERVBSRUNBVEVEOiB1c2UgZmVkZXJhdGVkU2VydmVycyBpbnN0ZWFkXCIpO1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZmVkZXJhdGVkU2VydmVycztcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogZmFsc2UsXG4gICAgICAgIGNvbmZpZ3VyYWJsZTogdHJ1ZVxuICAgIH0pO1xuICAgIC8qKlxuICAgICAqIEJlZ2lucyBhIG5ldyBicm93c2VyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluLiBJZiBgb3B0aW9ucy5wb3B1cGAgaXMgYHRydWVgIHRoZVxuICAgICAqIGF1dGhlbnRpY2F0aW9uIHdpbmRvdyB3aWxsIG9wZW4gaW4gYSBuZXcgdGFiL3dpbmRvdyBhbmQgdGhlIGZ1bmN0aW9uIHdpbGwgcmV0dXJuXG4gICAgICogUHJvbWlzZSZsdDtVc2VyU2Vzc2lvbiZndDsuIE90aGVyd2lzZSwgdGhlIHVzZXIgd2lsbCBiZSByZWRpcmVjdGVkIHRvIHRoZVxuICAgICAqIGF1dGhvcml6YXRpb24gcGFnZSBpbiB0aGVpciBjdXJyZW50IHRhYi93aW5kb3cgYW5kIHRoZSBmdW5jdGlvbiB3aWxsIHJldHVybiBgdW5kZWZpbmVkYC5cbiAgICAgKlxuICAgICAqIEBicm93c2VyT25seVxuICAgICAqL1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgVXNlclNlc3Npb24uYmVnaW5PQXV0aDIgPSBmdW5jdGlvbiAob3B0aW9ucywgd2luKSB7XG4gICAgICAgIGlmICh3aW4gPT09IHZvaWQgMCkgeyB3aW4gPSB3aW5kb3c7IH1cbiAgICAgICAgaWYgKG9wdGlvbnMuZHVyYXRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiREVQUkVDQVRFRDogJ2R1cmF0aW9uJyBpcyBkZXByZWNhdGVkIC0gdXNlICdleHBpcmF0aW9uJyBpbnN0ZWFkXCIpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHtcbiAgICAgICAgICAgIHBvcnRhbDogXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiLFxuICAgICAgICAgICAgcHJvdmlkZXI6IFwiYXJjZ2lzXCIsXG4gICAgICAgICAgICBleHBpcmF0aW9uOiAyMDE2MCxcbiAgICAgICAgICAgIHBvcHVwOiB0cnVlLFxuICAgICAgICAgICAgcG9wdXBXaW5kb3dGZWF0dXJlczogXCJoZWlnaHQ9NDAwLHdpZHRoPTYwMCxtZW51YmFyPW5vLGxvY2F0aW9uPXllcyxyZXNpemFibGU9eWVzLHNjcm9sbGJhcnM9eWVzLHN0YXR1cz15ZXNcIixcbiAgICAgICAgICAgIHN0YXRlOiBvcHRpb25zLmNsaWVudElkLFxuICAgICAgICAgICAgbG9jYWxlOiBcIlwiLFxuICAgICAgICB9LCBvcHRpb25zKSwgcG9ydGFsID0gX2EucG9ydGFsLCBwcm92aWRlciA9IF9hLnByb3ZpZGVyLCBjbGllbnRJZCA9IF9hLmNsaWVudElkLCBleHBpcmF0aW9uID0gX2EuZXhwaXJhdGlvbiwgcmVkaXJlY3RVcmkgPSBfYS5yZWRpcmVjdFVyaSwgcG9wdXAgPSBfYS5wb3B1cCwgcG9wdXBXaW5kb3dGZWF0dXJlcyA9IF9hLnBvcHVwV2luZG93RmVhdHVyZXMsIHN0YXRlID0gX2Euc3RhdGUsIGxvY2FsZSA9IF9hLmxvY2FsZSwgcGFyYW1zID0gX2EucGFyYW1zO1xuICAgICAgICB2YXIgdXJsO1xuICAgICAgICBpZiAocHJvdmlkZXIgPT09IFwiYXJjZ2lzXCIpIHtcbiAgICAgICAgICAgIHVybCA9IHBvcnRhbCArIFwiL29hdXRoMi9hdXRob3JpemU/Y2xpZW50X2lkPVwiICsgY2xpZW50SWQgKyBcIiZyZXNwb25zZV90eXBlPXRva2VuJmV4cGlyYXRpb249XCIgKyAob3B0aW9ucy5kdXJhdGlvbiB8fCBleHBpcmF0aW9uKSArIFwiJnJlZGlyZWN0X3VyaT1cIiArIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgKyBcIiZzdGF0ZT1cIiArIHN0YXRlICsgXCImbG9jYWxlPVwiICsgbG9jYWxlO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdXJsID0gcG9ydGFsICsgXCIvb2F1dGgyL3NvY2lhbC9hdXRob3JpemU/Y2xpZW50X2lkPVwiICsgY2xpZW50SWQgKyBcIiZzb2NpYWxMb2dpblByb3ZpZGVyTmFtZT1cIiArIHByb3ZpZGVyICsgXCImYXV0b0FjY291bnRDcmVhdGVGb3JTb2NpYWw9dHJ1ZSZyZXNwb25zZV90eXBlPXRva2VuJmV4cGlyYXRpb249XCIgKyAob3B0aW9ucy5kdXJhdGlvbiB8fCBleHBpcmF0aW9uKSArIFwiJnJlZGlyZWN0X3VyaT1cIiArIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgKyBcIiZzdGF0ZT1cIiArIHN0YXRlICsgXCImbG9jYWxlPVwiICsgbG9jYWxlO1xuICAgICAgICB9XG4gICAgICAgIC8vIGFwcGVuZCBhZGRpdGlvbmFsIHBhcmFtc1xuICAgICAgICBpZiAocGFyYW1zKSB7XG4gICAgICAgICAgICB1cmwgPSB1cmwgKyBcIiZcIiArIGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFwb3B1cCkge1xuICAgICAgICAgICAgd2luLmxvY2F0aW9uLmhyZWYgPSB1cmw7XG4gICAgICAgICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgICAgICB9XG4gICAgICAgIHZhciBzZXNzaW9uID0gZGVmZXIoKTtcbiAgICAgICAgd2luW1wiX19FU1JJX1JFU1RfQVVUSF9IQU5ETEVSX1wiICsgY2xpZW50SWRdID0gZnVuY3Rpb24gKGVycm9yU3RyaW5nLCBvYXV0aEluZm9TdHJpbmcpIHtcbiAgICAgICAgICAgIGlmIChlcnJvclN0cmluZykge1xuICAgICAgICAgICAgICAgIHZhciBlcnJvciA9IEpTT04ucGFyc2UoZXJyb3JTdHJpbmcpO1xuICAgICAgICAgICAgICAgIHNlc3Npb24ucmVqZWN0KG5ldyBBcmNHSVNBdXRoRXJyb3IoZXJyb3IuZXJyb3JNZXNzYWdlLCBlcnJvci5lcnJvcikpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChvYXV0aEluZm9TdHJpbmcpIHtcbiAgICAgICAgICAgICAgICB2YXIgb2F1dGhJbmZvID0gSlNPTi5wYXJzZShvYXV0aEluZm9TdHJpbmcpO1xuICAgICAgICAgICAgICAgIHNlc3Npb24ucmVzb2x2ZShuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgICAgICAgICBjbGllbnRJZDogY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgICAgIHBvcnRhbDogcG9ydGFsLFxuICAgICAgICAgICAgICAgICAgICBzc2w6IG9hdXRoSW5mby5zc2wsXG4gICAgICAgICAgICAgICAgICAgIHRva2VuOiBvYXV0aEluZm8udG9rZW4sXG4gICAgICAgICAgICAgICAgICAgIHRva2VuRXhwaXJlczogbmV3IERhdGUob2F1dGhJbmZvLmV4cGlyZXMpLFxuICAgICAgICAgICAgICAgICAgICB1c2VybmFtZTogb2F1dGhJbmZvLnVzZXJuYW1lLFxuICAgICAgICAgICAgICAgIH0pKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICAgICAgd2luLm9wZW4odXJsLCBcIm9hdXRoLXdpbmRvd1wiLCBwb3B1cFdpbmRvd0ZlYXR1cmVzKTtcbiAgICAgICAgcmV0dXJuIHNlc3Npb24ucHJvbWlzZTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIENvbXBsZXRlcyBhIGJyb3dzZXItYmFzZWQgT0F1dGggMi4wIHNpZ24gaW4uIElmIGBvcHRpb25zLnBvcHVwYCBpcyBgdHJ1ZWAgdGhlIHVzZXJcbiAgICAgKiB3aWxsIGJlIHJldHVybmVkIHRvIHRoZSBwcmV2aW91cyB3aW5kb3cuIE90aGVyd2lzZSBhIG5ldyBgVXNlclNlc3Npb25gXG4gICAgICogd2lsbCBiZSByZXR1cm5lZC4gWW91IG11c3QgcGFzcyB0aGUgc2FtZSB2YWx1ZXMgZm9yIGBvcHRpb25zLnBvcHVwYCBhbmRcbiAgICAgKiBgb3B0aW9ucy5wb3J0YWxgIGFzIHlvdSB1c2VkIGluIGBiZWdpbk9BdXRoMigpYC5cbiAgICAgKlxuICAgICAqIEBicm93c2VyT25seVxuICAgICAqL1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gICAgVXNlclNlc3Npb24uY29tcGxldGVPQXV0aDIgPSBmdW5jdGlvbiAob3B0aW9ucywgd2luKSB7XG4gICAgICAgIGlmICh3aW4gPT09IHZvaWQgMCkgeyB3aW4gPSB3aW5kb3c7IH1cbiAgICAgICAgdmFyIF9hID0gX19hc3NpZ24oeyBwb3J0YWw6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIiwgcG9wdXA6IHRydWUgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgcG9wdXAgPSBfYS5wb3B1cDtcbiAgICAgICAgZnVuY3Rpb24gY29tcGxldGVTaWduSW4oZXJyb3IsIG9hdXRoSW5mbykge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICB2YXIgaGFuZGxlckZuID0gdm9pZCAwO1xuICAgICAgICAgICAgICAgIHZhciBoYW5kbGVyRm5OYW1lID0gXCJfX0VTUklfUkVTVF9BVVRIX0hBTkRMRVJfXCIgKyBjbGllbnRJZDtcbiAgICAgICAgICAgICAgICBpZiAocG9wdXApIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gR3VhcmQgYi9jIElFIGRvZXMgbm90IHN1cHBvcnQgd2luZG93Lm9wZW5lclxuICAgICAgICAgICAgICAgICAgICBpZiAod2luLm9wZW5lcikge1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHdpbi5vcGVuZXIucGFyZW50ICYmIHdpbi5vcGVuZXIucGFyZW50W2hhbmRsZXJGbk5hbWVdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlckZuID0gd2luLm9wZW5lci5wYXJlbnRbaGFuZGxlckZuTmFtZV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBlbHNlIGlmICh3aW4ub3BlbmVyICYmIHdpbi5vcGVuZXJbaGFuZGxlckZuTmFtZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvLyBzdXBwb3J0IHBvcC1vdXQgb2F1dGggZnJvbSB3aXRoaW4gYW4gaWZyYW1lXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlckZuID0gd2luLm9wZW5lcltoYW5kbGVyRm5OYW1lXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vIElFXG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAod2luICE9PSB3aW4ucGFyZW50ICYmIHdpbi5wYXJlbnQgJiYgd2luLnBhcmVudFtoYW5kbGVyRm5OYW1lXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbiA9IHdpbi5wYXJlbnRbaGFuZGxlckZuTmFtZV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgLy8gaWYgd2UgaGF2ZSBhIGhhbmRsZXIgZm4sIGNhbGwgaXQgYW5kIGNsb3NlIHRoZSB3aW5kb3dcbiAgICAgICAgICAgICAgICAgICAgaWYgKGhhbmRsZXJGbikge1xuICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlckZuKGVycm9yID8gSlNPTi5zdHJpbmdpZnkoZXJyb3IpIDogdW5kZWZpbmVkLCBKU09OLnN0cmluZ2lmeShvYXV0aEluZm8pKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHdpbi5jbG9zZSgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcihcIlVuYWJsZSB0byBjb21wbGV0ZSBhdXRoZW50aWNhdGlvbi4gSXQncyBwb3NzaWJsZSB5b3Ugc3BlY2lmaWVkIHBvcHVwIGJhc2VkIG9BdXRoMiBidXQgbm8gaGFuZGxlciBmcm9tIFxcXCJiZWdpbk9BdXRoMigpXFxcIiBwcmVzZW50LiBUaGlzIGdlbmVyYWxseSBoYXBwZW5zIGJlY2F1c2UgdGhlIFxcXCJwb3B1cFxcXCIgb3B0aW9uIGRpZmZlcnMgYmV0d2VlbiBcXFwiYmVnaW5PQXV0aDIoKVxcXCIgYW5kIFxcXCJjb21wbGV0ZU9BdXRoMigpXFxcIi5cIik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKGVycm9yLmVycm9yTWVzc2FnZSwgZXJyb3IuZXJyb3IpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICAgICAgY2xpZW50SWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgIHBvcnRhbDogcG9ydGFsLFxuICAgICAgICAgICAgICAgIHNzbDogb2F1dGhJbmZvLnNzbCxcbiAgICAgICAgICAgICAgICB0b2tlbjogb2F1dGhJbmZvLnRva2VuLFxuICAgICAgICAgICAgICAgIHRva2VuRXhwaXJlczogb2F1dGhJbmZvLmV4cGlyZXMsXG4gICAgICAgICAgICAgICAgdXNlcm5hbWU6IG9hdXRoSW5mby51c2VybmFtZSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHZhciBwYXJhbXMgPSBkZWNvZGVRdWVyeVN0cmluZyh3aW4ubG9jYXRpb24uaGFzaCk7XG4gICAgICAgIGlmICghcGFyYW1zLmFjY2Vzc190b2tlbikge1xuICAgICAgICAgICAgdmFyIGVycm9yID0gdm9pZCAwO1xuICAgICAgICAgICAgdmFyIGVycm9yTWVzc2FnZSA9IFwiVW5rbm93biBlcnJvclwiO1xuICAgICAgICAgICAgaWYgKHBhcmFtcy5lcnJvcikge1xuICAgICAgICAgICAgICAgIGVycm9yID0gcGFyYW1zLmVycm9yO1xuICAgICAgICAgICAgICAgIGVycm9yTWVzc2FnZSA9IHBhcmFtcy5lcnJvcl9kZXNjcmlwdGlvbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBjb21wbGV0ZVNpZ25Jbih7IGVycm9yOiBlcnJvciwgZXJyb3JNZXNzYWdlOiBlcnJvck1lc3NhZ2UgfSk7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHRva2VuID0gcGFyYW1zLmFjY2Vzc190b2tlbjtcbiAgICAgICAgdmFyIGV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgcGFyc2VJbnQocGFyYW1zLmV4cGlyZXNfaW4sIDEwKSAqIDEwMDAgLSA2MCAqIDEwMDApO1xuICAgICAgICB2YXIgdXNlcm5hbWUgPSBwYXJhbXMudXNlcm5hbWU7XG4gICAgICAgIHZhciBzc2wgPSBwYXJhbXMuc3NsID09PSBcInRydWVcIjtcbiAgICAgICAgcmV0dXJuIGNvbXBsZXRlU2lnbkluKHVuZGVmaW5lZCwge1xuICAgICAgICAgICAgdG9rZW46IHRva2VuLFxuICAgICAgICAgICAgZXhwaXJlczogZXhwaXJlcyxcbiAgICAgICAgICAgIHNzbDogc3NsLFxuICAgICAgICAgICAgdXNlcm5hbWU6IHVzZXJuYW1lLFxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJlcXVlc3Qgc2Vzc2lvbiBpbmZvcm1hdGlvbiBmcm9tIHRoZSBwYXJlbnQgYXBwbGljYXRpb25cbiAgICAgKlxuICAgICAqIFdoZW4gYW4gYXBwbGljYXRpb24gaXMgZW1iZWRkZWQgaW50byBhbm90aGVyIGFwcGxpY2F0aW9uIHZpYSBhbiBJRnJhbWUsIHRoZSBlbWJlZGRlZCBhcHAgY2FuXG4gICAgICogdXNlIGB3aW5kb3cucG9zdE1lc3NhZ2VgIHRvIHJlcXVlc3QgY3JlZGVudGlhbHMgZnJvbSB0aGUgaG9zdCBhcHBsaWNhdGlvbi4gVGhpcyBmdW5jdGlvbiB3cmFwc1xuICAgICAqIHRoYXQgYmVoYXZpb3IuXG4gICAgICpcbiAgICAgKiBUaGUgQXJjR0lTIEFQSSBmb3IgSmF2YXNjcmlwdCBoYXMgdGhpcyBidWlsdCBpbnRvIHRoZSBJZGVudGl0eSBNYW5hZ2VyIGFzIG9mIHRoZSA0LjE5IHJlbGVhc2UuXG4gICAgICpcbiAgICAgKiBOb3RlOiBUaGUgcGFyZW50IGFwcGxpY2F0aW9uIHdpbGwgbm90IHJlc3BvbmQgaWYgdGhlIGVtYmVkZGVkIGFwcCdzIG9yaWdpbiBpcyBub3Q6XG4gICAgICogLSB0aGUgc2FtZSBvcmlnaW4gYXMgdGhlIHBhcmVudCBvciAqLmFyY2dpcy5jb20gKEpTQVBJKVxuICAgICAqIC0gaW4gdGhlIGxpc3Qgb2YgdmFsaWQgY2hpbGQgb3JpZ2lucyAoUkVTVC1KUylcbiAgICAgKlxuICAgICAqXG4gICAgICogQHBhcmFtIHBhcmVudE9yaWdpbiBvcmlnaW4gb2YgdGhlIHBhcmVudCBmcmFtZS4gUGFzc2VkIGludG8gdGhlIGVtYmVkZGVkIGFwcGxpY2F0aW9uIGFzIGBwYXJlbnRPcmlnaW5gIHF1ZXJ5IHBhcmFtXG4gICAgICogQGJyb3dzZXJPbmx5XG4gICAgICovXG4gICAgVXNlclNlc3Npb24uZnJvbVBhcmVudCA9IGZ1bmN0aW9uIChwYXJlbnRPcmlnaW4sIHdpbikge1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dDogbXVzdCBwYXNzIGluIGEgbW9ja3dpbmRvdyBmb3IgdGVzdHMgc28gd2UgY2FuJ3QgY292ZXIgdGhlIG90aGVyIGJyYW5jaCAqL1xuICAgICAgICBpZiAoIXdpbiAmJiB3aW5kb3cpIHtcbiAgICAgICAgICAgIHdpbiA9IHdpbmRvdztcbiAgICAgICAgfVxuICAgICAgICAvLyBEZWNsYXJlIGhhbmRsZXIgb3V0c2lkZSBvZiBwcm9taXNlIHNjb3BlIHNvIHdlIGNhbiBkZXRhY2ggaXRcbiAgICAgICAgdmFyIGhhbmRsZXI7XG4gICAgICAgIC8vIHJldHVybiBhIHByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2hlbiB0aGUgaGFuZGxlciByZWNlaXZlc1xuICAgICAgICAvLyBzZXNzaW9uIGluZm9ybWF0aW9uIGZyb20gdGhlIGNvcnJlY3Qgb3JpZ2luXG4gICAgICAgIHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgICAvLyBjcmVhdGUgYW4gZXZlbnQgaGFuZGxlciB0aGF0IGp1c3Qgd3JhcHMgdGhlIHBhcmVudE1lc3NhZ2VIYW5kbGVyXG4gICAgICAgICAgICBoYW5kbGVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgICAgICAgICAgLy8gZW5zdXJlIHdlIG9ubHkgbGlzdGVuIHRvIGV2ZW50cyBmcm9tIHRoZSBwYXJlbnRcbiAgICAgICAgICAgICAgICBpZiAoZXZlbnQuc291cmNlID09PSB3aW4ucGFyZW50ICYmIGV2ZW50LmRhdGEpIHtcbiAgICAgICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXNvbHZlKFVzZXJTZXNzaW9uLnBhcmVudE1lc3NhZ2VIYW5kbGVyKGV2ZW50KSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgY2F0Y2ggKGVycikge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlamVjdChlcnIpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIC8vIGFkZCBsaXN0ZW5lclxuICAgICAgICAgICAgd2luLmFkZEV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIGhhbmRsZXIsIGZhbHNlKTtcbiAgICAgICAgICAgIHdpbi5wYXJlbnQucG9zdE1lc3NhZ2UoeyB0eXBlOiBcImFyY2dpczphdXRoOnJlcXVlc3RDcmVkZW50aWFsXCIgfSwgcGFyZW50T3JpZ2luKTtcbiAgICAgICAgfSkudGhlbihmdW5jdGlvbiAoc2Vzc2lvbikge1xuICAgICAgICAgICAgd2luLnJlbW92ZUV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIGhhbmRsZXIsIGZhbHNlKTtcbiAgICAgICAgICAgIHJldHVybiBzZXNzaW9uO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEJlZ2lucyBhIG5ldyBzZXJ2ZXItYmFzZWQgT0F1dGggMi4wIHNpZ24gaW4uIFRoaXMgd2lsbCByZWRpcmVjdCB0aGUgdXNlciB0b1xuICAgICAqIHRoZSBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlIGF1dGhvcml6YXRpb24gcGFnZS5cbiAgICAgKlxuICAgICAqIEBub2RlT25seVxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmF1dGhvcml6ZSA9IGZ1bmN0aW9uIChvcHRpb25zLCByZXNwb25zZSkge1xuICAgICAgICBpZiAob3B0aW9ucy5kdXJhdGlvbikge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJERVBSRUNBVEVEOiAnZHVyYXRpb24nIGlzIGRlcHJlY2F0ZWQgLSB1c2UgJ2V4cGlyYXRpb24nIGluc3RlYWRcIik7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIF9hID0gX19hc3NpZ24oeyBwb3J0YWw6IFwiaHR0cHM6Ly9hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiLCBleHBpcmF0aW9uOiAyMDE2MCB9LCBvcHRpb25zKSwgcG9ydGFsID0gX2EucG9ydGFsLCBjbGllbnRJZCA9IF9hLmNsaWVudElkLCBleHBpcmF0aW9uID0gX2EuZXhwaXJhdGlvbiwgcmVkaXJlY3RVcmkgPSBfYS5yZWRpcmVjdFVyaTtcbiAgICAgICAgcmVzcG9uc2Uud3JpdGVIZWFkKDMwMSwge1xuICAgICAgICAgICAgTG9jYXRpb246IHBvcnRhbCArIFwiL29hdXRoMi9hdXRob3JpemU/Y2xpZW50X2lkPVwiICsgY2xpZW50SWQgKyBcIiZleHBpcmF0aW9uPVwiICsgKG9wdGlvbnMuZHVyYXRpb24gfHwgZXhwaXJhdGlvbikgKyBcIiZyZXNwb25zZV90eXBlPWNvZGUmcmVkaXJlY3RfdXJpPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHJlZGlyZWN0VXJpKSxcbiAgICAgICAgfSk7XG4gICAgICAgIHJlc3BvbnNlLmVuZCgpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogQ29tcGxldGVzIHRoZSBzZXJ2ZXItYmFzZWQgT0F1dGggMi4wIHNpZ24gaW4gcHJvY2VzcyBieSBleGNoYW5naW5nIHRoZSBgYXV0aG9yaXphdGlvbkNvZGVgXG4gICAgICogZm9yIGEgYGFjY2Vzc190b2tlbmAuXG4gICAgICpcbiAgICAgKiBAbm9kZU9ubHlcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5leGNoYW5nZUF1dGhvcml6YXRpb25Db2RlID0gZnVuY3Rpb24gKG9wdGlvbnMsIGF1dGhvcml6YXRpb25Db2RlKSB7XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHtcbiAgICAgICAgICAgIHBvcnRhbDogXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiAyMDE2MCxcbiAgICAgICAgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgcmVkaXJlY3RVcmkgPSBfYS5yZWRpcmVjdFVyaSwgcmVmcmVzaFRva2VuVFRMID0gX2EucmVmcmVzaFRva2VuVFRMO1xuICAgICAgICByZXR1cm4gZmV0Y2hUb2tlbihwb3J0YWwgKyBcIi9vYXV0aDIvdG9rZW5cIiwge1xuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgZ3JhbnRfdHlwZTogXCJhdXRob3JpemF0aW9uX2NvZGVcIixcbiAgICAgICAgICAgICAgICBjbGllbnRfaWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgIHJlZGlyZWN0X3VyaTogcmVkaXJlY3RVcmksXG4gICAgICAgICAgICAgICAgY29kZTogYXV0aG9yaXphdGlvbkNvZGUsXG4gICAgICAgICAgICB9LFxuICAgICAgICB9KS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICAgICAgY2xpZW50SWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgIHBvcnRhbDogcG9ydGFsLFxuICAgICAgICAgICAgICAgIHNzbDogcmVzcG9uc2Uuc3NsLFxuICAgICAgICAgICAgICAgIHJlZGlyZWN0VXJpOiByZWRpcmVjdFVyaSxcbiAgICAgICAgICAgICAgICByZWZyZXNoVG9rZW46IHJlc3BvbnNlLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IHJlZnJlc2hUb2tlblRUTCxcbiAgICAgICAgICAgICAgICByZWZyZXNoVG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShEYXRlLm5vdygpICsgKHJlZnJlc2hUb2tlblRUTCAtIDEpICogNjAgKiAxMDAwKSxcbiAgICAgICAgICAgICAgICB0b2tlbjogcmVzcG9uc2UudG9rZW4sXG4gICAgICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiByZXNwb25zZS5leHBpcmVzLFxuICAgICAgICAgICAgICAgIHVzZXJuYW1lOiByZXNwb25zZS51c2VybmFtZSxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIFVzZXJTZXNzaW9uLmRlc2VyaWFsaXplID0gZnVuY3Rpb24gKHN0cikge1xuICAgICAgICB2YXIgb3B0aW9ucyA9IEpTT04ucGFyc2Uoc3RyKTtcbiAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICBjbGllbnRJZDogb3B0aW9ucy5jbGllbnRJZCxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlbjogb3B0aW9ucy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShvcHRpb25zLnJlZnJlc2hUb2tlbkV4cGlyZXMpLFxuICAgICAgICAgICAgdXNlcm5hbWU6IG9wdGlvbnMudXNlcm5hbWUsXG4gICAgICAgICAgICBwYXNzd29yZDogb3B0aW9ucy5wYXNzd29yZCxcbiAgICAgICAgICAgIHRva2VuOiBvcHRpb25zLnRva2VuLFxuICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiBuZXcgRGF0ZShvcHRpb25zLnRva2VuRXhwaXJlcyksXG4gICAgICAgICAgICBwb3J0YWw6IG9wdGlvbnMucG9ydGFsLFxuICAgICAgICAgICAgc3NsOiBvcHRpb25zLnNzbCxcbiAgICAgICAgICAgIHRva2VuRHVyYXRpb246IG9wdGlvbnMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgIHJlZGlyZWN0VXJpOiBvcHRpb25zLnJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiBvcHRpb25zLnJlZnJlc2hUb2tlblRUTCxcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBUcmFuc2xhdGVzIGF1dGhlbnRpY2F0aW9uIGZyb20gdGhlIGZvcm1hdCB1c2VkIGluIHRoZSBbQXJjR0lTIEFQSSBmb3IgSmF2YVNjcmlwdF0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vamF2YXNjcmlwdC8pLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbCh7XG4gICAgICogICB1c2VySWQ6IFwianNtaXRoXCIsXG4gICAgICogICB0b2tlbjogXCJzZWNyZXRcIlxuICAgICAqIH0pO1xuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHJldHVybnMgVXNlclNlc3Npb25cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbCA9IGZ1bmN0aW9uIChjcmVkZW50aWFsKSB7XG4gICAgICAgIC8vIEF0IEFyY0dJUyBPbmxpbmUgOS4xLCBjcmVkZW50aWFscyBubyBsb25nZXIgaW5jbHVkZSB0aGUgc3NsIGFuZCBleHBpcmVzIHByb3BlcnRpZXNcbiAgICAgICAgLy8gSGVyZSwgd2UgcHJvdmlkZSBkZWZhdWx0IHZhbHVlcyBmb3IgdGhlbSB0byBjb3ZlciB0aGlzIGNvbmRpdGlvblxuICAgICAgICB2YXIgc3NsID0gdHlwZW9mIGNyZWRlbnRpYWwuc3NsICE9PSBcInVuZGVmaW5lZFwiID8gY3JlZGVudGlhbC5zc2wgOiB0cnVlO1xuICAgICAgICB2YXIgZXhwaXJlcyA9IGNyZWRlbnRpYWwuZXhwaXJlcyB8fCBEYXRlLm5vdygpICsgNzIwMDAwMDsgLyogMiBob3VycyAqL1xuICAgICAgICByZXR1cm4gbmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgIHBvcnRhbDogY3JlZGVudGlhbC5zZXJ2ZXIuaW5jbHVkZXMoXCJzaGFyaW5nL3Jlc3RcIilcbiAgICAgICAgICAgICAgICA/IGNyZWRlbnRpYWwuc2VydmVyXG4gICAgICAgICAgICAgICAgOiBjcmVkZW50aWFsLnNlcnZlciArIFwiL3NoYXJpbmcvcmVzdFwiLFxuICAgICAgICAgICAgc3NsOiBzc2wsXG4gICAgICAgICAgICB0b2tlbjogY3JlZGVudGlhbC50b2tlbixcbiAgICAgICAgICAgIHVzZXJuYW1lOiBjcmVkZW50aWFsLnVzZXJJZCxcbiAgICAgICAgICAgIHRva2VuRXhwaXJlczogbmV3IERhdGUoZXhwaXJlcyksXG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogSGFuZGxlIHRoZSByZXNwb25zZSBmcm9tIHRoZSBwYXJlbnRcbiAgICAgKiBAcGFyYW0gZXZlbnQgRE9NIEV2ZW50XG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucGFyZW50TWVzc2FnZUhhbmRsZXIgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgaWYgKGV2ZW50LmRhdGEudHlwZSA9PT0gXCJhcmNnaXM6YXV0aDpjcmVkZW50aWFsXCIpIHtcbiAgICAgICAgICAgIHJldHVybiBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbChldmVudC5kYXRhLmNyZWRlbnRpYWwpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChldmVudC5kYXRhLnR5cGUgPT09IFwiYXJjZ2lzOmF1dGg6ZXJyb3JcIikge1xuICAgICAgICAgICAgdmFyIGVyciA9IG5ldyBFcnJvcihldmVudC5kYXRhLmVycm9yLm1lc3NhZ2UpO1xuICAgICAgICAgICAgZXJyLm5hbWUgPSBldmVudC5kYXRhLmVycm9yLm5hbWU7XG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJVbmtub3duIG1lc3NhZ2UgdHlwZS5cIik7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgYXV0aGVudGljYXRpb24gaW4gYSBmb3JtYXQgdXNlYWJsZSBpbiB0aGUgW0FyY0dJUyBBUEkgZm9yIEphdmFTY3JpcHRdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL2phdmFzY3JpcHQvKS5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogZXNyaUlkLnJlZ2lzdGVyVG9rZW4oc2Vzc2lvbi50b0NyZWRlbnRpYWwoKSk7XG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyBJQ3JlZGVudGlhbFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS50b0NyZWRlbnRpYWwgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBleHBpcmVzOiB0aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCksXG4gICAgICAgICAgICBzZXJ2ZXI6IHRoaXMucG9ydGFsLFxuICAgICAgICAgICAgc3NsOiB0aGlzLnNzbCxcbiAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgICAgdXNlcklkOiB0aGlzLnVzZXJuYW1lLFxuICAgICAgICB9O1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyBpbmZvcm1hdGlvbiBhYm91dCB0aGUgY3VycmVudGx5IGxvZ2dlZCBpbiBbdXNlcl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3VzZXIuaHRtKS4gU3Vic2VxdWVudCBjYWxscyB3aWxsICpub3QqIHJlc3VsdCBpbiBhZGRpdGlvbmFsIHdlYiB0cmFmZmljLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBzZXNzaW9uLmdldFVzZXIoKVxuICAgICAqICAgLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAqICAgICBjb25zb2xlLmxvZyhyZXNwb25zZS5yb2xlKTsgLy8gXCJvcmdfYWRtaW5cIlxuICAgICAqICAgfSlcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LiBOT1RFOiBgcmF3UmVzcG9uc2VgIGlzIG5vdCBzdXBwb3J0ZWQgYnkgdGhpcyBvcGVyYXRpb24uXG4gICAgICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGRhdGEgZnJvbSB0aGUgcmVzcG9uc2UuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFVzZXIgPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh0aGlzLl91c2VyKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMuX3VzZXIpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdmFyIHVybCA9IHRoaXMucG9ydGFsICsgXCIvY29tbXVuaXR5L3NlbGZcIjtcbiAgICAgICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIkdFVFwiLCBhdXRoZW50aWNhdGlvbjogdGhpcyB9LCByZXF1ZXN0T3B0aW9ucyksIHsgcmF3UmVzcG9uc2U6IGZhbHNlIH0pO1xuICAgICAgICAgICAgdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0ID0gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3VzZXIgPSByZXNwb25zZTtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0ID0gbnVsbDtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgaW5mb3JtYXRpb24gYWJvdXQgdGhlIGN1cnJlbnRseSBsb2dnZWQgaW4gdXNlcidzIFtwb3J0YWxdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy9wb3J0YWwtc2VsZi5odG0pLiBTdWJzZXF1ZW50IGNhbGxzIHdpbGwgKm5vdCogcmVzdWx0IGluIGFkZGl0aW9uYWwgd2ViIHRyYWZmaWMuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIHNlc3Npb24uZ2V0UG9ydGFsKClcbiAgICAgKiAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgKiAgICAgY29uc29sZS5sb2cocG9ydGFsLm5hbWUpOyAvLyBcIkNpdHkgb2YgLi4uXCJcbiAgICAgKiAgIH0pXG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC4gTk9URTogYHJhd1Jlc3BvbnNlYCBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoaXMgb3BlcmF0aW9uLlxuICAgICAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkYXRhIGZyb20gdGhlIHJlc3BvbnNlLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRQb3J0YWwgPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0KSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5fcG9ydGFsSW5mbykge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLl9wb3J0YWxJbmZvKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHZhciB1cmwgPSB0aGlzLnBvcnRhbCArIFwiL3BvcnRhbHMvc2VsZlwiO1xuICAgICAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiR0VUXCIsIGF1dGhlbnRpY2F0aW9uOiB0aGlzIH0sIHJlcXVlc3RPcHRpb25zKSwgeyByYXdSZXNwb25zZTogZmFsc2UgfSk7XG4gICAgICAgICAgICB0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdCA9IHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIF90aGlzLl9wb3J0YWxJbmZvID0gcmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0ID0gbnVsbDtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdDtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyB0aGUgdXNlcm5hbWUgZm9yIHRoZSBjdXJyZW50bHkgbG9nZ2VkIGluIFt1c2VyXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvdXNlci5odG0pLiBTdWJzZXF1ZW50IGNhbGxzIHdpbGwgKm5vdCogcmVzdWx0IGluIGFkZGl0aW9uYWwgd2ViIHRyYWZmaWMuIFRoaXMgaXMgYWxzbyB1c2VkIGludGVybmFsbHkgd2hlbiBhIHVzZXJuYW1lIGlzIHJlcXVpcmVkIGZvciBzb21lIHJlcXVlc3RzIGJ1dCBpcyBub3QgcHJlc2VudCBpbiB0aGUgb3B0aW9ucy5cbiAgICAgKlxuICAgICAqICAgICogYGBganNcbiAgICAgKiBzZXNzaW9uLmdldFVzZXJuYW1lKClcbiAgICAgKiAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgKiAgICAgY29uc29sZS5sb2cocmVzcG9uc2UpOyAvLyBcImNhc2V5X2pvbmVzXCJcbiAgICAgKiAgIH0pXG4gICAgICogYGBgXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFVzZXJuYW1lID0gZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAodGhpcy51c2VybmFtZSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLnVzZXJuYW1lKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh0aGlzLl91c2VyKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMuX3VzZXIudXNlcm5hbWUpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZ2V0VXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdXNlci51c2VybmFtZTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBHZXRzIGFuIGFwcHJvcHJpYXRlIHRva2VuIGZvciB0aGUgZ2l2ZW4gVVJMLiBJZiBgcG9ydGFsYCBpcyBBcmNHSVMgT25saW5lIGFuZFxuICAgICAqIHRoZSByZXF1ZXN0IGlzIHRvIGFuIEFyY0dJUyBPbmxpbmUgZG9tYWluIGB0b2tlbmAgd2lsbCBiZSB1c2VkLiBJZiB0aGUgcmVxdWVzdFxuICAgICAqIGlzIHRvIHRoZSBjdXJyZW50IGBwb3J0YWxgIHRoZSBjdXJyZW50IGB0b2tlbmAgd2lsbCBhbHNvIGJlIHVzZWQuIEhvd2V2ZXIgaWZcbiAgICAgKiB0aGUgcmVxdWVzdCBpcyB0byBhbiB1bmtub3duIHNlcnZlciB3ZSB3aWxsIHZhbGlkYXRlIHRoZSBzZXJ2ZXIgd2l0aCBhIHJlcXVlc3RcbiAgICAgKiB0byBvdXIgY3VycmVudCBgcG9ydGFsYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0VG9rZW4gPSBmdW5jdGlvbiAodXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICBpZiAoY2FuVXNlT25saW5lVG9rZW4odGhpcy5wb3J0YWwsIHVybCkpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldEZyZXNoVG9rZW4ocmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKG5ldyBSZWdFeHAodGhpcy5wb3J0YWwsIFwiaVwiKS50ZXN0KHVybCkpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldEZyZXNoVG9rZW4ocmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW5Gb3JTZXJ2ZXIodXJsLCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEdldCBhcHBsaWNhdGlvbiBhY2Nlc3MgaW5mb3JtYXRpb24gZm9yIHRoZSBjdXJyZW50IHVzZXJcbiAgICAgKiBzZWUgYHZhbGlkYXRlQXBwQWNjZXNzYCBmdW5jdGlvbiBmb3IgZGV0YWlsc1xuICAgICAqXG4gICAgICogQHBhcmFtIGNsaWVudElkIGFwcGxpY2F0aW9uIGNsaWVudCBpZFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS52YWxpZGF0ZUFwcEFjY2VzcyA9IGZ1bmN0aW9uIChjbGllbnRJZCkge1xuICAgICAgICByZXR1cm4gdGhpcy5nZXRUb2tlbih0aGlzLnBvcnRhbCkudGhlbihmdW5jdGlvbiAodG9rZW4pIHtcbiAgICAgICAgICAgIHJldHVybiB2YWxpZGF0ZUFwcEFjY2Vzcyh0b2tlbiwgY2xpZW50SWQpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS50b0pTT04gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBjbGllbnRJZDogdGhpcy5jbGllbnRJZCxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlbjogdGhpcy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5FeHBpcmVzOiB0aGlzLnJlZnJlc2hUb2tlbkV4cGlyZXMsXG4gICAgICAgICAgICB1c2VybmFtZTogdGhpcy51c2VybmFtZSxcbiAgICAgICAgICAgIHBhc3N3b3JkOiB0aGlzLnBhc3N3b3JkLFxuICAgICAgICAgICAgdG9rZW46IHRoaXMudG9rZW4sXG4gICAgICAgICAgICB0b2tlbkV4cGlyZXM6IHRoaXMudG9rZW5FeHBpcmVzLFxuICAgICAgICAgICAgcG9ydGFsOiB0aGlzLnBvcnRhbCxcbiAgICAgICAgICAgIHNzbDogdGhpcy5zc2wsXG4gICAgICAgICAgICB0b2tlbkR1cmF0aW9uOiB0aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICByZWRpcmVjdFVyaTogdGhpcy5yZWRpcmVjdFVyaSxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogdGhpcy5yZWZyZXNoVG9rZW5UVEwsXG4gICAgICAgIH07XG4gICAgfTtcbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuc2VyaWFsaXplID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkodGhpcyk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBGb3IgYSBcIkhvc3RcIiBhcHAgdGhhdCBlbWJlZHMgb3RoZXIgcGxhdGZvcm0gYXBwcyB2aWEgaWZyYW1lcywgYWZ0ZXIgYXV0aGVudGljYXRpbmcgdGhlIHVzZXJcbiAgICAgKiBhbmQgY3JlYXRpbmcgYSBVc2VyU2Vzc2lvbiwgdGhlIGFwcCBjYW4gdGhlbiBlbmFibGUgXCJwb3N0IG1lc3NhZ2VcIiBzdHlsZSBhdXRoZW50aWNhdGlvbiBieSBjYWxsaW5nXG4gICAgICogdGhpcyBtZXRob2QuXG4gICAgICpcbiAgICAgKiBJbnRlcm5hbGx5IHRoaXMgYWRkcyBhbiBldmVudCBsaXN0ZW5lciBvbiB3aW5kb3cgZm9yIHRoZSBgbWVzc2FnZWAgZXZlbnRcbiAgICAgKlxuICAgICAqIEBwYXJhbSB2YWxpZENoaWxkT3JpZ2lucyBBcnJheSBvZiBvcmlnaW5zIHRoYXQgYXJlIGFsbG93ZWQgdG8gcmVxdWVzdCBhdXRoZW50aWNhdGlvbiBmcm9tIHRoZSBob3N0IGFwcFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5lbmFibGVQb3N0TWVzc2FnZUF1dGggPSBmdW5jdGlvbiAodmFsaWRDaGlsZE9yaWdpbnMsIHdpbikge1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dDogbXVzdCBwYXNzIGluIGEgbW9ja3dpbmRvdyBmb3IgdGVzdHMgc28gd2UgY2FuJ3QgY292ZXIgdGhlIG90aGVyIGJyYW5jaCAqL1xuICAgICAgICBpZiAoIXdpbiAmJiB3aW5kb3cpIHtcbiAgICAgICAgICAgIHdpbiA9IHdpbmRvdztcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9ob3N0SGFuZGxlciA9IHRoaXMuY3JlYXRlUG9zdE1lc3NhZ2VIYW5kbGVyKHZhbGlkQ2hpbGRPcmlnaW5zKTtcbiAgICAgICAgd2luLmFkZEV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIHRoaXMuX2hvc3RIYW5kbGVyLCBmYWxzZSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBGb3IgYSBcIkhvc3RcIiBhcHAgdGhhdCBoYXMgZW1iZWRkZWQgb3RoZXIgcGxhdGZvcm0gYXBwcyB2aWEgaWZyYW1lcywgd2hlbiB0aGUgaG9zdCBuZWVkc1xuICAgICAqIHRvIHRyYW5zaXRpb24gcm91dGVzLCBpdCBzaG91bGQgY2FsbCBgVXNlclNlc3Npb24uZGlzYWJsZVBvc3RNZXNzYWdlQXV0aCgpYCB0byByZW1vdmVcbiAgICAgKiB0aGUgZXZlbnQgbGlzdGVuZXIgYW5kIHByZXZlbnQgbWVtb3J5IGxlYWtzXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmRpc2FibGVQb3N0TWVzc2FnZUF1dGggPSBmdW5jdGlvbiAod2luKSB7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0OiBtdXN0IHBhc3MgaW4gYSBtb2Nrd2luZG93IGZvciB0ZXN0cyBzbyB3ZSBjYW4ndCBjb3ZlciB0aGUgb3RoZXIgYnJhbmNoICovXG4gICAgICAgIGlmICghd2luICYmIHdpbmRvdykge1xuICAgICAgICAgICAgd2luID0gd2luZG93O1xuICAgICAgICB9XG4gICAgICAgIHdpbi5yZW1vdmVFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCB0aGlzLl9ob3N0SGFuZGxlciwgZmFsc2UpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogTWFudWFsbHkgcmVmcmVzaGVzIHRoZSBjdXJyZW50IGB0b2tlbmAgYW5kIGB0b2tlbkV4cGlyZXNgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5yZWZyZXNoU2Vzc2lvbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICAvLyBtYWtlIHN1cmUgc3Vic2VxdWVudCBjYWxscyB0byBnZXRVc2VyKCkgZG9uJ3QgcmV0dXJuZWQgY2FjaGVkIG1ldGFkYXRhXG4gICAgICAgIHRoaXMuX3VzZXIgPSBudWxsO1xuICAgICAgICBpZiAodGhpcy51c2VybmFtZSAmJiB0aGlzLnBhc3N3b3JkKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5yZWZyZXNoV2l0aFVzZXJuYW1lQW5kUGFzc3dvcmQocmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLmNsaWVudElkICYmIHRoaXMucmVmcmVzaFRva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5yZWZyZXNoV2l0aFJlZnJlc2hUb2tlbigpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgQXJjR0lTQXV0aEVycm9yKFwiVW5hYmxlIHRvIHJlZnJlc2ggdG9rZW4uXCIpKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIERldGVybWluZXMgdGhlIHJvb3Qgb2YgdGhlIEFyY0dJUyBTZXJ2ZXIgb3IgUG9ydGFsIGZvciBhIGdpdmVuIFVSTC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB1cmwgdGhlIFVSbCB0byBkZXRlcm1pbmUgdGhlIHJvb3QgdXJsIGZvci5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0U2VydmVyUm9vdFVybCA9IGZ1bmN0aW9uICh1cmwpIHtcbiAgICAgICAgdmFyIHJvb3QgPSBjbGVhblVybCh1cmwpLnNwbGl0KC9cXC9yZXN0KFxcL2FkbWluKT9cXC9zZXJ2aWNlcyg/OlxcL3wjfFxcP3wkKS8pWzBdO1xuICAgICAgICB2YXIgX2EgPSByb290Lm1hdGNoKC8oaHR0cHM/OlxcL1xcLykoLispLyksIG1hdGNoID0gX2FbMF0sIHByb3RvY29sID0gX2FbMV0sIGRvbWFpbkFuZFBhdGggPSBfYVsyXTtcbiAgICAgICAgdmFyIF9iID0gZG9tYWluQW5kUGF0aC5zcGxpdChcIi9cIiksIGRvbWFpbiA9IF9iWzBdLCBwYXRoID0gX2Iuc2xpY2UoMSk7XG4gICAgICAgIC8vIG9ubHkgdGhlIGRvbWFpbiBpcyBsb3dlcmNhc2VkIGJlY2F1c2UgaW4gc29tZSBjYXNlcyBhbiBvcmcgaWQgbWlnaHQgYmVcbiAgICAgICAgLy8gaW4gdGhlIHBhdGggd2hpY2ggY2Fubm90IGJlIGxvd2VyY2FzZWQuXG4gICAgICAgIHJldHVybiBcIlwiICsgcHJvdG9jb2wgKyBkb21haW4udG9Mb3dlckNhc2UoKSArIFwiL1wiICsgcGF0aC5qb2luKFwiL1wiKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIHByb3BlciBbYGNyZWRlbnRpYWxzYF0gb3B0aW9uIGZvciBgZmV0Y2hgIGZvciBhIGdpdmVuIGRvbWFpbi5cbiAgICAgKiBTZWUgW3RydXN0ZWQgc2VydmVyXShodHRwczovL2VudGVycHJpc2UuYXJjZ2lzLmNvbS9lbi9wb3J0YWwvbGF0ZXN0L2FkbWluaXN0ZXIvd2luZG93cy9jb25maWd1cmUtc2VjdXJpdHkuaHRtI0VTUklfU0VDVElPTjFfNzBDQzE1OUIzNTQwNDQwQUIzMjVCRTVEODlEQkU5NEEpLlxuICAgICAqIFVzZWQgaW50ZXJuYWxseSBieSB1bmRlcmx5aW5nIHJlcXVlc3QgbWV0aG9kcyB0byBhZGQgc3VwcG9ydCBmb3Igc3BlY2lmaWMgc2VjdXJpdHkgY29uc2lkZXJhdGlvbnMuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gdXJsIFRoZSB1cmwgb2YgdGhlIHJlcXVlc3RcbiAgICAgKiBAcmV0dXJucyBcImluY2x1ZGVcIiBvciBcInNhbWUtb3JpZ2luXCJcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0RG9tYWluQ3JlZGVudGlhbHMgPSBmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgIGlmICghdGhpcy50cnVzdGVkRG9tYWlucyB8fCAhdGhpcy50cnVzdGVkRG9tYWlucy5sZW5ndGgpIHtcbiAgICAgICAgICAgIHJldHVybiBcInNhbWUtb3JpZ2luXCI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMudHJ1c3RlZERvbWFpbnMuc29tZShmdW5jdGlvbiAoZG9tYWluV2l0aFByb3RvY29sKSB7XG4gICAgICAgICAgICByZXR1cm4gdXJsLnN0YXJ0c1dpdGgoZG9tYWluV2l0aFByb3RvY29sKTtcbiAgICAgICAgfSlcbiAgICAgICAgICAgID8gXCJpbmNsdWRlXCJcbiAgICAgICAgICAgIDogXCJzYW1lLW9yaWdpblwiO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJuIGEgZnVuY3Rpb24gdGhhdCBjbG9zZXMgb3ZlciB0aGUgdmFsaWRPcmlnaW5zIGFycmF5IGFuZFxuICAgICAqIGNhbiBiZSB1c2VkIGFzIGFuIGV2ZW50IGhhbmRsZXIgZm9yIHRoZSBgbWVzc2FnZWAgZXZlbnRcbiAgICAgKlxuICAgICAqIEBwYXJhbSB2YWxpZE9yaWdpbnMgQXJyYXkgb2YgdmFsaWQgb3JpZ2luc1xuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5jcmVhdGVQb3N0TWVzc2FnZUhhbmRsZXIgPSBmdW5jdGlvbiAodmFsaWRPcmlnaW5zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIC8vIHJldHVybiBhIGZ1bmN0aW9uIHRoYXQgY2xvc2VzIG92ZXIgdGhlIHZhbGlkT3JpZ2lucyBhbmRcbiAgICAgICAgLy8gaGFzIGFjY2VzcyB0byB0aGUgY3JlZGVudGlhbFxuICAgICAgICByZXR1cm4gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgICAgICAvLyBWZXJpZnkgdGhhdCB0aGUgb3JpZ2luIGlzIHZhbGlkXG4gICAgICAgICAgICAvLyBOb3RlOiBkbyBub3QgdXNlIHJlZ2V4J3MgaGVyZS4gdmFsaWRPcmlnaW5zIGlzIGFuIGFycmF5IHNvIHdlJ3JlIGNoZWNraW5nIHRoYXQgdGhlIGV2ZW50J3Mgb3JpZ2luXG4gICAgICAgICAgICAvLyBpcyBpbiB0aGUgYXJyYXkgdmlhIGV4YWN0IG1hdGNoLiBNb3JlIGluZm8gYWJvdXQgYXZvaWRpbmcgcG9zdE1lc3NhZ2UgeHNzIGlzc3VlcyBoZXJlXG4gICAgICAgICAgICAvLyBodHRwczovL2psYWphcmEuZ2l0bGFiLmlvL3dlYi8yMDIwLzA3LzE3L0RvbV9YU1NfUG9zdE1lc3NhZ2VfMi5odG1sI3RpcHNieXBhc3Nlcy1pbi1wb3N0bWVzc2FnZS12dWxuZXJhYmlsaXRpZXNcbiAgICAgICAgICAgIHZhciBpc1ZhbGlkT3JpZ2luID0gdmFsaWRPcmlnaW5zLmluZGV4T2YoZXZlbnQub3JpZ2luKSA+IC0xO1xuICAgICAgICAgICAgLy8gSlNBUEkgaGFuZGxlcyB0aGlzIHNsaWdodGx5IGRpZmZlcmVudGx5IC0gaW5zdGVhZCBvZiBjaGVja2luZyBhIGxpc3QsIGl0IHdpbGwgcmVzcG9uZCBpZlxuICAgICAgICAgICAgLy8gZXZlbnQub3JpZ2luID09PSB3aW5kb3cubG9jYXRpb24ub3JpZ2luIHx8IGV2ZW50Lm9yaWdpbi5lbmRzV2l0aCgnLmFyY2dpcy5jb20nKVxuICAgICAgICAgICAgLy8gRm9yIEh1YiwgYW5kIHRvIGVuYWJsZSBjcm9zcyBkb21haW4gZGVidWdnaW5nIHdpdGggcG9ydCdzIGluIHVybHMsIHdlIGFyZSBvcHRpbmcgdG9cbiAgICAgICAgICAgIC8vIHVzZSBhIGxpc3Qgb2YgdmFsaWQgb3JpZ2luc1xuICAgICAgICAgICAgLy8gRW5zdXJlIHRoZSBtZXNzYWdlIHR5cGUgaXMgc29tZXRoaW5nIHdlIHdhbnQgdG8gaGFuZGxlXG4gICAgICAgICAgICB2YXIgaXNWYWxpZFR5cGUgPSBldmVudC5kYXRhLnR5cGUgPT09IFwiYXJjZ2lzOmF1dGg6cmVxdWVzdENyZWRlbnRpYWxcIjtcbiAgICAgICAgICAgIHZhciBpc1Rva2VuVmFsaWQgPSBfdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKTtcbiAgICAgICAgICAgIGlmIChpc1ZhbGlkT3JpZ2luICYmIGlzVmFsaWRUeXBlKSB7XG4gICAgICAgICAgICAgICAgdmFyIG1zZyA9IHt9O1xuICAgICAgICAgICAgICAgIGlmIChpc1Rva2VuVmFsaWQpIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIGNyZWRlbnRpYWwgPSBfdGhpcy50b0NyZWRlbnRpYWwoKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gYXJjZ2lzOmF1dGg6ZXJyb3Igd2l0aCB7bmFtZTogXCJcIiwgbWVzc2FnZTogXCJcIn1cbiAgICAgICAgICAgICAgICAgICAgLy8gdGhlIGZvbGxvd2luZyBsaW5lIGFsbG93cyB1cyB0byBjb25mb3JtIHRvIG91ciBzcGVjIHdpdGhvdXQgY2hhbmdpbmcgb3RoZXIgZGVwZW5kZWQtb24gZnVuY3Rpb25hbGl0eVxuICAgICAgICAgICAgICAgICAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9hcmNnaXMtcmVzdC1qcy9ibG9iL21hc3Rlci9wYWNrYWdlcy9hcmNnaXMtcmVzdC1hdXRoL3Bvc3QtbWVzc2FnZS1hdXRoLXNwZWMubWQjYXJjZ2lzYXV0aGNyZWRlbnRpYWxcbiAgICAgICAgICAgICAgICAgICAgY3JlZGVudGlhbC5zZXJ2ZXIgPSBjcmVkZW50aWFsLnNlcnZlci5yZXBsYWNlKFwiL3NoYXJpbmcvcmVzdFwiLCBcIlwiKTtcbiAgICAgICAgICAgICAgICAgICAgbXNnID0geyB0eXBlOiBcImFyY2dpczphdXRoOmNyZWRlbnRpYWxcIiwgY3JlZGVudGlhbDogY3JlZGVudGlhbCB9O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gUmV0dXJuIGFuIGVycm9yXG4gICAgICAgICAgICAgICAgICAgIG1zZyA9IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHR5cGU6IFwiYXJjZ2lzOmF1dGg6ZXJyb3JcIixcbiAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbmFtZTogXCJ0b2tlbkV4cGlyZWRFcnJvclwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1lc3NhZ2U6IFwiU2Vzc2lvbiB0b2tlbiB3YXMgZXhwaXJlZCwgYW5kIG5vdCByZXR1cm5lZCB0byB0aGUgY2hpbGQgYXBwbGljYXRpb25cIixcbiAgICAgICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGV2ZW50LnNvdXJjZS5wb3N0TWVzc2FnZShtc2csIGV2ZW50Lm9yaWdpbik7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBWYWxpZGF0ZXMgdGhhdCBhIGdpdmVuIFVSTCBpcyBwcm9wZXJseSBmZWRlcmF0ZWQgd2l0aCBvdXIgY3VycmVudCBgcG9ydGFsYC5cbiAgICAgKiBBdHRlbXB0cyB0byB1c2UgdGhlIGludGVybmFsIGBmZWRlcmF0ZWRTZXJ2ZXJzYCBjYWNoZSBmaXJzdC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0VG9rZW5Gb3JTZXJ2ZXIgPSBmdW5jdGlvbiAodXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAvLyByZXF1ZXN0cyB0byAvcmVzdC9zZXJ2aWNlcy8gYW5kIC9yZXN0L2FkbWluL3NlcnZpY2VzLyBhcmUgYm90aCB2YWxpZFxuICAgICAgICAvLyBGZWRlcmF0ZWQgc2VydmVycyBtYXkgaGF2ZSBpbmNvbnNpc3RlbnQgY2FzaW5nLCBzbyBsb3dlckNhc2UgaXRcbiAgICAgICAgdmFyIHJvb3QgPSB0aGlzLmdldFNlcnZlclJvb3RVcmwodXJsKTtcbiAgICAgICAgdmFyIGV4aXN0aW5nVG9rZW4gPSB0aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF07XG4gICAgICAgIGlmIChleGlzdGluZ1Rva2VuICYmXG4gICAgICAgICAgICBleGlzdGluZ1Rva2VuLmV4cGlyZXMgJiZcbiAgICAgICAgICAgIGV4aXN0aW5nVG9rZW4uZXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGV4aXN0aW5nVG9rZW4udG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdID0gdGhpcy5mZXRjaEF1dGhvcml6ZWREb21haW5zKCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVxdWVzdChyb290ICsgXCIvcmVzdC9pbmZvXCIsIHtcbiAgICAgICAgICAgICAgICBjcmVkZW50aWFsczogX3RoaXMuZ2V0RG9tYWluQ3JlZGVudGlhbHModXJsKSxcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlLm93bmluZ1N5c3RlbVVybCkge1xuICAgICAgICAgICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAgICAgICAgICogaWYgdGhpcyBzZXJ2ZXIgaXMgbm90IG93bmVkIGJ5IHRoaXMgcG9ydGFsXG4gICAgICAgICAgICAgICAgICAgICAqIGJhaWwgb3V0IHdpdGggYW4gZXJyb3Igc2luY2Ugd2Uga25vdyB3ZSB3b250XG4gICAgICAgICAgICAgICAgICAgICAqIGJlIGFibGUgdG8gZ2VuZXJhdGUgYSB0b2tlblxuICAgICAgICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICAgICAgaWYgKCFpc0ZlZGVyYXRlZChyZXNwb25zZS5vd25pbmdTeXN0ZW1VcmwsIF90aGlzLnBvcnRhbCkpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IodXJsICsgXCIgaXMgbm90IGZlZGVyYXRlZCB3aXRoIFwiICsgX3RoaXMucG9ydGFsICsgXCIuXCIsIFwiTk9UX0ZFREVSQVRFRFwiKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICAgICAgICAgICAgICogaWYgdGhlIHNlcnZlciBpcyBmZWRlcmF0ZWQsIHVzZSB0aGUgcmVsZXZhbnQgdG9rZW4gZW5kcG9pbnQuXG4gICAgICAgICAgICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXF1ZXN0KHJlc3BvbnNlLm93bmluZ1N5c3RlbVVybCArIFwiL3NoYXJpbmcvcmVzdC9pbmZvXCIsIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmIChyZXNwb25zZS5hdXRoSW5mbyAmJlxuICAgICAgICAgICAgICAgICAgICBfdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgICAgICAgICAqIGlmIGl0cyBhIHN0YW5kLWFsb25lIGluc3RhbmNlIG9mIEFyY0dJUyBTZXJ2ZXIgdGhhdCBkb2Vzbid0IGFkdmVydGlzZVxuICAgICAgICAgICAgICAgICAgICAgKiBmZWRlcmF0aW9uLCBidXQgdGhlIHJvb3Qgc2VydmVyIHVybCBpcyByZWNvZ25pemVkLCB1c2UgaXRzIGJ1aWx0IGluIHRva2VuIGVuZHBvaW50LlxuICAgICAgICAgICAgICAgICAgICAgKi9cbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh7XG4gICAgICAgICAgICAgICAgICAgICAgICBhdXRoSW5mbzogcmVzcG9uc2UuYXV0aEluZm8sXG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcih1cmwgKyBcIiBpcyBub3QgZmVkZXJhdGVkIHdpdGggYW55IHBvcnRhbCBhbmQgaXMgbm90IGV4cGxpY2l0bHkgdHJ1c3RlZC5cIiwgXCJOT1RfRkVERVJBVEVEXCIpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmF1dGhJbmZvLnRva2VuU2VydmljZXNVcmw7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uICh0b2tlblNlcnZpY2VzVXJsKSB7XG4gICAgICAgICAgICAgICAgLy8gYW4gZXhwaXJlZCB0b2tlbiBjYW50IGJlIHVzZWQgdG8gZ2VuZXJhdGUgYSBuZXcgdG9rZW5cbiAgICAgICAgICAgICAgICBpZiAoX3RoaXMudG9rZW4gJiYgX3RoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCkpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGdlbmVyYXRlVG9rZW4odG9rZW5TZXJ2aWNlc1VybCwge1xuICAgICAgICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdG9rZW46IF90aGlzLnRva2VuLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlcnZlclVybDogdXJsLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4cGlyYXRpb246IF90aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50OiBcInJlZmVyZXJcIixcbiAgICAgICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAvLyBnZW5lcmF0ZSBhbiBlbnRpcmVseSBmcmVzaCB0b2tlbiBpZiBuZWNlc3NhcnlcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBnZW5lcmF0ZVRva2VuKHRva2VuU2VydmljZXNVcmwsIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHVzZXJuYW1lOiBfdGhpcy51c2VybmFtZSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXNzd29yZDogX3RoaXMucGFzc3dvcmQsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZXhwaXJhdGlvbjogX3RoaXMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjbGllbnQ6IFwicmVmZXJlclwiLFxuICAgICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IG5ldyBEYXRlKHJlc3BvbnNlLmV4cGlyZXMpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIF90aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF0gPSB7XG4gICAgICAgICAgICAgICAgICAgIGV4cGlyZXM6IG5ldyBEYXRlKHJlc3BvbnNlLmV4cGlyZXMpLFxuICAgICAgICAgICAgICAgICAgICB0b2tlbjogcmVzcG9uc2UudG9rZW4sXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICBkZWxldGUgX3RoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3Jvb3RdO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmV0dXJucyBhbiB1bmV4cGlyZWQgdG9rZW4gZm9yIHRoZSBjdXJyZW50IGBwb3J0YWxgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRGcmVzaFRva2VuID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLnRva2VuICYmICF0aGlzLnRva2VuRXhwaXJlcykge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLnRva2VuKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy50b2tlbiAmJlxuICAgICAgICAgICAgdGhpcy50b2tlbkV4cGlyZXMgJiZcbiAgICAgICAgICAgIHRoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCkpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy50b2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1t0aGlzLnBvcnRhbF0pIHtcbiAgICAgICAgICAgIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3RoaXMucG9ydGFsXSA9IHRoaXMucmVmcmVzaFNlc3Npb24ocmVxdWVzdE9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHNlc3Npb24pIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbX3RoaXMucG9ydGFsXSA9IG51bGw7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHNlc3Npb24udG9rZW47XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbdGhpcy5wb3J0YWxdO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogUmVmcmVzaGVzIHRoZSBjdXJyZW50IGB0b2tlbmAgYW5kIGB0b2tlbkV4cGlyZXNgIHdpdGggYHVzZXJuYW1lYCBhbmRcbiAgICAgKiBgcGFzc3dvcmRgLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5yZWZyZXNoV2l0aFVzZXJuYW1lQW5kUGFzc3dvcmQgPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IHBhcmFtczoge1xuICAgICAgICAgICAgICAgIHVzZXJuYW1lOiB0aGlzLnVzZXJuYW1lLFxuICAgICAgICAgICAgICAgIHBhc3N3b3JkOiB0aGlzLnBhc3N3b3JkLFxuICAgICAgICAgICAgICAgIGV4cGlyYXRpb246IHRoaXMudG9rZW5EdXJhdGlvbixcbiAgICAgICAgICAgIH0gfSwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gZ2VuZXJhdGVUb2tlbih0aGlzLnBvcnRhbCArIFwiL2dlbmVyYXRlVG9rZW5cIiwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IG5ldyBEYXRlKHJlc3BvbnNlLmV4cGlyZXMpO1xuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJlZnJlc2hlcyB0aGUgY3VycmVudCBgdG9rZW5gIGFuZCBgdG9rZW5FeHBpcmVzYCB3aXRoIGByZWZyZXNoVG9rZW5gLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5yZWZyZXNoV2l0aFJlZnJlc2hUb2tlbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy5yZWZyZXNoVG9rZW4gJiZcbiAgICAgICAgICAgIHRoaXMucmVmcmVzaFRva2VuRXhwaXJlcyAmJlxuICAgICAgICAgICAgdGhpcy5yZWZyZXNoVG9rZW5FeHBpcmVzLmdldFRpbWUoKSA8IERhdGUubm93KCkpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hSZWZyZXNoVG9rZW4ocmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBjbGllbnRfaWQ6IHRoaXMuY2xpZW50SWQsXG4gICAgICAgICAgICAgICAgcmVmcmVzaF90b2tlbjogdGhpcy5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICAgICAgZ3JhbnRfdHlwZTogXCJyZWZyZXNoX3Rva2VuXCIsXG4gICAgICAgICAgICB9IH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIGZldGNoVG9rZW4odGhpcy5wb3J0YWwgKyBcIi9vYXV0aDIvdG9rZW5cIiwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IHJlc3BvbnNlLmV4cGlyZXM7XG4gICAgICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRXhjaGFuZ2VzIGFuIHVuZXhwaXJlZCBgcmVmcmVzaFRva2VuYCBmb3IgYSBuZXcgb25lLCBhbHNvIHVwZGF0ZXMgYHRva2VuYCBhbmRcbiAgICAgKiBgdG9rZW5FeHBpcmVzYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFJlZnJlc2hUb2tlbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgY2xpZW50X2lkOiB0aGlzLmNsaWVudElkLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgICAgIHJlZGlyZWN0X3VyaTogdGhpcy5yZWRpcmVjdFVyaSxcbiAgICAgICAgICAgICAgICBncmFudF90eXBlOiBcImV4Y2hhbmdlX3JlZnJlc2hfdG9rZW5cIixcbiAgICAgICAgICAgIH0gfSwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gZmV0Y2hUb2tlbih0aGlzLnBvcnRhbCArIFwiL29hdXRoMi90b2tlblwiLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuID0gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW5FeHBpcmVzID0gcmVzcG9uc2UuZXhwaXJlcztcbiAgICAgICAgICAgIF90aGlzLl9yZWZyZXNoVG9rZW4gPSByZXNwb25zZS5yZWZyZXNoVG9rZW47XG4gICAgICAgICAgICBfdGhpcy5fcmVmcmVzaFRva2VuRXhwaXJlcyA9IG5ldyBEYXRlKERhdGUubm93KCkgKyAoX3RoaXMucmVmcmVzaFRva2VuVFRMIC0gMSkgKiA2MCAqIDEwMDApO1xuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIGVuc3VyZXMgdGhhdCB0aGUgYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWlucyBhcmUgb2J0YWluZWQgZnJvbSB0aGUgcG9ydGFsIGFuZCBjYWNoZWRcbiAgICAgKiBzbyB3ZSBjYW4gY2hlY2sgdGhlbSBsYXRlci5cbiAgICAgKlxuICAgICAqIEByZXR1cm5zIHRoaXNcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZmV0Y2hBdXRob3JpemVkRG9tYWlucyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgLy8gaWYgdGhpcyB0b2tlbiBpcyBmb3IgYSBzcGVjaWZpYyBzZXJ2ZXIgb3Igd2UgZG9uJ3QgaGF2ZSBhIHBvcnRhbFxuICAgICAgICAvLyBkb24ndCBnZXQgdGhlIHBvcnRhbCBpbmZvIGJlY2F1c2Ugd2UgY2FudCBnZXQgdGhlIGF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnNcbiAgICAgICAgaWYgKHRoaXMuc2VydmVyIHx8ICF0aGlzLnBvcnRhbCkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdGhpcy5nZXRQb3J0YWwoKS50aGVuKGZ1bmN0aW9uIChwb3J0YWxJbmZvKSB7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIFNwZWNpZmljIGRvbWFpbnMgY2FuIGJlIGNvbmZpZ3VyZWQgYXMgc2VjdXJlLmVzcmkuY29tIG9yIGh0dHBzOi8vc2VjdXJlLmVzcmkuY29tIHRoaXNcbiAgICAgICAgICAgICAqIG5vcm1hbGl6ZXMgdG8gaHR0cHM6Ly9zZWN1cmUuZXNyaS5jb20gc28gd2UgY2FuIHVzZSBzdGFydHNXaXRoIGxhdGVyLlxuICAgICAgICAgICAgICovXG4gICAgICAgICAgICBpZiAocG9ydGFsSW5mby5hdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zICYmXG4gICAgICAgICAgICAgICAgcG9ydGFsSW5mby5hdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zLmxlbmd0aCkge1xuICAgICAgICAgICAgICAgIF90aGlzLnRydXN0ZWREb21haW5zID0gcG9ydGFsSW5mby5hdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zXG4gICAgICAgICAgICAgICAgICAgIC5maWx0ZXIoZnVuY3Rpb24gKGQpIHsgcmV0dXJuICFkLnN0YXJ0c1dpdGgoXCJodHRwOi8vXCIpOyB9KVxuICAgICAgICAgICAgICAgICAgICAubWFwKGZ1bmN0aW9uIChkKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmIChkLnN0YXJ0c1dpdGgoXCJodHRwczovL1wiKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gXCJodHRwczovL1wiICsgZDtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBVc2VyU2Vzc2lvbjtcbn0oKSk7XG5leHBvcnQgeyBVc2VyU2Vzc2lvbiB9O1xuLy8jIHNvdXJjZU1hcHBpbmdVUkw9VXNlclNlc3Npb24uanMubWFwIiwiaW1wb3J0IHsgY2xlYW5VcmwgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBVc2VkIHRvIHRlc3QgaWYgYSBVUkwgaXMgYW4gQXJjR0lTIE9ubGluZSBVUkxcbiAqL1xudmFyIGFyY2dpc09ubGluZVVybFJlZ2V4ID0gL15odHRwcz86XFwvXFwvKFxcUyspXFwuYXJjZ2lzXFwuY29tLisvO1xuLyoqXG4gKiBVc2VkIHRvIHRlc3QgaWYgYSBVUkwgaXMgcHJvZHVjdGlvbiBBcmNHSVMgT25saW5lIFBvcnRhbFxuICovXG52YXIgYXJjZ2lzT25saW5lUG9ydGFsUmVnZXggPSAvXmh0dHBzPzpcXC9cXC8oZGV2fGRldmV4dHxxYXxxYWV4dHx3d3cpXFwuYXJjZ2lzXFwuY29tXFwvc2hhcmluZ1xcL3Jlc3QrLztcbi8qKlxuICogVXNlZCB0byB0ZXN0IGlmIGEgVVJMIGlzIGFuIEFyY0dJUyBPbmxpbmUgT3JnYW5pemF0aW9uIFBvcnRhbFxuICovXG52YXIgYXJjZ2lzT25saW5lT3JnUG9ydGFsUmVnZXggPSAvXmh0dHBzPzpcXC9cXC8oPzpbYS16MC05LV0rXFwubWFwcyhkZXZ8ZGV2ZXh0fHFhfHFhZXh0KT8pPy5hcmNnaXNcXC5jb21cXC9zaGFyaW5nXFwvcmVzdC87XG5leHBvcnQgZnVuY3Rpb24gaXNPbmxpbmUodXJsKSB7XG4gICAgcmV0dXJuIGFyY2dpc09ubGluZVVybFJlZ2V4LnRlc3QodXJsKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBub3JtYWxpemVPbmxpbmVQb3J0YWxVcmwocG9ydGFsVXJsKSB7XG4gICAgaWYgKCFhcmNnaXNPbmxpbmVVcmxSZWdleC50ZXN0KHBvcnRhbFVybCkpIHtcbiAgICAgICAgcmV0dXJuIHBvcnRhbFVybDtcbiAgICB9XG4gICAgc3dpdGNoIChnZXRPbmxpbmVFbnZpcm9ubWVudChwb3J0YWxVcmwpKSB7XG4gICAgICAgIGNhc2UgXCJkZXZcIjpcbiAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vZGV2ZXh0LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgICAgIGNhc2UgXCJxYVwiOlxuICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly9xYWV4dC5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICB9XG59XG5leHBvcnQgZnVuY3Rpb24gZ2V0T25saW5lRW52aXJvbm1lbnQodXJsKSB7XG4gICAgaWYgKCFhcmNnaXNPbmxpbmVVcmxSZWdleC50ZXN0KHVybCkpIHtcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHZhciBtYXRjaCA9IHVybC5tYXRjaChhcmNnaXNPbmxpbmVVcmxSZWdleCk7XG4gICAgdmFyIHN1YmRvbWFpbiA9IG1hdGNoWzFdLnNwbGl0KFwiLlwiKS5wb3AoKTtcbiAgICBpZiAoc3ViZG9tYWluLmluY2x1ZGVzKFwiZGV2XCIpKSB7XG4gICAgICAgIHJldHVybiBcImRldlwiO1xuICAgIH1cbiAgICBpZiAoc3ViZG9tYWluLmluY2x1ZGVzKFwicWFcIikpIHtcbiAgICAgICAgcmV0dXJuIFwicWFcIjtcbiAgICB9XG4gICAgcmV0dXJuIFwicHJvZHVjdGlvblwiO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGlzRmVkZXJhdGVkKG93bmluZ1N5c3RlbVVybCwgcG9ydGFsVXJsKSB7XG4gICAgdmFyIG5vcm1hbGl6ZWRQb3J0YWxVcmwgPSBjbGVhblVybChub3JtYWxpemVPbmxpbmVQb3J0YWxVcmwocG9ydGFsVXJsKSkucmVwbGFjZSgvaHR0cHM/OlxcL1xcLy8sIFwiXCIpO1xuICAgIHZhciBub3JtYWxpemVkT3duaW5nU3lzdGVtVXJsID0gY2xlYW5Vcmwob3duaW5nU3lzdGVtVXJsKS5yZXBsYWNlKC9odHRwcz86XFwvXFwvLywgXCJcIik7XG4gICAgcmV0dXJuIG5ldyBSZWdFeHAobm9ybWFsaXplZE93bmluZ1N5c3RlbVVybCwgXCJpXCIpLnRlc3Qobm9ybWFsaXplZFBvcnRhbFVybCk7XG59XG5leHBvcnQgZnVuY3Rpb24gY2FuVXNlT25saW5lVG9rZW4ocG9ydGFsVXJsLCByZXF1ZXN0VXJsKSB7XG4gICAgdmFyIHBvcnRhbElzT25saW5lID0gaXNPbmxpbmUocG9ydGFsVXJsKTtcbiAgICB2YXIgcmVxdWVzdElzT25saW5lID0gaXNPbmxpbmUocmVxdWVzdFVybCk7XG4gICAgdmFyIHBvcnRhbEVudiA9IGdldE9ubGluZUVudmlyb25tZW50KHBvcnRhbFVybCk7XG4gICAgdmFyIHJlcXVlc3RFbnYgPSBnZXRPbmxpbmVFbnZpcm9ubWVudChyZXF1ZXN0VXJsKTtcbiAgICBpZiAocG9ydGFsSXNPbmxpbmUgJiYgcmVxdWVzdElzT25saW5lICYmIHBvcnRhbEVudiA9PT0gcmVxdWVzdEVudikge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgcmV0dXJuIGZhbHNlO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZmVkZXJhdGlvbi11dGlscy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcmVxdWVzdCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG5leHBvcnQgZnVuY3Rpb24gZmV0Y2hUb2tlbih1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIG9wdGlvbnMgPSByZXF1ZXN0T3B0aW9ucztcbiAgICAvLyB3ZSBnZW5lcmF0ZSBhIHJlc3BvbnNlLCBzbyB3ZSBjYW4ndCByZXR1cm4gdGhlIHJhdyByZXNwb25zZVxuICAgIG9wdGlvbnMucmF3UmVzcG9uc2UgPSBmYWxzZTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIHZhciByID0ge1xuICAgICAgICAgICAgdG9rZW46IHJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgIHVzZXJuYW1lOiByZXNwb25zZS51c2VybmFtZSxcbiAgICAgICAgICAgIGV4cGlyZXM6IG5ldyBEYXRlKFxuICAgICAgICAgICAgLy8gY29udmVydCBzZWNvbmRzIGluIHJlc3BvbnNlIHRvIG1pbGxpc2Vjb25kcyBhbmQgYWRkIHRoZSB2YWx1ZSB0byB0aGUgY3VycmVudCB0aW1lIHRvIGNhbGN1bGF0ZSBhIHN0YXRpYyBleHBpcmF0aW9uIHRpbWVzdGFtcFxuICAgICAgICAgICAgRGF0ZS5ub3coKSArIChyZXNwb25zZS5leHBpcmVzX2luICogMTAwMCAtIDEwMDApKSxcbiAgICAgICAgICAgIHNzbDogcmVzcG9uc2Uuc3NsID09PSB0cnVlXG4gICAgICAgIH07XG4gICAgICAgIGlmIChyZXNwb25zZS5yZWZyZXNoX3Rva2VuKSB7XG4gICAgICAgICAgICByLnJlZnJlc2hUb2tlbiA9IHJlc3BvbnNlLnJlZnJlc2hfdG9rZW47XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHI7XG4gICAgfSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1mZXRjaC10b2tlbi5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyByZXF1ZXN0LCBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUiwgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuZXhwb3J0IGZ1bmN0aW9uIGdlbmVyYXRlVG9rZW4odXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBvcHRpb25zID0gcmVxdWVzdE9wdGlvbnM7XG4gICAgLyogaXN0YW5idWwgaWdub3JlIGVsc2UgKi9cbiAgICBpZiAodHlwZW9mIHdpbmRvdyAhPT0gXCJ1bmRlZmluZWRcIiAmJlxuICAgICAgICB3aW5kb3cubG9jYXRpb24gJiZcbiAgICAgICAgd2luZG93LmxvY2F0aW9uLmhvc3QpIHtcbiAgICAgICAgb3B0aW9ucy5wYXJhbXMucmVmZXJlciA9IHdpbmRvdy5sb2NhdGlvbi5ob3N0O1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgb3B0aW9ucy5wYXJhbXMucmVmZXJlciA9IE5PREVKU19ERUZBVUxUX1JFRkVSRVJfSEVBREVSO1xuICAgIH1cbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9Z2VuZXJhdGUtdG9rZW4uanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE4LTIwMjAgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcmVxdWVzdCB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIFZhbGlkYXRlcyB0aGF0IHRoZSB1c2VyIGhhcyBhY2Nlc3MgdG8gdGhlIGFwcGxpY2F0aW9uXG4gKiBhbmQgaWYgdGhleSB1c2VyIHNob3VsZCBiZSBwcmVzZW50ZWQgYSBcIlZpZXcgT25seVwiIG1vZGVcbiAqXG4gKiBUaGlzIGlzIG9ubHkgbmVlZGVkL3ZhbGlkIGZvciBFc3JpIGFwcGxpY2F0aW9ucyB0aGF0IGFyZSBcImxpY2Vuc2VkXCJcbiAqIGFuZCBzaGlwcGVkIGluIEFyY0dJUyBPbmxpbmUgb3IgQXJjR0lTIEVudGVycHJpc2UuIE1vc3QgY3VzdG9tIGFwcGxpY2F0aW9uc1xuICogc2hvdWxkIG5vdCBuZWVkIG9yIHVzZSB0aGlzLlxuICpcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyB2YWxpZGF0ZUFwcEFjY2VzcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgnO1xuICpcbiAqIHJldHVybiB2YWxpZGF0ZUFwcEFjY2VzcygneW91ci10b2tlbicsICd0aGVDbGllbnRJZCcpXG4gKiAudGhlbigocmVzdWx0KSA9PiB7XG4gKiAgICBpZiAoIXJlc3VsdC52YWx1ZSkge1xuICogICAgICAvLyByZWRpcmVjdCBvciBzaG93IHNvbWUgb3RoZXIgdWlcbiAqICAgIH0gZWxzZSB7XG4gKiAgICAgIGlmIChyZXN1bHQudmlld09ubHlVc2VyVHlwZUFwcCkge1xuICogICAgICAgIC8vIHVzZSB0aGlzIHRvIGluZm9ybSB5b3VyIGFwcCB0byBzaG93IGEgXCJWaWV3IE9ubHlcIiBtb2RlXG4gKiAgICAgIH1cbiAqICAgIH1cbiAqIH0pXG4gKiAuY2F0Y2goKGVycikgPT4ge1xuICogIC8vIHR3byBwb3NzaWJsZSBlcnJvcnNcbiAqICAvLyBpbnZhbGlkIGNsaWVudElkOiB7XCJlcnJvclwiOntcImNvZGVcIjo0MDAsXCJtZXNzYWdlQ29kZVwiOlwiR1dNXzAwMDdcIixcIm1lc3NhZ2VcIjpcIkludmFsaWQgcmVxdWVzdFwiLFwiZGV0YWlsc1wiOltdfX1cbiAqICAvLyBpbnZhbGlkIHRva2VuOiB7XCJlcnJvclwiOntcImNvZGVcIjo0OTgsXCJtZXNzYWdlXCI6XCJJbnZhbGlkIHRva2VuLlwiLFwiZGV0YWlsc1wiOltdfX1cbiAqIH0pXG4gKiBgYGBcbiAqXG4gKiBOb3RlOiBUaGlzIGlzIG9ubHkgdXNhYmxlIGJ5IEVzcmkgYXBwbGljYXRpb25zIGhvc3RlZCBvbiAqYXJjZ2lzLmNvbSwgKmVzcmkuY29tIG9yIHdpdGhpblxuICogYW4gQXJjR0lTIEVudGVycHJpc2UgaW5zdGFsbGF0aW9uLiBDdXN0b20gYXBwbGljYXRpb25zIGNhbiBub3QgdXNlIHRoaXMuXG4gKlxuICogQHBhcmFtIHRva2VuIHBsYXRmb3JtIHRva2VuXG4gKiBAcGFyYW0gY2xpZW50SWQgYXBwbGljYXRpb24gY2xpZW50IGlkXG4gKiBAcGFyYW0gcG9ydGFsIE9wdGlvbmFsXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB2YWxpZGF0ZUFwcEFjY2Vzcyh0b2tlbiwgY2xpZW50SWQsIHBvcnRhbCkge1xuICAgIGlmIChwb3J0YWwgPT09IHZvaWQgMCkgeyBwb3J0YWwgPSBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7IH1cbiAgICB2YXIgdXJsID0gcG9ydGFsICsgXCIvb2F1dGgyL3ZhbGlkYXRlQXBwQWNjZXNzXCI7XG4gICAgdmFyIHJvID0ge1xuICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgIGY6IFwianNvblwiLFxuICAgICAgICAgICAgY2xpZW50X2lkOiBjbGllbnRJZCxcbiAgICAgICAgICAgIHRva2VuOiB0b2tlbixcbiAgICAgICAgfSxcbiAgICB9O1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgcm8pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9dmFsaWRhdGUtYXBwLWFjY2Vzcy5qcy5tYXAiLCIvKiEgKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcclxuQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uXHJcblxyXG5QZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcclxucHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLlxyXG5cclxuVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVMgV0lUSFxyXG5SRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRiBNRVJDSEFOVEFCSUxJVFlcclxuQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUiBBTlkgU1BFQ0lBTCwgRElSRUNULFxyXG5JTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST01cclxuTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1JcclxuT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUlxyXG5QRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxyXG4qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiAqL1xyXG4vKiBnbG9iYWwgUmVmbGVjdCwgUHJvbWlzZSAqL1xyXG5cclxudmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbihkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XHJcbiAgICAgICAgKHsgX19wcm90b19fOiBbXSB9IGluc3RhbmNlb2YgQXJyYXkgJiYgZnVuY3Rpb24gKGQsIGIpIHsgZC5fX3Byb3RvX18gPSBiOyB9KSB8fFxyXG4gICAgICAgIGZ1bmN0aW9uIChkLCBiKSB7IGZvciAodmFyIHAgaW4gYikgaWYgKGIuaGFzT3duUHJvcGVydHkocCkpIGRbcF0gPSBiW3BdOyB9O1xyXG4gICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHRlbmRzKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbiAgICBmdW5jdGlvbiBfXygpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGQ7IH1cclxuICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcclxufVxyXG5cclxuZXhwb3J0IHZhciBfX2Fzc2lnbiA9IGZ1bmN0aW9uKCkge1xyXG4gICAgX19hc3NpZ24gPSBPYmplY3QuYXNzaWduIHx8IGZ1bmN0aW9uIF9fYXNzaWduKHQpIHtcclxuICAgICAgICBmb3IgKHZhciBzLCBpID0gMSwgbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcclxuICAgICAgICAgICAgcyA9IGFyZ3VtZW50c1tpXTtcclxuICAgICAgICAgICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApKSB0W3BdID0gc1twXTtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHQ7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gX19hc3NpZ24uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVzdChzLCBlKSB7XHJcbiAgICB2YXIgdCA9IHt9O1xyXG4gICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApICYmIGUuaW5kZXhPZihwKSA8IDApXHJcbiAgICAgICAgdFtwXSA9IHNbcF07XHJcbiAgICBpZiAocyAhPSBudWxsICYmIHR5cGVvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzID09PSBcImZ1bmN0aW9uXCIpXHJcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIHAgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzKHMpOyBpIDwgcC5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgICAgICBpZiAoZS5pbmRleE9mKHBbaV0pIDwgMCAmJiBPYmplY3QucHJvdG90eXBlLnByb3BlcnR5SXNFbnVtZXJhYmxlLmNhbGwocywgcFtpXSkpXHJcbiAgICAgICAgICAgICAgICB0W3BbaV1dID0gc1twW2ldXTtcclxuICAgICAgICB9XHJcbiAgICByZXR1cm4gdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpIHtcclxuICAgIHZhciBjID0gYXJndW1lbnRzLmxlbmd0aCwgciA9IGMgPCAzID8gdGFyZ2V0IDogZGVzYyA9PT0gbnVsbCA/IGRlc2MgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHRhcmdldCwga2V5KSA6IGRlc2MsIGQ7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUgPT09IFwiZnVuY3Rpb25cIikgciA9IFJlZmxlY3QuZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpO1xyXG4gICAgZWxzZSBmb3IgKHZhciBpID0gZGVjb3JhdG9ycy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkgaWYgKGQgPSBkZWNvcmF0b3JzW2ldKSByID0gKGMgPCAzID8gZChyKSA6IGMgPiAzID8gZCh0YXJnZXQsIGtleSwgcikgOiBkKHRhcmdldCwga2V5KSkgfHwgcjtcclxuICAgIHJldHVybiBjID4gMyAmJiByICYmIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0YXJnZXQsIGtleSwgciksIHI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3BhcmFtKHBhcmFtSW5kZXgsIGRlY29yYXRvcikge1xyXG4gICAgcmV0dXJuIGZ1bmN0aW9uICh0YXJnZXQsIGtleSkgeyBkZWNvcmF0b3IodGFyZ2V0LCBrZXksIHBhcmFtSW5kZXgpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKSB7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QubWV0YWRhdGEgPT09IFwiZnVuY3Rpb25cIikgcmV0dXJuIFJlZmxlY3QubWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdGVyKHRoaXNBcmcsIF9hcmd1bWVudHMsIFAsIGdlbmVyYXRvcikge1xyXG4gICAgZnVuY3Rpb24gYWRvcHQodmFsdWUpIHsgcmV0dXJuIHZhbHVlIGluc3RhbmNlb2YgUCA/IHZhbHVlIDogbmV3IFAoZnVuY3Rpb24gKHJlc29sdmUpIHsgcmVzb2x2ZSh2YWx1ZSk7IH0pOyB9XHJcbiAgICByZXR1cm4gbmV3IChQIHx8IChQID0gUHJvbWlzZSkpKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcclxuICAgICAgICBmdW5jdGlvbiBmdWxmaWxsZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3IubmV4dCh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gcmVqZWN0ZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3JbXCJ0aHJvd1wiXSh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gc3RlcChyZXN1bHQpIHsgcmVzdWx0LmRvbmUgPyByZXNvbHZlKHJlc3VsdC52YWx1ZSkgOiBhZG9wdChyZXN1bHQudmFsdWUpLnRoZW4oZnVsZmlsbGVkLCByZWplY3RlZCk7IH1cclxuICAgICAgICBzdGVwKChnZW5lcmF0b3IgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSkpLm5leHQoKSk7XHJcbiAgICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZ2VuZXJhdG9yKHRoaXNBcmcsIGJvZHkpIHtcclxuICAgIHZhciBfID0geyBsYWJlbDogMCwgc2VudDogZnVuY3Rpb24oKSB7IGlmICh0WzBdICYgMSkgdGhyb3cgdFsxXTsgcmV0dXJuIHRbMV07IH0sIHRyeXM6IFtdLCBvcHM6IFtdIH0sIGYsIHksIHQsIGc7XHJcbiAgICByZXR1cm4gZyA9IHsgbmV4dDogdmVyYigwKSwgXCJ0aHJvd1wiOiB2ZXJiKDEpLCBcInJldHVyblwiOiB2ZXJiKDIpIH0sIHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiAoZ1tTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24oKSB7IHJldHVybiB0aGlzOyB9KSwgZztcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyByZXR1cm4gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIHN0ZXAoW24sIHZdKTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc3RlcChvcCkge1xyXG4gICAgICAgIGlmIChmKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiR2VuZXJhdG9yIGlzIGFscmVhZHkgZXhlY3V0aW5nLlwiKTtcclxuICAgICAgICB3aGlsZSAoXykgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKGYgPSAxLCB5ICYmICh0ID0gb3BbMF0gJiAyID8geVtcInJldHVyblwiXSA6IG9wWzBdID8geVtcInRocm93XCJdIHx8ICgodCA9IHlbXCJyZXR1cm5cIl0pICYmIHQuY2FsbCh5KSwgMCkgOiB5Lm5leHQpICYmICEodCA9IHQuY2FsbCh5LCBvcFsxXSkpLmRvbmUpIHJldHVybiB0O1xyXG4gICAgICAgICAgICBpZiAoeSA9IDAsIHQpIG9wID0gW29wWzBdICYgMiwgdC52YWx1ZV07XHJcbiAgICAgICAgICAgIHN3aXRjaCAob3BbMF0pIHtcclxuICAgICAgICAgICAgICAgIGNhc2UgMDogY2FzZSAxOiB0ID0gb3A7IGJyZWFrO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA0OiBfLmxhYmVsKys7IHJldHVybiB7IHZhbHVlOiBvcFsxXSwgZG9uZTogZmFsc2UgfTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNTogXy5sYWJlbCsrOyB5ID0gb3BbMV07IG9wID0gWzBdOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNzogb3AgPSBfLm9wcy5wb3AoKTsgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKCEodCA9IF8udHJ5cywgdCA9IHQubGVuZ3RoID4gMCAmJiB0W3QubGVuZ3RoIC0gMV0pICYmIChvcFswXSA9PT0gNiB8fCBvcFswXSA9PT0gMikpIHsgXyA9IDA7IGNvbnRpbnVlOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSAzICYmICghdCB8fCAob3BbMV0gPiB0WzBdICYmIG9wWzFdIDwgdFszXSkpKSB7IF8ubGFiZWwgPSBvcFsxXTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDYgJiYgXy5sYWJlbCA8IHRbMV0pIHsgXy5sYWJlbCA9IHRbMV07IHQgPSBvcDsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodCAmJiBfLmxhYmVsIDwgdFsyXSkgeyBfLmxhYmVsID0gdFsyXTsgXy5vcHMucHVzaChvcCk7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRbMl0pIF8ub3BzLnBvcCgpO1xyXG4gICAgICAgICAgICAgICAgICAgIF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgb3AgPSBib2R5LmNhbGwodGhpc0FyZywgXyk7XHJcbiAgICAgICAgfSBjYXRjaCAoZSkgeyBvcCA9IFs2LCBlXTsgeSA9IDA7IH0gZmluYWxseSB7IGYgPSB0ID0gMDsgfVxyXG4gICAgICAgIGlmIChvcFswXSAmIDUpIHRocm93IG9wWzFdOyByZXR1cm4geyB2YWx1ZTogb3BbMF0gPyBvcFsxXSA6IHZvaWQgMCwgZG9uZTogdHJ1ZSB9O1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jcmVhdGVCaW5kaW5nKG8sIG0sIGssIGsyKSB7XHJcbiAgICBpZiAoazIgPT09IHVuZGVmaW5lZCkgazIgPSBrO1xyXG4gICAgb1trMl0gPSBtW2tdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHBvcnRTdGFyKG0sIGV4cG9ydHMpIHtcclxuICAgIGZvciAodmFyIHAgaW4gbSkgaWYgKHAgIT09IFwiZGVmYXVsdFwiICYmICFleHBvcnRzLmhhc093blByb3BlcnR5KHApKSBleHBvcnRzW3BdID0gbVtwXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fdmFsdWVzKG8pIHtcclxuICAgIHZhciBzID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIFN5bWJvbC5pdGVyYXRvciwgbSA9IHMgJiYgb1tzXSwgaSA9IDA7XHJcbiAgICBpZiAobSkgcmV0dXJuIG0uY2FsbChvKTtcclxuICAgIGlmIChvICYmIHR5cGVvZiBvLmxlbmd0aCA9PT0gXCJudW1iZXJcIikgcmV0dXJuIHtcclxuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XHJcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XHJcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcclxuICAgICAgICB9XHJcbiAgICB9O1xyXG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihzID8gXCJPYmplY3QgaXMgbm90IGl0ZXJhYmxlLlwiIDogXCJTeW1ib2wuaXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZWFkKG8sIG4pIHtcclxuICAgIHZhciBtID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIG9bU3ltYm9sLml0ZXJhdG9yXTtcclxuICAgIGlmICghbSkgcmV0dXJuIG87XHJcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcclxuICAgIHRyeSB7XHJcbiAgICAgICAgd2hpbGUgKChuID09PSB2b2lkIDAgfHwgbi0tID4gMCkgJiYgIShyID0gaS5uZXh0KCkpLmRvbmUpIGFyLnB1c2goci52YWx1ZSk7XHJcbiAgICB9XHJcbiAgICBjYXRjaCAoZXJyb3IpIHsgZSA9IHsgZXJyb3I6IGVycm9yIH07IH1cclxuICAgIGZpbmFsbHkge1xyXG4gICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChyICYmICFyLmRvbmUgJiYgKG0gPSBpW1wicmV0dXJuXCJdKSkgbS5jYWxsKGkpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cclxuICAgIH1cclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkKCkge1xyXG4gICAgZm9yICh2YXIgYXIgPSBbXSwgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspXHJcbiAgICAgICAgYXIgPSBhci5jb25jYXQoX19yZWFkKGFyZ3VtZW50c1tpXSkpO1xyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWRBcnJheXMoKSB7XHJcbiAgICBmb3IgKHZhciBzID0gMCwgaSA9IDAsIGlsID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGlsOyBpKyspIHMgKz0gYXJndW1lbnRzW2ldLmxlbmd0aDtcclxuICAgIGZvciAodmFyIHIgPSBBcnJheShzKSwgayA9IDAsIGkgPSAwOyBpIDwgaWw7IGkrKylcclxuICAgICAgICBmb3IgKHZhciBhID0gYXJndW1lbnRzW2ldLCBqID0gMCwgamwgPSBhLmxlbmd0aDsgaiA8IGpsOyBqKyssIGsrKylcclxuICAgICAgICAgICAgcltrXSA9IGFbal07XHJcbiAgICByZXR1cm4gcjtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0KHYpIHtcclxuICAgIHJldHVybiB0aGlzIGluc3RhbmNlb2YgX19hd2FpdCA/ICh0aGlzLnYgPSB2LCB0aGlzKSA6IG5ldyBfX2F3YWl0KHYpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0dlbmVyYXRvcih0aGlzQXJnLCBfYXJndW1lbnRzLCBnZW5lcmF0b3IpIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgZyA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSwgaSwgcSA9IFtdO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlmIChnW25dKSBpW25dID0gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChhLCBiKSB7IHEucHVzaChbbiwgdiwgYSwgYl0pID4gMSB8fCByZXN1bWUobiwgdik7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiByZXN1bWUobiwgdikgeyB0cnkgeyBzdGVwKGdbbl0odikpOyB9IGNhdGNoIChlKSB7IHNldHRsZShxWzBdWzNdLCBlKTsgfSB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKHIpIHsgci52YWx1ZSBpbnN0YW5jZW9mIF9fYXdhaXQgPyBQcm9taXNlLnJlc29sdmUoci52YWx1ZS52KS50aGVuKGZ1bGZpbGwsIHJlamVjdCkgOiBzZXR0bGUocVswXVsyXSwgcik7IH1cclxuICAgIGZ1bmN0aW9uIGZ1bGZpbGwodmFsdWUpIHsgcmVzdW1lKFwibmV4dFwiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHJlamVjdCh2YWx1ZSkgeyByZXN1bWUoXCJ0aHJvd1wiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShmLCB2KSB7IGlmIChmKHYpLCBxLnNoaWZ0KCksIHEubGVuZ3RoKSByZXN1bWUocVswXVswXSwgcVswXVsxXSk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNEZWxlZ2F0b3Iobykge1xyXG4gICAgdmFyIGksIHA7XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIsIGZ1bmN0aW9uIChlKSB7IHRocm93IGU7IH0pLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuLCBmKSB7IGlbbl0gPSBvW25dID8gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIChwID0gIXApID8geyB2YWx1ZTogX19hd2FpdChvW25dKHYpKSwgZG9uZTogbiA9PT0gXCJyZXR1cm5cIiB9IDogZiA/IGYodikgOiB2OyB9IDogZjsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY1ZhbHVlcyhvKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIG0gPSBvW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSwgaTtcclxuICAgIHJldHVybiBtID8gbS5jYWxsKG8pIDogKG8gPSB0eXBlb2YgX192YWx1ZXMgPT09IFwiZnVuY3Rpb25cIiA/IF9fdmFsdWVzKG8pIDogb1tTeW1ib2wuaXRlcmF0b3JdKCksIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpKTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpW25dID0gb1tuXSAmJiBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkgeyB2ID0gb1tuXSh2KSwgc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgdi5kb25lLCB2LnZhbHVlKTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShyZXNvbHZlLCByZWplY3QsIGQsIHYpIHsgUHJvbWlzZS5yZXNvbHZlKHYpLnRoZW4oZnVuY3Rpb24odikgeyByZXNvbHZlKHsgdmFsdWU6IHYsIGRvbmU6IGQgfSk7IH0sIHJlamVjdCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWFrZVRlbXBsYXRlT2JqZWN0KGNvb2tlZCwgcmF3KSB7XHJcbiAgICBpZiAoT2JqZWN0LmRlZmluZVByb3BlcnR5KSB7IE9iamVjdC5kZWZpbmVQcm9wZXJ0eShjb29rZWQsIFwicmF3XCIsIHsgdmFsdWU6IHJhdyB9KTsgfSBlbHNlIHsgY29va2VkLnJhdyA9IHJhdzsgfVxyXG4gICAgcmV0dXJuIGNvb2tlZDtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydFN0YXIobW9kKSB7XHJcbiAgICBpZiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSByZXR1cm4gbW9kO1xyXG4gICAgdmFyIHJlc3VsdCA9IHt9O1xyXG4gICAgaWYgKG1vZCAhPSBudWxsKSBmb3IgKHZhciBrIGluIG1vZCkgaWYgKE9iamVjdC5oYXNPd25Qcm9wZXJ0eS5jYWxsKG1vZCwgaykpIHJlc3VsdFtrXSA9IG1vZFtrXTtcclxuICAgIHJlc3VsdC5kZWZhdWx0ID0gbW9kO1xyXG4gICAgcmV0dXJuIHJlc3VsdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0RGVmYXVsdChtb2QpIHtcclxuICAgIHJldHVybiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSA/IG1vZCA6IHsgZGVmYXVsdDogbW9kIH07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkR2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gZ2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHByaXZhdGVNYXAuZ2V0KHJlY2VpdmVyKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRTZXQocmVjZWl2ZXIsIHByaXZhdGVNYXAsIHZhbHVlKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gc2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcHJpdmF0ZU1hcC5zZXQocmVjZWl2ZXIsIHZhbHVlKTtcclxuICAgIHJldHVybiB2YWx1ZTtcclxufVxyXG4iLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgYWRkRmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBhZGRGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwczovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9TZXJ2aWNlUmVxdWVzdC9GZWF0dXJlU2VydmVyLzBcIixcbiAqICAgZmVhdHVyZXM6IFt7XG4gKiAgICAgZ2VvbWV0cnk6IHsgeDogLTEyMCwgeTogNDUsIHNwYXRpYWxSZWZlcmVuY2U6IHsgd2tpZDogNDMyNiB9IH0sXG4gKiAgICAgYXR0cmlidXRlczogeyBzdGF0dXM6IFwiYWxpdmVcIiB9XG4gKiAgIH1dXG4gKiB9KVxuICogICAudGhlbihyZXNwb25zZSlcbiAqIGBgYFxuICogQWRkIGZlYXR1cmVzIHJlcXVlc3QuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvYWRkLWZlYXR1cmVzLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgYWRkRmVhdHVyZXMgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhZGRGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvYWRkRmVhdHVyZXNcIjtcbiAgICAvLyBlZGl0IG9wZXJhdGlvbnMgYXJlIFBPU1Qgb25seVxuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXCJmZWF0dXJlc1wiLCBcImdkYlZlcnNpb25cIiwgXCJyZXR1cm5FZGl0TW9tZW50XCIsIFwicm9sbGJhY2tPbkZhaWx1cmVcIl0sIHsgcGFyYW1zOiBfX2Fzc2lnbih7fSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSB9KTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9YWRkLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBkZWxldGVGZWF0dXJlcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIGRlbGV0ZUZlYXR1cmVzKHtcbiAqICAgdXJsOiBcImh0dHBzOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL1NlcnZpY2VSZXF1ZXN0L0ZlYXR1cmVTZXJ2ZXIvMFwiLFxuICogICBvYmplY3RJZHM6IFsxLDIsM11cbiAqIH0pO1xuICogYGBgXG4gKiBEZWxldGUgZmVhdHVyZXMgcmVxdWVzdC4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9kZWxldGUtZmVhdHVyZXMuaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gZGVsZXRlRmVhdHVyZXNSZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGRlbGV0ZUZlYXR1cmVzIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZGVsZXRlRmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL2RlbGV0ZUZlYXR1cmVzXCI7XG4gICAgLy8gZWRpdCBvcGVyYXRpb25zIFBPU1Qgb25seVxuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXG4gICAgICAgIFwid2hlcmVcIixcbiAgICAgICAgXCJvYmplY3RJZHNcIixcbiAgICAgICAgXCJnZGJWZXJzaW9uXCIsXG4gICAgICAgIFwicmV0dXJuRWRpdE1vbWVudFwiLFxuICAgICAgICBcInJvbGxiYWNrT25GYWlsdXJlXCJcbiAgICBdLCB7IHBhcmFtczogX19hc3NpZ24oe30sIHJlcXVlc3RPcHRpb25zLnBhcmFtcykgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRlbGV0ZS5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBnZXRGZWF0dXJlIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogY29uc3QgdXJsID0gXCJodHRwczovL3NlcnZpY2VzLmFyY2dpcy5jb20vVjZaSEZyNnpkZ05adVZHMC9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9MYW5kc2NhcGVfVHJlZXMvRmVhdHVyZVNlcnZlci8wXCI7XG4gKiAvL1xuICogZ2V0RmVhdHVyZSh7XG4gKiAgIHVybCxcbiAqICAgaWQ6IDQyXG4gKiB9KS50aGVuKGZlYXR1cmUgPT4ge1xuICogIGNvbnNvbGUubG9nKGZlYXR1cmUuYXR0cmlidXRlcy5GSUQpOyAvLyA0MlxuICogfSk7XG4gKiBgYGBcbiAqIEdldCBhIGZlYXR1cmUgYnkgaWQuXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3RcbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBmZWF0dXJlIG9yIHRoZSBbcmVzcG9uc2VdKGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9SZXNwb25zZSkgaXRzZWxmIGlmIGByYXdSZXNwb25zZTogdHJ1ZWAgd2FzIHBhc3NlZCBpbi5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldEZlYXR1cmUocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL1wiICsgcmVxdWVzdE9wdGlvbnMuaWQ7XG4gICAgLy8gZGVmYXVsdCB0byBhIEdFVCByZXF1ZXN0XG4gICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiR0VUXCIgfSwgcmVxdWVzdE9wdGlvbnMpO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKG9wdGlvbnMucmF3UmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcmVzcG9uc2UuZmVhdHVyZTtcbiAgICB9KTtcbn1cbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IHF1ZXJ5RmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBxdWVyeUZlYXR1cmVzKHtcbiAqICAgdXJsOiBcImh0dHA6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvQ2Vuc3VzL01hcFNlcnZlci8zXCIsXG4gKiAgIHdoZXJlOiBcIlNUQVRFX05BTUUgPSAnQWxhc2thJ1wiXG4gKiB9KVxuICogICAudGhlbihyZXN1bHQpXG4gKiBgYGBcbiAqIFF1ZXJ5IGEgZmVhdHVyZSBzZXJ2aWNlLiBTZWUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvcXVlcnktZmVhdHVyZS1zZXJ2aWNlLWxheWVyLS5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0XG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgcXVlcnkgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBxdWVyeUZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHF1ZXJ5T3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1xuICAgICAgICBcIndoZXJlXCIsXG4gICAgICAgIFwib2JqZWN0SWRzXCIsXG4gICAgICAgIFwicmVsYXRpb25QYXJhbVwiLFxuICAgICAgICBcInRpbWVcIixcbiAgICAgICAgXCJkaXN0YW5jZVwiLFxuICAgICAgICBcInVuaXRzXCIsXG4gICAgICAgIFwib3V0RmllbGRzXCIsXG4gICAgICAgIFwiZ2VvbWV0cnlcIixcbiAgICAgICAgXCJnZW9tZXRyeVR5cGVcIixcbiAgICAgICAgXCJzcGF0aWFsUmVsXCIsXG4gICAgICAgIFwicmV0dXJuR2VvbWV0cnlcIixcbiAgICAgICAgXCJtYXhBbGxvd2FibGVPZmZzZXRcIixcbiAgICAgICAgXCJnZW9tZXRyeVByZWNpc2lvblwiLFxuICAgICAgICBcImluU1JcIixcbiAgICAgICAgXCJvdXRTUlwiLFxuICAgICAgICBcImdkYlZlcnNpb25cIixcbiAgICAgICAgXCJyZXR1cm5EaXN0aW5jdFZhbHVlc1wiLFxuICAgICAgICBcInJldHVybklkc09ubHlcIixcbiAgICAgICAgXCJyZXR1cm5Db3VudE9ubHlcIixcbiAgICAgICAgXCJyZXR1cm5FeHRlbnRPbmx5XCIsXG4gICAgICAgIFwib3JkZXJCeUZpZWxkc1wiLFxuICAgICAgICBcImdyb3VwQnlGaWVsZHNGb3JTdGF0aXN0aWNzXCIsXG4gICAgICAgIFwib3V0U3RhdGlzdGljc1wiLFxuICAgICAgICBcInJldHVyblpcIixcbiAgICAgICAgXCJyZXR1cm5NXCIsXG4gICAgICAgIFwibXVsdGlwYXRjaE9wdGlvblwiLFxuICAgICAgICBcInJlc3VsdE9mZnNldFwiLFxuICAgICAgICBcInJlc3VsdFJlY29yZENvdW50XCIsXG4gICAgICAgIFwicXVhbnRpemF0aW9uUGFyYW1ldGVyc1wiLFxuICAgICAgICBcInJldHVybkNlbnRyb2lkXCIsXG4gICAgICAgIFwicmVzdWx0VHlwZVwiLFxuICAgICAgICBcImhpc3RvcmljTW9tZW50XCIsXG4gICAgICAgIFwicmV0dXJuVHJ1ZUN1cnZlc1wiLFxuICAgICAgICBcInNxbEZvcm1hdFwiLFxuICAgICAgICBcInJldHVybkV4Y2VlZGVkTGltaXRGZWF0dXJlc1wiLFxuICAgICAgICBcImZcIlxuICAgIF0sIHtcbiAgICAgICAgaHR0cE1ldGhvZDogXCJHRVRcIixcbiAgICAgICAgcGFyYW1zOiBfX2Fzc2lnbih7IFxuICAgICAgICAgICAgLy8gc2V0IGRlZmF1bHQgcXVlcnkgcGFyYW1ldGVyc1xuICAgICAgICAgICAgd2hlcmU6IFwiMT0xXCIsIG91dEZpZWxkczogXCIqXCIgfSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKVxuICAgIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9xdWVyeVwiLCBxdWVyeU9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cXVlcnkuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICpcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBxdWVyeVJlbGF0ZWQgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJ1xuICogLy9cbiAqIHF1ZXJ5UmVsYXRlZCh7XG4gKiAgdXJsOiBcImh0dHA6Ly9zZXJ2aWNlcy5teXNlcnZlci9PcmdJRC9BcmNHSVMvcmVzdC9zZXJ2aWNlcy9QZXRyb2xldW0vS1NQZXRyby9GZWF0dXJlU2VydmVyLzBcIixcbiAqICByZWxhdGlvbnNoaXBJZDogMSxcbiAqICBwYXJhbXM6IHsgcmV0dXJuQ291bnRPbmx5OiB0cnVlIH1cbiAqIH0pXG4gKiAgLnRoZW4ocmVzcG9uc2UpIC8vIHJlc3BvbnNlLnJlbGF0ZWRSZWNvcmRzXG4gKiBgYGBcbiAqIFF1ZXJ5IHRoZSByZWxhdGVkIHJlY29yZHMgZm9yIGEgZmVhdHVyZSBzZXJ2aWNlLiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL3F1ZXJ5LXJlbGF0ZWQtcmVjb3Jkcy1mZWF0dXJlLXNlcnZpY2UtLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgcXVlcnkgcmVzcG9uc2VcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHF1ZXJ5UmVsYXRlZChyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXCJvYmplY3RJZHNcIiwgXCJyZWxhdGlvbnNoaXBJZFwiLCBcImRlZmluaXRpb25FeHByZXNzaW9uXCIsIFwib3V0RmllbGRzXCJdLCB7XG4gICAgICAgIGh0dHBNZXRob2Q6IFwiR0VUXCIsXG4gICAgICAgIHBhcmFtczogX19hc3NpZ24oeyBcbiAgICAgICAgICAgIC8vIHNldCBkZWZhdWx0IHF1ZXJ5IHBhcmFtZXRlcnNcbiAgICAgICAgICAgIGRlZmluaXRpb25FeHByZXNzaW9uOiBcIjE9MVwiLCBvdXRGaWVsZHM6IFwiKlwiLCByZWxhdGlvbnNoaXBJZDogMCB9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpXG4gICAgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QoY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL3F1ZXJ5UmVsYXRlZFJlY29yZHNcIiwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1xdWVyeVJlbGF0ZWQuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICpcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyB1cGRhdGVGZWF0dXJlcyB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIHVwZGF0ZUZlYXR1cmVzKHtcbiAqICAgdXJsOiBcImh0dHBzOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL1NlcnZpY2VSZXF1ZXN0L0ZlYXR1cmVTZXJ2ZXIvMFwiLFxuICogICBmZWF0dXJlczogW3tcbiAqICAgICBnZW9tZXRyeTogeyB4OiAtMTIwLCB5OiA0NSwgc3BhdGlhbFJlZmVyZW5jZTogeyB3a2lkOiA0MzI2IH0gfSxcbiAqICAgICBhdHRyaWJ1dGVzOiB7IHN0YXR1czogXCJhbGl2ZVwiIH1cbiAqICAgfV1cbiAqIH0pO1xuICogYGBgXG4gKiBVcGRhdGUgZmVhdHVyZXMgcmVxdWVzdC4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS91cGRhdGUtZmVhdHVyZXMuaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSB1cGRhdGVGZWF0dXJlcyByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHVwZGF0ZUZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi91cGRhdGVGZWF0dXJlc1wiO1xuICAgIC8vIGVkaXQgb3BlcmF0aW9ucyBhcmUgUE9TVCBvbmx5XG4gICAgdmFyIG9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcImZlYXR1cmVzXCIsIFwiZ2RiVmVyc2lvblwiLCBcInJldHVybkVkaXRNb21lbnRcIiwgXCJyb2xsYmFja09uRmFpbHVyZVwiLCBcInRydWVDdXJ2ZUNsaWVudFwiXSwgeyBwYXJhbXM6IF9fYXNzaWduKHt9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD11cGRhdGUuanMubWFwIiwiLyohICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXHJcbkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLlxyXG5cclxuUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XHJcbnB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZC5cclxuXHJcblRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEhcclxuUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZXHJcbkFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1IgQU5ZIFNQRUNJQUwsIERJUkVDVCxcclxuSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NXHJcbkxPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SXHJcbk9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1JcclxuUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cclxuKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogKi9cclxuLyogZ2xvYmFsIFJlZmxlY3QsIFByb21pc2UgKi9cclxuXHJcbnZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24oZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxyXG4gICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcclxuICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcclxuICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXh0ZW5kcyhkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG4gICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XHJcbiAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XHJcbn1cclxuXHJcbmV4cG9ydCB2YXIgX19hc3NpZ24gPSBmdW5jdGlvbigpIHtcclxuICAgIF9fYXNzaWduID0gT2JqZWN0LmFzc2lnbiB8fCBmdW5jdGlvbiBfX2Fzc2lnbih0KSB7XHJcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XHJcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XHJcbiAgICAgICAgICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSkgdFtwXSA9IHNbcF07XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3Jlc3QocywgZSkge1xyXG4gICAgdmFyIHQgPSB7fTtcclxuICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSAmJiBlLmluZGV4T2YocCkgPCAwKVxyXG4gICAgICAgIHRbcF0gPSBzW3BdO1xyXG4gICAgaWYgKHMgIT0gbnVsbCAmJiB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBwID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyhzKTsgaSA8IHAubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgaWYgKGUuaW5kZXhPZihwW2ldKSA8IDAgJiYgT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZS5jYWxsKHMsIHBbaV0pKVxyXG4gICAgICAgICAgICAgICAgdFtwW2ldXSA9IHNbcFtpXV07XHJcbiAgICAgICAgfVxyXG4gICAgcmV0dXJuIHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2RlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKSB7XHJcbiAgICB2YXIgYyA9IGFyZ3VtZW50cy5sZW5ndGgsIHIgPSBjIDwgMyA/IHRhcmdldCA6IGRlc2MgPT09IG51bGwgPyBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0YXJnZXQsIGtleSkgOiBkZXNjLCBkO1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0LmRlY29yYXRlID09PSBcImZ1bmN0aW9uXCIpIHIgPSBSZWZsZWN0LmRlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKTtcclxuICAgIGVsc2UgZm9yICh2YXIgaSA9IGRlY29yYXRvcnMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIGlmIChkID0gZGVjb3JhdG9yc1tpXSkgciA9IChjIDwgMyA/IGQocikgOiBjID4gMyA/IGQodGFyZ2V0LCBrZXksIHIpIDogZCh0YXJnZXQsIGtleSkpIHx8IHI7XHJcbiAgICByZXR1cm4gYyA+IDMgJiYgciAmJiBPYmplY3QuZGVmaW5lUHJvcGVydHkodGFyZ2V0LCBrZXksIHIpLCByO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19wYXJhbShwYXJhbUluZGV4LCBkZWNvcmF0b3IpIHtcclxuICAgIHJldHVybiBmdW5jdGlvbiAodGFyZ2V0LCBrZXkpIHsgZGVjb3JhdG9yKHRhcmdldCwga2V5LCBwYXJhbUluZGV4KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSkge1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0Lm1ldGFkYXRhID09PSBcImZ1bmN0aW9uXCIpIHJldHVybiBSZWZsZWN0Lm1ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXRlcih0aGlzQXJnLCBfYXJndW1lbnRzLCBQLCBnZW5lcmF0b3IpIHtcclxuICAgIGZ1bmN0aW9uIGFkb3B0KHZhbHVlKSB7IHJldHVybiB2YWx1ZSBpbnN0YW5jZW9mIFAgPyB2YWx1ZSA6IG5ldyBQKGZ1bmN0aW9uIChyZXNvbHZlKSB7IHJlc29sdmUodmFsdWUpOyB9KTsgfVxyXG4gICAgcmV0dXJuIG5ldyAoUCB8fCAoUCA9IFByb21pc2UpKShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XHJcbiAgICAgICAgZnVuY3Rpb24gZnVsZmlsbGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yLm5leHQodmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHJlamVjdGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yW1widGhyb3dcIl0odmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHN0ZXAocmVzdWx0KSB7IHJlc3VsdC5kb25lID8gcmVzb2x2ZShyZXN1bHQudmFsdWUpIDogYWRvcHQocmVzdWx0LnZhbHVlKS50aGVuKGZ1bGZpbGxlZCwgcmVqZWN0ZWQpOyB9XHJcbiAgICAgICAgc3RlcCgoZ2VuZXJhdG9yID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pKS5uZXh0KCkpO1xyXG4gICAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2dlbmVyYXRvcih0aGlzQXJnLCBib2R5KSB7XHJcbiAgICB2YXIgXyA9IHsgbGFiZWw6IDAsIHNlbnQ6IGZ1bmN0aW9uKCkgeyBpZiAodFswXSAmIDEpIHRocm93IHRbMV07IHJldHVybiB0WzFdOyB9LCB0cnlzOiBbXSwgb3BzOiBbXSB9LCBmLCB5LCB0LCBnO1xyXG4gICAgcmV0dXJuIGcgPSB7IG5leHQ6IHZlcmIoMCksIFwidGhyb3dcIjogdmVyYigxKSwgXCJyZXR1cm5cIjogdmVyYigyKSB9LCB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgKGdbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhpczsgfSksIGc7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgcmV0dXJuIGZ1bmN0aW9uICh2KSB7IHJldHVybiBzdGVwKFtuLCB2XSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAob3ApIHtcclxuICAgICAgICBpZiAoZikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy5cIik7XHJcbiAgICAgICAgd2hpbGUgKF8pIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChmID0gMSwgeSAmJiAodCA9IG9wWzBdICYgMiA/IHlbXCJyZXR1cm5cIl0gOiBvcFswXSA/IHlbXCJ0aHJvd1wiXSB8fCAoKHQgPSB5W1wicmV0dXJuXCJdKSAmJiB0LmNhbGwoeSksIDApIDogeS5uZXh0KSAmJiAhKHQgPSB0LmNhbGwoeSwgb3BbMV0pKS5kb25lKSByZXR1cm4gdDtcclxuICAgICAgICAgICAgaWYgKHkgPSAwLCB0KSBvcCA9IFtvcFswXSAmIDIsIHQudmFsdWVdO1xyXG4gICAgICAgICAgICBzd2l0Y2ggKG9wWzBdKSB7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDA6IGNhc2UgMTogdCA9IG9wOyBicmVhaztcclxuICAgICAgICAgICAgICAgIGNhc2UgNDogXy5sYWJlbCsrOyByZXR1cm4geyB2YWx1ZTogb3BbMV0sIGRvbmU6IGZhbHNlIH07XHJcbiAgICAgICAgICAgICAgICBjYXNlIDU6IF8ubGFiZWwrKzsgeSA9IG9wWzFdOyBvcCA9IFswXTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDc6IG9wID0gXy5vcHMucG9wKCk7IF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgIGlmICghKHQgPSBfLnRyeXMsIHQgPSB0Lmxlbmd0aCA+IDAgJiYgdFt0Lmxlbmd0aCAtIDFdKSAmJiAob3BbMF0gPT09IDYgfHwgb3BbMF0gPT09IDIpKSB7IF8gPSAwOyBjb250aW51ZTsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gMyAmJiAoIXQgfHwgKG9wWzFdID4gdFswXSAmJiBvcFsxXSA8IHRbM10pKSkgeyBfLmxhYmVsID0gb3BbMV07IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSA2ICYmIF8ubGFiZWwgPCB0WzFdKSB7IF8ubGFiZWwgPSB0WzFdOyB0ID0gb3A7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHQgJiYgXy5sYWJlbCA8IHRbMl0pIHsgXy5sYWJlbCA9IHRbMl07IF8ub3BzLnB1c2gob3ApOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0WzJdKSBfLm9wcy5wb3AoKTtcclxuICAgICAgICAgICAgICAgICAgICBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIG9wID0gYm9keS5jYWxsKHRoaXNBcmcsIF8pO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgb3AgPSBbNiwgZV07IHkgPSAwOyB9IGZpbmFsbHkgeyBmID0gdCA9IDA7IH1cclxuICAgICAgICBpZiAob3BbMF0gJiA1KSB0aHJvdyBvcFsxXTsgcmV0dXJuIHsgdmFsdWU6IG9wWzBdID8gb3BbMV0gOiB2b2lkIDAsIGRvbmU6IHRydWUgfTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY3JlYXRlQmluZGluZyhvLCBtLCBrLCBrMikge1xyXG4gICAgaWYgKGsyID09PSB1bmRlZmluZWQpIGsyID0gaztcclxuICAgIG9bazJdID0gbVtrXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXhwb3J0U3RhcihtLCBleHBvcnRzKSB7XHJcbiAgICBmb3IgKHZhciBwIGluIG0pIGlmIChwICE9PSBcImRlZmF1bHRcIiAmJiAhZXhwb3J0cy5oYXNPd25Qcm9wZXJ0eShwKSkgZXhwb3J0c1twXSA9IG1bcF07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3ZhbHVlcyhvKSB7XHJcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xyXG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XHJcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XHJcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xyXG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xyXG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XHJcbiAgICAgICAgfVxyXG4gICAgfTtcclxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVhZChvLCBuKSB7XHJcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XHJcbiAgICBpZiAoIW0pIHJldHVybiBvO1xyXG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xyXG4gICAgfVxyXG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XHJcbiAgICBmaW5hbGx5IHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZCgpIHtcclxuICAgIGZvciAodmFyIGFyID0gW10sIGkgPSAwOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKVxyXG4gICAgICAgIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkQXJyYXlzKCkge1xyXG4gICAgZm9yICh2YXIgcyA9IDAsIGkgPSAwLCBpbCA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBpbDsgaSsrKSBzICs9IGFyZ3VtZW50c1tpXS5sZW5ndGg7XHJcbiAgICBmb3IgKHZhciByID0gQXJyYXkocyksIGsgPSAwLCBpID0gMDsgaSA8IGlsOyBpKyspXHJcbiAgICAgICAgZm9yICh2YXIgYSA9IGFyZ3VtZW50c1tpXSwgaiA9IDAsIGpsID0gYS5sZW5ndGg7IGogPCBqbDsgaisrLCBrKyspXHJcbiAgICAgICAgICAgIHJba10gPSBhW2pdO1xyXG4gICAgcmV0dXJuIHI7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdCh2KSB7XHJcbiAgICByZXR1cm4gdGhpcyBpbnN0YW5jZW9mIF9fYXdhaXQgPyAodGhpcy52ID0gdiwgdGhpcykgOiBuZXcgX19hd2FpdCh2KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNHZW5lcmF0b3IodGhpc0FyZywgX2FyZ3VtZW50cywgZ2VuZXJhdG9yKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIGcgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSksIGksIHEgPSBbXTtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpZiAoZ1tuXSkgaVtuXSA9IGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAoYSwgYikgeyBxLnB1c2goW24sIHYsIGEsIGJdKSA+IDEgfHwgcmVzdW1lKG4sIHYpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gcmVzdW1lKG4sIHYpIHsgdHJ5IHsgc3RlcChnW25dKHYpKTsgfSBjYXRjaCAoZSkgeyBzZXR0bGUocVswXVszXSwgZSk7IH0gfVxyXG4gICAgZnVuY3Rpb24gc3RlcChyKSB7IHIudmFsdWUgaW5zdGFuY2VvZiBfX2F3YWl0ID8gUHJvbWlzZS5yZXNvbHZlKHIudmFsdWUudikudGhlbihmdWxmaWxsLCByZWplY3QpIDogc2V0dGxlKHFbMF1bMl0sIHIpOyB9XHJcbiAgICBmdW5jdGlvbiBmdWxmaWxsKHZhbHVlKSB7IHJlc3VtZShcIm5leHRcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiByZWplY3QodmFsdWUpIHsgcmVzdW1lKFwidGhyb3dcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUoZiwgdikgeyBpZiAoZih2KSwgcS5zaGlmdCgpLCBxLmxlbmd0aCkgcmVzdW1lKHFbMF1bMF0sIHFbMF1bMV0pOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jRGVsZWdhdG9yKG8pIHtcclxuICAgIHZhciBpLCBwO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiLCBmdW5jdGlvbiAoZSkgeyB0aHJvdyBlOyB9KSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobiwgZikgeyBpW25dID0gb1tuXSA/IGZ1bmN0aW9uICh2KSB7IHJldHVybiAocCA9ICFwKSA/IHsgdmFsdWU6IF9fYXdhaXQob1tuXSh2KSksIGRvbmU6IG4gPT09IFwicmV0dXJuXCIgfSA6IGYgPyBmKHYpIDogdjsgfSA6IGY7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNWYWx1ZXMobykge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBtID0gb1tTeW1ib2wuYXN5bmNJdGVyYXRvcl0sIGk7XHJcbiAgICByZXR1cm4gbSA/IG0uY2FsbChvKSA6IChvID0gdHlwZW9mIF9fdmFsdWVzID09PSBcImZ1bmN0aW9uXCIgPyBfX3ZhbHVlcyhvKSA6IG9bU3ltYm9sLml0ZXJhdG9yXSgpLCBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaSk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaVtuXSA9IG9bbl0gJiYgZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHsgdiA9IG9bbl0odiksIHNldHRsZShyZXNvbHZlLCByZWplY3QsIHYuZG9uZSwgdi52YWx1ZSk7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCBkLCB2KSB7IFByb21pc2UucmVzb2x2ZSh2KS50aGVuKGZ1bmN0aW9uKHYpIHsgcmVzb2x2ZSh7IHZhbHVlOiB2LCBkb25lOiBkIH0pOyB9LCByZWplY3QpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ha2VUZW1wbGF0ZU9iamVjdChjb29rZWQsIHJhdykge1xyXG4gICAgaWYgKE9iamVjdC5kZWZpbmVQcm9wZXJ0eSkgeyBPYmplY3QuZGVmaW5lUHJvcGVydHkoY29va2VkLCBcInJhd1wiLCB7IHZhbHVlOiByYXcgfSk7IH0gZWxzZSB7IGNvb2tlZC5yYXcgPSByYXc7IH1cclxuICAgIHJldHVybiBjb29rZWQ7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnRTdGFyKG1vZCkge1xyXG4gICAgaWYgKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgcmV0dXJuIG1vZDtcclxuICAgIHZhciByZXN1bHQgPSB7fTtcclxuICAgIGlmIChtb2QgIT0gbnVsbCkgZm9yICh2YXIgayBpbiBtb2QpIGlmIChPYmplY3QuaGFzT3duUHJvcGVydHkuY2FsbChtb2QsIGspKSByZXN1bHRba10gPSBtb2Rba107XHJcbiAgICByZXN1bHQuZGVmYXVsdCA9IG1vZDtcclxuICAgIHJldHVybiByZXN1bHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydERlZmF1bHQobW9kKSB7XHJcbiAgICByZXR1cm4gKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgPyBtb2QgOiB7IGRlZmF1bHQ6IG1vZCB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZEdldChyZWNlaXZlciwgcHJpdmF0ZU1hcCkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIGdldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHJldHVybiBwcml2YXRlTWFwLmdldChyZWNlaXZlcik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkU2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwLCB2YWx1ZSkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIHNldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHByaXZhdGVNYXAuc2V0KHJlY2VpdmVyLCB2YWx1ZSk7XHJcbiAgICByZXR1cm4gdmFsdWU7XHJcbn1cclxuIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24sIF9fZXh0ZW5kcyB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgZW5jb2RlRm9ybURhdGEgfSBmcm9tIFwiLi91dGlscy9lbmNvZGUtZm9ybS1kYXRhXCI7XG5pbXBvcnQgeyBlbmNvZGVRdWVyeVN0cmluZyB9IGZyb20gXCIuL3V0aWxzL2VuY29kZS1xdWVyeS1zdHJpbmdcIjtcbmltcG9ydCB7IHJlcXVpcmVzRm9ybURhdGEgfSBmcm9tIFwiLi91dGlscy9wcm9jZXNzLXBhcmFtc1wiO1xuaW1wb3J0IHsgQXJjR0lTUmVxdWVzdEVycm9yIH0gZnJvbSBcIi4vdXRpbHMvQXJjR0lTUmVxdWVzdEVycm9yXCI7XG5pbXBvcnQgeyB3YXJuIH0gZnJvbSBcIi4vdXRpbHMvd2FyblwiO1xuZXhwb3J0IHZhciBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUiA9IFwiQGVzcmkvYXJjZ2lzLXJlc3QtanNcIjtcbnZhciBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMgPSB7XG4gICAgaHR0cE1ldGhvZDogXCJQT1NUXCIsXG4gICAgcGFyYW1zOiB7XG4gICAgICAgIGY6IFwianNvblwiLFxuICAgIH0sXG59O1xuLyoqXG4gKiBTZXRzIHRoZSBkZWZhdWx0IG9wdGlvbnMgdGhhdCB3aWxsIGJlIHBhc3NlZCBpbiAqKmFsbCByZXF1ZXN0cyBhY3Jvc3MgYWxsIGBAZXNyaS9hcmNnaXMtcmVzdC1qc2AgbW9kdWxlcyoqLlxuICpcbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgc2V0RGVmYXVsdFJlcXVlc3RPcHRpb25zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbiAqIHNldERlZmF1bHRSZXF1ZXN0T3B0aW9ucyh7XG4gKiAgIGF1dGhlbnRpY2F0aW9uOiB1c2VyU2Vzc2lvbiAvLyBhbGwgcmVxdWVzdHMgd2lsbCB1c2UgdGhpcyBzZXNzaW9uIGJ5IGRlZmF1bHRcbiAqIH0pXG4gKiBgYGBcbiAqIFlvdSBzaG91bGQgKipuZXZlcioqIHNldCBhIGRlZmF1bHQgYGF1dGhlbnRpY2F0aW9uYCB3aGVuIHlvdSBhcmUgaW4gYSBzZXJ2ZXIgc2lkZSBlbnZpcm9ubWVudCB3aGVyZSB5b3UgbWF5IGJlIGhhbmRsaW5nIHJlcXVlc3RzIGZvciBtYW55IGRpZmZlcmVudCBhdXRoZW50aWNhdGVkIHVzZXJzLlxuICpcbiAqIEBwYXJhbSBvcHRpb25zIFRoZSBkZWZhdWx0IG9wdGlvbnMgdG8gcGFzcyB3aXRoIGV2ZXJ5IHJlcXVlc3QuIEV4aXN0aW5nIGRlZmF1bHQgd2lsbCBiZSBvdmVyd3JpdHRlbi5cbiAqIEBwYXJhbSBoaWRlV2FybmluZ3MgU2lsZW5jZSB3YXJuaW5ncyBhYm91dCBzZXR0aW5nIGRlZmF1bHQgYGF1dGhlbnRpY2F0aW9uYCBpbiBzaGFyZWQgZW52aXJvbm1lbnRzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gc2V0RGVmYXVsdFJlcXVlc3RPcHRpb25zKG9wdGlvbnMsIGhpZGVXYXJuaW5ncykge1xuICAgIGlmIChvcHRpb25zLmF1dGhlbnRpY2F0aW9uICYmICFoaWRlV2FybmluZ3MpIHtcbiAgICAgICAgd2FybihcIllvdSBzaG91bGQgbm90IHNldCBgYXV0aGVudGljYXRpb25gIGFzIGEgZGVmYXVsdCBpbiBhIHNoYXJlZCBlbnZpcm9ubWVudCBzdWNoIGFzIGEgd2ViIHNlcnZlciB3aGljaCB3aWxsIHByb2Nlc3MgbXVsdGlwbGUgdXNlcnMgcmVxdWVzdHMuIFlvdSBjYW4gY2FsbCBgc2V0RGVmYXVsdFJlcXVlc3RPcHRpb25zYCB3aXRoIGB0cnVlYCBhcyBhIHNlY29uZCBhcmd1bWVudCB0byBkaXNhYmxlIHRoaXMgd2FybmluZy5cIik7XG4gICAgfVxuICAgIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUyA9IG9wdGlvbnM7XG59XG52YXIgQXJjR0lTQXV0aEVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhBcmNHSVNBdXRoRXJyb3IsIF9zdXBlcik7XG4gICAgLyoqXG4gICAgICogQ3JlYXRlIGEgbmV3IGBBcmNHSVNBdXRoRXJyb3JgICBvYmplY3QuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gbWVzc2FnZSAtIFRoZSBlcnJvciBtZXNzYWdlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSBjb2RlIC0gVGhlIGVycm9yIGNvZGUgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIHJlc3BvbnNlIC0gVGhlIG9yaWdpbmFsIHJlc3BvbnNlIGZyb20gdGhlIEFQSSB0aGF0IGNhdXNlZCB0aGUgZXJyb3JcbiAgICAgKiBAcGFyYW0gdXJsIC0gVGhlIG9yaWdpbmFsIHVybCBvZiB0aGUgcmVxdWVzdFxuICAgICAqIEBwYXJhbSBvcHRpb25zIC0gVGhlIG9yaWdpbmFsIG9wdGlvbnMgb2YgdGhlIHJlcXVlc3RcbiAgICAgKi9cbiAgICBmdW5jdGlvbiBBcmNHSVNBdXRoRXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucykge1xuICAgICAgICBpZiAobWVzc2FnZSA9PT0gdm9pZCAwKSB7IG1lc3NhZ2UgPSBcIkFVVEhFTlRJQ0FUSU9OX0VSUk9SXCI7IH1cbiAgICAgICAgaWYgKGNvZGUgPT09IHZvaWQgMCkgeyBjb2RlID0gXCJBVVRIRU5USUNBVElPTl9FUlJPUl9DT0RFXCI7IH1cbiAgICAgICAgdmFyIF90aGlzID0gX3N1cGVyLmNhbGwodGhpcywgbWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucykgfHwgdGhpcztcbiAgICAgICAgX3RoaXMubmFtZSA9IFwiQXJjR0lTQXV0aEVycm9yXCI7XG4gICAgICAgIF90aGlzLm1lc3NhZ2UgPVxuICAgICAgICAgICAgY29kZSA9PT0gXCJBVVRIRU5USUNBVElPTl9FUlJPUl9DT0RFXCIgPyBtZXNzYWdlIDogY29kZSArIFwiOiBcIiArIG1lc3NhZ2U7XG4gICAgICAgIHJldHVybiBfdGhpcztcbiAgICB9XG4gICAgQXJjR0lTQXV0aEVycm9yLnByb3RvdHlwZS5yZXRyeSA9IGZ1bmN0aW9uIChnZXRTZXNzaW9uLCByZXRyeUxpbWl0KSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmIChyZXRyeUxpbWl0ID09PSB2b2lkIDApIHsgcmV0cnlMaW1pdCA9IDM7IH1cbiAgICAgICAgdmFyIHRyaWVzID0gMDtcbiAgICAgICAgdmFyIHJldHJ5UmVxdWVzdCA9IGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgICAgIGdldFNlc3Npb24oX3RoaXMudXJsLCBfdGhpcy5vcHRpb25zKVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChzZXNzaW9uKSB7XG4gICAgICAgICAgICAgICAgdmFyIG5ld09wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgX3RoaXMub3B0aW9ucyksIHsgYXV0aGVudGljYXRpb246IHNlc3Npb24gfSk7XG4gICAgICAgICAgICAgICAgdHJpZXMgPSB0cmllcyArIDE7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlcXVlc3QoX3RoaXMudXJsLCBuZXdPcHRpb25zKTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgcmVzb2x2ZShyZXNwb25zZSk7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoZSkge1xuICAgICAgICAgICAgICAgIGlmIChlLm5hbWUgPT09IFwiQXJjR0lTQXV0aEVycm9yXCIgJiYgdHJpZXMgPCByZXRyeUxpbWl0KSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHJ5UmVxdWVzdChyZXNvbHZlLCByZWplY3QpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmIChlLm5hbWUgPT09IFwiQXJjR0lTQXV0aEVycm9yXCIgJiYgdHJpZXMgPj0gcmV0cnlMaW1pdCkge1xuICAgICAgICAgICAgICAgICAgICByZWplY3QoX3RoaXMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgcmV0cnlSZXF1ZXN0KHJlc29sdmUsIHJlamVjdCk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgcmV0dXJuIEFyY0dJU0F1dGhFcnJvcjtcbn0oQXJjR0lTUmVxdWVzdEVycm9yKSk7XG5leHBvcnQgeyBBcmNHSVNBdXRoRXJyb3IgfTtcbi8qKlxuICogQ2hlY2tzIGZvciBlcnJvcnMgaW4gYSBKU09OIHJlc3BvbnNlIGZyb20gdGhlIEFyY0dJUyBSRVNUIEFQSS4gSWYgdGhlcmUgYXJlIG5vIGVycm9ycywgaXQgd2lsbCByZXR1cm4gdGhlIGBkYXRhYCBwYXNzZWQgaW4uIElmIHRoZXJlIGlzIGFuIGVycm9yLCBpdCB3aWxsIHRocm93IGFuIGBBcmNHSVNSZXF1ZXN0RXJyb3JgIG9yIGBBcmNHSVNBdXRoRXJyb3JgLlxuICpcbiAqIEBwYXJhbSBkYXRhIFRoZSByZXNwb25zZSBKU09OIHRvIGNoZWNrIGZvciBlcnJvcnMuXG4gKiBAcGFyYW0gdXJsIFRoZSB1cmwgb2YgdGhlIG9yaWdpbmFsIHJlcXVlc3RcbiAqIEBwYXJhbSBwYXJhbXMgVGhlIHBhcmFtZXRlcnMgb2YgdGhlIG9yaWdpbmFsIHJlcXVlc3RcbiAqIEBwYXJhbSBvcHRpb25zIFRoZSBvcHRpb25zIG9mIHRoZSBvcmlnaW5hbCByZXF1ZXN0XG4gKiBAcmV0dXJucyBUaGUgZGF0YSB0aGF0IHdhcyBwYXNzZWQgaW4gdGhlIGBkYXRhYCBwYXJhbWV0ZXJcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrRm9yRXJyb3JzKHJlc3BvbnNlLCB1cmwsIHBhcmFtcywgb3B0aW9ucywgb3JpZ2luYWxBdXRoRXJyb3IpIHtcbiAgICAvLyB0aGlzIGlzIGFuIGVycm9yIG1lc3NhZ2UgZnJvbSBiaWxsaW5nLmFyY2dpcy5jb20gYmFja2VuZFxuICAgIGlmIChyZXNwb25zZS5jb2RlID49IDQwMCkge1xuICAgICAgICB2YXIgbWVzc2FnZSA9IHJlc3BvbnNlLm1lc3NhZ2UsIGNvZGUgPSByZXNwb25zZS5jb2RlO1xuICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgIH1cbiAgICAvLyBlcnJvciBmcm9tIEFyY0dJUyBPbmxpbmUgb3IgYW4gQXJjR0lTIFBvcnRhbCBvciBzZXJ2ZXIgaW5zdGFuY2UuXG4gICAgaWYgKHJlc3BvbnNlLmVycm9yKSB7XG4gICAgICAgIHZhciBfYSA9IHJlc3BvbnNlLmVycm9yLCBtZXNzYWdlID0gX2EubWVzc2FnZSwgY29kZSA9IF9hLmNvZGUsIG1lc3NhZ2VDb2RlID0gX2EubWVzc2FnZUNvZGU7XG4gICAgICAgIHZhciBlcnJvckNvZGUgPSBtZXNzYWdlQ29kZSB8fCBjb2RlIHx8IFwiVU5LTk9XTl9FUlJPUl9DT0RFXCI7XG4gICAgICAgIGlmIChjb2RlID09PSA0OTggfHxcbiAgICAgICAgICAgIGNvZGUgPT09IDQ5OSB8fFxuICAgICAgICAgICAgbWVzc2FnZUNvZGUgPT09IFwiR1dNXzAwMDNcIiB8fFxuICAgICAgICAgICAgKGNvZGUgPT09IDQwMCAmJiBtZXNzYWdlID09PSBcIlVuYWJsZSB0byBnZW5lcmF0ZSB0b2tlbi5cIikpIHtcbiAgICAgICAgICAgIGlmIChvcmlnaW5hbEF1dGhFcnJvcikge1xuICAgICAgICAgICAgICAgIHRocm93IG9yaWdpbmFsQXV0aEVycm9yO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcihtZXNzYWdlLCBlcnJvckNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgZXJyb3JDb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICB9XG4gICAgLy8gZXJyb3IgZnJvbSBhIHN0YXR1cyBjaGVja1xuICAgIGlmIChyZXNwb25zZS5zdGF0dXMgPT09IFwiZmFpbGVkXCIgfHwgcmVzcG9uc2Uuc3RhdHVzID09PSBcImZhaWx1cmVcIikge1xuICAgICAgICB2YXIgbWVzc2FnZSA9IHZvaWQgMDtcbiAgICAgICAgdmFyIGNvZGUgPSBcIlVOS05PV05fRVJST1JfQ09ERVwiO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgbWVzc2FnZSA9IEpTT04ucGFyc2UocmVzcG9uc2Uuc3RhdHVzTWVzc2FnZSkubWVzc2FnZTtcbiAgICAgICAgICAgIGNvZGUgPSBKU09OLnBhcnNlKHJlc3BvbnNlLnN0YXR1c01lc3NhZ2UpLmNvZGU7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgIG1lc3NhZ2UgPSByZXNwb25zZS5zdGF0dXNNZXNzYWdlIHx8IHJlc3BvbnNlLm1lc3NhZ2U7XG4gICAgICAgIH1cbiAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3BvbnNlO1xufVxuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgcmVxdWVzdCB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QnO1xuICogLy9cbiAqIHJlcXVlc3QoJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0JylcbiAqICAgLnRoZW4ocmVzcG9uc2UpIC8vIHJlc3BvbnNlLmN1cnJlbnRWZXJzaW9uID09PSA1LjJcbiAqIC8vXG4gKiByZXF1ZXN0KCdodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdCcsIHtcbiAqICAgaHR0cE1ldGhvZDogXCJHRVRcIlxuICogfSlcbiAqIC8vXG4gKiByZXF1ZXN0KCdodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdC9zZWFyY2gnLCB7XG4gKiAgIHBhcmFtczogeyBxOiAncGFya3MnIH1cbiAqIH0pXG4gKiAgIC50aGVuKHJlc3BvbnNlKSAvLyByZXNwb25zZS50b3RhbCA9PiA3ODM3OVxuICogYGBgXG4gKiBHZW5lcmljIG1ldGhvZCBmb3IgbWFraW5nIEhUVFAgcmVxdWVzdHMgdG8gQXJjR0lTIFJFU1QgQVBJIGVuZHBvaW50cy5cbiAqXG4gKiBAcGFyYW0gdXJsIC0gVGhlIFVSTCBvZiB0aGUgQXJjR0lTIFJFU1QgQVBJIGVuZHBvaW50LlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QsIGluY2x1ZGluZyBwYXJhbWV0ZXJzIHJlbGV2YW50IHRvIHRoZSBlbmRwb2ludC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkYXRhIGZyb20gdGhlIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcmVxdWVzdCh1cmwsIHJlcXVlc3RPcHRpb25zKSB7XG4gICAgaWYgKHJlcXVlc3RPcHRpb25zID09PSB2b2lkIDApIHsgcmVxdWVzdE9wdGlvbnMgPSB7IHBhcmFtczogeyBmOiBcImpzb25cIiB9IH07IH1cbiAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJQT1NUXCIgfSwgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TKSwgcmVxdWVzdE9wdGlvbnMpLCB7XG4gICAgICAgIHBhcmFtczogX19hc3NpZ24oX19hc3NpZ24oe30sIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUy5wYXJhbXMpLCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpLFxuICAgICAgICBoZWFkZXJzOiBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TLmhlYWRlcnMpLCByZXF1ZXN0T3B0aW9ucy5oZWFkZXJzKSxcbiAgICB9KTtcbiAgICB2YXIgbWlzc2luZ0dsb2JhbHMgPSBbXTtcbiAgICB2YXIgcmVjb21tZW5kZWRQYWNrYWdlcyA9IFtdO1xuICAgIC8vIGRvbid0IGNoZWNrIGZvciBhIGdsb2JhbCBmZXRjaCBpZiBhIGN1c3RvbSBpbXBsZW1lbnRhdGlvbiB3YXMgcGFzc2VkIHRocm91Z2hcbiAgICBpZiAoIW9wdGlvbnMuZmV0Y2ggJiYgdHlwZW9mIGZldGNoICE9PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIG9wdGlvbnMuZmV0Y2ggPSBmZXRjaC5iaW5kKEZ1bmN0aW9uKFwicmV0dXJuIHRoaXNcIikoKSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBtaXNzaW5nR2xvYmFscy5wdXNoKFwiYGZldGNoYFwiKTtcbiAgICAgICAgcmVjb21tZW5kZWRQYWNrYWdlcy5wdXNoKFwiYG5vZGUtZmV0Y2hgXCIpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIFByb21pc2UgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgbWlzc2luZ0dsb2JhbHMucHVzaChcImBQcm9taXNlYFwiKTtcbiAgICAgICAgcmVjb21tZW5kZWRQYWNrYWdlcy5wdXNoKFwiYGVzNi1wcm9taXNlYFwiKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBGb3JtRGF0YSA9PT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICBtaXNzaW5nR2xvYmFscy5wdXNoKFwiYEZvcm1EYXRhYFwiKTtcbiAgICAgICAgcmVjb21tZW5kZWRQYWNrYWdlcy5wdXNoKFwiYGlzb21vcnBoaWMtZm9ybS1kYXRhYFwiKTtcbiAgICB9XG4gICAgaWYgKCFvcHRpb25zLmZldGNoIHx8XG4gICAgICAgIHR5cGVvZiBQcm9taXNlID09PSBcInVuZGVmaW5lZFwiIHx8XG4gICAgICAgIHR5cGVvZiBGb3JtRGF0YSA9PT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJgYXJjZ2lzLXJlc3QtcmVxdWVzdGAgcmVxdWlyZXMgYSBgZmV0Y2hgIGltcGxlbWVudGF0aW9uIGFuZCBnbG9iYWwgdmFyaWFibGVzIGZvciBgUHJvbWlzZWAgYW5kIGBGb3JtRGF0YWAgdG8gYmUgcHJlc2VudCBpbiB0aGUgZ2xvYmFsIHNjb3BlLiBZb3UgYXJlIG1pc3NpbmcgXCIgKyBtaXNzaW5nR2xvYmFscy5qb2luKFwiLCBcIikgKyBcIi4gV2UgcmVjb21tZW5kIGluc3RhbGxpbmcgdGhlIFwiICsgcmVjb21tZW5kZWRQYWNrYWdlcy5qb2luKFwiLCBcIikgKyBcIiBtb2R1bGVzIGF0IHRoZSByb290IG9mIHlvdXIgYXBwbGljYXRpb24gdG8gYWRkIHRoZXNlIHRvIHRoZSBnbG9iYWwgc2NvcGUuIFNlZSBodHRwczovL2JpdC5seS8yS053V2FKIGZvciBtb3JlIGluZm8uXCIpO1xuICAgIH1cbiAgICB2YXIgaHR0cE1ldGhvZCA9IG9wdGlvbnMuaHR0cE1ldGhvZCwgYXV0aGVudGljYXRpb24gPSBvcHRpb25zLmF1dGhlbnRpY2F0aW9uLCByYXdSZXNwb25zZSA9IG9wdGlvbnMucmF3UmVzcG9uc2U7XG4gICAgdmFyIHBhcmFtcyA9IF9fYXNzaWduKHsgZjogXCJqc29uXCIgfSwgb3B0aW9ucy5wYXJhbXMpO1xuICAgIHZhciBvcmlnaW5hbEF1dGhFcnJvciA9IG51bGw7XG4gICAgdmFyIGZldGNoT3B0aW9ucyA9IHtcbiAgICAgICAgbWV0aG9kOiBodHRwTWV0aG9kLFxuICAgICAgICAvKiBlbnN1cmVzIGJlaGF2aW9yIG1pbWljcyBYTUxIdHRwUmVxdWVzdC5cbiAgICAgICAgbmVlZGVkIHRvIHN1cHBvcnQgc2VuZGluZyBJV0EgY29va2llcyAqL1xuICAgICAgICBjcmVkZW50aWFsczogb3B0aW9ucy5jcmVkZW50aWFscyB8fCBcInNhbWUtb3JpZ2luXCIsXG4gICAgfTtcbiAgICAvLyB0aGUgL29hdXRoMi9wbGF0Zm9ybVNlbGYgcm91dGUgd2lsbCBhZGQgWC1Fc3JpLUF1dGgtQ2xpZW50LUlkIGhlYWRlclxuICAgIC8vIGFuZCB0aGF0IHJlcXVlc3QgbmVlZHMgdG8gc2VuZCBjb29raWVzIGNyb3NzIGRvbWFpblxuICAgIC8vIHNvIHdlIG5lZWQgdG8gc2V0IHRoZSBjcmVkZW50aWFscyB0byBcImluY2x1ZGVcIlxuICAgIGlmIChvcHRpb25zLmhlYWRlcnMgJiZcbiAgICAgICAgb3B0aW9ucy5oZWFkZXJzW1wiWC1Fc3JpLUF1dGgtQ2xpZW50LUlkXCJdICYmXG4gICAgICAgIHVybC5pbmRleE9mKFwiL29hdXRoMi9wbGF0Zm9ybVNlbGZcIikgPiAtMSkge1xuICAgICAgICBmZXRjaE9wdGlvbnMuY3JlZGVudGlhbHMgPSBcImluY2x1ZGVcIjtcbiAgICB9XG4gICAgcmV0dXJuIChhdXRoZW50aWNhdGlvblxuICAgICAgICA/IGF1dGhlbnRpY2F0aW9uLmdldFRva2VuKHVybCwgeyBmZXRjaDogb3B0aW9ucy5mZXRjaCB9KS5jYXRjaChmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIGFwcGVuZCBvcmlnaW5hbCByZXF1ZXN0IHVybCBhbmQgcmVxdWVzdE9wdGlvbnNcbiAgICAgICAgICAgICAqIHRvIHRoZSBlcnJvciB0aHJvd24gYnkgZ2V0VG9rZW4oKVxuICAgICAgICAgICAgICogdG8gYXNzaXN0IHdpdGggcmV0cnlpbmdcbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgZXJyLnVybCA9IHVybDtcbiAgICAgICAgICAgIGVyci5vcHRpb25zID0gb3B0aW9ucztcbiAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICogaWYgYW4gYXR0ZW1wdCBpcyBtYWRlIHRvIHRhbGsgdG8gYW4gdW5mZWRlcmF0ZWQgc2VydmVyXG4gICAgICAgICAgICAgKiBmaXJzdCB0cnkgdGhlIHJlcXVlc3QgYW5vbnltb3VzbHkuIGlmIGEgJ3Rva2VuIHJlcXVpcmVkJ1xuICAgICAgICAgICAgICogZXJyb3IgaXMgdGhyb3duLCB0aHJvdyB0aGUgVU5GRURFUkFURUQgZXJyb3IgdGhlbi5cbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgb3JpZ2luYWxBdXRoRXJyb3IgPSBlcnI7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKFwiXCIpO1xuICAgICAgICB9KVxuICAgICAgICA6IFByb21pc2UucmVzb2x2ZShcIlwiKSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHRva2VuKSB7XG4gICAgICAgIGlmICh0b2tlbi5sZW5ndGgpIHtcbiAgICAgICAgICAgIHBhcmFtcy50b2tlbiA9IHRva2VuO1xuICAgICAgICB9XG4gICAgICAgIGlmIChhdXRoZW50aWNhdGlvbiAmJiBhdXRoZW50aWNhdGlvbi5nZXREb21haW5DcmVkZW50aWFscykge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmNyZWRlbnRpYWxzID0gYXV0aGVudGljYXRpb24uZ2V0RG9tYWluQ3JlZGVudGlhbHModXJsKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBDdXN0b20gaGVhZGVycyB0byBhZGQgdG8gcmVxdWVzdC4gSVJlcXVlc3RPcHRpb25zLmhlYWRlcnMgd2l0aCBtZXJnZSBvdmVyIHJlcXVlc3RIZWFkZXJzLlxuICAgICAgICB2YXIgcmVxdWVzdEhlYWRlcnMgPSB7fTtcbiAgICAgICAgaWYgKGZldGNoT3B0aW9ucy5tZXRob2QgPT09IFwiR0VUXCIpIHtcbiAgICAgICAgICAgIC8vIFByZXZlbnRzIHRva2VuIGZyb20gYmVpbmcgcGFzc2VkIGluIHF1ZXJ5IHBhcmFtcyB3aGVuIGhpZGVUb2tlbiBvcHRpb24gaXMgdXNlZC5cbiAgICAgICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBpZiAtIHdpbmRvdyBpcyBhbHdheXMgZGVmaW5lZCBpbiBhIGJyb3dzZXIuIFRlc3QgY2FzZSBpcyBjb3ZlcmVkIGJ5IEphc21pbmUgaW4gbm9kZSB0ZXN0ICovXG4gICAgICAgICAgICBpZiAocGFyYW1zLnRva2VuICYmXG4gICAgICAgICAgICAgICAgb3B0aW9ucy5oaWRlVG9rZW4gJiZcbiAgICAgICAgICAgICAgICAvLyBTaGFyaW5nIEFQSSBkb2VzIG5vdCBzdXBwb3J0IHByZWZsaWdodCBjaGVjayByZXF1aXJlZCBieSBtb2Rlcm4gYnJvd3NlcnMgaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9HbG9zc2FyeS9QcmVmbGlnaHRfcmVxdWVzdFxuICAgICAgICAgICAgICAgIHR5cGVvZiB3aW5kb3cgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgICAgICAgICByZXF1ZXN0SGVhZGVyc1tcIlgtRXNyaS1BdXRob3JpemF0aW9uXCJdID0gXCJCZWFyZXIgXCIgKyBwYXJhbXMudG9rZW47XG4gICAgICAgICAgICAgICAgZGVsZXRlIHBhcmFtcy50b2tlbjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIGVuY29kZSB0aGUgcGFyYW1ldGVycyBpbnRvIHRoZSBxdWVyeSBzdHJpbmdcbiAgICAgICAgICAgIHZhciBxdWVyeVBhcmFtcyA9IGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcyk7XG4gICAgICAgICAgICAvLyBkb250IGFwcGVuZCBhICc/JyB1bmxlc3MgcGFyYW1ldGVycyBhcmUgYWN0dWFsbHkgcHJlc2VudFxuICAgICAgICAgICAgdmFyIHVybFdpdGhRdWVyeVN0cmluZyA9IHF1ZXJ5UGFyYW1zID09PSBcIlwiID8gdXJsIDogdXJsICsgXCI/XCIgKyBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgLy8gVGhpcyB3b3VsZCBleGNlZWQgdGhlIG1heGltdW0gbGVuZ3RoIGZvciBVUkxzIHNwZWNpZmllZCBieSB0aGUgY29uc3VtZXIgYW5kIHJlcXVpcmVzIFBPU1RcbiAgICAgICAgICAgIChvcHRpb25zLm1heFVybExlbmd0aCAmJlxuICAgICAgICAgICAgICAgIHVybFdpdGhRdWVyeVN0cmluZy5sZW5ndGggPiBvcHRpb25zLm1heFVybExlbmd0aCkgfHxcbiAgICAgICAgICAgICAgICAvLyBPciBpZiB0aGUgY3VzdG9tZXIgcmVxdWlyZXMgdGhlIHRva2VuIHRvIGJlIGhpZGRlbiBhbmQgaXQgaGFzIG5vdCBhbHJlYWR5IGJlZW4gaGlkZGVuIGluIHRoZSBoZWFkZXIgKGZvciBicm93c2VycylcbiAgICAgICAgICAgICAgICAocGFyYW1zLnRva2VuICYmIG9wdGlvbnMuaGlkZVRva2VuKSkge1xuICAgICAgICAgICAgICAgIC8vIHRoZSBjb25zdW1lciBzcGVjaWZpZWQgYSBtYXhpbXVtIGxlbmd0aCBmb3IgVVJMc1xuICAgICAgICAgICAgICAgIC8vIGFuZCB0aGlzIHdvdWxkIGV4Y2VlZCBpdCwgc28gdXNlIHBvc3QgaW5zdGVhZFxuICAgICAgICAgICAgICAgIGZldGNoT3B0aW9ucy5tZXRob2QgPSBcIlBPU1RcIjtcbiAgICAgICAgICAgICAgICAvLyBJZiB0aGUgdG9rZW4gd2FzIGFscmVhZHkgYWRkZWQgYXMgYSBBdXRoIGhlYWRlciwgYWRkIHRoZSB0b2tlbiBiYWNrIHRvIGJvZHkgd2l0aCBvdGhlciBwYXJhbXMgaW5zdGVhZCBvZiBoZWFkZXJcbiAgICAgICAgICAgICAgICBpZiAodG9rZW4ubGVuZ3RoICYmIG9wdGlvbnMuaGlkZVRva2VuKSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcmFtcy50b2tlbiA9IHRva2VuO1xuICAgICAgICAgICAgICAgICAgICAvLyBSZW1vdmUgZXhpc3RpbmcgaGVhZGVyIHRoYXQgd2FzIGFkZGVkIGJlZm9yZSB1cmwgcXVlcnkgbGVuZ3RoIHdhcyBjaGVja2VkXG4gICAgICAgICAgICAgICAgICAgIGRlbGV0ZSByZXF1ZXN0SGVhZGVyc1tcIlgtRXNyaS1BdXRob3JpemF0aW9uXCJdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIC8vIGp1c3QgdXNlIEdFVFxuICAgICAgICAgICAgICAgIHVybCA9IHVybFdpdGhRdWVyeVN0cmluZztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICAvKiB1cGRhdGVSZXNvdXJjZXMgY3VycmVudGx5IHJlcXVpcmVzIEZvcm1EYXRhIGV2ZW4gd2hlbiB0aGUgaW5wdXQgcGFyYW1ldGVycyBkb250IHdhcnJhbnQgaXQuXG4gICAgaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3VwZGF0ZS1yZXNvdXJjZXMuaHRtXG4gICAgICAgIHNlZSBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9hcmNnaXMtcmVzdC1qcy9wdWxsLzUwMCBmb3IgbW9yZSBpbmZvLiAqL1xuICAgICAgICB2YXIgZm9yY2VGb3JtRGF0YSA9IG5ldyBSZWdFeHAoXCIvaXRlbXMvLisvdXBkYXRlUmVzb3VyY2VzXCIpLnRlc3QodXJsKTtcbiAgICAgICAgaWYgKGZldGNoT3B0aW9ucy5tZXRob2QgPT09IFwiUE9TVFwiKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuYm9keSA9IGVuY29kZUZvcm1EYXRhKHBhcmFtcywgZm9yY2VGb3JtRGF0YSk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gTWl4aW4gaGVhZGVycyBmcm9tIHJlcXVlc3Qgb3B0aW9uc1xuICAgICAgICBmZXRjaE9wdGlvbnMuaGVhZGVycyA9IF9fYXNzaWduKF9fYXNzaWduKHt9LCByZXF1ZXN0SGVhZGVycyksIG9wdGlvbnMuaGVhZGVycyk7XG4gICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0IC0ga2FybWEgcmVwb3J0cyBjb3ZlcmFnZSBvbiBicm93c2VyIHRlc3RzIG9ubHkgKi9cbiAgICAgICAgaWYgKHR5cGVvZiB3aW5kb3cgPT09IFwidW5kZWZpbmVkXCIgJiYgIWZldGNoT3B0aW9ucy5oZWFkZXJzLnJlZmVyZXIpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5oZWFkZXJzLnJlZmVyZXIgPSBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUjtcbiAgICAgICAgfVxuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgZWxzZSBibG9iIHJlc3BvbnNlcyBhcmUgZGlmZmljdWx0IHRvIG1ha2UgY3Jvc3MgcGxhdGZvcm0gd2Ugd2lsbCBqdXN0IGhhdmUgdG8gdHJ1c3QgdGhlIGlzb21vcnBoaWMgZmV0Y2ggd2lsbCBkbyBpdHMgam9iICovXG4gICAgICAgIGlmICghcmVxdWlyZXNGb3JtRGF0YShwYXJhbXMpICYmICFmb3JjZUZvcm1EYXRhKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuaGVhZGVyc1tcIkNvbnRlbnQtVHlwZVwiXSA9XG4gICAgICAgICAgICAgICAgXCJhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWRcIjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gb3B0aW9ucy5mZXRjaCh1cmwsIGZldGNoT3B0aW9ucyk7XG4gICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmICghcmVzcG9uc2Uub2spIHtcbiAgICAgICAgICAgIC8vIHNlcnZlciByZXNwb25kZWQgdy8gYW4gYWN0dWFsIGVycm9yICg0MDQsIDUwMCwgZXRjKVxuICAgICAgICAgICAgdmFyIHN0YXR1c18xID0gcmVzcG9uc2Uuc3RhdHVzLCBzdGF0dXNUZXh0ID0gcmVzcG9uc2Uuc3RhdHVzVGV4dDtcbiAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3Ioc3RhdHVzVGV4dCwgXCJIVFRQIFwiICsgc3RhdHVzXzEsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChyYXdSZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICB9XG4gICAgICAgIHN3aXRjaCAocGFyYW1zLmYpIHtcbiAgICAgICAgICAgIGNhc2UgXCJqc29uXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgIGNhc2UgXCJnZW9qc29uXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmpzb24oKTtcbiAgICAgICAgICAgIGNhc2UgXCJodG1sXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLnRleHQoKTtcbiAgICAgICAgICAgIGNhc2UgXCJ0ZXh0XCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLnRleHQoKTtcbiAgICAgICAgICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0IGJsb2IgcmVzcG9uc2VzIGFyZSBkaWZmaWN1bHQgdG8gbWFrZSBjcm9zcyBwbGF0Zm9ybSB3ZSB3aWxsIGp1c3QgaGF2ZSB0byB0cnVzdCB0aGF0IGlzb21vcnBoaWMgZmV0Y2ggd2lsbCBkbyBpdHMgam9iICovXG4gICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5ibG9iKCk7XG4gICAgICAgIH1cbiAgICB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoZGF0YSkge1xuICAgICAgICBpZiAoKHBhcmFtcy5mID09PSBcImpzb25cIiB8fCBwYXJhbXMuZiA9PT0gXCJnZW9qc29uXCIpICYmICFyYXdSZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIHJlc3BvbnNlID0gY2hlY2tGb3JFcnJvcnMoZGF0YSwgdXJsLCBwYXJhbXMsIG9wdGlvbnMsIG9yaWdpbmFsQXV0aEVycm9yKTtcbiAgICAgICAgICAgIGlmIChvcmlnaW5hbEF1dGhFcnJvcikge1xuICAgICAgICAgICAgICAgIC8qIElmIHRoZSByZXF1ZXN0IHdhcyBtYWRlIHRvIGFuIHVuZmVkZXJhdGVkIHNlcnZpY2UgdGhhdFxuICAgICAgICAgICAgICAgIGRpZG4ndCByZXF1aXJlIGF1dGhlbnRpY2F0aW9uLCBhZGQgdGhlIGJhc2UgdXJsIGFuZCBhIGR1bW15IHRva2VuXG4gICAgICAgICAgICAgICAgdG8gdGhlIGxpc3Qgb2YgdHJ1c3RlZCBzZXJ2ZXJzIHRvIGF2b2lkIGFub3RoZXIgZmVkZXJhdGlvbiBjaGVja1xuICAgICAgICAgICAgICAgIGluIHRoZSBldmVudCBvZiBhIHJlcGVhdCByZXF1ZXN0ICovXG4gICAgICAgICAgICAgICAgdmFyIHRydW5jYXRlZFVybCA9IHVybFxuICAgICAgICAgICAgICAgICAgICAudG9Mb3dlckNhc2UoKVxuICAgICAgICAgICAgICAgICAgICAuc3BsaXQoL1xcL3Jlc3QoXFwvYWRtaW4pP1xcL3NlcnZpY2VzXFwvLylbMF07XG4gICAgICAgICAgICAgICAgb3B0aW9ucy5hdXRoZW50aWNhdGlvbi5mZWRlcmF0ZWRTZXJ2ZXJzW3RydW5jYXRlZFVybF0gPSB7XG4gICAgICAgICAgICAgICAgICAgIHRva2VuOiBbXSxcbiAgICAgICAgICAgICAgICAgICAgLy8gZGVmYXVsdCB0byAyNCBob3Vyc1xuICAgICAgICAgICAgICAgICAgICBleHBpcmVzOiBuZXcgRGF0ZShEYXRlLm5vdygpICsgODY0MDAgKiAxMDAwKSxcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgIG9yaWdpbmFsQXV0aEVycm9yID0gbnVsbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiBkYXRhO1xuICAgICAgICB9XG4gICAgfSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1yZXF1ZXN0LmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vLyBUeXBlU2NyaXB0IDIuMSBubyBsb25nZXIgYWxsb3dzIHlvdSB0byBleHRlbmQgYnVpbHQgaW4gdHlwZXMuIFNlZSBodHRwczovL2dpdGh1Yi5jb20vTWljcm9zb2Z0L1R5cGVTY3JpcHQvaXNzdWVzLzEyNzkwI2lzc3VlY29tbWVudC0yNjU5ODE0NDJcbi8vIGFuZCBodHRwczovL2dpdGh1Yi5jb20vTWljcm9zb2Z0L1R5cGVTY3JpcHQtd2lraS9ibG9iL21hc3Rlci9CcmVha2luZy1DaGFuZ2VzLm1kI2V4dGVuZGluZy1idWlsdC1pbnMtbGlrZS1lcnJvci1hcnJheS1hbmQtbWFwLW1heS1uby1sb25nZXItd29ya1xuLy9cbi8vIFRoaXMgY29kZSBpcyBmcm9tIE1ETiBodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9KYXZhU2NyaXB0L1JlZmVyZW5jZS9HbG9iYWxfT2JqZWN0cy9FcnJvciNDdXN0b21fRXJyb3JfVHlwZXMuXG52YXIgQXJjR0lTUmVxdWVzdEVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIC8qKlxuICAgICAqIENyZWF0ZSBhIG5ldyBgQXJjR0lTUmVxdWVzdEVycm9yYCAgb2JqZWN0LlxuICAgICAqXG4gICAgICogQHBhcmFtIG1lc3NhZ2UgLSBUaGUgZXJyb3IgbWVzc2FnZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gY29kZSAtIFRoZSBlcnJvciBjb2RlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSByZXNwb25zZSAtIFRoZSBvcmlnaW5hbCByZXNwb25zZSBmcm9tIHRoZSBBUEkgdGhhdCBjYXVzZWQgdGhlIGVycm9yXG4gICAgICogQHBhcmFtIHVybCAtIFRoZSBvcmlnaW5hbCB1cmwgb2YgdGhlIHJlcXVlc3RcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyAtIFRoZSBvcmlnaW5hbCBvcHRpb25zIGFuZCBwYXJhbWV0ZXJzIG9mIHRoZSByZXF1ZXN0XG4gICAgICovXG4gICAgZnVuY3Rpb24gQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpIHtcbiAgICAgICAgbWVzc2FnZSA9IG1lc3NhZ2UgfHwgXCJVTktOT1dOX0VSUk9SXCI7XG4gICAgICAgIGNvZGUgPSBjb2RlIHx8IFwiVU5LTk9XTl9FUlJPUl9DT0RFXCI7XG4gICAgICAgIHRoaXMubmFtZSA9IFwiQXJjR0lTUmVxdWVzdEVycm9yXCI7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9XG4gICAgICAgICAgICBjb2RlID09PSBcIlVOS05PV05fRVJST1JfQ09ERVwiID8gbWVzc2FnZSA6IGNvZGUgKyBcIjogXCIgKyBtZXNzYWdlO1xuICAgICAgICB0aGlzLm9yaWdpbmFsTWVzc2FnZSA9IG1lc3NhZ2U7XG4gICAgICAgIHRoaXMuY29kZSA9IGNvZGU7XG4gICAgICAgIHRoaXMucmVzcG9uc2UgPSByZXNwb25zZTtcbiAgICAgICAgdGhpcy51cmwgPSB1cmw7XG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgfVxuICAgIHJldHVybiBBcmNHSVNSZXF1ZXN0RXJyb3I7XG59KCkpO1xuZXhwb3J0IHsgQXJjR0lTUmVxdWVzdEVycm9yIH07XG5BcmNHSVNSZXF1ZXN0RXJyb3IucHJvdG90eXBlID0gT2JqZWN0LmNyZWF0ZShFcnJvci5wcm90b3R5cGUpO1xuQXJjR0lTUmVxdWVzdEVycm9yLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IEFyY0dJU1JlcXVlc3RFcnJvcjtcbi8vIyBzb3VyY2VNYXBwaW5nVVJMPUFyY0dJU1JlcXVlc3RFcnJvci5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuLyoqXG4gKiBIZWxwZXIgZm9yIG1ldGhvZHMgd2l0aCBsb3RzIG9mIGZpcnN0IG9yZGVyIHJlcXVlc3Qgb3B0aW9ucyB0byBwYXNzIHRocm91Z2ggYXMgcmVxdWVzdCBwYXJhbWV0ZXJzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gYXBwZW5kQ3VzdG9tUGFyYW1zKGN1c3RvbU9wdGlvbnMsIGtleXMsIGJhc2VPcHRpb25zKSB7XG4gICAgdmFyIHJlcXVlc3RPcHRpb25zS2V5cyA9IFtcbiAgICAgICAgXCJwYXJhbXNcIixcbiAgICAgICAgXCJodHRwTWV0aG9kXCIsXG4gICAgICAgIFwicmF3UmVzcG9uc2VcIixcbiAgICAgICAgXCJhdXRoZW50aWNhdGlvblwiLFxuICAgICAgICBcInBvcnRhbFwiLFxuICAgICAgICBcImZldGNoXCIsXG4gICAgICAgIFwibWF4VXJsTGVuZ3RoXCIsXG4gICAgICAgIFwiaGVhZGVyc1wiXG4gICAgXTtcbiAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHsgcGFyYW1zOiB7fSB9LCBiYXNlT3B0aW9ucyksIGN1c3RvbU9wdGlvbnMpO1xuICAgIC8vIG1lcmdlIGFsbCBrZXlzIGluIGN1c3RvbU9wdGlvbnMgaW50byBvcHRpb25zLnBhcmFtc1xuICAgIG9wdGlvbnMucGFyYW1zID0ga2V5cy5yZWR1Y2UoZnVuY3Rpb24gKHZhbHVlLCBrZXkpIHtcbiAgICAgICAgaWYgKGN1c3RvbU9wdGlvbnNba2V5XSB8fCB0eXBlb2YgY3VzdG9tT3B0aW9uc1trZXldID09PSBcImJvb2xlYW5cIikge1xuICAgICAgICAgICAgdmFsdWVba2V5XSA9IGN1c3RvbU9wdGlvbnNba2V5XTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gdmFsdWU7XG4gICAgfSwgb3B0aW9ucy5wYXJhbXMpO1xuICAgIC8vIG5vdyByZW1vdmUgYWxsIHByb3BlcnRpZXMgaW4gb3B0aW9ucyB0aGF0IGRvbid0IGV4aXN0IGluIElSZXF1ZXN0T3B0aW9uc1xuICAgIHJldHVybiByZXF1ZXN0T3B0aW9uc0tleXMucmVkdWNlKGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICAgIGlmIChvcHRpb25zW2tleV0pIHtcbiAgICAgICAgICAgIHZhbHVlW2tleV0gPSBvcHRpb25zW2tleV07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHZhbHVlO1xuICAgIH0sIHt9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWFwcGVuZC1jdXN0b20tcGFyYW1zLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vKipcbiAqIEhlbHBlciBtZXRob2QgdG8gZW5zdXJlIHRoYXQgdXNlciBzdXBwbGllZCB1cmxzIGRvbid0IGluY2x1ZGUgd2hpdGVzcGFjZSBvciBhIHRyYWlsaW5nIHNsYXNoLlxuICovXG5leHBvcnQgZnVuY3Rpb24gY2xlYW5VcmwodXJsKSB7XG4gICAgLy8gR3VhcmQgc28gd2UgZG9uJ3QgdHJ5IHRvIHRyaW0gc29tZXRoaW5nIHRoYXQncyBub3QgYSBzdHJpbmdcbiAgICBpZiAodHlwZW9mIHVybCAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICByZXR1cm4gdXJsO1xuICAgIH1cbiAgICAvLyB0cmltIGxlYWRpbmcgYW5kIHRyYWlsaW5nIHNwYWNlcywgYnV0IG5vdCBzcGFjZXMgaW5zaWRlIHRoZSB1cmxcbiAgICB1cmwgPSB1cmwudHJpbSgpO1xuICAgIC8vIHJlbW92ZSB0aGUgdHJhaWxpbmcgc2xhc2ggdG8gdGhlIHVybCBpZiBvbmUgd2FzIGluY2x1ZGVkXG4gICAgaWYgKHVybFt1cmwubGVuZ3RoIC0gMV0gPT09IFwiL1wiKSB7XG4gICAgICAgIHVybCA9IHVybC5zbGljZSgwLCAtMSk7XG4gICAgfVxuICAgIHJldHVybiB1cmw7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1jbGVhbi11cmwuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMjAgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlY29kZVBhcmFtKHBhcmFtKSB7XG4gICAgdmFyIF9hID0gcGFyYW0uc3BsaXQoXCI9XCIpLCBrZXkgPSBfYVswXSwgdmFsdWUgPSBfYVsxXTtcbiAgICByZXR1cm4geyBrZXk6IGRlY29kZVVSSUNvbXBvbmVudChrZXkpLCB2YWx1ZTogZGVjb2RlVVJJQ29tcG9uZW50KHZhbHVlKSB9O1xufVxuLyoqXG4gKiBEZWNvZGVzIHRoZSBwYXNzZWQgcXVlcnkgc3RyaW5nIGFzIGFuIG9iamVjdC5cbiAqXG4gKiBAcGFyYW0gcXVlcnkgQSBzdHJpbmcgdG8gYmUgZGVjb2RlZC5cbiAqIEByZXR1cm5zIEEgZGVjb2RlZCBxdWVyeSBwYXJhbSBvYmplY3QuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVRdWVyeVN0cmluZyhxdWVyeSkge1xuICAgIHJldHVybiBxdWVyeVxuICAgICAgICAucmVwbGFjZSgvXiMvLCBcIlwiKVxuICAgICAgICAuc3BsaXQoXCImXCIpXG4gICAgICAgIC5yZWR1Y2UoZnVuY3Rpb24gKGFjYywgZW50cnkpIHtcbiAgICAgICAgdmFyIF9hID0gZGVjb2RlUGFyYW0oZW50cnkpLCBrZXkgPSBfYS5rZXksIHZhbHVlID0gX2EudmFsdWU7XG4gICAgICAgIGFjY1trZXldID0gdmFsdWU7XG4gICAgICAgIHJldHVybiBhY2M7XG4gICAgfSwge30pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGVjb2RlLXF1ZXJ5LXN0cmluZy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcHJvY2Vzc1BhcmFtcywgcmVxdWlyZXNGb3JtRGF0YSB9IGZyb20gXCIuL3Byb2Nlc3MtcGFyYW1zXCI7XG5pbXBvcnQgeyBlbmNvZGVRdWVyeVN0cmluZyB9IGZyb20gXCIuL2VuY29kZS1xdWVyeS1zdHJpbmdcIjtcbi8qKlxuICogRW5jb2RlcyBwYXJhbWV0ZXJzIGluIGEgW0Zvcm1EYXRhXShodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvRm9ybURhdGEpIG9iamVjdCBpbiBicm93c2VycyBvciBpbiBhIFtGb3JtRGF0YV0oaHR0cHM6Ly9naXRodWIuY29tL2Zvcm0tZGF0YS9mb3JtLWRhdGEpIGluIE5vZGUuanNcbiAqXG4gKiBAcGFyYW0gcGFyYW1zIEFuIG9iamVjdCB0byBiZSBlbmNvZGVkLlxuICogQHJldHVybnMgVGhlIGNvbXBsZXRlIFtGb3JtRGF0YV0oaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvQVBJL0Zvcm1EYXRhKSBvYmplY3QuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbmNvZGVGb3JtRGF0YShwYXJhbXMsIGZvcmNlRm9ybURhdGEpIHtcbiAgICAvLyBzZWUgaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvaXNzdWVzLzQ5OSBmb3IgbW9yZSBpbmZvLlxuICAgIHZhciB1c2VGb3JtRGF0YSA9IHJlcXVpcmVzRm9ybURhdGEocGFyYW1zKSB8fCBmb3JjZUZvcm1EYXRhO1xuICAgIHZhciBuZXdQYXJhbXMgPSBwcm9jZXNzUGFyYW1zKHBhcmFtcyk7XG4gICAgaWYgKHVzZUZvcm1EYXRhKSB7XG4gICAgICAgIHZhciBmb3JtRGF0YV8xID0gbmV3IEZvcm1EYXRhKCk7XG4gICAgICAgIE9iamVjdC5rZXlzKG5ld1BhcmFtcykuZm9yRWFjaChmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgICAgICBpZiAodHlwZW9mIEJsb2IgIT09IFwidW5kZWZpbmVkXCIgJiYgbmV3UGFyYW1zW2tleV0gaW5zdGFuY2VvZiBCbG9iKSB7XG4gICAgICAgICAgICAgICAgLyogVG8gbmFtZSB0aGUgQmxvYjpcbiAgICAgICAgICAgICAgICAgMS4gbG9vayB0byBhbiBhbHRlcm5hdGUgcmVxdWVzdCBwYXJhbWV0ZXIgY2FsbGVkICdmaWxlTmFtZSdcbiAgICAgICAgICAgICAgICAgMi4gc2VlIGlmICduYW1lJyBoYXMgYmVlbiB0YWNrZWQgb250byB0aGUgQmxvYiBtYW51YWxseVxuICAgICAgICAgICAgICAgICAzLiBpZiBhbGwgZWxzZSBmYWlscywgdXNlIHRoZSByZXF1ZXN0IHBhcmFtZXRlclxuICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgdmFyIGZpbGVuYW1lID0gbmV3UGFyYW1zW1wiZmlsZU5hbWVcIl0gfHwgbmV3UGFyYW1zW2tleV0ubmFtZSB8fCBrZXk7XG4gICAgICAgICAgICAgICAgZm9ybURhdGFfMS5hcHBlbmQoa2V5LCBuZXdQYXJhbXNba2V5XSwgZmlsZW5hbWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgZm9ybURhdGFfMS5hcHBlbmQoa2V5LCBuZXdQYXJhbXNba2V5XSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gZm9ybURhdGFfMTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIHJldHVybiBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgIH1cbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWVuY29kZS1mb3JtLWRhdGEuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHByb2Nlc3NQYXJhbXMgfSBmcm9tIFwiLi9wcm9jZXNzLXBhcmFtc1wiO1xuLyoqXG4gKiBFbmNvZGVzIGtleXMgYW5kIHBhcmFtZXRlcnMgZm9yIHVzZSBpbiBhIFVSTCdzIHF1ZXJ5IHN0cmluZy5cbiAqXG4gKiBAcGFyYW0ga2V5IFBhcmFtZXRlcidzIGtleVxuICogQHBhcmFtIHZhbHVlIFBhcmFtZXRlcidzIHZhbHVlXG4gKiBAcmV0dXJucyBRdWVyeSBzdHJpbmcgd2l0aCBrZXkgYW5kIHZhbHVlIHBhaXJzIHNlcGFyYXRlZCBieSBcIiZcIlxuICovXG5leHBvcnQgZnVuY3Rpb24gZW5jb2RlUGFyYW0oa2V5LCB2YWx1ZSkge1xuICAgIC8vIEZvciBhcnJheSBvZiBhcnJheXMsIHJlcGVhdCBrZXk9dmFsdWUgZm9yIGVhY2ggZWxlbWVudCBvZiBjb250YWluaW5nIGFycmF5XG4gICAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpICYmIHZhbHVlWzBdICYmIEFycmF5LmlzQXJyYXkodmFsdWVbMF0pKSB7XG4gICAgICAgIHJldHVybiB2YWx1ZS5tYXAoZnVuY3Rpb24gKGFycmF5RWxlbSkgeyByZXR1cm4gZW5jb2RlUGFyYW0oa2V5LCBhcnJheUVsZW0pOyB9KS5qb2luKFwiJlwiKTtcbiAgICB9XG4gICAgcmV0dXJuIGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsgXCI9XCIgKyBlbmNvZGVVUklDb21wb25lbnQodmFsdWUpO1xufVxuLyoqXG4gKiBFbmNvZGVzIHRoZSBwYXNzZWQgb2JqZWN0IGFzIGEgcXVlcnkgc3RyaW5nLlxuICpcbiAqIEBwYXJhbSBwYXJhbXMgQW4gb2JqZWN0IHRvIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJucyBBbiBlbmNvZGVkIHF1ZXJ5IHN0cmluZy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVuY29kZVF1ZXJ5U3RyaW5nKHBhcmFtcykge1xuICAgIHZhciBuZXdQYXJhbXMgPSBwcm9jZXNzUGFyYW1zKHBhcmFtcyk7XG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKG5ld1BhcmFtcylcbiAgICAgICAgLm1hcChmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHJldHVybiBlbmNvZGVQYXJhbShrZXksIG5ld1BhcmFtc1trZXldKTtcbiAgICB9KVxuICAgICAgICAuam9pbihcIiZcIik7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1lbmNvZGUtcXVlcnktc3RyaW5nLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vKipcbiAqIENoZWNrcyBwYXJhbWV0ZXJzIHRvIHNlZSBpZiB3ZSBzaG91bGQgdXNlIEZvcm1EYXRhIHRvIHNlbmQgdGhlIHJlcXVlc3RcbiAqIEBwYXJhbSBwYXJhbXMgVGhlIG9iamVjdCB3aG9zZSBrZXlzIHdpbGwgYmUgZW5jb2RlZC5cbiAqIEByZXR1cm4gQSBib29sZWFuIGluZGljYXRpbmcgaWYgRm9ybURhdGEgd2lsbCBiZSByZXF1aXJlZC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHJlcXVpcmVzRm9ybURhdGEocGFyYW1zKSB7XG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKHBhcmFtcykuc29tZShmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHZhciB2YWx1ZSA9IHBhcmFtc1trZXldO1xuICAgICAgICBpZiAoIXZhbHVlKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHZhbHVlICYmIHZhbHVlLnRvUGFyYW0pIHtcbiAgICAgICAgICAgIHZhbHVlID0gdmFsdWUudG9QYXJhbSgpO1xuICAgICAgICB9XG4gICAgICAgIHZhciB0eXBlID0gdmFsdWUuY29uc3RydWN0b3IubmFtZTtcbiAgICAgICAgc3dpdGNoICh0eXBlKSB7XG4gICAgICAgICAgICBjYXNlIFwiQXJyYXlcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiT2JqZWN0XCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIkRhdGVcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiRnVuY3Rpb25cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiQm9vbGVhblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJTdHJpbmdcIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiTnVtYmVyXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgIH0pO1xufVxuLyoqXG4gKiBDb252ZXJ0cyBwYXJhbWV0ZXJzIHRvIHRoZSBwcm9wZXIgcmVwcmVzZW50YXRpb24gdG8gc2VuZCB0byB0aGUgQXJjR0lTIFJFU1QgQVBJLlxuICogQHBhcmFtIHBhcmFtcyBUaGUgb2JqZWN0IHdob3NlIGtleXMgd2lsbCBiZSBlbmNvZGVkLlxuICogQHJldHVybiBBIG5ldyBvYmplY3Qgd2l0aCBwcm9wZXJseSBlbmNvZGVkIHZhbHVlcy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHByb2Nlc3NQYXJhbXMocGFyYW1zKSB7XG4gICAgdmFyIG5ld1BhcmFtcyA9IHt9O1xuICAgIE9iamVjdC5rZXlzKHBhcmFtcykuZm9yRWFjaChmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHZhciBfYSwgX2I7XG4gICAgICAgIHZhciBwYXJhbSA9IHBhcmFtc1trZXldO1xuICAgICAgICBpZiAocGFyYW0gJiYgcGFyYW0udG9QYXJhbSkge1xuICAgICAgICAgICAgcGFyYW0gPSBwYXJhbS50b1BhcmFtKCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFwYXJhbSAmJlxuICAgICAgICAgICAgcGFyYW0gIT09IDAgJiZcbiAgICAgICAgICAgIHR5cGVvZiBwYXJhbSAhPT0gXCJib29sZWFuXCIgJiZcbiAgICAgICAgICAgIHR5cGVvZiBwYXJhbSAhPT0gXCJzdHJpbmdcIikge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHZhciB0eXBlID0gcGFyYW0uY29uc3RydWN0b3IubmFtZTtcbiAgICAgICAgdmFyIHZhbHVlO1xuICAgICAgICAvLyBwcm9wZXJseSBlbmNvZGVzIG9iamVjdHMsIGFycmF5cyBhbmQgZGF0ZXMgZm9yIGFyY2dpcy5jb20gYW5kIG90aGVyIHNlcnZpY2VzLlxuICAgICAgICAvLyBwb3J0ZWQgZnJvbSBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9lc3JpLWxlYWZsZXQvYmxvYi9tYXN0ZXIvc3JjL1JlcXVlc3QuanMjTDIyLUwzMFxuICAgICAgICAvLyBhbHNvIHNlZSBodHRwczovL2dpdGh1Yi5jb20vRXNyaS9hcmNnaXMtcmVzdC1qcy9pc3N1ZXMvMTg6XG4gICAgICAgIC8vIG51bGwsIHVuZGVmaW5lZCwgZnVuY3Rpb24gYXJlIGV4Y2x1ZGVkLiBJZiB5b3Ugd2FudCB0byBzZW5kIGFuIGVtcHR5IGtleSB5b3UgbmVlZCB0byBzZW5kIGFuIGVtcHR5IHN0cmluZyBcIlwiLlxuICAgICAgICBzd2l0Y2ggKHR5cGUpIHtcbiAgICAgICAgICAgIGNhc2UgXCJBcnJheVwiOlxuICAgICAgICAgICAgICAgIC8vIEJhc2VkIG9uIHRoZSBmaXJzdCBlbGVtZW50IG9mIHRoZSBhcnJheSwgY2xhc3NpZnkgYXJyYXkgYXMgYW4gYXJyYXkgb2YgYXJyYXlzLCBhbiBhcnJheSBvZiBvYmplY3RzXG4gICAgICAgICAgICAgICAgLy8gdG8gYmUgc3RyaW5naWZpZWQsIG9yIGFuIGFycmF5IG9mIG5vbi1vYmplY3RzIHRvIGJlIGNvbW1hLXNlcGFyYXRlZFxuICAgICAgICAgICAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby1jYXNlLWRlY2xhcmF0aW9uc1xuICAgICAgICAgICAgICAgIHZhciBmaXJzdEVsZW1lbnRUeXBlID0gKF9iID0gKF9hID0gcGFyYW1bMF0pID09PSBudWxsIHx8IF9hID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYS5jb25zdHJ1Y3RvcikgPT09IG51bGwgfHwgX2IgPT09IHZvaWQgMCA/IHZvaWQgMCA6IF9iLm5hbWU7XG4gICAgICAgICAgICAgICAgdmFsdWUgPVxuICAgICAgICAgICAgICAgICAgICBmaXJzdEVsZW1lbnRUeXBlID09PSBcIkFycmF5XCIgPyBwYXJhbSA6IC8vIHBhc3MgdGhydSBhcnJheSBvZiBhcnJheXNcbiAgICAgICAgICAgICAgICAgICAgICAgIGZpcnN0RWxlbWVudFR5cGUgPT09IFwiT2JqZWN0XCIgPyBKU09OLnN0cmluZ2lmeShwYXJhbSkgOiAvLyBzdHJpbmdpZnkgYXJyYXkgb2Ygb2JqZWN0c1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHBhcmFtLmpvaW4oXCIsXCIpOyAvLyBqb2luIG90aGVyIHR5cGVzIG9mIGFycmF5IGVsZW1lbnRzXG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIFwiT2JqZWN0XCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBKU09OLnN0cmluZ2lmeShwYXJhbSk7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBjYXNlIFwiRGF0ZVwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gcGFyYW0udmFsdWVPZigpO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIkZ1bmN0aW9uXCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBudWxsO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIkJvb2xlYW5cIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IHBhcmFtICsgXCJcIjtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBwYXJhbTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBpZiAodmFsdWUgfHwgdmFsdWUgPT09IDAgfHwgdHlwZW9mIHZhbHVlID09PSBcInN0cmluZ1wiIHx8IEFycmF5LmlzQXJyYXkodmFsdWUpKSB7XG4gICAgICAgICAgICBuZXdQYXJhbXNba2V5XSA9IHZhbHVlO1xuICAgICAgICB9XG4gICAgfSk7XG4gICAgcmV0dXJuIG5ld1BhcmFtcztcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXByb2Nlc3MtcGFyYW1zLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbi8qKlxuICogTWV0aG9kIHVzZWQgaW50ZXJuYWxseSB0byBzdXJmYWNlIG1lc3NhZ2VzIHRvIGRldmVsb3BlcnMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB3YXJuKG1lc3NhZ2UpIHtcbiAgICBpZiAoY29uc29sZSAmJiBjb25zb2xlLndhcm4pIHtcbiAgICAgICAgY29uc29sZS53YXJuLmFwcGx5KGNvbnNvbGUsIFttZXNzYWdlXSk7XG4gICAgfVxufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9d2Fybi5qcy5tYXAiLCIvKiEgKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcclxuQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uXHJcblxyXG5QZXJtaXNzaW9uIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBhbmQvb3IgZGlzdHJpYnV0ZSB0aGlzIHNvZnR3YXJlIGZvciBhbnlcclxucHVycG9zZSB3aXRoIG9yIHdpdGhvdXQgZmVlIGlzIGhlcmVieSBncmFudGVkLlxyXG5cclxuVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiBBTkQgVEhFIEFVVEhPUiBESVNDTEFJTVMgQUxMIFdBUlJBTlRJRVMgV0lUSFxyXG5SRUdBUkQgVE8gVEhJUyBTT0ZUV0FSRSBJTkNMVURJTkcgQUxMIElNUExJRUQgV0FSUkFOVElFUyBPRiBNRVJDSEFOVEFCSUxJVFlcclxuQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUiBBTlkgU1BFQ0lBTCwgRElSRUNULFxyXG5JTkRJUkVDVCwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIE9SIEFOWSBEQU1BR0VTIFdIQVRTT0VWRVIgUkVTVUxUSU5HIEZST01cclxuTE9TUyBPRiBVU0UsIERBVEEgT1IgUFJPRklUUywgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIE5FR0xJR0VOQ0UgT1JcclxuT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUlxyXG5QRVJGT1JNQU5DRSBPRiBUSElTIFNPRlRXQVJFLlxyXG4qKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiAqL1xyXG4vKiBnbG9iYWwgUmVmbGVjdCwgUHJvbWlzZSAqL1xyXG5cclxudmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbihkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XHJcbiAgICAgICAgKHsgX19wcm90b19fOiBbXSB9IGluc3RhbmNlb2YgQXJyYXkgJiYgZnVuY3Rpb24gKGQsIGIpIHsgZC5fX3Byb3RvX18gPSBiOyB9KSB8fFxyXG4gICAgICAgIGZ1bmN0aW9uIChkLCBiKSB7IGZvciAodmFyIHAgaW4gYikgaWYgKGIuaGFzT3duUHJvcGVydHkocCkpIGRbcF0gPSBiW3BdOyB9O1xyXG4gICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHRlbmRzKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MoZCwgYik7XHJcbiAgICBmdW5jdGlvbiBfXygpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGQ7IH1cclxuICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcclxufVxyXG5cclxuZXhwb3J0IHZhciBfX2Fzc2lnbiA9IGZ1bmN0aW9uKCkge1xyXG4gICAgX19hc3NpZ24gPSBPYmplY3QuYXNzaWduIHx8IGZ1bmN0aW9uIF9fYXNzaWduKHQpIHtcclxuICAgICAgICBmb3IgKHZhciBzLCBpID0gMSwgbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBuOyBpKyspIHtcclxuICAgICAgICAgICAgcyA9IGFyZ3VtZW50c1tpXTtcclxuICAgICAgICAgICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApKSB0W3BdID0gc1twXTtcclxuICAgICAgICB9XHJcbiAgICAgICAgcmV0dXJuIHQ7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gX19hc3NpZ24uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVzdChzLCBlKSB7XHJcbiAgICB2YXIgdCA9IHt9O1xyXG4gICAgZm9yICh2YXIgcCBpbiBzKSBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHMsIHApICYmIGUuaW5kZXhPZihwKSA8IDApXHJcbiAgICAgICAgdFtwXSA9IHNbcF07XHJcbiAgICBpZiAocyAhPSBudWxsICYmIHR5cGVvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzID09PSBcImZ1bmN0aW9uXCIpXHJcbiAgICAgICAgZm9yICh2YXIgaSA9IDAsIHAgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlTeW1ib2xzKHMpOyBpIDwgcC5sZW5ndGg7IGkrKykge1xyXG4gICAgICAgICAgICBpZiAoZS5pbmRleE9mKHBbaV0pIDwgMCAmJiBPYmplY3QucHJvdG90eXBlLnByb3BlcnR5SXNFbnVtZXJhYmxlLmNhbGwocywgcFtpXSkpXHJcbiAgICAgICAgICAgICAgICB0W3BbaV1dID0gc1twW2ldXTtcclxuICAgICAgICB9XHJcbiAgICByZXR1cm4gdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpIHtcclxuICAgIHZhciBjID0gYXJndW1lbnRzLmxlbmd0aCwgciA9IGMgPCAzID8gdGFyZ2V0IDogZGVzYyA9PT0gbnVsbCA/IGRlc2MgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHRhcmdldCwga2V5KSA6IGRlc2MsIGQ7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QuZGVjb3JhdGUgPT09IFwiZnVuY3Rpb25cIikgciA9IFJlZmxlY3QuZGVjb3JhdGUoZGVjb3JhdG9ycywgdGFyZ2V0LCBrZXksIGRlc2MpO1xyXG4gICAgZWxzZSBmb3IgKHZhciBpID0gZGVjb3JhdG9ycy5sZW5ndGggLSAxOyBpID49IDA7IGktLSkgaWYgKGQgPSBkZWNvcmF0b3JzW2ldKSByID0gKGMgPCAzID8gZChyKSA6IGMgPiAzID8gZCh0YXJnZXQsIGtleSwgcikgOiBkKHRhcmdldCwga2V5KSkgfHwgcjtcclxuICAgIHJldHVybiBjID4gMyAmJiByICYmIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0YXJnZXQsIGtleSwgciksIHI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3BhcmFtKHBhcmFtSW5kZXgsIGRlY29yYXRvcikge1xyXG4gICAgcmV0dXJuIGZ1bmN0aW9uICh0YXJnZXQsIGtleSkgeyBkZWNvcmF0b3IodGFyZ2V0LCBrZXksIHBhcmFtSW5kZXgpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKSB7XHJcbiAgICBpZiAodHlwZW9mIFJlZmxlY3QgPT09IFwib2JqZWN0XCIgJiYgdHlwZW9mIFJlZmxlY3QubWV0YWRhdGEgPT09IFwiZnVuY3Rpb25cIikgcmV0dXJuIFJlZmxlY3QubWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdGVyKHRoaXNBcmcsIF9hcmd1bWVudHMsIFAsIGdlbmVyYXRvcikge1xyXG4gICAgZnVuY3Rpb24gYWRvcHQodmFsdWUpIHsgcmV0dXJuIHZhbHVlIGluc3RhbmNlb2YgUCA/IHZhbHVlIDogbmV3IFAoZnVuY3Rpb24gKHJlc29sdmUpIHsgcmVzb2x2ZSh2YWx1ZSk7IH0pOyB9XHJcbiAgICByZXR1cm4gbmV3IChQIHx8IChQID0gUHJvbWlzZSkpKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcclxuICAgICAgICBmdW5jdGlvbiBmdWxmaWxsZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3IubmV4dCh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gcmVqZWN0ZWQodmFsdWUpIHsgdHJ5IHsgc3RlcChnZW5lcmF0b3JbXCJ0aHJvd1wiXSh2YWx1ZSkpOyB9IGNhdGNoIChlKSB7IHJlamVjdChlKTsgfSB9XHJcbiAgICAgICAgZnVuY3Rpb24gc3RlcChyZXN1bHQpIHsgcmVzdWx0LmRvbmUgPyByZXNvbHZlKHJlc3VsdC52YWx1ZSkgOiBhZG9wdChyZXN1bHQudmFsdWUpLnRoZW4oZnVsZmlsbGVkLCByZWplY3RlZCk7IH1cclxuICAgICAgICBzdGVwKChnZW5lcmF0b3IgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSkpLm5leHQoKSk7XHJcbiAgICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZ2VuZXJhdG9yKHRoaXNBcmcsIGJvZHkpIHtcclxuICAgIHZhciBfID0geyBsYWJlbDogMCwgc2VudDogZnVuY3Rpb24oKSB7IGlmICh0WzBdICYgMSkgdGhyb3cgdFsxXTsgcmV0dXJuIHRbMV07IH0sIHRyeXM6IFtdLCBvcHM6IFtdIH0sIGYsIHksIHQsIGc7XHJcbiAgICByZXR1cm4gZyA9IHsgbmV4dDogdmVyYigwKSwgXCJ0aHJvd1wiOiB2ZXJiKDEpLCBcInJldHVyblwiOiB2ZXJiKDIpIH0sIHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiAoZ1tTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24oKSB7IHJldHVybiB0aGlzOyB9KSwgZztcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyByZXR1cm4gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIHN0ZXAoW24sIHZdKTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc3RlcChvcCkge1xyXG4gICAgICAgIGlmIChmKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiR2VuZXJhdG9yIGlzIGFscmVhZHkgZXhlY3V0aW5nLlwiKTtcclxuICAgICAgICB3aGlsZSAoXykgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKGYgPSAxLCB5ICYmICh0ID0gb3BbMF0gJiAyID8geVtcInJldHVyblwiXSA6IG9wWzBdID8geVtcInRocm93XCJdIHx8ICgodCA9IHlbXCJyZXR1cm5cIl0pICYmIHQuY2FsbCh5KSwgMCkgOiB5Lm5leHQpICYmICEodCA9IHQuY2FsbCh5LCBvcFsxXSkpLmRvbmUpIHJldHVybiB0O1xyXG4gICAgICAgICAgICBpZiAoeSA9IDAsIHQpIG9wID0gW29wWzBdICYgMiwgdC52YWx1ZV07XHJcbiAgICAgICAgICAgIHN3aXRjaCAob3BbMF0pIHtcclxuICAgICAgICAgICAgICAgIGNhc2UgMDogY2FzZSAxOiB0ID0gb3A7IGJyZWFrO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA0OiBfLmxhYmVsKys7IHJldHVybiB7IHZhbHVlOiBvcFsxXSwgZG9uZTogZmFsc2UgfTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNTogXy5sYWJlbCsrOyB5ID0gb3BbMV07IG9wID0gWzBdOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGNhc2UgNzogb3AgPSBfLm9wcy5wb3AoKTsgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKCEodCA9IF8udHJ5cywgdCA9IHQubGVuZ3RoID4gMCAmJiB0W3QubGVuZ3RoIC0gMV0pICYmIChvcFswXSA9PT0gNiB8fCBvcFswXSA9PT0gMikpIHsgXyA9IDA7IGNvbnRpbnVlOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSAzICYmICghdCB8fCAob3BbMV0gPiB0WzBdICYmIG9wWzFdIDwgdFszXSkpKSB7IF8ubGFiZWwgPSBvcFsxXTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDYgJiYgXy5sYWJlbCA8IHRbMV0pIHsgXy5sYWJlbCA9IHRbMV07IHQgPSBvcDsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodCAmJiBfLmxhYmVsIDwgdFsyXSkgeyBfLmxhYmVsID0gdFsyXTsgXy5vcHMucHVzaChvcCk7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHRbMl0pIF8ub3BzLnBvcCgpO1xyXG4gICAgICAgICAgICAgICAgICAgIF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgb3AgPSBib2R5LmNhbGwodGhpc0FyZywgXyk7XHJcbiAgICAgICAgfSBjYXRjaCAoZSkgeyBvcCA9IFs2LCBlXTsgeSA9IDA7IH0gZmluYWxseSB7IGYgPSB0ID0gMDsgfVxyXG4gICAgICAgIGlmIChvcFswXSAmIDUpIHRocm93IG9wWzFdOyByZXR1cm4geyB2YWx1ZTogb3BbMF0gPyBvcFsxXSA6IHZvaWQgMCwgZG9uZTogdHJ1ZSB9O1xyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jcmVhdGVCaW5kaW5nKG8sIG0sIGssIGsyKSB7XHJcbiAgICBpZiAoazIgPT09IHVuZGVmaW5lZCkgazIgPSBrO1xyXG4gICAgb1trMl0gPSBtW2tdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19leHBvcnRTdGFyKG0sIGV4cG9ydHMpIHtcclxuICAgIGZvciAodmFyIHAgaW4gbSkgaWYgKHAgIT09IFwiZGVmYXVsdFwiICYmICFleHBvcnRzLmhhc093blByb3BlcnR5KHApKSBleHBvcnRzW3BdID0gbVtwXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fdmFsdWVzKG8pIHtcclxuICAgIHZhciBzID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIFN5bWJvbC5pdGVyYXRvciwgbSA9IHMgJiYgb1tzXSwgaSA9IDA7XHJcbiAgICBpZiAobSkgcmV0dXJuIG0uY2FsbChvKTtcclxuICAgIGlmIChvICYmIHR5cGVvZiBvLmxlbmd0aCA9PT0gXCJudW1iZXJcIikgcmV0dXJuIHtcclxuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XHJcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XHJcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcclxuICAgICAgICB9XHJcbiAgICB9O1xyXG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihzID8gXCJPYmplY3QgaXMgbm90IGl0ZXJhYmxlLlwiIDogXCJTeW1ib2wuaXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZWFkKG8sIG4pIHtcclxuICAgIHZhciBtID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIG9bU3ltYm9sLml0ZXJhdG9yXTtcclxuICAgIGlmICghbSkgcmV0dXJuIG87XHJcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcclxuICAgIHRyeSB7XHJcbiAgICAgICAgd2hpbGUgKChuID09PSB2b2lkIDAgfHwgbi0tID4gMCkgJiYgIShyID0gaS5uZXh0KCkpLmRvbmUpIGFyLnB1c2goci52YWx1ZSk7XHJcbiAgICB9XHJcbiAgICBjYXRjaCAoZXJyb3IpIHsgZSA9IHsgZXJyb3I6IGVycm9yIH07IH1cclxuICAgIGZpbmFsbHkge1xyXG4gICAgICAgIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChyICYmICFyLmRvbmUgJiYgKG0gPSBpW1wicmV0dXJuXCJdKSkgbS5jYWxsKGkpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cclxuICAgIH1cclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkKCkge1xyXG4gICAgZm9yICh2YXIgYXIgPSBbXSwgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspXHJcbiAgICAgICAgYXIgPSBhci5jb25jYXQoX19yZWFkKGFyZ3VtZW50c1tpXSkpO1xyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWRBcnJheXMoKSB7XHJcbiAgICBmb3IgKHZhciBzID0gMCwgaSA9IDAsIGlsID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGlsOyBpKyspIHMgKz0gYXJndW1lbnRzW2ldLmxlbmd0aDtcclxuICAgIGZvciAodmFyIHIgPSBBcnJheShzKSwgayA9IDAsIGkgPSAwOyBpIDwgaWw7IGkrKylcclxuICAgICAgICBmb3IgKHZhciBhID0gYXJndW1lbnRzW2ldLCBqID0gMCwgamwgPSBhLmxlbmd0aDsgaiA8IGpsOyBqKyssIGsrKylcclxuICAgICAgICAgICAgcltrXSA9IGFbal07XHJcbiAgICByZXR1cm4gcjtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0KHYpIHtcclxuICAgIHJldHVybiB0aGlzIGluc3RhbmNlb2YgX19hd2FpdCA/ICh0aGlzLnYgPSB2LCB0aGlzKSA6IG5ldyBfX2F3YWl0KHYpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0dlbmVyYXRvcih0aGlzQXJnLCBfYXJndW1lbnRzLCBnZW5lcmF0b3IpIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgZyA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSwgaSwgcSA9IFtdO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlmIChnW25dKSBpW25dID0gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChhLCBiKSB7IHEucHVzaChbbiwgdiwgYSwgYl0pID4gMSB8fCByZXN1bWUobiwgdik7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiByZXN1bWUobiwgdikgeyB0cnkgeyBzdGVwKGdbbl0odikpOyB9IGNhdGNoIChlKSB7IHNldHRsZShxWzBdWzNdLCBlKTsgfSB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKHIpIHsgci52YWx1ZSBpbnN0YW5jZW9mIF9fYXdhaXQgPyBQcm9taXNlLnJlc29sdmUoci52YWx1ZS52KS50aGVuKGZ1bGZpbGwsIHJlamVjdCkgOiBzZXR0bGUocVswXVsyXSwgcik7IH1cclxuICAgIGZ1bmN0aW9uIGZ1bGZpbGwodmFsdWUpIHsgcmVzdW1lKFwibmV4dFwiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHJlamVjdCh2YWx1ZSkgeyByZXN1bWUoXCJ0aHJvd1wiLCB2YWx1ZSk7IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShmLCB2KSB7IGlmIChmKHYpLCBxLnNoaWZ0KCksIHEubGVuZ3RoKSByZXN1bWUocVswXVswXSwgcVswXVsxXSk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNEZWxlZ2F0b3Iobykge1xyXG4gICAgdmFyIGksIHA7XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIsIGZ1bmN0aW9uIChlKSB7IHRocm93IGU7IH0pLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuLCBmKSB7IGlbbl0gPSBvW25dID8gZnVuY3Rpb24gKHYpIHsgcmV0dXJuIChwID0gIXApID8geyB2YWx1ZTogX19hd2FpdChvW25dKHYpKSwgZG9uZTogbiA9PT0gXCJyZXR1cm5cIiB9IDogZiA/IGYodikgOiB2OyB9IDogZjsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY1ZhbHVlcyhvKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIG0gPSBvW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSwgaTtcclxuICAgIHJldHVybiBtID8gbS5jYWxsKG8pIDogKG8gPSB0eXBlb2YgX192YWx1ZXMgPT09IFwiZnVuY3Rpb25cIiA/IF9fdmFsdWVzKG8pIDogb1tTeW1ib2wuaXRlcmF0b3JdKCksIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiKSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuYXN5bmNJdGVyYXRvcl0gPSBmdW5jdGlvbiAoKSB7IHJldHVybiB0aGlzOyB9LCBpKTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpW25dID0gb1tuXSAmJiBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkgeyB2ID0gb1tuXSh2KSwgc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgdi5kb25lLCB2LnZhbHVlKTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHNldHRsZShyZXNvbHZlLCByZWplY3QsIGQsIHYpIHsgUHJvbWlzZS5yZXNvbHZlKHYpLnRoZW4oZnVuY3Rpb24odikgeyByZXNvbHZlKHsgdmFsdWU6IHYsIGRvbmU6IGQgfSk7IH0sIHJlamVjdCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWFrZVRlbXBsYXRlT2JqZWN0KGNvb2tlZCwgcmF3KSB7XHJcbiAgICBpZiAoT2JqZWN0LmRlZmluZVByb3BlcnR5KSB7IE9iamVjdC5kZWZpbmVQcm9wZXJ0eShjb29rZWQsIFwicmF3XCIsIHsgdmFsdWU6IHJhdyB9KTsgfSBlbHNlIHsgY29va2VkLnJhdyA9IHJhdzsgfVxyXG4gICAgcmV0dXJuIGNvb2tlZDtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydFN0YXIobW9kKSB7XHJcbiAgICBpZiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSByZXR1cm4gbW9kO1xyXG4gICAgdmFyIHJlc3VsdCA9IHt9O1xyXG4gICAgaWYgKG1vZCAhPSBudWxsKSBmb3IgKHZhciBrIGluIG1vZCkgaWYgKE9iamVjdC5oYXNPd25Qcm9wZXJ0eS5jYWxsKG1vZCwgaykpIHJlc3VsdFtrXSA9IG1vZFtrXTtcclxuICAgIHJlc3VsdC5kZWZhdWx0ID0gbW9kO1xyXG4gICAgcmV0dXJuIHJlc3VsdDtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0RGVmYXVsdChtb2QpIHtcclxuICAgIHJldHVybiAobW9kICYmIG1vZC5fX2VzTW9kdWxlKSA/IG1vZCA6IHsgZGVmYXVsdDogbW9kIH07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkR2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gZ2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHByaXZhdGVNYXAuZ2V0KHJlY2VpdmVyKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRTZXQocmVjZWl2ZXIsIHByaXZhdGVNYXAsIHZhbHVlKSB7XHJcbiAgICBpZiAoIXByaXZhdGVNYXAuaGFzKHJlY2VpdmVyKSkge1xyXG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJhdHRlbXB0ZWQgdG8gc2V0IHByaXZhdGUgZmllbGQgb24gbm9uLWluc3RhbmNlXCIpO1xyXG4gICAgfVxyXG4gICAgcHJpdmF0ZU1hcC5zZXQocmVjZWl2ZXIsIHZhbHVlKTtcclxuICAgIHJldHVybiB2YWx1ZTtcclxufVxyXG4iLCJpbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCI7XHJcbmltcG9ydCB7XHJcbiAgQXBwV2lkZ2V0Q29uZmlnLCBBc3Nlc3NtZW50LCBcclxuICBDbHNzUmVzcG9uc2UsXHJcbiAgQ0xTU1RlbXBsYXRlLCBcclxuICBDb21wb25lbnRUZW1wbGF0ZSwgXHJcbiAgSGF6YXJkLFxyXG4gIEluY2lkZW50LFxyXG4gIEluQ29tbWVudCxcclxuICBJbmRpY2F0b3JBc3Nlc3NtZW50LFxyXG4gIEluZGljYXRvclRlbXBsYXRlLCBJbmRpY2F0b3JXZWlnaHQsIExpZmVsaW5lU3RhdHVzLCBMaWZlTGluZVRlbXBsYXRlLFxyXG4gIE9yZ2FuaXphdGlvbiwgU2NhbGVGYWN0b3JcclxufSBmcm9tIFwiLi9kYXRhLWRlZmluaXRpb25zXCI7XHJcbmltcG9ydCB7XHJcbiAgQVNTRVNTTUVOVF9VUkxfRVJST1IsIFxyXG4gIEJBU0VMSU5FX1RFTVBMQVRFX05BTUUsIFxyXG4gIENPTVBPTkVOVF9VUkxfRVJST1IsIEVOVklST05NRU5UX1BSRVNFUlZBVElPTiwgSEFaQVJEX1VSTF9FUlJPUiwgSU5DSURFTlRfU1RBQklMSVpBVElPTiwgSU5DSURFTlRfVVJMX0VSUk9SLCBJTkRJQ0FUT1JfVVJMX0VSUk9SLFxyXG4gIExJRkVfU0FGRVRZLFxyXG4gIExJRkVfU0FGRVRZX1NDQUxFX0ZBQ1RPUixcclxuICBMSUZFTElORV9VUkxfRVJST1IsIE1BWElNVU1fV0VJR0hULCBPUkdBTklaQVRJT05fVVJMX0VSUk9SLCBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUiwgXHJcbiAgUE9SVEFMX1VSTCwgXHJcbiAgUFJPUEVSVFlfUFJPVEVDVElPTiwgXHJcbiAgUkFOSywgXHJcbiAgVEVNUExBVEVfVVJMX0VSUk9SfSBmcm9tIFwiLi9jb25zdGFudHNcIjtcclxuaW1wb3J0IHsgZ2V0QXBwU3RvcmUgfSBmcm9tIFwiamltdS1jb3JlXCI7XHJcbmltcG9ydCB7XHJcbiAgSUZlYXR1cmUsIElGZWF0dXJlU2V0LCBJRmllbGR9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyXCI7XHJcbmltcG9ydCB7IHF1ZXJ5VGFibGVGZWF0dXJlcywgXHJcbiAgIHVwZGF0ZVRhYmxlRmVhdHVyZSwgZGVsZXRlVGFibGVGZWF0dXJlcywgXHJcbiAgICBhZGRUYWJsZUZlYXR1cmVzLCB1cGRhdGVUYWJsZUZlYXR1cmVzLCBxdWVyeVRhYmxlRmVhdHVyZVNldCB9IGZyb20gXCIuL2VzcmktYXBpXCI7XHJcbmltcG9ydCB7IGxvZywgTG9nVHlwZSB9IGZyb20gXCIuL2xvZ2dlclwiO1xyXG5pbXBvcnQgeyBJQ29kZWRWYWx1ZSB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC10eXBlc1wiO1xyXG5pbXBvcnQgeyBjaGVja0N1cnJlbnRTdGF0dXMsIHNpZ25JbiB9IGZyb20gXCIuL2F1dGhcIjtcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi9jbHNzLXN0b3JlXCI7XHJcbmltcG9ydCB7IElDcmVkZW50aWFsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWF1dGhcIjtcclxuaW1wb3J0IHsgcGFyc2VEYXRlIH0gZnJvbSBcIi4vdXRpbHNcIjtcclxuXHJcblxyXG4vLz09PT09PT09PT09PT09PT09PT09PT09PVBVQkxJQz09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cclxuXHJcbmV4cG9ydCBjb25zdCBpbml0aWFsaXplQXV0aCA9IGFzeW5jKGFwcElkOiBzdHJpbmcpID0+eyAgIFxyXG4gIGNvbnNvbGUubG9nKCdpbml0aWFsaXplQXV0aCBjYWxsZWQnKVxyXG4gIGxldCBjcmVkID0gYXdhaXQgY2hlY2tDdXJyZW50U3RhdHVzKGFwcElkLCBQT1JUQUxfVVJMKTtcclxuXHJcbiAgaWYoIWNyZWQpe1xyXG4gICAgY3JlZCA9IGF3YWl0IHNpZ25JbihhcHBJZCwgUE9SVEFMX1VSTCk7ICAgIFxyXG4gIH1cclxuXHJcbiAgY29uc3QgY3JlZGVudGlhbCA9IHtcclxuICAgIGV4cGlyZXM6IGNyZWQuZXhwaXJlcyxcclxuICAgIHNlcnZlcjogY3JlZC5zZXJ2ZXIsXHJcbiAgICBzc2w6IGNyZWQuc3NsLFxyXG4gICAgdG9rZW46IGNyZWQudG9rZW4sXHJcbiAgICB1c2VySWQ6IGNyZWQudXNlcklkXHJcbiAgfSBhcyBJQ3JlZGVudGlhbFxyXG5cclxuICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5BVVRIRU5USUNBVEVfQUNUSU9OLCBjcmVkZW50aWFsKTsgXHJcbn1cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZUxpZmVsaW5lU3RhdHVzKGxpZmVsaW5lU3RhdHVzOiBMaWZlbGluZVN0YXR1cywgXHJcbiAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIGFzc2Vzc21lbnRPYmplY3RJZDogbnVtYmVyLCAgdXNlcjogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gIFxyXG4gIGNvbnNvbGUubG9nKCdjYWxsZWQgdXBkYXRlTGlmZWxpbmVTdGF0dXMnKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmxpZmVsaW5lU3RhdHVzLCAnTGlmZWxpbmUgU3RhdHVzIFVSTCBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgY29uc3QgYXR0cmlidXRlcyA9IHtcclxuICAgIE9CSkVDVElEOiBsaWZlbGluZVN0YXR1cy5vYmplY3RJZCxcclxuICAgIFNjb3JlOiBsaWZlbGluZVN0YXR1cy5zY29yZSwgXHJcbiAgICBDb2xvcjogbGlmZWxpbmVTdGF0dXMuY29sb3IsIFxyXG4gICAgSXNPdmVycmlkZW46IGxpZmVsaW5lU3RhdHVzLmlzT3ZlcnJpZGVuLCBcclxuICAgIE92ZXJyaWRlblNjb3JlOiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZVNjb3JlLCAgXHJcbiAgICBPdmVycmlkZW5Db2xvcjogbGlmZWxpbmVTdGF0dXMub3ZlcnJpZGVuQ29sb3IsXHJcbiAgICBPdmVycmlkZW5CeTogbGlmZWxpbmVTdGF0dXMub3ZlcnJpZGVuQnksICBcclxuICAgIE92ZXJyaWRlQ29tbWVudDogbGlmZWxpbmVTdGF0dXMub3ZlcnJpZGVDb21tZW50IFxyXG4gIH1cclxuICBsZXQgcmVzcG9uc2UgID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5saWZlbGluZVN0YXR1cywgYXR0cmlidXRlcywgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuXHJcbiAgICBjb25zdCBpYUZlYXR1cmVzID0gbGlmZWxpbmVTdGF0dXMuaW5kaWNhdG9yQXNzZXNzbWVudHMubWFwKGkgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIE9CSkVDVElEOiBpLm9iamVjdElkLFxyXG4gICAgICAgICAgc3RhdHVzOiBpLnN0YXR1cyxcclxuICAgICAgICAgIENvbW1lbnRzOiBpLmNvbW1lbnRzICYmIGkuY29tbWVudHMubGVuZ3RoID4gMCA/IEpTT04uc3RyaW5naWZ5KGkuY29tbWVudHMpOiAnJ1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSlcclxuXHJcbiAgICByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBpYUZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcblxyXG4gICAgICBjb25zdCBhc3Nlc3NGZWF0dXJlID0ge1xyXG4gICAgICAgIE9CSkVDVElEOiBhc3Nlc3NtZW50T2JqZWN0SWQsXHJcbiAgICAgICAgRWRpdGVkRGF0ZTogbmV3IERhdGUoKS5nZXRUaW1lKCksXHJcbiAgICAgICAgRWRpdG9yOiB1c2VyXHJcbiAgICAgIH1cclxuICAgICAgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmFzc2Vzc21lbnRzLCBhc3Nlc3NGZWF0dXJlLCBjb25maWcpXHJcbiAgICAgIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9ICAgIFxyXG4gIH1cclxuICBsb2coJ1VwZGF0aW5nIExpZmVsaW5lIHNjb3JlIGZhaWxlZCcsIExvZ1R5cGUuRVJST1IsICd1cGRhdGVMaWZlbGluZVN0YXR1cycpO1xyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdVcGRhdGluZyBMaWZlbGluZSBzY29yZSBmYWlsZWQnXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29tcGxldGVBc3Nlc3NtZW50KGFzc2Vzc21lbnQ6IEFzc2Vzc21lbnQsIFxyXG4gIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB1c2VyTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gICBjaGVja1BhcmFtKGNvbmZpZy5hc3Nlc3NtZW50cywgJ05vIEFzc2Vzc21lbnQgVXJsIHByb3ZpZGVkJyk7XHJcblxyXG4gICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmFzc2Vzc21lbnRzLCB7XHJcbiAgICAgIE9CSkVDVElEOiBhc3Nlc3NtZW50Lm9iamVjdElkLFxyXG4gICAgICBFZGl0b3I6IHVzZXJOYW1lLFxyXG4gICAgICBFZGl0ZWREYXRlOiBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcclxuICAgICAgSXNDb21wbGV0ZWQ6IDFcclxuICAgfSwgY29uZmlnKTtcclxuICAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xyXG4gICByZXR1cm57XHJcbiAgICAgZGF0YTogcmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBwYXNzRGF0YUludGVncml0eSA9IGFzeW5jIChzZXJ2aWNlVXJsOiBzdHJpbmcsIGZpZWxkczogSUZpZWxkW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSA9PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oc2VydmljZVVybCwgJ1NlcnZpY2UgVVJMIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICAvLyBzZXJ2aWNlVXJsID0gYCR7c2VydmljZVVybH0/Zj1qc29uJnRva2VuPSR7dG9rZW59YDtcclxuICAvLyBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKHNlcnZpY2VVcmwsIHtcclxuICAvLyAgIG1ldGhvZDogXCJHRVRcIixcclxuICAvLyAgIGhlYWRlcnM6IHtcclxuICAvLyAgICAgJ2NvbnRlbnQtdHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgLy8gICB9XHJcbiAgLy8gfVxyXG4gIC8vICk7XHJcbiAgLy8gY29uc3QganNvbiA9IGF3YWl0IHJlc3BvbnNlLmpzb24oKTtcclxuXHJcbiAgLy8gY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoc2VydmljZVVybCwgJzE9MScsIGNvbmZpZyk7XHJcblxyXG4gIC8vIGNvbnN0IGRhdGFGaWVsZHMgPSBmZWF0dXJlc1swXS4gYXMgSUZpZWxkW107XHJcblxyXG4gIC8vIGRlYnVnZ2VyO1xyXG4gIC8vIGlmIChmaWVsZHMubGVuZ3RoID4gZGF0YUZpZWxkcy5sZW5ndGgpIHtcclxuICAvLyAgIHRocm93IG5ldyBFcnJvcignTnVtYmVyIG9mIGZpZWxkcyBkbyBub3QgbWF0Y2ggZm9yICcgKyBzZXJ2aWNlVXJsKTtcclxuICAvLyB9XHJcblxyXG4gIC8vIGNvbnN0IGFsbEZpZWxkc0dvb2QgPSBmaWVsZHMuZXZlcnkoZiA9PiB7XHJcbiAgLy8gICBjb25zdCBmb3VuZCA9IGRhdGFGaWVsZHMuZmluZChmMSA9PiBmMS5uYW1lID09PSBmLm5hbWUgJiYgZjEudHlwZS50b1N0cmluZygpID09PSBmLnR5cGUudG9TdHJpbmcoKSAmJiBmMS5kb21haW4gPT0gZi5kb21haW4pO1xyXG4gIC8vICAgcmV0dXJuIGZvdW5kO1xyXG4gIC8vIH0pO1xyXG5cclxuICAvLyBpZiAoIWFsbEZpZWxkc0dvb2QpIHtcclxuICAvLyAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBmaWVsZHMgaW4gdGhlIGZlYXR1cmUgc2VydmljZSAnICsgc2VydmljZVVybClcclxuICAvLyB9XHJcbiAgcmV0dXJuIHRydWU7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEluZGljYXRvckZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IEluZGljYXRvcnMgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldFdlaWdodHNGZWF0dXJlcyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBXZWlnaHRzIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRMaWZlbGluZUZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IExpZmVsaW5lIGNhbGxlZCcpO1xyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lcywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldENvbXBvbmVudEZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IENvbXBvbmVudHMgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuY29tcG9uZW50cywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldFRlbXBsYXRlRmVhdHVyZVNldChxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVTZXQ+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgVGVtcGxhdGUgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlU2V0KGNvbmZpZy50ZW1wbGF0ZXMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0VGVtcGxhdGVzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCB0ZW1wbGF0ZUlkPzogc3RyaW5nLCBxdWVyeVN0cmluZz86c3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Q0xTU1RlbXBsYXRlW10+PiB7XHJcblxyXG4gIGNvbnN0IHRlbXBsYXRlVXJsID0gY29uZmlnLnRlbXBsYXRlcztcclxuICBjb25zdCBsaWZlbGluZVVybCA9IGNvbmZpZy5saWZlbGluZXM7XHJcbiAgY29uc3QgY29tcG9uZW50VXJsID0gY29uZmlnLmNvbXBvbmVudHM7XHJcblxyXG4gIHRyeXtcclxuICAgIGNoZWNrUGFyYW0odGVtcGxhdGVVcmwsIFRFTVBMQVRFX1VSTF9FUlJPUik7XHJcbiAgICBjaGVja1BhcmFtKGxpZmVsaW5lVXJsLCBMSUZFTElORV9VUkxfRVJST1IpO1xyXG4gICAgY2hlY2tQYXJhbShjb21wb25lbnRVcmwsIENPTVBPTkVOVF9VUkxfRVJST1IpO1xyXG5cclxuICAgIGNvbnN0IHRlbXBRdWVyeSA9IHRlbXBsYXRlSWQgPyBgR2xvYmFsSUQ9JyR7dGVtcGxhdGVJZH1gIDoocXVlcnlTdHJpbmcgPyBxdWVyeVN0cmluZyA6ICcxPTEnICk7XHJcblxyXG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBQcm9taXNlLmFsbChbXHJcbiAgICAgIGdldFRlbXBsYXRlRmVhdHVyZVNldCh0ZW1wUXVlcnksIGNvbmZpZyksXHJcbiAgICAgIGdldExpZmVsaW5lRmVhdHVyZXMoJzE9MScsIGNvbmZpZyksIFxyXG4gICAgICBnZXRDb21wb25lbnRGZWF0dXJlcygnMT0xJywgY29uZmlnKV0pO1xyXG4gICAgXHJcbiAgICBjb25zdCB0ZW1wbGF0ZUZlYXR1cmVTZXQgPSByZXNwb25zZVswXTtcclxuICAgIGNvbnN0IGxpZmVsaW5lRmVhdHVyZXMgPSByZXNwb25zZVsxXTtcclxuICAgIGNvbnN0IGNvbXBvbmVudEZlYXR1cmVzID0gcmVzcG9uc2VbMl07XHJcblxyXG4gICAgY29uc3QgaW5kaWNhdG9yRmVhdHVyZXMgPSBhd2FpdCBnZXRJbmRpY2F0b3JGZWF0dXJlcygnMT0xJywgY29uZmlnKTtcclxuICAgIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gYXdhaXQgZ2V0V2VpZ2h0c0ZlYXR1cmVzKCcxPTEnLCBjb25maWcpO1xyXG5cclxuICAgIGNvbnN0IHRlbXBsYXRlcyA9IGF3YWl0IFByb21pc2UuYWxsKHRlbXBsYXRlRmVhdHVyZVNldC5mZWF0dXJlcy5tYXAoYXN5bmMgKHRlbXBsYXRlRmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgICAgY29uc3QgdGVtcGxhdGVJbmRpY2F0b3JGZWF0dXJlcyA9IGluZGljYXRvckZlYXR1cmVzLmZpbHRlcihpID0+aS5hdHRyaWJ1dGVzLlRlbXBsYXRlSUQgPT0gdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpICAgICAgXHJcbiAgICAgIHJldHVybiBhd2FpdCBnZXRUZW1wbGF0ZSh0ZW1wbGF0ZUZlYXR1cmUsIGxpZmVsaW5lRmVhdHVyZXMsIGNvbXBvbmVudEZlYXR1cmVzLCBcclxuICAgICAgICB0ZW1wbGF0ZUluZGljYXRvckZlYXR1cmVzLCB3ZWlnaHRGZWF0dXJlcywgXHJcbiAgICAgICAgdGVtcGxhdGVGZWF0dXJlU2V0LmZpZWxkcy5maW5kKGYgPT4gZi5uYW1lID09PSAnU3RhdHVzJykuZG9tYWluLmNvZGVkVmFsdWVzKVxyXG4gICAgfSkpO1xyXG5cclxuICAgIGlmKHRlbXBsYXRlcy5maWx0ZXIodCA9PiB0LmlzU2VsZWN0ZWQpLmxlbmd0aCA+IDEgfHwgdGVtcGxhdGVzLmZpbHRlcih0ID0+IHQuaXNTZWxlY3RlZCkubGVuZ3RoID09IDApe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRlbXBsYXRlcy5tYXAodCA9PiB7XHJcbiAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAuLi50LFxyXG4gICAgICAgICAgICBpc1NlbGVjdGVkOiB0Lm5hbWUgPT09IEJBU0VMSU5FX1RFTVBMQVRFX05BTUVcclxuICAgICAgICAgIH1cclxuICAgICAgICB9KVxyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYodGVtcGxhdGVzLmxlbmd0aCA9PT0gMSl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdGVtcGxhdGVzLm1hcCh0ID0+IHtcclxuICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLnQsXHJcbiAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IHRydWVcclxuICAgICAgICAgIH1cclxuICAgICAgICB9KVxyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0ZW1wbGF0ZXNcclxuICAgIH1cclxuICB9XHJcbiAgY2F0Y2goZSl7IFxyXG4gICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdnZXRUZW1wbGF0ZXMnKTtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogJ1RlbXBsYXRlcyByZXF1ZXN0IGZhaWxlZC4nXHJcbiAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gdXNlRmV0Y2hEYXRhPFQ+KHVybDogc3RyaW5nLCBjYWxsYmFja0FkYXB0ZXI/OiBGdW5jdGlvbik6IFtULCBGdW5jdGlvbiwgYm9vbGVhbiwgc3RyaW5nXSB7XHJcbiAgY29uc3QgW2RhdGEsIHNldERhdGFdID0gUmVhY3QudXNlU3RhdGUobnVsbCk7XHJcbiAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gUmVhY3QudXNlU3RhdGUodHJ1ZSk7XHJcbiAgY29uc3QgW2Vycm9yLCBzZXRFcnJvcl0gPSBSZWFjdC51c2VTdGF0ZSgnJyk7XHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICBjb25zdCBjb250cm9sbGVyID0gbmV3IEFib3J0Q29udHJvbGxlcigpO1xyXG4gICAgcmVxdWVzdERhdGEodXJsLCBjb250cm9sbGVyKVxyXG4gICAgICAudGhlbigoZGF0YSkgPT4ge1xyXG4gICAgICAgIGlmIChjYWxsYmFja0FkYXB0ZXIpIHtcclxuICAgICAgICAgIHNldERhdGEoY2FsbGJhY2tBZGFwdGVyKGRhdGEpKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgc2V0RGF0YShkYXRhKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XHJcbiAgICAgIH0pXHJcbiAgICAgIC5jYXRjaCgoZXJyKSA9PiB7XHJcbiAgICAgICAgY29uc29sZS5sb2coZXJyKTtcclxuICAgICAgICBzZXRFcnJvcihlcnIpO1xyXG4gICAgICB9KVxyXG4gICAgcmV0dXJuICgpID0+IGNvbnRyb2xsZXIuYWJvcnQoKTtcclxuICB9LCBbdXJsXSlcclxuXHJcbiAgcmV0dXJuIFtkYXRhLCBzZXREYXRhLCBsb2FkaW5nLCBlcnJvcl1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGRpc3BhdGNoQWN0aW9uKHR5cGU6IGFueSwgdmFsOiBhbnkpIHtcclxuICBnZXRBcHBTdG9yZSgpLmRpc3BhdGNoKHtcclxuICAgIHR5cGUsXHJcbiAgICB2YWxcclxuICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEluY2lkZW50cyhjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SW5jaWRlbnRbXT4ge1xyXG4gICBcclxuICBjb25zb2xlLmxvZygnZ2V0IGluY2lkZW50cyBjYWxsZWQuJylcclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmNpZGVudHMsIElOQ0lERU5UX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmNpZGVudHMsICcxPTEnLCBjb25maWcpO1xyXG5cclxuICBjb25zdCBxdWVyeSA9IGBHbG9iYWxJRCBJTiAoJHtmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuSGF6YXJkSUQpLm1hcChpZCA9PiBgJyR7aWR9J2ApLmpvaW4oJywnKX0pYDtcclxuICBcclxuICBjb25zdCBoYXphcmRGZWF0dXJlc2V0ID0gYXdhaXQgZ2V0SGF6YXJkRmVhdHVyZXMoY29uZmlnLCBxdWVyeSwgJ2dldEluY2lkZW50cycpO1xyXG5cclxuICByZXR1cm4gZmVhdHVyZXMubWFwKChmOiBJRmVhdHVyZSkgPT57XHJcbiAgICAgIGNvbnN0IGhmID0gaGF6YXJkRmVhdHVyZXNldC5mZWF0dXJlcy5maW5kKGggPT4gaC5hdHRyaWJ1dGVzLkdsb2JhbElEID09IGYuYXR0cmlidXRlcy5IYXphcmRJRClcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBvYmplY3RJZDogZi5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgIGlkOiBmLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgaGF6YXJkOiBoZiA/IHtcclxuICAgICAgICAgIG9iamVjdElkOiBoZi5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgICAgaWQ6IGhmLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgICBuYW1lOiBoZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgICB0aXRsZTogaGYuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUgfHwgaGYuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBoZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgICB0eXBlOiBoZi5hdHRyaWJ1dGVzLlR5cGUsXHJcbiAgICAgICAgICBkZXNjcmlwdGlvbjogaGYuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgICAgICAgIGRvbWFpbnM6IGhhemFyZEZlYXR1cmVzZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdUeXBlJykuZG9tYWluLmNvZGVkVmFsdWVzXHJcbiAgICAgICAgfSA6IG51bGwsXHJcbiAgICAgICAgZGVzY3JpcHRpb246IGYuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgICAgICBzdGFydERhdGU6IE51bWJlcihmLmF0dHJpYnV0ZXMuU3RhcnREYXRlKSxcclxuICAgICAgICBlbmREYXRlOiBOdW1iZXIoZi5hdHRyaWJ1dGVzLkVuZERhdGUpXHJcbiAgICAgIH0gYXMgSW5jaWRlbnQ7XHJcbiAgfSk7XHJcbiAgcmV0dXJuIFtdO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRIYXphcmRGZWF0dXJlcyAoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHF1ZXJ5OiBzdHJpbmcsIGNhbGxlcjogc3RyaW5nKTogUHJvbWlzZTxJRmVhdHVyZVNldD4ge1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgSGF6YXJkcyBjYWxsZWQgYnkgJytjYWxsZXIpXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaGF6YXJkcywgSEFaQVJEX1VSTF9FUlJPUik7ICBcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVTZXQoY29uZmlnLmhhemFyZHMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0SGF6YXJkcyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgcXVlcnlTdHJpbmc6IHN0cmluZywgY2FsbGVyOiBzdHJpbmcpOiBQcm9taXNlPEhhemFyZFtdPiB7XHJcbiAgXHJcbiAgY29uc3QgZmVhdHVyZVNldCA9IGF3YWl0IGdldEhhemFyZEZlYXR1cmVzKGNvbmZpZywgcXVlcnlTdHJpbmcsIGNhbGxlcik7XHJcbiAgaWYoIWZlYXR1cmVTZXQgfHwgZmVhdHVyZVNldC5mZWF0dXJlcy5sZW5ndGggPT0gMCl7XHJcbiAgICByZXR1cm4gW107XHJcbiAgfVxyXG4gIHJldHVybiBmZWF0dXJlU2V0LmZlYXR1cmVzLm1hcCgoZjogSUZlYXR1cmUpID0+IHtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIG9iamVjdElkOiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiBmLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICB0aXRsZTogZi5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSB8fCBmLmF0dHJpYnV0ZXMuRGlzcGxheU5hbWUgfHwgZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIHR5cGU6IGYuYXR0cmlidXRlcy5UeXBlLFxyXG4gICAgICBkZXNjcmlwdGlvbjogZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICBkb21haW5zOiBmZWF0dXJlU2V0LmZpZWxkcy5maW5kKGYgPT4gZi5uYW1lID09PSAnVHlwZScpLmRvbWFpbi5jb2RlZFZhbHVlc1xyXG4gICAgfSBhcyBIYXphcmRcclxuICB9KVxyXG4gIHJldHVybiBbXTtcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldE9yZ2FuaXphdGlvbnMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBQcm9taXNlPE9yZ2FuaXphdGlvbltdPiB7XHJcbiAgY29uc29sZS5sb2coJ2dldCBPcmdhbml6YXRpb25zIGNhbGxlZCcpXHJcbiAgY2hlY2tQYXJhbShjb25maWcub3JnYW5pemF0aW9ucywgT1JHQU5JWkFUSU9OX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGZlYXR1cmVTZXQgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZVNldChjb25maWcub3JnYW5pemF0aW9ucywgcXVlcnlTdHJpbmcsIGNvbmZpZyk7XHJcbiBcclxuICBpZihmZWF0dXJlU2V0ICYmIGZlYXR1cmVTZXQuZmVhdHVyZXMgJiYgZmVhdHVyZVNldC5mZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgIHJldHVybiBmZWF0dXJlU2V0LmZlYXR1cmVzLm1hcCgoZjogSUZlYXR1cmUpID0+IHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBvYmplY3RJZDogZi5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgIGlkOiBmLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgdGl0bGU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIHR5cGU6IGYuYXR0cmlidXRlcy5UeXBlLFxyXG4gICAgICAgIHBhcmVudElkOiBmLmF0dHJpYnV0ZXMuUGFyZW50SUQsXHJcbiAgICAgICAgZGVzY3JpcHRpb246IGYuYXR0cmlidXRlcy5EZXNjcmlwdGlvbixcclxuICAgICAgICBkb21haW5zOiBmZWF0dXJlU2V0LmZpZWxkcy5maW5kKGYgPT4gZi5uYW1lID09PSAnVHlwZScpLmRvbWFpbi5jb2RlZFZhbHVlc1xyXG4gICAgICB9IGFzIE9yZ2FuaXphdGlvblxyXG4gICAgfSlcclxuICB9XHJcbiAgcmV0dXJuIFtdO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY3JlYXRlTmV3VGVtcGxhdGUoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUsIFxyXG4gdXNlck5hbWU6IHN0cmluZywgb3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb24sIGhhemFyZDogSGF6YXJkKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuIFxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLnRlbXBsYXRlcywgVEVNUExBVEVfVVJMX0VSUk9SKTtcclxuICBjaGVja1BhcmFtKHRlbXBsYXRlLCAnVGVtcGxhdGUgZGF0YSBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgY29uc3QgY3JlYXRlRGF0ZSA9IG5ldyBEYXRlKCkuZ2V0VGltZSgpO1xyXG4gIGNvbnN0IHRlbXBsYXRlTmFtZSA9IHRlbXBsYXRlLm5hbWVbMF0udG9Mb2NhbGVVcHBlckNhc2UoKSt0ZW1wbGF0ZS5uYW1lLnN1YnN0cmluZygxKTtcclxuIFxyXG4gIGxldCBmZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBPcmdhbml6YXRpb25JRDogb3JnYW5pemF0aW9uID8gb3JnYW5pemF0aW9uLmlkIDogIG51bGwsXHJcbiAgICAgIE9yZ2FuaXphdGlvbk5hbWU6IG9yZ2FuaXphdGlvbiA/IG9yZ2FuaXphdGlvbi5uYW1lOiBudWxsLFxyXG4gICAgICBPcmdhbml6YXRpb25UeXBlOiBvcmdhbml6YXRpb24gPyAob3JnYW5pemF0aW9uLnR5cGUuY29kZSA/IG9yZ2FuaXphdGlvbi50eXBlLmNvZGU6IG9yZ2FuaXphdGlvbi50eXBlICk6IG51bGwsXHJcbiAgICAgIEhhemFyZElEOiAgaGF6YXJkID8gaGF6YXJkLmlkIDogbnVsbCxcclxuICAgICAgSGF6YXJkTmFtZTogIGhhemFyZCA/IGhhemFyZC5uYW1lIDogbnVsbCxcclxuICAgICAgSGF6YXJkVHlwZTogIGhhemFyZCA/IChoYXphcmQudHlwZS5jb2RlID8gaGF6YXJkLnR5cGUuY29kZSA6IGhhemFyZC50eXBlKSA6IG51bGwsXHJcbiAgICAgIE5hbWU6IHRlbXBsYXRlTmFtZSAsXHJcbiAgICAgIENyZWF0b3I6IHVzZXJOYW1lLFxyXG4gICAgICBDcmVhdGVkRGF0ZTogY3JlYXRlRGF0ZSwgICAgICBcclxuICAgICAgU3RhdHVzOiAxLFxyXG4gICAgICBJc1NlbGVjdGVkOiAwLFxyXG4gICAgICBFZGl0b3I6IHVzZXJOYW1lLFxyXG4gICAgICBFZGl0ZWREYXRlOiBjcmVhdGVEYXRlICAgICBcclxuICAgIH1cclxuICB9XHJcbiAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcudGVtcGxhdGVzLCBbZmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICBcclxuICAgIGNvbnN0IHRlbXBsYXRlSWQgPSByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkO1xyXG4gICAgLy9jcmVhdGUgbmV3IGluZGljYXRvcnMgICBcclxuICAgIGNvbnN0IGluZGljYXRvcnMgPSBnZXRUZW1wbGF0ZUluZGljYXRvcnModGVtcGxhdGUpO1xyXG4gICAgY29uc3QgaW5kaWNhdG9yRmVhdHVyZXMgPSBpbmRpY2F0b3JzLm1hcChpbmRpY2F0b3IgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIFRlbXBsYXRlSUQ6IHRlbXBsYXRlSWQsICBcclxuICAgICAgICAgIENvbXBvbmVudElEOiBpbmRpY2F0b3IuY29tcG9uZW50SWQsXHJcbiAgICAgICAgICBDb21wb25lbnROYW1lOiBpbmRpY2F0b3IuY29tcG9uZW50TmFtZSwgIFxyXG4gICAgICAgICAgTmFtZTogaW5kaWNhdG9yLm5hbWUsICAgXHJcbiAgICAgICAgICBUZW1wbGF0ZU5hbWU6IHRlbXBsYXRlTmFtZSwgXHJcbiAgICAgICAgICBMaWZlbGluZU5hbWU6IGluZGljYXRvci5saWZlbGluZU5hbWUgICAgICBcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0pXHJcbiAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIGluZGljYXRvckZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcblxyXG4gICAgICBjb25zdCBnbG9iYWxJZHMgPSBgKCR7cmVzcG9uc2UuYWRkUmVzdWx0cy5tYXAociA9PiBgJyR7ci5nbG9iYWxJZH0nYCkuam9pbignLCcpfSlgO1xyXG4gICAgICBjb25zdCBxdWVyeSA9ICdHbG9iYWxJRCBJTiAnK2dsb2JhbElkczsgICAgIFxyXG4gICAgICBjb25zdCBhZGRlZEluZGljYXRvckZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLHF1ZXJ5ICwgY29uZmlnKTtcclxuXHJcbiAgICAgICBsZXQgd2VpZ2h0c0ZlYXR1cmVzID0gW107XHJcbiAgICAgICBmb3IobGV0IGZlYXR1cmUgb2YgYWRkZWRJbmRpY2F0b3JGZWF0dXJlcyl7ICAgXHJcbiAgICAgICAgIGNvbnN0IGluY29taW5nSW5kaWNhdG9yID0gaW5kaWNhdG9ycy5maW5kKGkgPT4gaS5uYW1lID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSk7XHJcbiAgICAgICAgIGlmKGluY29taW5nSW5kaWNhdG9yKXtcclxuICAgICAgICAgIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gaW5jb21pbmdJbmRpY2F0b3Iud2VpZ2h0cy5tYXAodyA9PiB7ICAgICAgICBcclxuICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICAgICAgICBJbmRpY2F0b3JJRDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELCAgXHJcbiAgICAgICAgICAgICAgICBOYW1lOiB3Lm5hbWUgLFxyXG4gICAgICAgICAgICAgICAgV2VpZ2h0OiB3LndlaWdodCwgXHJcbiAgICAgICAgICAgICAgICBTY2FsZUZhY3RvcjogMCwgIFxyXG4gICAgICAgICAgICAgICAgQWRqdXN0ZWRXZWlnaHQgOiAwLFxyXG4gICAgICAgICAgICAgICAgTWF4QWRqdXN0ZWRXZWlnaHQ6MFxyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgICB3ZWlnaHRzRmVhdHVyZXMgPSB3ZWlnaHRzRmVhdHVyZXMuY29uY2F0KHdlaWdodEZlYXR1cmVzKVxyXG4gICAgICAgICB9ICAgICAgICAgICAgXHJcbiAgICAgICB9XHJcblxyXG4gICAgICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCB3ZWlnaHRzRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICAgIH1cclxuICAgICAgIH1cclxuICAgIH1cclxuICAgIC8vIGNvbnN0IHByb21pc2VzID0gaW5kaWNhdG9ycy5tYXAoaW5kaWNhdG9yID0+IGNyZWF0ZU5ld0luZGljYXRvcihpbmRpY2F0b3IsIGNvbmZpZywgdGVtcGxhdGVJZCwgdGVtcGxhdGVOYW1lKSk7XHJcblxyXG4gICAgLy8gY29uc3QgcHJvbWlzZVJlc3BvbnNlID0gYXdhaXQgUHJvbWlzZS5hbGwocHJvbWlzZXMpO1xyXG4gICAgLy8gaWYocHJvbWlzZVJlc3BvbnNlLmV2ZXJ5KHAgPT4gcC5kYXRhKSl7XHJcbiAgICAvLyAgIHJldHVybiB7XHJcbiAgICAvLyAgICAgZGF0YTogdHJ1ZVxyXG4gICAgLy8gICB9XHJcbiAgICAvLyB9XHJcbiAgfSBcclxuXHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ2NyZWF0ZU5ld1RlbXBsYXRlJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgY3JlYXRpbmcgdGhlIG5ldyB0ZW1wbGF0ZSdcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1cGRhdGVUZW1wbGF0ZU9yZ2FuaXphdGlvbkFuZEhhemFyZChjb25maWc6IEFwcFdpZGdldENvbmZpZywgXHJcbiAgdGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgdXNlck5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0odGVtcGxhdGUsICdUZW1wbGF0ZSBub3QgcHJvdmlkZWQnKTtcclxuICBjaGVja1BhcmFtKGNvbmZpZy50ZW1wbGF0ZXMsIFRFTVBMQVRFX1VSTF9FUlJPUik7IFxyXG5cclxuICBjb25zdCBhdHRyaWJ1dGVzID0ge1xyXG4gICAgT0JKRUNUSUQ6IHRlbXBsYXRlLm9iamVjdElkLFxyXG4gICAgT3JnYW5pemF0aW9uSUQ6IHRlbXBsYXRlLm9yZ2FuaXphdGlvbklkLFxyXG4gICAgSGF6YXJkSUQ6IHRlbXBsYXRlLmhhemFyZElkLFxyXG4gICAgT3JnYW5pemF0aW9uTmFtZTogdGVtcGxhdGUub3JnYW5pemF0aW9uTmFtZSxcclxuICAgIE9yZ2FuaXphdGlvblR5cGU6IHRlbXBsYXRlLm9yZ2FuaXphdGlvblR5cGUsXHJcbiAgICBIYXphcmROYW1lOiB0ZW1wbGF0ZS5oYXphcmROYW1lLFxyXG4gICAgSGF6YXJkVHlwZTogdGVtcGxhdGUuaGF6YXJkVHlwZSxcclxuICAgIE5hbWU6IHRlbXBsYXRlLm5hbWUsXHJcbiAgICBFZGl0b3I6IHVzZXJOYW1lLFxyXG4gICAgRWRpdGVkRGF0ZTogbmV3IERhdGUoKS5nZXRUaW1lKCksXHJcbiAgICBTdGF0dXM6IHRlbXBsYXRlLnN0YXR1cy5jb2RlLFxyXG4gICAgSXNTZWxlY3RlZDogdGVtcGxhdGUuaXNTZWxlY3RlZCA/IDE6IDBcclxuICB9IFxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcudGVtcGxhdGVzLCBhdHRyaWJ1dGVzLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgfVxyXG4gIH1cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlVGVtcGxhdGVPcmdhbml6YXRpb25BbmRIYXphcmQnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSB1cGRhdGluZyB0ZW1wbGF0ZS4nXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2VsZWN0VGVtcGxhdGUob2JqZWN0SWQ6IG51bWJlciwgb2JqZWN0SWRzOiBudW1iZXJbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxTdHJpbmc+PiB7XHJcbiAgXHJcbiAgICBjb25zb2xlLmxvZygnc2VsZWN0IFRlbXBsYXRlIGNhbGxlZCcpXHJcbiAgICB0cnl7XHJcbiAgICAgIGNoZWNrUGFyYW0oY29uZmlnLnRlbXBsYXRlcywgVEVNUExBVEVfVVJMX0VSUk9SKTtcclxuXHJcbiAgICAgIC8vbGV0IGZlYXR1cmVzID0gYXdhaXQgZ2V0VGVtcGxhdGVGZWF0dXJlcygnMT0xJywgY29uZmlnKS8vIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcudGVtcGxhdGVzLCAnMT0xJywgY29uZmlnKVxyXG4gICAgXHJcbiAgICAgIGNvbnN0IGZlYXR1cmVzID0gIG9iamVjdElkcy5tYXAob2lkID0+IHtcclxuICAgICAgICByZXR1cm4geyAgICAgICAgICBcclxuICAgICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgICAgT0JKRUNUSUQ6IG9pZCxcclxuICAgICAgICAgICAgSXNTZWxlY3RlZDogb2lkID09PSBvYmplY3RJZCA/IDEgOiAwXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgICB9KVxyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLnRlbXBsYXRlcywgZmVhdHVyZXMsIGNvbmZpZylcclxuICAgICAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhOiByZXNwb25zZS51cGRhdGVSZXN1bHRzWzBdLmdsb2JhbElkXHJcbiAgICAgICAgIH0gYXMgQ2xzc1Jlc3BvbnNlPFN0cmluZz47XHJcbiAgICAgIH1cclxuICAgIH1jYXRjaChlKSB7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnc2VsZWN0VGVtcGxhdGUnKTtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBlcnJvcnM6IGVcclxuICAgICAgfVxyXG4gICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbG9hZFNjYWxlRmFjdG9ycyhjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPFNjYWxlRmFjdG9yW10+PntcclxuXHJcbiAgY2hlY2tQYXJhbShjb25maWcuY29uc3RhbnRzLCAnUmF0aW5nIFNjYWxlcyB1cmwgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIHRyeXtcclxuXHJcbiAgIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5jb25zdGFudHMsICcxPTEnLCBjb25maWcpO1xyXG4gICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICBjb25zdCBzY2FsZXMgPSAgZmVhdHVyZXMubWFwKGYgPT57XHJcbiAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICAgdmFsdWU6IGYuYXR0cmlidXRlcy5WYWx1ZVxyXG4gICAgICAgfSBhcyBTY2FsZUZhY3RvcjsgICAgICAgXHJcbiAgICAgfSlcclxuXHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogc2NhbGVzXHJcbiAgICB9IGFzIENsc3NSZXNwb25zZTxTY2FsZUZhY3RvcltdPlxyXG4gICB9XHJcblxyXG4gICBsb2coJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHJlcXVlc3RpbmcgcmF0aW5nIHNjYWxlcycsIExvZ1R5cGUuRVJST1IsICdsb2FkUmF0aW5nU2NhbGVzJylcclxuICAgcmV0dXJuIHtcclxuICAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSByZXF1ZXN0aW5nIHJhdGluZyBzY2FsZXMnXHJcbiAgIH1cclxuICB9IGNhdGNoKGUpe1xyXG4gICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnbG9hZFJhdGluZ1NjYWxlcycpOyAgICBcclxuICB9ICBcclxuICAgXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcmVhdGVOZXdJbmRpY2F0b3IoaW5kaWNhdG9yOiBJbmRpY2F0b3JUZW1wbGF0ZSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlSWQ6IHN0cmluZywgdGVtcGxhdGVOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkRJQ0FUT1JfVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgaW5kaWNhdG9yRmVhdHVyZSA9IHtcclxuICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgVGVtcGxhdGVJRDogdGVtcGxhdGVJZCwgIFxyXG4gICAgICBDb21wb25lbnRJRDogaW5kaWNhdG9yLmNvbXBvbmVudElkLFxyXG4gICAgICBDb21wb25lbnROYW1lOiBpbmRpY2F0b3IuY29tcG9uZW50TmFtZSwgIFxyXG4gICAgICBOYW1lOiBpbmRpY2F0b3IubmFtZSwgICBcclxuICAgICAgVGVtcGxhdGVOYW1lOiB0ZW1wbGF0ZU5hbWUsIFxyXG4gICAgICBMaWZlbGluZU5hbWU6IGluZGljYXRvci5saWZlbGluZU5hbWUgICAgICBcclxuICAgIH1cclxuICB9XHJcblxyXG4gIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMsIFtpbmRpY2F0b3JGZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuXHJcbiAgICBjb25zdCB3ZWlnaHRGZWF0dXJlcyA9IGluZGljYXRvci53ZWlnaHRzLm1hcCh3ID0+IHtcclxuICAgICAgIFxyXG4gICAgICAgcmV0dXJuIHtcclxuICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICBJbmRpY2F0b3JJRDogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZCwgIFxyXG4gICAgICAgICAgTmFtZTogdy5uYW1lICxcclxuICAgICAgICAgIFdlaWdodDogdy53ZWlnaHQsIFxyXG4gICAgICAgICAgU2NhbGVGYWN0b3I6IDAsICBcclxuICAgICAgICAgIEFkanVzdGVkV2VpZ2h0IDogMCxcclxuICAgICAgICAgIE1heEFkanVzdGVkV2VpZ2h0OjBcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0pO1xyXG5cclxuICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgd2VpZ2h0RmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ2NyZWF0ZU5ld0luZGljYXRvcicpO1xyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBzYXZpbmcgdGhlIGluZGljYXRvci4nXHJcbiAgfVxyXG5cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZUluZGljYXRvck5hbWUoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIGluZGljYXRvclRlbXA6SW5kaWNhdG9yVGVtcGxhdGUpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIFxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElORElDQVRPUl9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBhdHRyaWJ1dGVzID0ge1xyXG4gICAgT0JKRUNUSUQ6IGluZGljYXRvclRlbXAub2JqZWN0SWQsXHJcbiAgICBOYW1lOiBpbmRpY2F0b3JUZW1wLm5hbWUsXHJcbiAgICBEaXNwbGF5VGl0bGU6IGluZGljYXRvclRlbXAubmFtZSxcclxuICAgIElzQWN0aXZlOiAxXHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcuaW5kaWNhdG9ycywgYXR0cmlidXRlcywgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gIH1cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlSW5kaWNhdG9yTmFtZScpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHVwZGF0aW5nIGluZGljYXRvcidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1cGRhdGVJbmRpY2F0b3IoaW5kaWNhdG9yOiBJbmRpY2F0b3JUZW1wbGF0ZSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIFxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElOQ0lERU5UX1VSTF9FUlJPUik7XHJcblxyXG4gIGxldCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgYE5hbWU9JyR7aW5kaWNhdG9yLm5hbWV9JyBBTkQgVGVtcGxhdGVOYW1lPScke2luZGljYXRvci50ZW1wbGF0ZU5hbWV9J2AsIGNvbmZpZylcclxuIFxyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDEpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiAnQW4gaW5kaWNhdG9yIHdpdGggdGhlIHNhbWUgbmFtZSBhbHJlYWR5IGV4aXN0cydcclxuICAgIH1cclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVJbmRpY2F0b3JOYW1lKGNvbmZpZywgaW5kaWNhdG9yKTtcclxuXHJcbiAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogcmVzcG9uc2UuZXJyb3JzXHJcbiAgICB9XHJcbiAgfVxyXG4gXHJcbiAgIGZlYXR1cmVzID0gaW5kaWNhdG9yLndlaWdodHMubWFwKHcgPT4ge1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICBPQkpFQ1RJRDogdy5vYmplY3RJZCxcclxuICAgICAgICAgIFdlaWdodDogTnVtYmVyKHcud2VpZ2h0KSwgXHJcbiAgICAgICAgICBBZGp1c3RlZFdlaWdodDogTnVtYmVyKHcud2VpZ2h0KSAqIHcuc2NhbGVGYWN0b3JcclxuICAgICAgIH1cclxuICAgICB9XHJcbiAgIH0pO1xyXG5cclxuICAgY29uc3QgdXBkYXRlUmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCBmZWF0dXJlcywgY29uZmlnKTtcclxuICAgaWYodXBkYXRlUmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiB1cGRhdGVSZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgIH1cclxuICAgfVxyXG5cclxuICAgbG9nKEpTT04uc3RyaW5naWZ5KHVwZGF0ZVJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZUluZGljYXRvcicpO1xyXG4gICByZXR1cm4ge1xyXG4gICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHVwZGF0aW5nIGluZGljYXRvci4nXHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUluZGljYXRvcihpbmRpY2F0b3JUZW1wbGF0ZTogSW5kaWNhdG9yVGVtcGxhdGUsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5ESUNBVE9SX1VSTF9FUlJPUik7XHJcbiAgY2hlY2tQYXJhbShjb25maWcud2VpZ2h0cywgJ1dlaWdodHMgVVJMIG5vdCBwcm92aWRlZCcpO1xyXG4gIFxyXG4gIGxldCByZXNwID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgW2luZGljYXRvclRlbXBsYXRlLm9iamVjdElkXSwgY29uZmlnKTtcclxuICBpZihyZXNwLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcC5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgY29uc3Qgd2VpZ2h0c09iamVjdElkcyA9IGluZGljYXRvclRlbXBsYXRlLndlaWdodHMubWFwKHcgPT4gdy5vYmplY3RJZCk7XHJcbiAgICAgcmVzcCA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHdlaWdodHNPYmplY3RJZHMsIGNvbmZpZyk7XHJcbiAgICAgaWYocmVzcC5kZWxldGVSZXN1bHRzICYmIHJlc3AuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgfVxyXG4gICAgIH1cclxuICB9XHJcblxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwKSwgTG9nVHlwZS5FUlJPUiwgJ2RlbGV0ZUluZGljYXRvcicpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIGRlbGV0aW5nIHRoZSBpbmRpY2F0b3InXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gYXJjaGl2ZVRlbXBsYXRlKG9iamVjdElkOiBudW1iZXIsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuIFxyXG4gIGNvbnN0IHJlc3BvbnNlICA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcudGVtcGxhdGVzLCB7XHJcbiAgICBPQkpFQ1RJRDogb2JqZWN0SWQsXHJcbiAgICBJc1NlbGVjdGVkOiAwLFxyXG4gICAgSXNBY3RpdmU6IDBcclxuICB9LCBjb25maWcpO1xyXG4gIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcclxuICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkoZSA9PiBlLnN1Y2Nlc3MpKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgIH1cclxuICB9XHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSwgTG9nVHlwZS5FUlJPUiwgJ2FyY2hpdmVUZW1wbGF0ZScpO1xyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdUaGUgdGVtcGxhdGUgY2Fubm90IGJlIGFyY2hpdmVkLidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzYXZlT3JnYW5pemF0aW9uKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBvcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbik6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPE9yZ2FuaXphdGlvbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShjb25maWcub3JnYW5pemF0aW9ucywgT1JHQU5JWkFUSU9OX1VSTF9FUlJPUik7XHJcbiAgY2hlY2tQYXJhbShvcmdhbml6YXRpb24sICdPcmdhbml6YXRpb24gb2JqZWN0IG5vdCBwcm92aWRlZCcpO1xyXG4gXHJcbiAgY29uc3QgZmVhdHVyZSA9IHtcclxuICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgTmFtZTogb3JnYW5pemF0aW9uLm5hbWUsXHJcbiAgICAgIFR5cGU6IG9yZ2FuaXphdGlvbi50eXBlPy5jb2RlLFxyXG4gICAgICBEaXNwbGF5VGl0bGU6IG9yZ2FuaXphdGlvbi5uYW1lLFxyXG4gICAgICBQYXJlbnRJRDogb3JnYW5pemF0aW9uPy5wYXJlbnRJZFxyXG4gICAgfVxyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9ICBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5vcmdhbml6YXRpb25zLCBbZmVhdHVyZV0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7IFxyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YToge1xyXG4gICAgICAgIC4uLm9yZ2FuaXphdGlvblxyXG4gICAgICB9IGFzIE9yZ2FuaXphdGlvbiAvLyAoYXdhaXQgZ2V0T3JnYW5pemF0aW9ucyhjb25maWcsIGBHbG9iYWxJRD0nJHtyZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkfSdgKSlbMF1cclxuICAgIH1cclxuICB9XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2F2ZUhhemFyZChjb25maWc6IEFwcFdpZGdldENvbmZpZywgaGF6YXJkOiBIYXphcmQpOiBQcm9taXNlPENsc3NSZXNwb25zZTxIYXphcmQ+PiB7XHJcbiAgXHJcbiAgY29uc3QgZmVhdHVyZSA9IHtcclxuICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgTmFtZTogaGF6YXJkLm5hbWUsXHJcbiAgICAgIERpc3BsYXlUaXRsZTogaGF6YXJkLm5hbWUsXHJcbiAgICAgIFR5cGU6IGhhemFyZC50eXBlLmNvZGUsXHJcbiAgICAgIERlc2NyaXB0aW9uOiBoYXphcmQuZGVzY3JpcHRpb25cclxuICAgIH1cclxuICB9XHJcblxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmhhemFyZHMsIFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXsgICBcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB7XHJcbiAgICAgICAgICAuLi5oYXphcmQsXHJcbiAgICAgICAgICBvYmplY3RJZDogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5vYmplY3RJZCxcclxuICAgICAgICAgIGlkOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkXHJcbiAgICAgICAgfSBhcyBIYXphcmQgIFxyXG4gICAgICB9XHJcbiAgfVxyXG5cclxuICBsb2coYEVycm9yIG9jY3VycmVkIHdoaWxlIHNhdmluZyBoYXphcmQuIFJlc3RhcnRpbmcgdGhlIGFwcGxpY2F0aW9uIG1heSBmaXggdGhpcyBpc3N1ZS5gLCBMb2dUeXBlLkVSUk9SLCAnc2F2ZUhhemFyZCcpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHNhdmluZyBoYXphcmQuIFJlc3RhcnRpbmcgdGhlIGFwcGxpY2F0aW9uIG1heSBmaXggdGhpcyBpc3N1ZS4nXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlSW5jaWRlbnQoaW5jaWRlbnQ6IEluY2lkZW50LCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmluY2lkZW50cywgW2luY2lkZW50Lm9iamVjdElkXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5kZWxldGVSZXN1bHRzICYmIHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgIH1cclxuICB9XHJcbiAgcmV0dXJuIHtcclxuICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVIYXphcmQoaGF6YXJkOiBIYXphcmQsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmhhemFyZHMsIFtoYXphcmQub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gICBpZihyZXNwb25zZS5kZWxldGVSZXN1bHRzICYmIHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgIH1cclxuICAgfVxyXG4gICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlT3JnYW5pemF0aW9uKG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLm9yZ2FuaXphdGlvbnMsIFtvcmdhbml6YXRpb24ub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcG9uc2UuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNoZWNrUGFyYW0ocGFyYW06IGFueSwgZXJyb3I6IHN0cmluZykge1xyXG4gIGlmICghcGFyYW0gfHwgcGFyYW0gPT0gbnVsbCB8fCBwYXJhbSA9PT0gJycgfHwgcGFyYW0gPT0gdW5kZWZpbmVkKSB7XHJcbiAgICB0aHJvdyBuZXcgRXJyb3IoZXJyb3IpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdGVtcGxDbGVhblVwKGluZFVybDogc3RyaW5nLCBhbGlnVXJsOiBzdHJpbmcsIHRva2VuOiBzdHJpbmcpIHtcclxuXHJcblxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc2F2ZU5ld0Fzc2Vzc21lbnQobmV3QXNzZXNzbWVudDogQXNzZXNzbWVudCwgdGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgXHJcbiAgICAgICAgICAgICAgICAgIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBwcmV2QXNzZXNzbWVudD86IEFzc2Vzc21lbnQpOiBQcm9taXNlPENsc3NSZXNwb25zZTxzdHJpbmc+PnsgICAgXHJcbiAgICAgIFxyXG4gICAgICBjb25zdCByZXNwID0gYXdhaXQgc2F2ZUFzc2Vzc21lbnQobmV3QXNzZXNzbWVudCwgY29uZmlnKTtcclxuICAgICAgaWYocmVzcC5lcnJvcnMpe1xyXG4gICAgICAgIGxvZygnVW5hYmxlIHRvIGNyZWF0ZSB0aGUgYXNzZXNzbWVudC4nLCBMb2dUeXBlLkVSUk9SLCAnc2F2ZU5ld0Fzc2Vzc21lbnQnKTtcclxuXHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGVycm9yczogJ1VuYWJsZSB0byBjcmVhdGUgdGhlIGFzc2Vzc21lbnQuJ1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgIFxyXG4gICAgICB0cnl7XHJcblxyXG4gICAgICAgIGNvbnN0IGluZGljYXRvcnMgPSBnZXRUZW1wbGF0ZUluZGljYXRvcnModGVtcGxhdGUpO1xyXG4gICAgICAgIGlmKCFpbmRpY2F0b3JzIHx8IGluZGljYXRvcnMubGVuZ3RoID09PSAwKXtcclxuICAgICAgICAgIGxvZygnVGVtcGxhdGUgaW5kaWNhdG9ycyBub3QgZm91bmQnLCBMb2dUeXBlLkVSUk9SLCAnc2F2ZU5ld0Fzc2Vzc21lbnQnKTsgIFxyXG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdUZW1wbGF0ZSBpbmRpY2F0b3JzIG5vdCBmb3VuZC4nKVxyXG4gICAgICAgIH0gICAgICBcclxuICBcclxuICAgICAgICBjb25zdCBsaWZlbGluZVN0YXR1c0ZlYXR1cmVzID0gdGVtcGxhdGUubGlmZWxpbmVUZW1wbGF0ZXMubWFwKGx0ID0+IHtcclxuICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICBhdHRyaWJ1dGVzOiB7IFxyXG4gICAgICAgICAgICAgIEFzc2Vzc21lbnRJRCA6IHJlc3AuZGF0YSxcclxuICAgICAgICAgICAgICBTY29yZTogbnVsbCwgXHJcbiAgICAgICAgICAgICAgQ29sb3I6IG51bGwsIFxyXG4gICAgICAgICAgICAgIExpZmVsaW5lSUQ6IGx0LmlkLCBcclxuICAgICAgICAgICAgICBJc092ZXJyaWRlbjogMCwgXHJcbiAgICAgICAgICAgICAgT3ZlcnJpZGVuU2NvcmU6IG51bGwsIFxyXG4gICAgICAgICAgICAgIE92ZXJyaWRlbkJ5OiBudWxsLCBcclxuICAgICAgICAgICAgICBPdmVycmlkZUNvbW1lbnQ6IG51bGwsIFxyXG4gICAgICAgICAgICAgIExpZmVsaW5lTmFtZTogbHQudGl0bGUsIFxyXG4gICAgICAgICAgICAgIFRlbXBsYXRlTmFtZTogdGVtcGxhdGUubmFtZVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSlcclxuICAgICAgICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgbGlmZWxpbmVTdGF0dXNGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICAgICBpZihyZXNwb25zZSAmJiByZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgICAgICAgICBjb25zdCBxdWVyeSA9ICdHbG9iYWxJRCBJTiAoJysgcmVzcG9uc2UuYWRkUmVzdWx0cy5tYXAociA9PiBgJyR7ci5nbG9iYWxJZH0nYCkuam9pbignLCcpK1wiKVwiO1xyXG4gICAgICAgICAgIGNvbnN0IGxzRmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBxdWVyeSwgY29uZmlnKTtcclxuICAgICAgICAgICBcclxuICAgICAgICAgICBjb25zdCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMgPSBpbmRpY2F0b3JzLm1hcChpID0+IHtcclxuICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIGNvbnN0IGxpZmVsaW5lU3RhdHVzRmVhdHVyZSA9IGxzRmVhdHVyZXMuZmluZChscyA9PiBcclxuICAgICAgICAgICAgICAgIGxzLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lLnNwbGl0KC9bJyAnJl8sXSsvKS5qb2luKCdfJykgID09PSBpLmxpZmVsaW5lTmFtZSk7XHJcbiAgICAgICAgICAgIGlmKCFsaWZlbGluZVN0YXR1c0ZlYXR1cmUpe1xyXG4gICAgICAgICAgICAgIGNvbnNvbGUubG9nKGAke2kubGlmZWxpbmVOYW1lfSBub3QgZm91bmRgKTtcclxuICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYCR7aS5saWZlbGluZU5hbWV9IG5vdCBmb3VuZGApO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgICAgICAgTGlmZWxpbmVTdGF0dXNJRCA6IGxpZmVsaW5lU3RhdHVzRmVhdHVyZT8gbGlmZWxpbmVTdGF0dXNGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQgOiAnJyxcclxuICAgICAgICAgICAgICAgIEluZGljYXRvcklEOiBpLmlkLCAgXHJcbiAgICAgICAgICAgICAgICBUZW1wbGF0ZU5hbWU6IGkudGVtcGxhdGVOYW1lLCAgXHJcbiAgICAgICAgICAgICAgICBMaWZlbGluZU5hbWU6IGkubGlmZWxpbmVOYW1lLCAgXHJcbiAgICAgICAgICAgICAgICBDb21wb25lbnROYW1lOiBpLmNvbXBvbmVudE5hbWUsICBcclxuICAgICAgICAgICAgICAgIEluZGljYXRvck5hbWU6IGkubmFtZSxcclxuICAgICAgICAgICAgICAgIENvbW1lbnRzOiBcIlwiLFxyXG4gICAgICAgICAgICAgICAgUmFuazogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IFJBTkspPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBMaWZlU2FmZXR5OiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gTElGRV9TQUZFVFkpPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBQcm9wZXJ0eVByb3RlY3Rpb246IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBQUk9QRVJUWV9QUk9URUNUSU9OKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgSW5jaWRlbnRTdGFiaWxpemF0aW9uOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gSU5DSURFTlRfU1RBQklMSVpBVElPTik/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIEVudmlyb25tZW50UHJlc2VydmF0aW9uOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgU3RhdHVzOiA0IC8vdW5rbm93blxyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgIH0pXHJcbiAgXHJcbiAgICAgICAgICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgaW5kaWNhdG9yQXNzZXNzbWVudEZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgICAgICAgIGlmKHJlc3BvbnNlICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIGRhdGE6IHJlc3AuZGF0YVxyXG4gICAgICAgICAgICB9IFxyXG4gICAgICAgICAgIH1lbHNle1xyXG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ZhaWxlZCB0byBhZGQgaW5kaWNhdG9yIGFzc2Vzc21lbnQgZmVhdHVyZXMnKTtcclxuICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGVsc2V7XHJcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ZhaWxlZCB0byBhZGQgTGlmZWxpbmUgU3RhdHVzIEZlYXR1cmVzJyk7XHJcbiAgICAgICAgfSBcclxuXHJcbiAgICAgIH1jYXRjaChlKXtcclxuICAgICAgICBhd2FpdCBjbGVhblVwQXNzZXNzbWVudEZhaWxlZERhdGEocmVzcC5kYXRhLCBjb25maWcpO1xyXG4gICAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAnc2F2ZU5ld0Fzc2Vzc21lbnQnKVxyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBlcnJvcnM6J0Vycm9yIG9jY3VycmVkIHdoaWxlIGNyZWF0aW5nIEFzc2Vzc21lbnQuJ1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gY2xlYW5VcEFzc2Vzc21lbnRGYWlsZWREYXRhKGFzc2Vzc21lbnRHbG9iYWxJZDogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyl7XHJcbiAgIFxyXG4gICBsZXQgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBgR2xvYmFsSUQ9JyR7YXNzZXNzbWVudEdsb2JhbElkfSdgLCBjb25maWcpO1xyXG4gICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLk9CSkVDVElEKSwgY29uZmlnKTtcclxuICAgfVxyXG5cclxuICAgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBgQXNzZXNzbWVudElEPScke2Fzc2Vzc21lbnRHbG9iYWxJZH0nYCwgY29uZmlnKTtcclxuICAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLk9CSkVDVElEKSwgY29uZmlnKTtcclxuXHJcbiAgICBjb25zdCBxdWVyeSA9IGBMaWZlbGluZVN0YXR1c0lEIElOICgke2ZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5HbG9iYWxJRCkuam9pbignLCcpfSlgO1xyXG4gICAgY29uc29sZS5sb2coJ2RlbGV0ZSBxdWVyaWVzJywgcXVlcnkpXHJcbiAgICBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIHF1ZXJ5LCBjb25maWcpO1xyXG4gICAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgIGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQpLCBjb25maWcpO1xyXG4gICAgfVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRBc3Nlc3NtZW50TmFtZXMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8e25hbWU6IHN0cmluZywgZGF0ZTogc3RyaW5nfVtdPj57XHJcbiAgXHJcbiAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBgVGVtcGxhdGU9JyR7dGVtcGxhdGVOYW1lfSdgLCBjb25maWcpO1xyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA9PT0gMCl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiBbXVxyXG4gICAgfVxyXG4gIH1cclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgXHJcbiAgICAgY29uc3QgYXNzZXNzID0gIGZlYXR1cmVzLm1hcChmID0+IHtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICBkYXRlOiBwYXJzZURhdGUoTnVtYmVyKGYuYXR0cmlidXRlcy5DcmVhdGVkRGF0ZSkpXHJcbiAgICAgIH1cclxuICAgICB9KTtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgZGF0YTogYXNzZXNzXHJcbiAgICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnUmVxdWVzdCBmb3IgYXNzZXNzbWVudCBuYW1lcyBmYWlsZWQuJ1xyXG4gIH1cclxuXHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEFzc2Vzc21lbnRGZWF0dXJlcyhjb25maWcpIHtcclxuICAgY29uc29sZS5sb2coJ2dldCBBc3Nlc3NtZW50IEZlYXR1cmVzIGNhbGxlZC4nKTtcclxuICAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGAxPTFgLCBjb25maWcpO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbG9hZEFsbEFzc2Vzc21lbnRzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8QXNzZXNzbWVudFtdPj57XHJcblxyXG4gICB0cnl7XHJcbiAgICBjb25zdCBhc3Nlc3NtZW50RmVhdHVyZXMgPSBhd2FpdCBnZXRBc3Nlc3NtZW50RmVhdHVyZXMoY29uZmlnKTtcclxuICAgIGlmKCFhc3Nlc3NtZW50RmVhdHVyZXMgfHwgYXNzZXNzbWVudEZlYXR1cmVzLmxlbmd0aCA9PSAwKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiBbXVxyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgICBcclxuICAgIGNvbnN0IGxzRmVhdHVyZXMgPSBhd2FpdCBnZXRMaWZlbGluZVN0YXR1c0ZlYXR1cmVzKGNvbmZpZywgYDE9MWApO1xyXG5cclxuICAgIGNvbnN0IHF1ZXJ5ID0gYExpZmVsaW5lU3RhdHVzSUQgSU4gKCR7bHNGZWF0dXJlcy5tYXAoZiA9PiBgJyR7Zi5hdHRyaWJ1dGVzLkdsb2JhbElEfSdgKS5qb2luKCcsJyl9KWBcclxuICAgIFxyXG4gICAgY29uc3QgaW5kaWNhdG9yQXNzZXNzbWVudHMgPSBhd2FpdCBnZXRJbmRpY2F0b3JBc3Nlc3NtZW50cyhxdWVyeSwgY29uZmlnKTtcclxuXHJcbiAgICBpZihhc3Nlc3NtZW50RmVhdHVyZXMgJiYgYXNzZXNzbWVudEZlYXR1cmVzLmxlbmd0aCA+IDApeyAgIFxyXG4gICAgICBjb25zdCBhc3Nlc3NtZW50cyA9IGFzc2Vzc21lbnRGZWF0dXJlcy5tYXAoKGZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcbiAgICAgICAgY29uc3QgYXNzZXNzbWVudExzRmVhdHVyZXMgPSBsc0ZlYXR1cmVzLmZpbHRlcihsID0+bC5hdHRyaWJ1dGVzLkFzc2Vzc21lbnRJRCA9PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpICAgICAgICBcclxuICAgICAgICByZXR1cm4gbG9hZEFzc2Vzc21lbnQoZmVhdHVyZSwgYXNzZXNzbWVudExzRmVhdHVyZXMsIGluZGljYXRvckFzc2Vzc21lbnRzKTtcclxuICAgICAgfSk7XHJcblxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IGFzc2Vzc21lbnRzXHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBpZihhc3Nlc3NtZW50RmVhdHVyZXMgJiYgYXNzZXNzbWVudEZlYXR1cmVzLmxlbmd0aCA9PSAwKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiBbXVxyXG4gICAgICB9ICBcclxuICAgIH1cclxuICAgfWNhdGNoKGUpe1xyXG4gICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdsb2FkQWxsQXNzZXNzbWVudHMnKTtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogZVxyXG4gICAgfVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcmVhdGVJbmNpZGVudChjb25maWc6IEFwcFdpZGdldENvbmZpZywgaW5jaWRlbnQ6IEluY2lkZW50KTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8dm9pZD4+e1xyXG4gICBcclxuICAgIHRyeXtcclxuICAgICAgY2hlY2tQYXJhbShjb25maWcuaW5jaWRlbnRzLCBJTkNJREVOVF9VUkxfRVJST1IpO1xyXG4gICAgICBjaGVja1BhcmFtKGluY2lkZW50LCAnSW5jaWRlbnQgZGF0YSBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgICAgIGNvbnN0IGZlYXR1cmVzID0gW3tcclxuICAgICAgICBhdHRyaWJ1dGVzIDoge1xyXG4gICAgICAgICAgSGF6YXJkSUQ6IGluY2lkZW50LmhhemFyZC5pZCxcclxuICAgICAgICAgIE5hbWUgOiBpbmNpZGVudC5uYW1lLFxyXG4gICAgICAgICAgRGVzY3JpcHRpb246IGluY2lkZW50LmRlc2NyaXB0aW9uLFxyXG4gICAgICAgICAgU3RhcnREYXRlIDogU3RyaW5nKGluY2lkZW50LnN0YXJ0RGF0ZSksXHJcbiAgICAgICAgICBFbmREYXRlIDogU3RyaW5nKGluY2lkZW50LmVuZERhdGUpXHJcbiAgICAgICAgfVxyXG4gICAgICB9XVxyXG5cclxuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmNpZGVudHMsIGZlYXR1cmVzLCBjb25maWcpO1xyXG5cclxuICAgICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmxlbmd0aCA+IDApe1xyXG4gICAgICAgIHJldHVybnt9IFxyXG4gICAgICB9XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZXJyb3JzOiAnSW5jaWRlbnQgY291bGQgbm90IGJlIHNhdmVkLidcclxuICAgICAgfVxyXG4gICAgfWNhdGNoKGUpIHtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdjcmVhdGVJbmNpZGVudCcpO1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGVycm9yczogJ0luY2lkZW50IGNvdWxkIG5vdCBiZSBzYXZlZC4nXHJcbiAgICAgIH1cclxuICAgIH1cclxufVxyXG5cclxuLy89PT09PT09PT09PT09PT09PT09PVBSSVZBVEU9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxyXG5cclxuY29uc3QgcmVxdWVzdERhdGEgPSBhc3luYyAodXJsOiBzdHJpbmcsIGNvbnRyb2xsZXI/OiBhbnkpOiBQcm9taXNlPElGZWF0dXJlU2V0PiA9PiB7XHJcbiAgaWYgKCFjb250cm9sbGVyKSB7XHJcbiAgICBjb250cm9sbGVyID0gbmV3IEFib3J0Q29udHJvbGxlcigpO1xyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGZldGNoKHVybCwge1xyXG4gICAgbWV0aG9kOiBcIkdFVFwiLFxyXG4gICAgaGVhZGVyczoge1xyXG4gICAgICAnY29udGVudC10eXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAgIH0sXHJcbiAgICBzaWduYWw6IGNvbnRyb2xsZXIuc2lnbmFsXHJcbiAgfVxyXG4gICk7XHJcbiAgcmV0dXJuIHJlc3BvbnNlLmpzb24oKTtcclxufVxyXG5cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldFRlbXBsYXRlKFxyXG4gIHRlbXBsYXRlRmVhdHVyZTogSUZlYXR1cmUsIFxyXG4gIGxpZmVsaW5lRmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIGNvbXBvbmVudEZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICBpbmRpY2F0b3JzRmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIHdlaWdodHNGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgdGVtcGxhdGVEb21haW5zOiBJQ29kZWRWYWx1ZVtdKTogUHJvbWlzZTxDTFNTVGVtcGxhdGU+e1xyXG5cclxuICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlcyA9IGluZGljYXRvcnNGZWF0dXJlcy5maWx0ZXIoaSA9PiBpLmF0dHJpYnV0ZXMuVGVtcGxhdGVJRCA9IGAnJHt0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRH0nYCkvLyAgYXdhaXQgZ2V0SW5kaWNhdG9yRmVhdHVyZXMoYFRlbXBsYXRlSUQ9JyR7dGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUR9J2AsIGNvbmZpZyk7XHJcbiAgXHJcbiAgLy9jb25zdCBxdWVyeSA9IGluZGljYXRvckZlYXR1cmVzLm1hcChpID0+IGBJbmRpY2F0b3JJRD0nJHtpLmF0dHJpYnV0ZXMuR2xvYmFsSUQudG9VcHBlckNhc2UoKX0nYCkuam9pbignIE9SICcpXHJcbiAgXHJcbiAgY29uc3QgaW5kaWNhdG9ySWRzID0gaW5kaWNhdG9yRmVhdHVyZXMubWFwKGkgPT4gaS5hdHRyaWJ1dGVzLkdsb2JhbElEKTtcclxuICBjb25zdCB3ZWlnaHRGZWF0dXJlcyA9IHdlaWdodHNGZWF0dXJlcy5maWx0ZXIodyA9PiBpbmRpY2F0b3JJZHMuaW5kZXhPZih3LmF0dHJpYnV0ZXMuSW5kaWNhdG9ySUQpKSAvL2F3YWl0IGdldFdlaWdodHNGZWF0dXJlcyhxdWVyeSwgY29uZmlnKTtcclxuICBcclxuICBjb25zdCBpbmRpY2F0b3JUZW1wbGF0ZXMgPSBpbmRpY2F0b3JGZWF0dXJlcy5tYXAoKGZlYXR1cmU6IElGZWF0dXJlKSA9PiB7XHJcblxyXG4gICAgIGNvbnN0IHdlaWdodHMgPSB3ZWlnaHRzRmVhdHVyZXNcclxuICAgICAgLmZpbHRlcih3ID0+IHcuYXR0cmlidXRlcy5JbmRpY2F0b3JJRD09PWZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRClcclxuICAgICAgLm1hcCh3ID0+IHtcclxuICAgICAgIHJldHVybiB7IFxyXG4gICAgICAgIG9iamVjdElkOiB3LmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgbmFtZTogdy5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgd2VpZ2h0OiB3LmF0dHJpYnV0ZXMuV2VpZ2h0LFxyXG4gICAgICAgIHNjYWxlRmFjdG9yIDogdy5hdHRyaWJ1dGVzLlNjYWxlRmFjdG9yLCBcclxuICAgICAgICBhZGp1c3RlZFdlaWdodDogdy5hdHRyaWJ1dGVzLkFkanVzdGVkV2VpZ2h0LFxyXG4gICAgICAgIG1heEFkanVzdGVkV2VpZ2h0OiB3LmF0dHJpYnV0ZXMuTWF4QWRqdXN0ZWRXZWlnaHRcclxuICAgICAgIH0gYXMgSW5kaWNhdG9yV2VpZ2h0XHJcbiAgICAgfSlcclxuXHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgb2JqZWN0SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCwgXHJcbiAgICAgIG5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICB0ZW1wbGF0ZU5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZU5hbWUsXHJcbiAgICAgIHdlaWdodHMsXHJcbiAgICAgIGNvbXBvbmVudElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tcG9uZW50SUQsXHJcbiAgICAgIHRlbXBsYXRlSWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZUlELCAgXHJcbiAgICAgIGNvbXBvbmVudE5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5Db21wb25lbnROYW1lLFxyXG4gICAgICBsaWZlbGluZU5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZU5hbWVcclxuICAgICB9IGFzIEluZGljYXRvclRlbXBsYXRlXHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IGNvbXBvbmVudFRlbXBsYXRlcyA9IGNvbXBvbmVudEZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgICAgdGl0bGU6IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlLFxyXG4gICAgICAgIG5hbWU6IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIGxpZmVsaW5lSWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZUlELFxyXG4gICAgICAgIGluZGljYXRvcnM6IChpbmRpY2F0b3JUZW1wbGF0ZXMuZmlsdGVyKGkgPT4gaS5jb21wb25lbnRJZCA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSBhcyBhbnkpLm9yZGVyQnkoJ25hbWUnKVxyXG4gICAgIH1cclxuICB9KTtcclxuXHJcbiAgY29uc3QgbGlmZWxpbmVUZW1wbGF0ZXMgPSBsaWZlbGluZUZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIHRpdGxlOiBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheU5hbWUgfHwgZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSxcclxuICAgICAgbmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsICAgICAgXHJcbiAgICAgIGNvbXBvbmVudFRlbXBsYXRlczogKGNvbXBvbmVudFRlbXBsYXRlcy5maWx0ZXIoYyA9PiBjLmxpZmVsaW5lSWQgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgYXMgYW55KS5vcmRlckJ5KCd0aXRsZScpXHJcbiAgICB9IGFzIExpZmVMaW5lVGVtcGxhdGU7XHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IHRlbXBsYXRlID0ge1xyXG4gICAgICBvYmplY3RJZDogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgaXNTZWxlY3RlZDogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuSXNTZWxlY3RlZCA9PSAxLFxyXG4gICAgICBzdGF0dXM6IHtcclxuICAgICAgICBjb2RlOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5TdGF0dXMsXHJcbiAgICAgICAgbmFtZTogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuU3RhdHVzID09PSAxID8gXCJBY3RpdmVcIjogJ0FyY2hpdmVkJ1xyXG4gICAgICB9IGFzIElDb2RlZFZhbHVlLFxyXG4gICAgICBuYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICBoYXphcmROYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmROYW1lLFxyXG4gICAgICBoYXphcmRUeXBlOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmRUeXBlLFxyXG4gICAgICBvcmdhbml6YXRpb25OYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb25OYW1lLFxyXG4gICAgICBvcmdhbml6YXRpb25UeXBlOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb25UeXBlLCBcclxuICAgICAgY3JlYXRvcjogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRvcixcclxuICAgICAgY3JlYXRlZERhdGU6IE51bWJlcih0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdGVkRGF0ZSksXHJcbiAgICAgIGVkaXRvcjogdGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuRWRpdG9yLFxyXG4gICAgICBlZGl0ZWREYXRlOiBOdW1iZXIodGVtcGxhdGVGZWF0dXJlLmF0dHJpYnV0ZXMuRWRpdGVkRGF0ZSksXHJcbiAgICAgIGxpZmVsaW5lVGVtcGxhdGVzOiAgKGxpZmVsaW5lVGVtcGxhdGVzIGFzIGFueSkub3JkZXJCeSgndGl0bGUnKSxcclxuICAgICAgZG9tYWluczogdGVtcGxhdGVEb21haW5zXHJcbiAgfSBhcyBDTFNTVGVtcGxhdGU7XHJcblxyXG4gIHJldHVybiB0ZW1wbGF0ZTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gc2F2ZUFzc2Vzc21lbnQoYXNzZXNzbWVudDogQXNzZXNzbWVudCwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxzdHJpbmc+PntcclxuXHJcbiAgdHJ5e1xyXG4gICAgY29uc3QgZmVhdHVyZSA9IHtcclxuICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgIE5hbWUgOmFzc2Vzc21lbnQubmFtZSxcclxuICAgICAgICBEZXNjcmlwdGlvbjogYXNzZXNzbWVudC5kZXNjcmlwdGlvbixcclxuICAgICAgICBBc3Nlc3NtZW50VHlwZTogYXNzZXNzbWVudC5hc3Nlc3NtZW50VHlwZSwgXHJcbiAgICAgICAgT3JnYW5pemF0aW9uOiBhc3Nlc3NtZW50Lm9yZ2FuaXphdGlvbiwgXHJcbiAgICAgICAgSW5jaWRlbnQ6IGFzc2Vzc21lbnQuaW5jaWRlbnQsIFxyXG4gICAgICAgIEhhemFyZDogYXNzZXNzbWVudC5oYXphcmQsIFxyXG4gICAgICAgIENyZWF0b3I6IGFzc2Vzc21lbnQuY3JlYXRvciwgXHJcbiAgICAgICAgQ3JlYXRlZERhdGU6IGFzc2Vzc21lbnQuY3JlYXRlZERhdGUsIFxyXG4gICAgICAgIEVkaXRvcjogYXNzZXNzbWVudC5lZGl0b3IsIFxyXG4gICAgICAgIEVkaXRlZERhdGU6IGFzc2Vzc21lbnQuZWRpdGVkRGF0ZSwgXHJcbiAgICAgICAgSXNDb21wbGV0ZWQ6IGFzc2Vzc21lbnQuaXNDb21wbGV0ZWQsIFxyXG4gICAgICAgIEhhemFyZFR5cGU6IGFzc2Vzc21lbnQuaGF6YXJkVHlwZSxcclxuICAgICAgICBPcmdhbml6YXRpb25UeXBlOmFzc2Vzc21lbnQub3JnYW5pemF0aW9uVHlwZSxcclxuICAgICAgICBUZW1wbGF0ZTogYXNzZXNzbWVudC50ZW1wbGF0ZVxyXG4gICAgICB9XHJcbiAgICB9XHJcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICByZXR1cm57IGRhdGE6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWR9XHJcbiAgICB9XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6ICBKU09OLnN0cmluZ2lmeShyZXNwb25zZSkgICAgXHJcbiAgICB9XHJcblxyXG4gIH1jYXRjaChlKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogZVxyXG4gICAgfVxyXG4gIH1cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0SW5kaWNhdG9yQXNzZXNzbWVudHMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPEluZGljYXRvckFzc2Vzc21lbnRbXT57XHJcbiAgY29uc29sZS5sb2coJ2dldCBJbmRpY2F0b3IgQXNzZXNzbWVudHMgY2FsbGVkLicpXHJcblxyXG4gIGNvbnN0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgcXVlcnksIGNvbmZpZyk7XHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMCl7XHJcbiAgICAgcmV0dXJuIGZlYXR1cmVzLm1hcChmZWF0dXJlID0+IHsgICAgICAgIFxyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBvYmplY3RJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICAgIGluZGljYXRvcklkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSW5kaWNhdG9ySUQsXHJcbiAgICAgICAgICBpbmRpY2F0b3I6IGZlYXR1cmUuYXR0cmlidXRlcy5JbmRpY2F0b3JOYW1lLFxyXG4gICAgICAgICAgdGVtcGxhdGU6IGZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZU5hbWUsXHJcbiAgICAgICAgICBsaWZlbGluZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZSxcclxuICAgICAgICAgIGNvbXBvbmVudDogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbXBvbmVudE5hbWUsICAgICAgICAgIFxyXG4gICAgICAgICAgY29tbWVudHM6IHBhcnNlQ29tbWVudChmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tbWVudHMpLCAgICAgICAgICBcclxuICAgICAgICAgIGxpZmVsaW5lU3RhdHVzSWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5MaWZlbGluZVN0YXR1c0lELFxyXG4gICAgICAgICAgZW52aXJvbm1lbnRQcmVzZXJ2YXRpb246IGZlYXR1cmUuYXR0cmlidXRlcy5FbnZpcm9ubWVudFByZXNlcnZhdGlvbixcclxuICAgICAgICAgIGluY2lkZW50U3RhYmlsaXphdGlvbjogZmVhdHVyZS5hdHRyaWJ1dGVzLkluY2lkZW50U3RhYmlsaXphdGlvbixcclxuICAgICAgICAgIHJhbms6IGZlYXR1cmUuYXR0cmlidXRlcy5SYW5rLFxyXG4gICAgICAgICAgbGlmZVNhZmV0eTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVTYWZldHksXHJcbiAgICAgICAgICBwcm9wZXJ0eVByb3RlY3Rpb246IGZlYXR1cmUuYXR0cmlidXRlcy5Qcm9wZXJ0eVByb3RlY3Rpb24sXHJcbiAgICAgICAgICBzdGF0dXM6IGZlYXR1cmUuYXR0cmlidXRlcy5TdGF0dXNcclxuICAgICAgICB9IGFzIEluZGljYXRvckFzc2Vzc21lbnQ7XHJcbiAgICAgfSlcclxuICB9XHJcblxyXG59XHJcblxyXG5mdW5jdGlvbiBwYXJzZUNvbW1lbnQoY29tbWVudHM6IHN0cmluZyl7XHJcbiAgaWYoIWNvbW1lbnRzIHx8IGNvbW1lbnRzID09PSBcIlwiKXtcclxuICAgIHJldHVybiBbXTtcclxuICB9XHJcbiAgbGV0IHBhcnNlZENvbW1lbnRzID0gSlNPTi5wYXJzZShjb21tZW50cykgYXMgSW5Db21tZW50W107XHJcbiAgXHJcbiAgaWYocGFyc2VkQ29tbWVudHMgJiYgcGFyc2VkQ29tbWVudHMubGVuZ3RoID4gMCl7XHJcbiAgICBwYXJzZWRDb21tZW50cy5tYXAoKGNvbW1lbnREYXRhOiBJbkNvbW1lbnQpID0+IHtcclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAuLi5jb21tZW50RGF0YSxcclxuICAgICAgICAgICAgZGF0ZXRpbWU6IE51bWJlcihjb21tZW50RGF0YS5kYXRldGltZSlcclxuICAgICAgICB9IGFzIEluQ29tbWVudFxyXG4gICAgfSk7XHJcbiAgICBwYXJzZWRDb21tZW50cyA9IChwYXJzZWRDb21tZW50cyBhcyBhbnkpLm9yZGVyQnkoJ2RhdGV0aW1lJywgdHJ1ZSk7XHJcbiAgfWVsc2V7XHJcbiAgICBwYXJzZWRDb21tZW50cyA9IFtdO1xyXG4gIH1cclxuICBcclxuICByZXR1cm4gcGFyc2VkQ29tbWVudHM7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldExpZmVsaW5lU3RhdHVzRmVhdHVyZXMoY29uZmlnLCBxdWVyeSkge1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgTGlmZWxpbmUgU3RhdHVzIGNhbGxlZCcpXHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIHF1ZXJ5LCBjb25maWcpO1xyXG59XHJcblxyXG5mdW5jdGlvbiBsb2FkQXNzZXNzbWVudChhc3Nlc3NtZW50RmVhdHVyZTogSUZlYXR1cmUsIGxzRmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIGluZGljYXRvckFzc2Vzc21lbnRzOiBJbmRpY2F0b3JBc3Nlc3NtZW50W10pOiBBc3Nlc3NtZW50eyAgIFxyXG5cclxuICBjb25zdCBsaWZlbGluZVN0YXR1c2VzID0gbHNGZWF0dXJlcy5tYXAoKGZlYXR1cmUpID0+IHsgXHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBvYmplY3RJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICBhc3Nlc3NtZW50SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5Bc3Nlc3NtZW50SUQsXHJcbiAgICAgIGxpZmVsaW5lTmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZSxcclxuICAgICAgaW5kaWNhdG9yQXNzZXNzbWVudHM6IGluZGljYXRvckFzc2Vzc21lbnRzLmZpbHRlcihpID0+IGkubGlmZWxpbmVTdGF0dXNJZCA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSwgICAgICBcclxuICAgICAgc2NvcmU6IGZlYXR1cmUuYXR0cmlidXRlcy5TY29yZSxcclxuICAgICAgY29sb3I6IGZlYXR1cmUuYXR0cmlidXRlcy5Db2xvcixcclxuICAgICAgaXNPdmVycmlkZW46IGZlYXR1cmUuYXR0cmlidXRlcy5Jc092ZXJyaWRlbixcclxuICAgICAgb3ZlcnJpZGVTY29yZTpmZWF0dXJlLmF0dHJpYnV0ZXMuT3ZlcnJpZGVuU2NvcmUsXHJcbiAgICAgIG92ZXJyaWRlbkJ5OiBmZWF0dXJlLmF0dHJpYnV0ZXMuT3ZlcnJpZGVuQnksXHJcbiAgICAgIG92ZXJyaWRlbkNvbG9yOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT3ZlcnJpZGVuQ29sb3IsICAgICBcclxuICAgICAgb3ZlcnJpZGVDb21tZW50OiBmZWF0dXJlLmF0dHJpYnV0ZXMuT3ZlcnJpZGVDb21tZW50ICAgICAgXHJcbiAgICB9IGFzIExpZmVsaW5lU3RhdHVzO1xyXG4gIH0pO1xyXG5cclxuICBjb25zdCBhc3Nlc3NtZW50ID0ge1xyXG4gICAgb2JqZWN0SWQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICBpZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgIG5hbWU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgIGFzc2Vzc21lbnRUeXBlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkFzc2Vzc21lbnRUeXBlLFxyXG4gICAgbGlmZWxpbmVTdGF0dXNlczogbGlmZWxpbmVTdGF0dXNlcyxcclxuICAgIGRlc2NyaXB0aW9uOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgdGVtcGxhdGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuVGVtcGxhdGUsXHJcbiAgICBvcmdhbml6YXRpb246IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuT3JnYW5pemF0aW9uLFxyXG4gICAgb3JnYW5pemF0aW9uVHlwZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb25UeXBlLFxyXG4gICAgaW5jaWRlbnQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuSW5jaWRlbnQsXHJcbiAgICBoYXphcmQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuSGF6YXJkLFxyXG4gICAgaGF6YXJkVHlwZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmRUeXBlLFxyXG4gICAgY3JlYXRvcjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdG9yLFxyXG4gICAgY3JlYXRlZERhdGU6IE51bWJlcihhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0ZWREYXRlKSxcclxuICAgIGVkaXRvcjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5FZGl0b3IsXHJcbiAgICBlZGl0ZWREYXRlOiBOdW1iZXIoYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5FZGl0ZWREYXRlKSxcclxuICAgIGlzU2VsZWN0ZWQ6IGZhbHNlLFxyXG4gICAgaXNDb21wbGV0ZWQ6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuSXNDb21wbGV0ZWQsXHJcbiAgfSBhcyBBc3Nlc3NtZW50XHJcblxyXG4gIHJldHVybiBhc3Nlc3NtZW50OyAgXHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIHNhdmVMaWZlbGluZVN0YXR1cyhsaWZlbGluZVN0YXR1c0ZlYXR1cmU6IElGZWF0dXJlLCBsc0luZEFzc2Vzc0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBjb25maWcpOiBQcm9taXNlPGJvb2xlYW4+e1xyXG4gIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBbbGlmZWxpbmVTdGF0dXNGZWF0dXJlXSwgY29uZmlnKVxyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShlID0+IGUuc3VjY2Vzcykpe1xyXG4gICAgIGNvbnN0IGdsb2JhbElkID0gcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZDtcclxuXHJcbiAgICAgY29uc3QgaW5kaWNhdG9yQXNzZXNzbWVudEZlYXR1cmVzID0gbHNJbmRBc3Nlc3NGZWF0dXJlcy5tYXAoaW5kID0+IHtcclxuICAgICAgICBpbmQuYXR0cmlidXRlcy5MaWZlbGluZVN0YXR1c0lEID0gZ2xvYmFsSWRcclxuICAgICAgICByZXR1cm4gaW5kO1xyXG4gICAgIH0pXHJcbiAgICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgaW5kaWNhdG9yQXNzZXNzbWVudEZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShlID0+IGUuc3VjY2Vzcykpe1xyXG4gICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgfVxyXG4gIH1cclxufVxyXG5cclxuZnVuY3Rpb24gZ2V0VGVtcGxhdGVJbmRpY2F0b3JzKHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUpOiBJbmRpY2F0b3JUZW1wbGF0ZVtdIHtcclxuICByZXR1cm4gW10uY29uY2F0LmFwcGx5KFtdLCAoW10uY29uY2F0LmFwcGx5KFtdLCBcclxuICAgdGVtcGxhdGUubGlmZWxpbmVUZW1wbGF0ZXMubWFwKGwgPT4gbC5jb21wb25lbnRUZW1wbGF0ZXMpKSlcclxuICAgLm1hcCgoYzogQ29tcG9uZW50VGVtcGxhdGUpID0+IGMuaW5kaWNhdG9ycykpO1xyXG59IiwiLy9BZGFwdGVkIGZyb20gLy9odHRwczovL2dpdGh1Yi5jb20vb2RvZS9tYXAtdnVlL2Jsb2IvbWFzdGVyL3NyYy9kYXRhL2F1dGgudHNcclxuXHJcbmltcG9ydCB7IGxvYWRBcmNHSVNKU0FQSU1vZHVsZXMgfSBmcm9tIFwiamltdS1hcmNnaXNcIjtcclxuXHJcbi8qKlxyXG4gKiBBdHRlbXB0IHRvIHNpZ24gaW4sXHJcbiAqIGZpcnN0IGNoZWNrIGN1cnJlbnQgc3RhdHVzXHJcbiAqIGlmIG5vdCBzaWduZWQgaW4sIHRoZW4gZ28gdGhyb3VnaFxyXG4gKiBzdGVwcyB0byBnZXQgY3JlZGVudGlhbHNcclxuICovXHJcbmV4cG9ydCBjb25zdCBzaWduSW4gPSBhc3luYyAoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpID0+IHtcclxuICAgIHRyeSB7XHJcbiAgICAgICAgcmV0dXJuIGF3YWl0IGNoZWNrQ3VycmVudFN0YXR1cyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XHJcbiAgICAgICAgY29uc29sZS5sb2coZXJyb3IpO1xyXG4gICAgICAgIHJldHVybiBhd2FpdCBmZXRjaENyZWRlbnRpYWxzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgfVxyXG59O1xyXG5cclxuLyoqXHJcbiAqIFNpZ24gdGhlIHVzZXIgb3V0LCBidXQgaWYgd2UgY2hlY2tlZCBjcmVkZW50aWFsc1xyXG4gKiBtYW51YWxseSwgbWFrZSBzdXJlIHRoZXkgYXJlIHJlZ2lzdGVyZWQgd2l0aFxyXG4gKiBJZGVudGl0eU1hbmFnZXIsIHNvIGl0IGNhbiBkZXN0cm95IHRoZW0gcHJvcGVybHlcclxuICovXHJcbmV4cG9ydCBjb25zdCBzaWduT3V0ID0gYXN5bmMgKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSA9PiB7XHJcbiAgICBjb25zdCBJZGVudGl0eU1hbmFnZXIgPSBhd2FpdCBsb2FkTW9kdWxlcyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIGF3YWl0IHNpZ25JbihhcHBJZCwgcG9ydGFsVXJsKTtcclxuXHJcbiAgICBkZWxldGUgd2luZG93WydJZGVudGl0eU1hbmFnZXInXTtcclxuICAgIGRlbGV0ZSB3aW5kb3dbJ09BdXRoSW5mbyddO1xyXG4gICAgSWRlbnRpdHlNYW5hZ2VyLmRlc3Ryb3lDcmVkZW50aWFscygpO1xyXG4gICAgXHJcbn07XHJcblxyXG4vKipcclxuICogR2V0IHRoZSBjcmVkZW50aWFscyBmb3IgdGhlIHByb3ZpZGVkIHBvcnRhbFxyXG4gKi9cclxuYXN5bmMgZnVuY3Rpb24gZmV0Y2hDcmVkZW50aWFscyhhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZyl7XHJcbiAgICBjb25zdCBJZGVudGl0eU1hbmFnZXIgPSBhd2FpdCBsb2FkTW9kdWxlcyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIGNvbnN0IGNyZWRlbnRpYWwgPSBhd2FpdCBJZGVudGl0eU1hbmFnZXIuZ2V0Q3JlZGVudGlhbChgJHtwb3J0YWxVcmx9L3NoYXJpbmdgLCB7XHJcbiAgICAgICAgZXJyb3I6IG51bGwgYXMgYW55LFxyXG4gICAgICAgIG9BdXRoUG9wdXBDb25maXJtYXRpb246IGZhbHNlLFxyXG4gICAgICAgIHRva2VuOiBudWxsIGFzIGFueVxyXG4gICAgfSk7XHJcbiAgICByZXR1cm4gY3JlZGVudGlhbDtcclxufTtcclxuXHJcbi8qKlxyXG4gKiBJbXBvcnQgSWRlbnRpdHkgTWFuYWdlciwgYW5kIE9BdXRoSW5mb1xyXG4gKi9cclxuYXN5bmMgZnVuY3Rpb24gbG9hZE1vZHVsZXMoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpIHtcclxuICAgIGxldCBJZGVudGl0eU1hbmFnZXIgPSB3aW5kb3dbJ0lkZW50aXR5TWFuYWdlciddXHJcbiAgICBpZighSWRlbnRpdHlNYW5hZ2VyKXtcclxuICAgICAgICBjb25zdCBtb2R1bGVzID0gYXdhaXQgbG9hZEFyY0dJU0pTQVBJTW9kdWxlcyhbXHJcbiAgICAgICAgICAgICdlc3JpL2lkZW50aXR5L0lkZW50aXR5TWFuYWdlcicsXHJcbiAgICAgICAgICAgICdlc3JpL2lkZW50aXR5L09BdXRoSW5mbyddKTtcclxuXHJcbiAgICAgICAgICAgIHdpbmRvd1snSWRlbnRpdHlNYW5hZ2VyJ10gPSBtb2R1bGVzWzBdO1xyXG4gICAgICAgICAgICB3aW5kb3dbJ09BdXRoSW5mbyddID0gbW9kdWxlc1sxXTtcclxuICAgICAgICAgICAgXHJcbiAgICAgICAgSWRlbnRpdHlNYW5hZ2VyID0gbW9kdWxlc1swXTtcclxuICAgICAgICBjb25zdCBPQXV0aEluZm8gPSBtb2R1bGVzWzFdO1xyXG5cclxuICAgICAgICBjb25zdCBvYXV0aEluZm8gPSBuZXcgT0F1dGhJbmZvKHtcclxuICAgICAgICAgICAgYXBwSWQsXHJcbiAgICAgICAgICAgIHBvcnRhbFVybCxcclxuICAgICAgICAgICAgcG9wdXA6IGZhbHNlXHJcbiAgICAgICAgfSk7XHJcbiAgICAgICAgSWRlbnRpdHlNYW5hZ2VyLnJlZ2lzdGVyT0F1dGhJbmZvcyhbb2F1dGhJbmZvXSk7ICAgICAgICBcclxuICAgIH1cclxuICAgIHJldHVybiBJZGVudGl0eU1hbmFnZXI7XHJcbn1cclxuXHJcbi8qKlxyXG4gKiBDaGVjayBjdXJyZW50IGxvZ2dlZCBpbiBzdGF0dXMgZm9yIGN1cnJlbnQgcG9ydGFsXHJcbiAqL1xyXG5leHBvcnQgY29uc3QgY2hlY2tDdXJyZW50U3RhdHVzID0gYXN5bmMgKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKSA9PiB7XHJcbiAgICBjb25zdCBJZGVudGl0eU1hbmFnZXIgPSBhd2FpdCBsb2FkTW9kdWxlcyhhcHBJZCwgcG9ydGFsVXJsKTtcclxuICAgIHJldHVybiBJZGVudGl0eU1hbmFnZXIuY2hlY2tTaWduSW5TdGF0dXMoYCR7cG9ydGFsVXJsfS9zaGFyaW5nYCk7XHJcbn07IiwiaW1wb3J0IHsgZXh0ZW5zaW9uU3BlYywgSW1tdXRhYmxlT2JqZWN0LCBJTVN0YXRlIH0gZnJvbSAnamltdS1jb3JlJztcclxuaW1wb3J0IHsgQXNzZXNzbWVudCwgQ0xTU19TdGF0ZSwgXHJcbiAgQ0xTU1RlbXBsYXRlLCBDbHNzVXNlciwgSGF6YXJkLCBcclxuICBMaWZlbGluZVN0YXR1cywgT3JnYW5pemF0aW9uLCBcclxuICBSYXRpbmdTY2FsZSwgU2NhbGVGYWN0b3IgfSBmcm9tICcuL2RhdGEtZGVmaW5pdGlvbnMnO1xyXG5pbXBvcnQgeyBJQ29kZWRWYWx1ZSB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LXR5cGVzJztcclxuaW1wb3J0IHsgSUNyZWRlbnRpYWwgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1hdXRoJztcclxuXHJcblxyXG5leHBvcnQgZW51bSBDTFNTQWN0aW9uS2V5cyB7XHJcbiAgQVVUSEVOVElDQVRFX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gYXV0aGVuaWNhdGUgY3JlZGVudGlhbHMnLFxyXG4gIExPQURfSEFaQVJEU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgaGF6YXJkcycsXHJcbiAgTE9BRF9IQVpBUkRfVFlQRVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIGhhemFyZCB0eXBlcycsXHJcbiAgTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBvcmdhbml6YXRpb25zJyxcclxuICBMT0FEX09SR0FOSVpBVElPTl9UWVBFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgb3JnYW5pemF0aW9uIHR5cGVzJyxcclxuICBMT0FEX1RFTVBMQVRFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgdGVtcGxhdGVzJyxcclxuICBMT0FEX1BSSU9SSVRJRVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIHByaW9yaXRpZXMnLFxyXG4gIFNFTEVDVF9URU1QTEFURV9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIHNlbGVjdCB0ZW1wbGF0ZScsXHJcbiAgU0VBUkNIX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gc2VhcmNoIGZvciB0ZW1wbGF0ZScsXHJcbiAgU0lHTl9JTl9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNpZ24gaW4nLFxyXG4gIFNJR05fT1VUX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2lnbiBvdXQnLFxyXG4gIFNFVF9VU0VSX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2V0IENMU1MgVXNlcicsXHJcbiAgU0VUX0lERU5USVRZX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2V0IElkZW50aXR5JyxcclxuICBTRVRfRVJST1JTID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZXQgZ2xvYmFsIGVycm9ycycsXHJcbiAgVE9HR0xFX0lORElDQVRPUl9FRElUSU5HID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBUb2dnbGUgaW5kaWNhdG9yIGVkaXRpbmcnLCAgXHJcbiAgU0VMRUNUX0xJRkVMSU5FU1RBVFVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2VsZWN0IGEgbGlmZWxpbmUgc3RhdHVzJyxcclxuICBMT0FEX0FTU0VTU01FTlRTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gTG9hZCBhc3Nlc3NtZW50cycsXHJcbiAgU0VMRUNUX0FTU0VTU01FTlRfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZWxlY3QgYXNzZXNzbWVudCcsXHJcbiAgTE9BRF9SQVRJTkdTQ0FMRVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBMb2FkIHJhdGluZyBzY2FsZXMnLFxyXG4gIExPQURfU0NBTEVGQUNUT1JTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gTG9hZCBjb25zdGFudHMnXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9TY2FsZUZhY3RvcnNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9TQ0FMRUZBQ1RPUlNfQUNUSU9OLFxyXG4gIHZhbDogU2NhbGVGYWN0b3JbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfUmF0aW5nX1NjYWxlc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1JBVElOR1NDQUxFU19BQ1RJT04sXHJcbiAgdmFsOiBSYXRpbmdTY2FsZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VsZWN0X0Fzc2Vzc21lbnRfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VMRUNUX0FTU0VTU01FTlRfQUNUSU9OLFxyXG4gIHZhbDogQXNzZXNzbWVudFxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfQXNzZXNzbWVudHNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9BU1NFU1NNRU5UU19BQ1RJT04sXHJcbiAgdmFsOiBBc3Nlc3NtZW50W11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1ByaW9yaXRpZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9QUklPUklUSUVTX0FDVElPTixcclxuICB2YWw6IGFueVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9IYXphcmRfVHlwZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRfVFlQRVNfQUNUSU9OLFxyXG4gIHZhbDogSUNvZGVkVmFsdWVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfT3JnYW5pemF0aW9uX1R5cGVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OX1RZUEVTX0FDVElPTixcclxuICB2YWw6IElDb2RlZFZhbHVlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWxlY3RfTGlmZWxpbmVTdGF0dXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VMRUNUX0xJRkVMSU5FU1RBVFVTX0FDVElPTixcclxuICB2YWw6IExpZmVsaW5lU3RhdHVzXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0X1RvZ2dsZV9JbmRpY2F0b3JfRWRpdGluZ19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5UT0dHTEVfSU5ESUNBVE9SX0VESVRJTkcsXHJcbiAgdmFsOiBzdHJpbmdcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRfRXJyb3JzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsXHJcbiAgdmFsOiBzdHJpbmdcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX0hhemFyZHNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRTX0FDVElPTixcclxuICB2YWw6IEhhemFyZFtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Pcmdhbml6YXRpb25zX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfT1JHQU5JWkFUSU9OU19BQ1RJT04sXHJcbiAgdmFsOiBPcmdhbml6YXRpb25bXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldElkZW50aXR5X0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFVF9JREVOVElUWV9BQ1RJT04sXHJcbiAgdmFsOiBDbHNzVXNlclxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldFVzZXJfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX1VTRVJfQUNUSU9OLFxyXG4gIHZhbDogQ2xzc1VzZXJcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTaWduaW5fQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0lHTl9JTl9BQ1RJT05cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTaWdub3V0X0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNJR05fT1VUX0FDVElPTlxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlbGVjdF9UZW1wbGF0ZV9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfVEVNUExBVEVfQUNUSU9OLFxyXG4gIHZhbDogc3RyaW5nXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9UZW1wbGF0ZXNfQWN0aW9uX1R5cGUge1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfVEVNUExBVEVTX0FDVElPTixcclxuICB2YWw6IENMU1NUZW1wbGF0ZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VhcmNoX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VBUkNIX0FDVElPTixcclxuICB2YWw6IHN0cmluZ1xyXG59ICBcclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgQXV0aGVudGljYXRlX0FjdGlvbl9UeXBlIHtcclxuICAgdHlwZTogQ0xTU0FjdGlvbktleXMuQVVUSEVOVElDQVRFX0FDVElPTixcclxuICAgdmFsOiBJQ3JlZGVudGlhbDtcclxufVxyXG5cclxuXHJcbnR5cGUgQWN0aW9uVHlwZXMgPSBcclxuIFNlbGVjdF9UZW1wbGF0ZV9BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB8IFxyXG4gU2VhcmNoX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB8IFxyXG4gU2lnbmluX0FjdGlvbl9UeXBlIHxcclxuIFNpZ25vdXRfQWN0aW9uX1R5cGUgfFxyXG4gU2V0VXNlcl9BY3Rpb25fVHlwZSB8IFxyXG4gU2V0SWRlbnRpdHlfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9IYXphcmRzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfT3JnYW5pemF0aW9uc19BY3Rpb25fVHlwZSB8XHJcbiBTZXRfRXJyb3JzX0FjdGlvbl9UeXBlIHxcclxuIFNldF9Ub2dnbGVfSW5kaWNhdG9yX0VkaXRpbmdfQWN0aW9uX1R5cGUgfFxyXG4gU2VsZWN0X0xpZmVsaW5lU3RhdHVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfSGF6YXJkX1R5cGVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfT3JnYW5pemF0aW9uX1R5cGVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfUHJpb3JpdGllc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX0Fzc2Vzc21lbnRzX0FjdGlvbl9UeXBlIHxcclxuIFNlbGVjdF9Bc3Nlc3NtZW50X0FjdGlvbl9UeXBlfCBcclxuIExvYWRfUmF0aW5nX1NjYWxlc19BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX1NjYWxlRmFjdG9yc19BY3Rpb25fVHlwZSB8XHJcbiBBdXRoZW50aWNhdGVfQWN0aW9uX1R5cGUgO1xyXG5cclxudHlwZSBJTU15U3RhdGUgPSBJbW11dGFibGVPYmplY3Q8Q0xTU19TdGF0ZT47XHJcblxyXG5kZWNsYXJlIG1vZHVsZSAnamltdS1jb3JlL2xpYi90eXBlcy9zdGF0ZSd7XHJcbiAgaW50ZXJmYWNlIFN0YXRle1xyXG4gICAgY2xzc1N0YXRlPzogSU1NeVN0YXRlXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgZGVmYXVsdCBjbGFzcyBNeVJlZHV4U3RvcmVFeHRlbnNpb24gaW1wbGVtZW50cyBleHRlbnNpb25TcGVjLlJlZHV4U3RvcmVFeHRlbnNpb24ge1xyXG4gIGlkID0gJ2Nsc3MtcmVkdXgtc3RvcmUtZXh0ZW5zaW9uJztcclxuIFxyXG4gIGdldEFjdGlvbnMoKSB7XHJcbiAgICByZXR1cm4gT2JqZWN0LmtleXMoQ0xTU0FjdGlvbktleXMpLm1hcChrID0+IENMU1NBY3Rpb25LZXlzW2tdKTtcclxuICB9XHJcblxyXG4gIGdldEluaXRMb2NhbFN0YXRlKCkge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgIHNlbGVjdGVkVGVtcGxhdGU6IG51bGwsXHJcbiAgICAgICB0ZW1wbGF0ZXM6IFtdLFxyXG4gICAgICAgc2VhcmNoUmVzdWx0czogW10sXHJcbiAgICAgICB1c2VyOiBudWxsLFxyXG4gICAgICAgYXV0aDogbnVsbCxcclxuICAgICAgIGlkZW50aXR5OiBudWxsLCAgICAgICBcclxuICAgICAgIG5ld1RlbXBsYXRlTW9kYWxWaXNpYmxlOiBmYWxzZSxcclxuICAgICAgIGhhemFyZHM6IFtdLFxyXG4gICAgICAgb3JnYW5pemF0aW9uczogW10sXHJcbiAgICAgICBlcnJvcnM6ICcnLFxyXG4gICAgICAgaXNJbmRpY2F0b3JFZGl0aW5nOiBmYWxzZSxcclxuICAgICAgIHNlbGVjdGVkTGlmZWxpbmVTdGF0dXM6IG51bGwsXHJcbiAgICAgICBvcmdhbml6YXRpb25UeXBlczogW10sXHJcbiAgICAgICBoYXphcmRUeXBlczogW10sXHJcbiAgICAgICBwcmlvcml0aWVzOiBbXSxcclxuICAgICAgIGFzc2Vzc21lbnRzOiBbXSxcclxuICAgICAgIHJhdGluZ1NjYWxlczogW10sXHJcbiAgICAgICBzY2FsZUZhY3RvcnM6IFtdLFxyXG4gICAgICAgYXV0aGVudGljYXRlOiBudWxsXHJcbiAgICB9IGFzIENMU1NfU3RhdGU7XHJcbiAgfVxyXG5cclxuICBnZXRSZWR1Y2VyKCkge1xyXG4gICAgcmV0dXJuIChsb2NhbFN0YXRlOiBJTU15U3RhdGUsIGFjdGlvbjogQWN0aW9uVHlwZXMsIGFwcFN0YXRlOiBJTVN0YXRlKTogSU1NeVN0YXRlID0+IHsgICAgICBcclxuICAgICAgXHJcbiAgICAgIHN3aXRjaCAoYWN0aW9uLnR5cGUpIHtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5BVVRIRU5USUNBVEVfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdhdXRoZW50aWNhdGUnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1NDQUxFRkFDVE9SU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3NjYWxlRmFjdG9ycycsIGFjdGlvbi52YWwpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9SQVRJTkdTQ0FMRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdyYXRpbmdTY2FsZXMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfQVNTRVNTTUVOVF9BQ1RJT046XHJcbiAgICAgICAgICBjb25zdCBhc3Nlc3NtZW50cyA9IGxvY2FsU3RhdGUuYXNzZXNzbWVudHMubWFwKGFzc2VzcyA9PiB7XHJcbiAgICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIC4uLmFzc2VzcyxcclxuICAgICAgICAgICAgICBpc1NlbGVjdGVkOiBhc3Nlc3MuaWQgPT09IGFjdGlvbi52YWwuaWQudG9Mb3dlckNhc2UoKVxyXG4gICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfSlcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnYXNzZXNzbWVudHMnLCBhc3Nlc3NtZW50cyk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9BU1NFU1NNRU5UU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2Fzc2Vzc21lbnRzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9QUklPUklUSUVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgncHJpb3JpdGllcycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFTEVDVF9MSUZFTElORVNUQVRVU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3NlbGVjdGVkTGlmZWxpbmVTdGF0dXMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5UT0dHTEVfSU5ESUNBVE9SX0VESVRJTkc6XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2lzSW5kaWNhdG9yRWRpdGluZycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlM6XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2Vycm9ycycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfSEFaQVJEU19BQ1RJT046ICBcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaGF6YXJkcycsIGFjdGlvbi52YWwpXHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRfVFlQRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdoYXphcmRUeXBlcycsIGFjdGlvbi52YWwpXHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05fVFlQRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdvcmdhbml6YXRpb25UeXBlcycsIGFjdGlvbi52YWwpXHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTjpcclxuICAgICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdvcmdhbml6YXRpb25zJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRVRfSURFTlRJVFlfQUNUSU9OOiAgXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2lkZW50aXR5JywgYWN0aW9uLnZhbCk7XHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5TRVRfVVNFUl9BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3VzZXInLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1RFTVBMQVRFU19BQ1RJT046ICAgICAgICAgIFxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCd0ZW1wbGF0ZXMnLCBhY3Rpb24udmFsKTtcclxuICAgICAgICBcclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFTEVDVF9URU1QTEFURV9BQ1RJT046XHJcbiAgICAgICAgICBsZXQgdGVtcGxhdGVzID0gWy4uLmxvY2FsU3RhdGUudGVtcGxhdGVzXS5tYXAodCA9PiB7XHJcbiAgICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIC4uLnQsXHJcbiAgICAgICAgICAgICAgaXNTZWxlY3RlZDogdC5pZCA9PT0gYWN0aW9uLnZhbFxyXG4gICAgICAgICAgICAgfSBcclxuICAgICAgICAgIH0pXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3RlbXBsYXRlcycsIHRlbXBsYXRlcykgICAgICAgICAgICBcclxuICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGU7XHJcbiAgICAgIH1cclxuICAgIH1cclxuICB9XHJcblxyXG4gIGdldFN0b3JlS2V5KCkge1xyXG4gICAgcmV0dXJuICdjbHNzU3RhdGUnO1xyXG4gIH1cclxufSIsImV4cG9ydCBjb25zdCBDTFNTX0FETUlOID0gJ0NMU1NfQWRtaW4nO1xyXG5leHBvcnQgY29uc3QgQ0xTU19FRElUT1IgPSAnQ0xTU19FZGl0b3InO1xyXG5leHBvcnQgY29uc3QgQ0xTU19BU1NFU1NPUiA9ICdDTFNTX0Fzc2Vzc29yJztcclxuZXhwb3J0IGNvbnN0IENMU1NfVklFV0VSID0gJ0NMU1NfVmlld2VyJztcclxuZXhwb3J0IGNvbnN0IENMU1NfRk9MTE9XRVJTID0gJ0NMU1MgRm9sbG93ZXJzJztcclxuXHJcbmV4cG9ydCBjb25zdCBCQVNFTElORV9URU1QTEFURV9OQU1FID0gJ0Jhc2VsaW5lJztcclxuZXhwb3J0IGNvbnN0IFRPS0VOX0VSUk9SID0gJ1Rva2VuIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBURU1QTEFURV9VUkxfRVJST1IgPSAnVGVtcGxhdGUgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgQVNTRVNTTUVOVF9VUkxfRVJST1IgPSAnQXNzZXNzbWVudCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBPUkdBTklaQVRJT05fVVJMX0VSUk9SID0gJ09yZ2FuaXphdGlvbiBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBIQVpBUkRfVVJMX0VSUk9SID0gJ0hhemFyZCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBJTkRJQ0FUT1JfVVJMX0VSUk9SID0gJ0luZGljYXRvciBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBBTElHTk1FTlRfVVJMX0VSUk9SID0gJ0FsaWdubWVudHMgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgTElGRUxJTkVfVVJMX0VSUk9SID0gJ0xpZmVsaW5lIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IENPTVBPTkVOVF9VUkxfRVJST1IgPSAnQ29tcG9uZW50IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IFBSSU9SSVRZX1VSTF9FUlJPUiA9ICdQcmlvcml0eSBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBJTkNJREVOVF9VUkxfRVJST1IgPSAnSW5jaWRlbnQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgU0FWSU5HX1NBTUVfQVNfQkFTRUxJTkVfRVJST1IgPSAnQmFzZWxpbmUgdGVtcGxhdGUgY2Fubm90IGJlIHVwZGF0ZWQuIENoYW5nZSB0aGUgdGVtcGxhdGUgbmFtZSB0byBjcmVhdGUgYSBuZXcgb25lLidcclxuXHJcbmV4cG9ydCBjb25zdCBTVEFCSUxJWklOR19TQ0FMRV9GQUNUT1IgPSAnU3RhYmlsaXppbmdfU2NhbGVfRmFjdG9yJztcclxuZXhwb3J0IGNvbnN0IERFU1RBQklMSVpJTkdfU0NBTEVfRkFDVE9SID0gJ0Rlc3RhYmlsaXppbmdfU2NhbGVfRmFjdG9yJztcclxuZXhwb3J0IGNvbnN0IFVOQ0hBTkdFRF9TQ0FMRV9GQUNUT1IgPSAnVW5jaGFuZ2VkX0luZGljYXRvcnMnO1xyXG5leHBvcnQgY29uc3QgREVGQVVMVF9QUklPUklUWV9MRVZFTFMgPSBcIkRlZmF1bHRfUHJpb3JpdHlfTGV2ZWxzXCI7XHJcbmV4cG9ydCBjb25zdCBSQU5LID0gJ0ltcG9ydGFuY2Ugb2YgSW5kaWNhdG9yJztcclxuZXhwb3J0IGNvbnN0IExJRkVfU0FGRVRZID0gJ0xpZmUgU2FmZXR5JztcclxuZXhwb3J0IGNvbnN0IElOQ0lERU5UX1NUQUJJTElaQVRJT04gPSAnSW5jaWRlbnQgU3RhYmlsaXphdGlvbic7XHJcbmV4cG9ydCBjb25zdCBQUk9QRVJUWV9QUk9URUNUSU9OID0gJ1Byb3BlcnR5IFByb3RlY3Rpb24nO1xyXG5leHBvcnQgY29uc3QgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OID0gJ0Vudmlyb25tZW50IFByZXNlcnZhdGlvbic7XHJcblxyXG5leHBvcnQgY29uc3QgTElGRV9TQUZFVFlfU0NBTEVfRkFDVE9SID0gMjAwO1xyXG5leHBvcnQgY29uc3QgT1RIRVJfV0VJR0hUU19TQ0FMRV9GQUNUT1IgPSAxMDA7XHJcbmV4cG9ydCBjb25zdCBNQVhJTVVNX1dFSUdIVCA9IDU7XHJcblxyXG5leHBvcnQgZW51bSBVcGRhdGVBY3Rpb24ge1xyXG4gICAgSEVBREVSID0gJ2hlYWRlcicsXHJcbiAgICBJTkRJQ0FUT1JfTkFNRSA9ICdJbmRpY2F0b3IgTmFtZScsXHJcbiAgICBQUklPUklUSUVTID0gJ0luZGljYXRvciBQcmlvcml0aWVzJyxcclxuICAgIE5FV19JTkRJQ0FUT1IgPSAnQ3JlYXRlIE5ldyBJbmRpY2F0b3InLFxyXG4gICAgREVMRVRFX0lORElDQVRPUiA9ICdEZWxldGUgSW5kaWNhdG9yJ1xyXG59XHJcblxyXG5leHBvcnQgY29uc3QgSU5DTFVERV9JTkRJQ0FUT1IgPSAnSW1wYWN0ZWQgLSBZZXMgb3IgTm8nO1xyXG5leHBvcnQgY29uc3QgSU5DTFVERV9JTkRJQ0FUT1JfSEVMUCA9ICdZZXM6IFRoZSBpbmRpY2F0b3Igd2lsbCBiZSBjb25zaWRlcmVkIGluIHRoZSBhc3Nlc3NtZW50Llxcbk5vOiBUaGUgaW5kaWNhdG9yIHdpbGwgbm90IGJlIGNvbnNpZGVyZWQuXFxuVW5rbm93bjogTm90IHN1cmUgdG8gaW5jbHVkZSB0aGUgaW5kaWNhdG9yIGluIGFzc2Vzc21lbnQuJztcclxuXHJcbmV4cG9ydCBjb25zdCBJTkRJQ0FUT1JfU1RBVFVTID0gJ0luZGljYXRvciBJbXBhY3QgU3RhdHVzJztcclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9TVEFUVVNfSEVMUCA9ICdTdGFiaWxpemluZzogSGFzIHRoZSBpbmRpY2F0b3IgYmVlbiBpbXByb3ZlZCBvciBpbXByb3ZpbmcuXFxuRGVzdGFiaWxpemluZzogSXMgdGhlIGluZGljYXRvciBkZWdyYWRpbmcuXFxuVW5jaGFuZ2VkOiBObyBzaWduaWZpY2FudCBpbXByb3ZlbWVudCBzaW5jZSB0aGUgbGFzdCBhc3Nlc3NtZW50Lic7XHJcblxyXG5leHBvcnQgY29uc3QgQ09NTUVOVCA9ICdDb21tZW50JztcclxuZXhwb3J0IGNvbnN0IENPTU1FTlRfSEVMUCA9ICdQcm92aWRlIGp1c3RpZmljYXRpb24gZm9yIHRoZSBzZWxlY3RlZCBpbmRpY2F0b3Igc3RhdHVzLic7XHJcblxyXG5leHBvcnQgY29uc3QgREVMRVRFX0lORElDQVRPUl9DT05GSVJNQVRJT04gPSAnQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIGRlbGV0ZSBpbmRpY2F0b3I/JztcclxuXHJcbi8vQ2VsbCBXZWlnaHQgPSAgVHJlbmQgKiAoICgtMSpSYW5rKSArIDZcclxuZXhwb3J0IGNvbnN0IENSSVRJQ0FMID0gMjU7XHJcbmV4cG9ydCBjb25zdCBDUklUSUNBTF9MT1dFUl9CT1VOREFSWSA9IDEyLjU7XHJcbmV4cG9ydCBjb25zdCBNT0RFUkFURV9MT1dFUl9CT1VOREFSWSA9IDUuNTtcclxuZXhwb3J0IGNvbnN0IE5PREFUQV9DT0xPUiA9ICcjOTE5Mzk1JztcclxuZXhwb3J0IGNvbnN0IE5PREFUQV9WQUxVRSA9IDk5OTk5OTtcclxuZXhwb3J0IGNvbnN0IFJFRF9DT0xPUiA9ICcjQzUyMDM4JztcclxuZXhwb3J0IGNvbnN0IFlFTExPV19DT0xPUiA9ICcjRkJCQTE2JztcclxuZXhwb3J0IGNvbnN0IEdSRUVOX0NPTE9SID0gJyM1RTlDNDInO1xyXG5leHBvcnQgY29uc3QgU0FWSU5HX1RJTUVSID0gMTUwMDtcclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9DT01NRU5UX0xFTkdUSCA9IDMwMDtcclxuXHJcbmV4cG9ydCBjb25zdCBQT1JUQUxfVVJMID0gJ2h0dHBzOi8vd3d3LmFyY2dpcy5jb20nO1xyXG5cclxuZXhwb3J0IGNvbnN0IERFRkFVTFRfTElTVElURU0gPSB7aWQ6ICcwMDAnLCBuYW1lOiAnLU5vbmUtJywgdGl0bGU6ICctTm9uZS0nfSBhcyBhbnk7XHJcblxyXG5leHBvcnQgY29uc3QgUkFOS19NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byB5b3VyIGp1cmlzZGljdGlvbiBvciBoYXphcmQ/JztcclxuZXhwb3J0IGNvbnN0IExJRkVfU0FGRVRZX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIExpZmUgU2FmZXR5Pyc7XHJcbmV4cG9ydCBjb25zdCBQUk9QRVJUWV9QUk9URUNUSU9OX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIFByb3BlcnR5IFByb3RlY3Rpb24/JztcclxuZXhwb3J0IGNvbnN0IEVOVklST05NRU5UX1BSRVNFUlZBVElPTl9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBFbnZpcm9ubWVudCBQcmVzZXJ2YXRpb24/JztcclxuZXhwb3J0IGNvbnN0IElOQ0lERU5UX1NUQUJJTElaQVRJT05fTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gSW5jaWRlbnQgU3RhYmlsaXphdGlvbj8nO1xyXG5cclxuZXhwb3J0IGNvbnN0IE9WRVJXUklURV9TQ09SRV9NRVNTQUdFID0gJ0EgY29tcGxldGVkIGFzc2Vzc21lbnQgY2Fubm90IGJlIGVkaXRlZC4gQXJlIHlvdSBzdXJlIHlvdSB3YW50IHRvIGNvbXBsZXRlIHRoaXMgYXNzZXNzbWVudD8nOyIsImltcG9ydCB7IFVzZXJTZXNzaW9uIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWF1dGhcIjtcclxuaW1wb3J0IHsgcXVlcnlGZWF0dXJlcywgSVF1ZXJ5RmVhdHVyZXNSZXNwb25zZSwgXHJcbiAgICBJUmVsYXRlZFJlY29yZEdyb3VwLCBxdWVyeVJlbGF0ZWQsIHVwZGF0ZUZlYXR1cmVzLCBcclxuICAgIGFkZEZlYXR1cmVzLCBkZWxldGVGZWF0dXJlcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyXCI7XHJcbmltcG9ydCB7IElGZWF0dXJlU2V0LCBJRmVhdHVyZSB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC10eXBlc1wiO1xyXG5pbXBvcnQgeyBBcHBXaWRnZXRDb25maWcgfSBmcm9tIFwiLi9kYXRhLWRlZmluaXRpb25zXCI7XHJcbmltcG9ydCB7IGxvZywgTG9nVHlwZSB9IGZyb20gXCIuL2xvZ2dlclwiO1xyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0QXV0aGVudGljYXRpb24oY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuICByZXR1cm4gVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwoY29uZmlnLmNyZWRlbnRpYWwpO1xyXG59XHJcbiAgXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBxdWVyeVRhYmxlRmVhdHVyZVNldCh1cmw6IHN0cmluZywgd2hlcmU6IHN0cmluZywgXHJcbiAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlU2V0PiB7XHJcbiAgXHJcbiAgICB0cnl7XHJcblxyXG4gICAgICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcbiAgICAgIHJldHVybiBxdWVyeUZlYXR1cmVzKHsgdXJsLCB3aGVyZSwgYXV0aGVudGljYXRpb24sIGhpZGVUb2tlbjogdHJ1ZSB9KVxyXG4gICAgICAudGhlbigocmVzcG9uc2U6IElRdWVyeUZlYXR1cmVzUmVzcG9uc2UpID0+IHtcclxuICAgICAgICByZXR1cm4gcmVzcG9uc2VcclxuICAgICAgfSlcclxuXHJcbiAgICB9Y2F0Y2goZSl7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAncXVlcnlUYWJsZUZlYXR1cmVTZXQnKVxyXG4gICAgfSAgICBcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHF1ZXJ5VGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgd2hlcmU6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+IHtcclxuXHJcbiBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG4gIHRyeXtcclxuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBxdWVyeUZlYXR1cmVzKHsgdXJsLCB3aGVyZSwgYXV0aGVudGljYXRpb24sICBodHRwTWV0aG9kOidQT1NUJywgaGlkZVRva2VuOiB0cnVlIH0pXHJcbiAgICAgIHJldHVybiAocmVzcG9uc2UgYXMgSVF1ZXJ5RmVhdHVyZXNSZXNwb25zZSkuZmVhdHVyZXM7XHJcbiAgfWNhdGNoKGUpe1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ3F1ZXJ5VGFibGVGZWF0dXJlcycpXHJcbiAgICAgIGxvZyh1cmwsIExvZ1R5cGUuV1JOLCB3aGVyZSk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIHF1ZXJ5UmVsYXRlZFRhYmxlRmVhdHVyZXMob2JqZWN0SWRzOiBudW1iZXJbXSxcclxudXJsOiBzdHJpbmcsIHJlbGF0aW9uc2hpcElkOiBudW1iZXIsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJUmVsYXRlZFJlY29yZEdyb3VwW10+IHtcclxuXHJcbmNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbmNvbnN0IHJlc3BvbnNlID0gYXdhaXQgcXVlcnlSZWxhdGVkKHtcclxuICAgIG9iamVjdElkcyxcclxuICAgIHVybCwgcmVsYXRpb25zaGlwSWQsXHJcbiAgICBhdXRoZW50aWNhdGlvbixcclxuICAgIGhpZGVUb2tlbjogdHJ1ZVxyXG59KTtcclxucmV0dXJuIHJlc3BvbnNlLnJlbGF0ZWRSZWNvcmRHcm91cHM7XHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gdXBkYXRlVGFibGVGZWF0dXJlKHVybDogc3RyaW5nLCBhdHRyaWJ1dGVzOiBhbnksIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcbiAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuICByZXR1cm4gdXBkYXRlRmVhdHVyZXMoe1xyXG4gICAgICB1cmwsXHJcbiAgICAgIGF1dGhlbnRpY2F0aW9uLFxyXG4gICAgICBmZWF0dXJlczogW3tcclxuICAgICAgYXR0cmlidXRlc1xyXG4gICAgICB9XSxcclxuICAgICAgcm9sbGJhY2tPbkZhaWx1cmU6IHRydWVcclxuICB9KVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZVRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIGZlYXR1cmVzOiBJRmVhdHVyZVtdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG4gIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTsgIFxyXG4gIHJldHVybiB1cGRhdGVGZWF0dXJlcyh7XHJcbiAgICAgIHVybCxcclxuICAgICAgYXV0aGVudGljYXRpb24sXHJcbiAgICAgIGZlYXR1cmVzXHJcbiAgfSlcclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiBhZGRUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCBmZWF0dXJlczogYW55W10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcblxyXG4gIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbiAgdHJ5e1xyXG4gICAgcmV0dXJuIGFkZEZlYXR1cmVzKHsgdXJsLCBmZWF0dXJlcywgYXV0aGVudGljYXRpb24sIHJvbGxiYWNrT25GYWlsdXJlOiB0cnVlIH0pO1xyXG4gIH1jYXRjaChlKXtcclxuICAgIGNvbnNvbGUubG9nKGUpO1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiBkZWxldGVUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCBvYmplY3RJZHM6IG51bWJlcltdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG5cclxuICAgIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuICAgIHJldHVybiBkZWxldGVGZWF0dXJlcyh7IHVybCwgb2JqZWN0SWRzLCBhdXRoZW50aWNhdGlvbiwgcm9sbGJhY2tPbkZhaWx1cmU6IHRydWUgfSk7XHJcbn0iLCJleHBvcnQgZW51bSBMb2dUeXBlIHtcclxuICAgIElORk8gPSAnSW5mb3JtYXRpb24nLFxyXG4gICAgV1JOID0gJ1dhcm5pbmcnLFxyXG4gICAgRVJST1IgPSAnRXJyb3InXHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBsb2cobWVzc2FnZTogc3RyaW5nLCB0eXBlPzogTG9nVHlwZSwgZnVuYz86IHN0cmluZyl7XHJcbiAgICBpZighdHlwZSl7XHJcbiAgICAgICAgdHlwZSA9IExvZ1R5cGUuSU5GT1xyXG4gICAgfVxyXG5cclxuICAgIGlmKGZ1bmMpe1xyXG4gICAgICAgIGZ1bmMgPSBgKCR7ZnVuY30pYDtcclxuICAgIH1cclxuXHJcbiAgICBtZXNzYWdlID0gYFske25ldyBEYXRlKCkudG9Mb2NhbGVTdHJpbmcoKX1dOiAke21lc3NhZ2V9ICR7ZnVuY31gO1xyXG5cclxuICAgIHN3aXRjaCh0eXBlKXtcclxuICAgICAgICBjYXNlIExvZ1R5cGUuSU5GTzpcclxuICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZSk7XHJcbiAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGNhc2UgTG9nVHlwZS5XUk46XHJcbiAgICAgICAgICAgIGNvbnNvbGUud2FybihtZXNzYWdlKTtcclxuICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgY2FzZSBMb2dUeXBlLkVSUk9SOlxyXG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICBicmVhaztcclxuICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcclxuICAgIH1cclxufSIsIlxyXG5leHBvcnQgY29uc3Qgc29ydE9iamVjdCA9IDxUPihvYmo6IFRbXSwgcHJvcDogc3RyaW5nLCByZXZlcnNlPzpib29sZWFuKTogVFtdID0+IHtcclxuICAgcmV0dXJuIG9iai5zb3J0KChhOlQsIGI6VCkgPT4ge1xyXG4gICAgICBpZihhW3Byb3BdID4gYltwcm9wXSl7XHJcbiAgICAgICAgcmV0dXJuIHJldmVyc2UgPyAtMSA6IDFcclxuICAgICAgfVxyXG4gICAgICBpZihhW3Byb3BdIDwgYltwcm9wXSl7XHJcbiAgICAgICAgcmV0dXJuIHJldmVyc2UgPyAxIDogLTFcclxuICAgICAgfVxyXG4gICAgICByZXR1cm4gMDtcclxuICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IGNyZWF0ZUd1aWQgPSAoKSA9PntcclxuICByZXR1cm4gJ3h4eHh4eHh4LXh4eHgtNHh4eC15eHh4LXh4eHh4eHh4eHh4eCcucmVwbGFjZSgvW3h5XS9nLCBmdW5jdGlvbihjKSB7XHJcbiAgICB2YXIgciA9IE1hdGgucmFuZG9tKCkgKiAxNiB8IDAsIHYgPSBjID09ICd4JyA/IHIgOiAociAmIDB4MyB8IDB4OCk7XHJcbiAgICByZXR1cm4gdi50b1N0cmluZygxNik7XHJcbiAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBwYXJzZURhdGUgPSAobWlsbGlzZWNvbmRzOiBudW1iZXIpOiBzdHJpbmcgPT4ge1xyXG4gIGlmKCFtaWxsaXNlY29uZHMpe1xyXG4gICAgcmV0dXJuXHJcbiAgfVxyXG4gICByZXR1cm4gbmV3IERhdGUobWlsbGlzZWNvbmRzKS50b0xvY2FsZVN0cmluZygpO1xyXG59XHJcblxyXG5leHBvcnQgY29uc3Qgc2F2ZURhdGUgPSAoZGF0ZTogc3RyaW5nKTogbnVtYmVyID0+IHtcclxuICAgcmV0dXJuIG5ldyBEYXRlKGRhdGUpLmdldE1pbGxpc2Vjb25kcygpO1xyXG59XHJcblxyXG5cclxuLy9SZWZlcmVuY2U6IGh0dHBzOi8vc3RhY2tvdmVyZmxvdy5jb20vcXVlc3Rpb25zLzYxOTUzMzUvbGluZWFyLXJlZ3Jlc3Npb24taW4tamF2YXNjcmlwdFxyXG4vLyBleHBvcnQgY29uc3QgbGluZWFyUmVncmVzc2lvbiA9ICh5VmFsdWVzOiBudW1iZXJbXSwgeFZhbHVlczogbnVtYmVyW10pID0+e1xyXG4vLyAgIGRlYnVnZ2VyO1xyXG4vLyAgIGNvbnN0IHkgPSB5VmFsdWVzO1xyXG4vLyAgIGNvbnN0IHggPSB4VmFsdWVzO1xyXG5cclxuLy8gICB2YXIgbHIgPSB7c2xvcGU6IE5hTiwgaW50ZXJjZXB0OiBOYU4sIHIyOiBOYU59O1xyXG4vLyAgIHZhciBuID0geS5sZW5ndGg7XHJcbi8vICAgdmFyIHN1bV94ID0gMDtcclxuLy8gICB2YXIgc3VtX3kgPSAwO1xyXG4vLyAgIHZhciBzdW1feHkgPSAwO1xyXG4vLyAgIHZhciBzdW1feHggPSAwO1xyXG4vLyAgIHZhciBzdW1feXkgPSAwO1xyXG5cclxuLy8gICBmb3IgKHZhciBpID0gMDsgaSA8IHkubGVuZ3RoOyBpKyspIHtcclxuXHJcbi8vICAgICAgIHN1bV94ICs9IHhbaV07XHJcbi8vICAgICAgIHN1bV95ICs9IHlbaV07XHJcbi8vICAgICAgIHN1bV94eSArPSAoeFtpXSp5W2ldKTtcclxuLy8gICAgICAgc3VtX3h4ICs9ICh4W2ldKnhbaV0pO1xyXG4vLyAgICAgICBzdW1feXkgKz0gKHlbaV0qeVtpXSk7XHJcbi8vICAgfSBcclxuXHJcbi8vICAgbHIuc2xvcGUgPSAobiAqIHN1bV94eSAtIHN1bV94ICogc3VtX3kpIC8gKG4qc3VtX3h4IC0gc3VtX3ggKiBzdW1feCk7XHJcbi8vICAgbHIuaW50ZXJjZXB0ID0gKHN1bV95IC0gbHIuc2xvcGUgKiBzdW1feCkvbjtcclxuLy8gICBsci5yMiA9IE1hdGgucG93KChuKnN1bV94eSAtIHN1bV94KnN1bV95KS9NYXRoLnNxcnQoKG4qc3VtX3h4LXN1bV94KnN1bV94KSoobipzdW1feXktc3VtX3kqc3VtX3kpKSwyKTtcclxuLy8gICByZXR1cm4gbHI7XHJcbi8vIH1cclxuXHJcblN0cmluZy5wcm90b3R5cGUudG9UaXRsZUNhc2UgPSBmdW5jdGlvbiAoKSB7XHJcbiAgcmV0dXJuIHRoaXMucmVwbGFjZSgvXFx3XFxTKi9nLCBmdW5jdGlvbih0eHQpe3JldHVybiB0eHQuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyB0eHQuc3Vic3RyKDEpLnRvTG93ZXJDYXNlKCk7fSk7XHJcbn07XHJcblxyXG5BcnJheS5wcm90b3R5cGUub3JkZXJCeSA9IGZ1bmN0aW9uPFQ+KHByb3AsIHJldmVyc2UpIHtcclxuICByZXR1cm4gdGhpcy5zb3J0KChhOlQsIGI6VCkgPT4ge1xyXG4gICAgaWYoYVtwcm9wXSA+IGJbcHJvcF0pe1xyXG4gICAgICByZXR1cm4gcmV2ZXJzZSA/IC0xIDogMVxyXG4gICAgfVxyXG4gICAgaWYoYVtwcm9wXSA8IGJbcHJvcF0pe1xyXG4gICAgICByZXR1cm4gcmV2ZXJzZSA/IDEgOiAtMVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIDA7XHJcbiAgfSk7XHJcbn1cclxuXHJcbkFycmF5LnByb3RvdHlwZS5ncm91cEJ5ID0gZnVuY3Rpb24oa2V5KSB7XHJcbiAgcmV0dXJuIHRoaXMucmVkdWNlKGZ1bmN0aW9uKHJ2LCB4KSB7XHJcbiAgICAocnZbeFtrZXldXSA9IHJ2W3hba2V5XV0gfHwgW10pLnB1c2goeCk7XHJcbiAgICByZXR1cm4gcnY7XHJcbiAgfSwge30pO1xyXG59O1xyXG4iLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV9hcmNnaXNfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV9jb3JlX187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX3JlYWN0X187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX2ppbXVfdWlfXzsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdKG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiLy8gZGVmaW5lIGdldHRlciBmdW5jdGlvbnMgZm9yIGhhcm1vbnkgZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5kID0gKGV4cG9ydHMsIGRlZmluaXRpb24pID0+IHtcblx0Zm9yKHZhciBrZXkgaW4gZGVmaW5pdGlvbikge1xuXHRcdGlmKF9fd2VicGFja19yZXF1aXJlX18ubyhkZWZpbml0aW9uLCBrZXkpICYmICFfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZXhwb3J0cywga2V5KSkge1xuXHRcdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIGtleSwgeyBlbnVtZXJhYmxlOiB0cnVlLCBnZXQ6IGRlZmluaXRpb25ba2V5XSB9KTtcblx0XHR9XG5cdH1cbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5vID0gKG9iaiwgcHJvcCkgPT4gKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIHByb3ApKSIsIi8vIGRlZmluZSBfX2VzTW9kdWxlIG9uIGV4cG9ydHNcbl9fd2VicGFja19yZXF1aXJlX18uciA9IChleHBvcnRzKSA9PiB7XG5cdGlmKHR5cGVvZiBTeW1ib2wgIT09ICd1bmRlZmluZWQnICYmIFN5bWJvbC50b1N0cmluZ1RhZykge1xuXHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBTeW1ib2wudG9TdHJpbmdUYWcsIHsgdmFsdWU6ICdNb2R1bGUnIH0pO1xuXHR9XG5cdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCAnX19lc01vZHVsZScsIHsgdmFsdWU6IHRydWUgfSk7XG59OyIsIl9fd2VicGFja19yZXF1aXJlX18ucCA9IFwiXCI7IiwiLyoqXHJcbiAqIFdlYnBhY2sgd2lsbCByZXBsYWNlIF9fd2VicGFja19wdWJsaWNfcGF0aF9fIHdpdGggX193ZWJwYWNrX3JlcXVpcmVfXy5wIHRvIHNldCB0aGUgcHVibGljIHBhdGggZHluYW1pY2FsbHkuXHJcbiAqIFRoZSByZWFzb24gd2h5IHdlIGNhbid0IHNldCB0aGUgcHVibGljUGF0aCBpbiB3ZWJwYWNrIGNvbmZpZyBpczogd2UgY2hhbmdlIHRoZSBwdWJsaWNQYXRoIHdoZW4gZG93bmxvYWQuXHJcbiAqICovXHJcbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZVxyXG4vLyBAdHMtaWdub3JlXHJcbl9fd2VicGFja19wdWJsaWNfcGF0aF9fID0gd2luZG93LmppbXVDb25maWcuYmFzZVVybFxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgQWxsV2lkZ2V0UHJvcHMsIFJlYWN0UmVkdXggfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IElNQ29uZmlnIH0gZnJvbSAnLi4vY29uZmlnJ1xyXG5pbXBvcnQgeyBMYWJlbCB9IGZyb20gJ2ppbXUtdWknO1xyXG5pbXBvcnQgeyBBc3Nlc3NtZW50LCBMaWZlbGluZVN0YXR1cyB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9ucyc7XHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSAnLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlJztcclxuaW1wb3J0IHsgZGlzcGF0Y2hBY3Rpb24gfSBmcm9tICcuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaSc7XHJcbmNvbnN0IHsgdXNlU2VsZWN0b3IgfSA9IFJlYWN0UmVkdXg7XHJcblxyXG5mdW5jdGlvbiB1c2VXaW5kb3dTaXplKCkge1xyXG4gIGNvbnN0IFtzaXplLCBzZXRTaXplXSA9IFJlYWN0LnVzZVN0YXRlKFswLCAwXSk7XHJcbiAgUmVhY3QudXNlTGF5b3V0RWZmZWN0KCgpID0+IHtcclxuICAgIGZ1bmN0aW9uIHVwZGF0ZVNpemUoKSB7XHJcbiAgICAgIHNldFNpemUoW3dpbmRvdy5pbm5lcldpZHRoLCB3aW5kb3cuaW5uZXJIZWlnaHRdKTtcclxuICAgIH1cclxuICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdyZXNpemUnLCB1cGRhdGVTaXplKTtcclxuICAgIHVwZGF0ZVNpemUoKTtcclxuICAgIHJldHVybiAoKSA9PiB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcigncmVzaXplJywgdXBkYXRlU2l6ZSk7XHJcbiAgfSwgW10pO1xyXG4gIHJldHVybiBzaXplO1xyXG59XHJcblxyXG5jb25zdCBXaWRnZXQgPSAocHJvcHM6IEFsbFdpZGdldFByb3BzPElNQ29uZmlnPikgPT4ge1xyXG4gIC8vIGNvbnN0IFt3aWR0aCwgaGVpZ2h0XSA9IHVzZVdpbmRvd1NpemUoKTtcclxuICBjb25zdCBbbGlmZWxpbmVTdGF0dXNlcywgc2V0TGlmZWxpbmVTdGF0dXNlc10gPSBSZWFjdC51c2VTdGF0ZTxMaWZlbGluZVN0YXR1c1tdPihbXSk7XHJcbiAgY29uc3QgW3NlbGVjdGVkTGlmZWxpbmVTdGF0dXMsIHNldFNlbGVjdGVkTGlmZWxpbmVTdGF0dXNdID0gUmVhY3QudXNlU3RhdGU8TGlmZWxpbmVTdGF0dXM+KG51bGwpXHJcblxyXG4gIGNvbnN0IHNlbGVjdGVkQXNzZXNzbWVudCA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KT0+IHtcclxuICAgIGlmKHN0YXRlLmNsc3NTdGF0ZT8uYXNzZXNzbWVudHMgJiYgc3RhdGUuY2xzc1N0YXRlPy5hc3Nlc3NtZW50cy5sZW5ndGggPiAwKXsgICAgIFxyXG4gICAgICByZXR1cm4gKHN0YXRlLmNsc3NTdGF0ZT8uYXNzZXNzbWVudHMgYXMgQXNzZXNzbWVudFtdKT8uZmluZChhID0+IGEuaXNTZWxlY3RlZClcclxuICAgIH1cclxuICB9KVxyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgIGlmKHNlbGVjdGVkQXNzZXNzbWVudCl7ICAgICBcclxuICAgICAgc2V0TGlmZWxpbmVTdGF0dXNlcygoc2VsZWN0ZWRBc3Nlc3NtZW50Py5saWZlbGluZVN0YXR1c2VzIGFzIGFueSkub3JkZXJCeSgnbGlmZWxpbmVOYW1lJykpO1xyXG4gICAgfVxyXG4gIH0sIFtzZWxlY3RlZEFzc2Vzc21lbnRdKVxyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgIGlmKGxpZmVsaW5lU3RhdHVzZXMpe1xyXG4gICAgICBzZWxlY3RMaWZlbGluZVN0YXR1cyhsaWZlbGluZVN0YXR1c2VzWzBdKTtcclxuICAgIH1cclxuICB9LCBbbGlmZWxpbmVTdGF0dXNlc10pXHJcblxyXG4gIGNvbnN0IHNlbGVjdExpZmVsaW5lU3RhdHVzID0gKGxpZmVsaW5lU3RhdHVzOiBMaWZlbGluZVN0YXR1cykgPT57XHJcbiAgICBzZXRTZWxlY3RlZExpZmVsaW5lU3RhdHVzKGxpZmVsaW5lU3RhdHVzKTtcclxuICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFTEVDVF9MSUZFTElORVNUQVRVU19BQ1RJT04sIGxpZmVsaW5lU3RhdHVzKTtcclxuICB9XHJcblxyXG4gIGlmKCFsaWZlbGluZVN0YXR1c2VzIHx8IGxpZmVsaW5lU3RhdHVzZXMubGVuZ3RoID09IDApeyAgIFxyXG4gICAgcmV0dXJuIDxoNSBzdHlsZT17e3Bvc2l0aW9uOiAnYWJzb2x1dGUnLCBsZWZ0OiAnNDAlJywgdG9wOiAnNTAlJ319Pk5vIERhdGE8L2g1PlxyXG4gIH1cclxuICByZXR1cm4gKFxyXG4gICAgPGRpdiBjbGFzc05hbWU9XCJ3aWRnZXQtc2VsZWN0LWxpZmVsaW5lcyBqaW11LXdpZGdldFwiPlxyXG4gICAgICA8c3R5bGU+XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgIGBcclxuICAgICAgICAgICAgLndpZGdldC1zZWxlY3QtbGlmZWxpbmVze1xyXG4gICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgIGhlaWdodDogMTAwJTtcclxuICAgICAgICAgICAgICBwYWRkaW5nOiAxMHB4O1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5zZWxlY3QtbGlmZWxpbmUtY29udGFpbmVye1xyXG4gICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgaGVpZ2h0OiAxMDAlO1xyXG4gICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uO1xyXG4gICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgICBib3JkZXItcmFkaXVzOiAxMHB4O1xyXG4gICAgICAgICAgICAgICBvdmVyZmxvdy15OiBhdXRvO1xyXG4gICAgICAgICAgICAgICBvdmVyZmxvdy14OiBoaWRkZW47XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLmxpZmVsaW5lcy1oZWFkZXJ7XHJcbiAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjtcclxuICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgIHBhZGRpbmc6IDEwcHggMDtcclxuICAgICAgICAgICAgICBmb250LXNpemU6IDEuMnJlbTtcclxuICAgICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDsgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgIGJvcmRlci1yYWRpdXM6IDEwcHggMTBweCAwIDA7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLmxpZmVsaW5le1xyXG4gICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjsgICAgICAgICAgICBcclxuICAgICAgICAgICAgICB0ZXh0LWFsaWduOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgZm9udC1zaXplOiAyLjVlbTtcclxuICAgICAgICAgICAgICBwYWRkaW5nOiAwLjJlbSAwXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLmxpZmVsaW5lOmhvdmVye1xyXG4gICAgICAgICAgICAgIG9wYWNpdHk6IDAuNTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAubGlmZWxpbmUgbGFiZWx7XHJcbiAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIC5iYWNrLXRlbXBsYXRlcy1idXR0b257ICAgIFxyXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTtcclxuICAgICAgICAgICAgICBib3R0b206IDEwcHg7XHJcbiAgICAgICAgICAgICAgbGVmdDogMDsgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgIGhlaWdodDogNjVweDtcclxuICAgICAgICAgICAgICB3aWR0aDogODUlO1xyXG4gICAgICAgICAgICAgIGZvbnQtd2VpZ2h0OiBib2xkO1xyXG4gICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS41ZW07XHJcbiAgICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogNXB4O1xyXG4gICAgICAgICAgICAgIGxpbmUtaGVpZ2h0OiAxLjVlbTtcclxuICAgICAgICAgICAgICBtYXJnaW46IDEwcHggMThweCAxMHB4IDE4cHg7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLmJhY2stdGVtcGxhdGVzLWJ1dHRvbjpob3ZlcntcclxuICAgICAgICAgICAgICAgb3BhY2l0eTogMC44XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLnNlbGVjdGVkLWFzc2Vzc21lbnR7XHJcbiAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uO1xyXG4gICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgbWFyZ2luLXRvcDogNWVtO1xyXG4gICAgICAgICAgICAgIGNvbG9yOiAjOWE5YTlhO1xyXG4gICAgICAgICAgICAgIGJvcmRlci10b3A6IDFweCBzb2xpZDtcclxuICAgICAgICAgICAgICBwYWRkaW5nLXRvcDogMjBweDtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAuc2VsZWN0ZWQtYXNzZXNzbWVudCBoMixcclxuICAgICAgICAgICAgLnNlbGVjdGVkLWFzc2Vzc21lbnQgaDMsXHJcbiAgICAgICAgICAgIC5zZWxlY3RlZC1hc3Nlc3NtZW50LXRvcCBoMixcclxuICAgICAgICAgICAgLnNlbGVjdGVkLWFzc2Vzc21lbnQtdG9wIGgzIHtcclxuICAgICAgICAgICAgICBjb2xvcjogIzlhOWE5YTtcclxuICAgICAgICAgICAgICBtYXJnaW46IDA7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgLnNlbGVjdGVkLWFzc2Vzc21lbnQtdG9we1xyXG4gICAgICAgICAgICAgIGNvbG9yOiAjOWE5YTlhO1xyXG4gICAgICAgICAgICAgIG1hcmdpbjogMDtcclxuICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47XHJcbiAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjsgICBcclxuICAgICAgICAgICAgICBib3JkZXItYm90dG9tOiAxcHggc29saWQ7XHJcbiAgICAgICAgICAgICAgcGFkZGluZy10b3A6IDIwcHg7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICBgXHJcbiAgICAgICAgfVxyXG4gICAgICA8L3N0eWxlPlxyXG4gICAgICA8ZGl2IGNsYXNzTmFtZT1cInNlbGVjdC1saWZlbGluZS1jb250YWluZXJcIiBzdHlsZT17e1xyXG4gICAgICAgIGJhY2tncm91bmRDb2xvcjogIHByb3BzLmNvbmZpZy5iYWNrZ3JvdW5kQ29sb3J9fT5cclxuICAgICAgICBcclxuICAgICAgICA8TGFiZWwgY2hlY2sgY2xhc3NOYW1lPSdsaWZlbGluZXMtaGVhZGVyJ1xyXG4gICAgICAgICAgc3R5bGU9e3tiYWNrZ3JvdW5kQ29sb3I6IHByb3BzLmNvbmZpZy5iYWNrZ3JvdW5kQ29sb3IsXHJcbiAgICAgICAgICBjb2xvcjogcHJvcHMuY29uZmlnLmZvbnRDb2xvcn19PlxyXG4gICAgICAgICAgIEFzc2Vzc21lbnRcclxuICAgICAgICA8L0xhYmVsPlxyXG4gICAgICAgIDxoMiBzdHlsZT17e1xyXG4gICAgICAgICAgY29sb3I6ICdyZ2IoMTM5LCAxMzksIDEzOSknLFxyXG4gICAgICAgICAgbWFyZ2luVG9wOiAnLTE1cHgnLFxyXG4gICAgICAgICAgZm9udFNpemU6ICcyMXB4J1xyXG4gICAgICAgICAgfX0+e3NlbGVjdGVkQXNzZXNzbWVudD8ubmFtZX08L2gyPlxyXG5cclxuICAgICAgICB7LyogPExhYmVsIGNoZWNrIGNsYXNzTmFtZT0nbGlmZWxpbmVzLWhlYWRlcidcclxuICAgICAgICAgIHN0eWxlPXt7YmFja2dyb3VuZENvbG9yOiBwcm9wcy5jb25maWcuYmFja2dyb3VuZENvbG9yLFxyXG4gICAgICAgICAgY29sb3I6IHByb3BzLmNvbmZpZy5mb250Q29sb3IsXHJcbiAgICAgICAgICBtYXJnaW5Ub3A6ICctMTVweCd9fT5cclxuICAgICAgICAgICBBc3Nlc3NtZW50IFN0YXR1c1xyXG4gICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgPGgyIHN0eWxlPXt7XHJcbiAgICAgICAgICBjb2xvcjogJ3JnYigxMzksIDEzOSwgMTM5KScsXHJcbiAgICAgICAgICBtYXJnaW5Ub3A6ICctMTVweCcsXHJcbiAgICAgICAgICBmb250U2l6ZTogJzIxcHgnLCAgICAgICAgICAgXHJcbiAgICAgICAgICB9fT57c2VsZWN0ZWRBc3Nlc3NtZW50Py5pc0NvbXBsZXRlZCA/ICdDb21wbGV0ZWQnOiAnSW4gUHJvZ3Jlc3MnfTwvaDI+ICovfVxyXG5cclxuICAgICAgICA8TGFiZWwgY2hlY2sgY2xhc3NOYW1lPSdsaWZlbGluZXMtaGVhZGVyJ1xyXG4gICAgICAgICAgc3R5bGU9e3tiYWNrZ3JvdW5kQ29sb3I6IHByb3BzLmNvbmZpZy5iYWNrZ3JvdW5kQ29sb3IsXHJcbiAgICAgICAgICBjb2xvcjogcHJvcHMuY29uZmlnLmZvbnRDb2xvciwgYm9yZGVyVG9wOiAnMXB4IHNvbGlkIHdoaXRlJ319PlxyXG4gICAgICAgICAgIExpZmVsaW5lc1xyXG4gICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgbGlmZWxpbmVTdGF0dXNlcz8ubWFwKChsaWZlbGluZVN0YXR1czogTGlmZWxpbmVTdGF0dXMpID0+IHtcclxuICAgICAgICAgICAgcmV0dXJuIChcclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPSdsaWZlbGluZScga2V5PXtsaWZlbGluZVN0YXR1cy5pZH0gc3R5bGU9e3tcclxuICAgICAgICAgICAgICAgIGJhY2tncm91bmRDb2xvcjogc2VsZWN0ZWRMaWZlbGluZVN0YXR1cz8uaWQgPT09IGxpZmVsaW5lU3RhdHVzLmlkID8gcHJvcHMuY29uZmlnLnNlbGVjdGVkQmFja2dyb3VuZENvbG9yIDogJ3RyYW5zcGFyZW50J1xyXG4gICAgICAgICAgICAgICAgfX0gb25DbGljaz17KCkgPT4gc2VsZWN0TGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXMpfT5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgc2l6ZT0nbGcnIHN0eWxlPXt7Y29sb3I6IHByb3BzLmNvbmZpZy5mb250Q29sb3J9fT5cclxuICAgICAgICAgICAgICAgICAgICAgIHtsaWZlbGluZVN0YXR1cy5saWZlbGluZU5hbWV9XHJcbiAgICAgICAgICAgICAgICAgICAgPC9MYWJlbD5cclxuICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICApXHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgIH0gICAgICAgICAgICAgIFxyXG4gICAgICA8L2Rpdj4gICAgIFxyXG4gICAgPC9kaXY+XHJcbiAgKVxyXG59XHJcbmV4cG9ydCBkZWZhdWx0IFdpZGdldFxyXG4iXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=