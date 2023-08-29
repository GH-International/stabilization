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

/***/ "./jimu-icons/svg/filled/application/check.svg":
/*!*****************************************************!*\
  !*** ./jimu-icons/svg/filled/application/check.svg ***!
  \*****************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M16 2.443 5.851 14 0 8.115l1.45-1.538 4.31 4.334L14.463 1 16 2.443Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/filled/editor/close-circle.svg":
/*!*******************************************************!*\
  !*** ./jimu-icons/svg/filled/editor/close-circle.svg ***!
  \*******************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0Zm-5.737-3.394a.8.8 0 0 1 1.131 1.131L9.132 8l2.262 2.263a.8.8 0 0 1-1.131 1.131L8 9.131l-2.263 2.263a.8.8 0 0 1-1.13-1.131L6.868 8 4.606 5.737a.8.8 0 1 1 1.131-1.131L8 6.869l2.263-2.263Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/filled/editor/edit.svg":
/*!***********************************************!*\
  !*** ./jimu-icons/svg/filled/editor/edit.svg ***!
  \***********************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M9.795 1.282c.387-.387 1.028-.374 1.431.03l1.462 1.462c.404.403.417 1.044.03 1.431L5.413 11.51l-2.674.48a.637.637 0 0 1-.73-.73l.48-2.673 7.306-7.305ZM2 13a1 1 0 1 0 0 2h12a1 1 0 1 0 0-2H2Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/filled/editor/save.svg":
/*!***********************************************!*\
  !*** ./jimu-icons/svg/filled/editor/save.svg ***!
  \***********************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M1 3a2 2 0 0 1 2-2h8.086a1 1 0 0 1 .707.293l2.914 2.914a1 1 0 0 1 .293.707V13a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V3Zm1.75.75a1 1 0 0 1 1-1h5.875a1 1 0 0 1 1 1v1.5a1 1 0 0 1-1 1H3.75a1 1 0 0 1-1-1v-1.5Zm7.875 6.875a2.625 2.625 0 1 1-5.25 0 2.625 2.625 0 0 1 5.25 0Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/filled/suggested/help.svg":
/*!**************************************************!*\
  !*** ./jimu-icons/svg/filled/suggested/help.svg ***!
  \**************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M1 8c0-3.85 3.15-7 7-7s7 3.15 7 7-3.15 7-7 7-7-3.15-7-7Zm7.875 4.375a.875.875 0 1 1-1.75 0 .875.875 0 0 1 1.75 0Zm-.063-2.656c.132-.571.415-.916.848-1.299.433-.383.701-.709.701-.709.39-.472.701-1.102.701-1.811 0-1.732-1.402-3.15-3.117-3.15-1.357 0-2.52.928-2.946 2.157-.06.152-.06.299-.06.299a.648.648 0 0 0 .668.694l.1-.006c.4-.046.679-.275.829-.65.078-.164.108-.208.122-.229.281-.416.754-.69 1.287-.69.858 0 1.559.709 1.559 1.575 0 .472-.156.866-.468 1.103l-.935 1.023c-.505.447-.806 1.049-.901 1.722a.614.614 0 0 0-.005.064v.117a.748.748 0 0 0 .75.696l.092-.005c.393-.043.714-.358.743-.74l.032-.161Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/close.svg":
/*!**************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/close.svg ***!
  \**************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"m8.745 8 6.1 6.1a.527.527 0 1 1-.745.746L8 8.746l-6.1 6.1a.527.527 0 1 1-.746-.746l6.1-6.1-6.1-6.1a.527.527 0 0 1 .746-.746l6.1 6.1 6.1-6.1a.527.527 0 0 1 .746.746L8.746 8Z\" fill=\"#000\"></path></svg>"

/***/ }),

/***/ "./jimu-icons/svg/outlined/editor/edit.svg":
/*!*************************************************!*\
  !*** ./jimu-icons/svg/outlined/editor/edit.svg ***!
  \*************************************************/
/***/ ((module) => {

module.exports = "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path fill-rule=\"evenodd\" clip-rule=\"evenodd\" d=\"M11.226 1.312c-.403-.404-1.044-.417-1.431-.03L2.49 8.587l-.48 2.674a.637.637 0 0 0 .73.73l2.673-.48 7.305-7.306c.387-.387.374-1.028-.03-1.431l-1.462-1.462Zm-8.113 9.575.32-1.781 4.991-4.992 1.462 1.462-4.992 4.991-1.781.32Zm7.473-6.012 1.402-1.4-1.462-1.463-1.401 1.402 1.461 1.461Z\" fill=\"#000\"></path><path d=\"M1.5 14a.5.5 0 0 0 0 1h13a.5.5 0 0 0 0-1h-13Z\" fill=\"#000\"></path></svg>"

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

/***/ "./jimu-icons/filled/application/check.tsx":
/*!*************************************************!*\
  !*** ./jimu-icons/filled/application/check.tsx ***!
  \*************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CheckFilled": () => (/* binding */ CheckFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_application_check_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/application/check.svg */ "./jimu-icons/svg/filled/application/check.svg");
/* harmony import */ var _svg_filled_application_check_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_application_check_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const CheckFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_application_check_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/filled/editor/close-circle.tsx":
/*!***************************************************!*\
  !*** ./jimu-icons/filled/editor/close-circle.tsx ***!
  \***************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CloseCircleFilled": () => (/* binding */ CloseCircleFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_editor_close_circle_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/editor/close-circle.svg */ "./jimu-icons/svg/filled/editor/close-circle.svg");
/* harmony import */ var _svg_filled_editor_close_circle_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_editor_close_circle_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const CloseCircleFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_editor_close_circle_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/filled/editor/edit.tsx":
/*!*******************************************!*\
  !*** ./jimu-icons/filled/editor/edit.tsx ***!
  \*******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "EditFilled": () => (/* binding */ EditFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/editor/edit.svg */ "./jimu-icons/svg/filled/editor/edit.svg");
/* harmony import */ var _svg_filled_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const EditFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/filled/editor/save.tsx":
/*!*******************************************!*\
  !*** ./jimu-icons/filled/editor/save.tsx ***!
  \*******************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SaveFilled": () => (/* binding */ SaveFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_editor_save_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/editor/save.svg */ "./jimu-icons/svg/filled/editor/save.svg");
/* harmony import */ var _svg_filled_editor_save_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_editor_save_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const SaveFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_editor_save_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/filled/suggested/help.tsx":
/*!**********************************************!*\
  !*** ./jimu-icons/filled/suggested/help.tsx ***!
  \**********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "HelpFilled": () => (/* binding */ HelpFilled)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_filled_suggested_help_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/filled/suggested/help.svg */ "./jimu-icons/svg/filled/suggested/help.svg");
/* harmony import */ var _svg_filled_suggested_help_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_filled_suggested_help_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const HelpFilled = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_filled_suggested_help_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/editor/close.tsx":
/*!**********************************************!*\
  !*** ./jimu-icons/outlined/editor/close.tsx ***!
  \**********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CloseOutlined": () => (/* binding */ CloseOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_editor_close_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/editor/close.svg */ "./jimu-icons/svg/outlined/editor/close.svg");
/* harmony import */ var _svg_outlined_editor_close_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_editor_close_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const CloseOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_editor_close_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
};


/***/ }),

/***/ "./jimu-icons/outlined/editor/edit.tsx":
/*!*********************************************!*\
  !*** ./jimu-icons/outlined/editor/edit.tsx ***!
  \*********************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "EditOutlined": () => (/* binding */ EditOutlined)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _svg_outlined_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../svg/outlined/editor/edit.svg */ "./jimu-icons/svg/outlined/editor/edit.svg");
/* harmony import */ var _svg_outlined_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_svg_outlined_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1__);
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


const EditOutlined = (props) => {
    const SVG = window.SVG;
    const { className } = props, others = __rest(props, ["className"]);
    const classes = (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.classNames)('jimu-icon jimu-icon-component', className);
    if (!SVG)
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("svg", Object.assign({ className: classes }, others));
    return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(SVG, Object.assign({ className: classes, src: (_svg_outlined_editor_edit_svg__WEBPACK_IMPORTED_MODULE_1___default()) }, others));
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
/* harmony export */   "ANALYSIS_REPORTING_URL": () => (/* binding */ ANALYSIS_REPORTING_URL),
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
/* harmony export */   "DATA_LIBRARY_URL": () => (/* binding */ DATA_LIBRARY_URL),
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
const DATA_LIBRARY_URL = 'https://experience.arcgis.com/experience/f961191cd2514abf8e43486c6ffbf18b';
const ANALYSIS_REPORTING_URL = 'https://experience.arcgis.com/experience/8a760a7391254530b2cc9c9952e7aadd';


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

/***/ "./your-extensions/widgets/clss-custom-components/clss-assessments-list.tsx":
/*!**********************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-assessments-list.tsx ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "TemplateAssessmentView": () => (/* binding */ TemplateAssessmentView)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var _clss_modal__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./clss-modal */ "./your-extensions/widgets/clss-custom-components/clss-modal.tsx");


const TemplateAssessmentView = ({ assessments, toggle, isVisible }) => {
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_modal__WEBPACK_IMPORTED_MODULE_1__.ClssModal, { title: "Assessments created with this template", toggleVisibility: toggle, visible: isVisible, hideFooter: true },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", null,
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("style", null, `
                     .assessment-list tr:nth-child(2n+2){
                        background:#efefef;
                     }       
                     .assessment-list td{
                         line-height: 50px;
                     }     
                    `),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("table", { className: "assessment-list", style: { width: '100%' } }, assessments === null || assessments === void 0 ? void 0 : assessments.map((a, i) => {
                return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                        i + 1 + ") ",
                        a.name,
                        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("span", { style: { color: 'gray', marginLeft: '.2em' } }, "   (" + a.date + ")"))));
            })))));
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

/***/ "./your-extensions/widgets/clss-custom-components/clss-error.tsx":
/*!***********************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-error.tsx ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");

const ClssError = ({ error }) => {
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("h2", { style: { color: 'red', fontSize: '15px' } }, error));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (ClssError);


/***/ }),

/***/ "./your-extensions/widgets/clss-custom-components/clss-errors-panel.tsx":
/*!******************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-errors-panel.tsx ***!
  \******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var jimu_icons_filled_editor_close_circle__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-icons/filled/editor/close-circle */ "./jimu-icons/filled/editor/close-circle.tsx");



//const use
const ClssErrorsPanel = ({ close, errors }) => {
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'jimu-widget widget-error-container' },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
          .widget-error-container{
            display: flex;
            justify-content: center;
            align-items: center;
            background-color: #ffc6cd;
            border: 1px solid red;
            box-shadow: 1px 1px 12px 4px #5d5c5c;
            padding: 10px 20px;
            border-radius: 0 10px 0 0;
          }     
          .close-button{
             position: absolute;
             top: 0;
             right: 0;
             color: red;
             cursor: pointer;
          }     
        `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_icons_filled_editor_close_circle__WEBPACK_IMPORTED_MODULE_2__.CloseCircleFilled, { className: 'close-button', "data-testid": "btnCloseError", size: 30, onClick: () => close(), style: { color: 'red' }, title: 'Close' }),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_1__.Label, { style: { color: '#a50000',
                fontSize: '20px' }, check: true, size: 'lg' }, errors)));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (ClssErrorsPanel);


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

/***/ "./your-extensions/widgets/clss-custom-components/clss-lifeline-component.tsx":
/*!************************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-lifeline-component.tsx ***!
  \************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "LifelineComponent": () => (/* binding */ LifelineComponent)
/* harmony export */ });
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-icons/outlined/editor/trash */ "./jimu-icons/outlined/editor/trash.tsx");
/* harmony import */ var jimu_icons_filled_editor_edit__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/filled/editor/edit */ "./jimu-icons/filled/editor/edit.tsx");
/* harmony import */ var jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-icons/filled/suggested/help */ "./jimu-icons/filled/suggested/help.tsx");
/* harmony import */ var jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! jimu-icons/outlined/editor/close */ "./jimu-icons/outlined/editor/close.tsx");
/* harmony import */ var _clss_loading__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");
/* harmony import */ var jimu_icons_filled_application_check__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! jimu-icons/filled/application/check */ "./jimu-icons/filled/application/check.tsx");
/* harmony import */ var _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../clss-application/src/extensions/constants */ "./your-extensions/widgets/clss-application/src/extensions/constants.ts");
/* harmony import */ var _clss_error__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./clss-error */ "./your-extensions/widgets/clss-custom-components/clss-error.tsx");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};













const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_10__.ReactRedux;
const TableRowCommand = ({ isInEditMode, onEdit, onDelete, onSave, onCancel, canSave }) => {
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "command-container" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `
                        .command-container{
                            display: flex;
                            justify-content: space-between;
                            align-items: center;
                        }
                        .command{
                            flex: 1
                        }
                        .edit-delete, .save-cancel{
                            display: flex;
                            align-items: center;
                            flex-wrap: nowrap;
                        }
                        `),
            isInEditMode ?
                (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "edit-delete" },
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_application_check__WEBPACK_IMPORTED_MODULE_7__.CheckFilled, { style: { pointerEvents: !canSave ? 'none' : 'all' }, size: 20, className: "command", title: "Save Edits", onClick: () => onSave() }),
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_5__.CloseOutlined, { size: 20, className: "command", title: "Cancel Edits", onClick: () => onCancel() })))
                : (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "edit-delete" },
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_editor_edit__WEBPACK_IMPORTED_MODULE_3__.EditFilled, { size: 20, className: "command", title: "Edit", onClick: () => onEdit() }),
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_outlined_editor_trash__WEBPACK_IMPORTED_MODULE_2__.TrashOutlined, { size: 20, className: "command", title: "Delete", onClick: () => onDelete() }))))));
};
const EditableTableRow = ({ indicator, isEditable, component, template, config, setError, onActionComplete, onCancel }) => {
    const [isEditing, setEditing] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(indicator.isBeingEdited);
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const [name, setName] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [rank, setRank] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [lifeSafety, setLifeSafety] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [incidentStab, setIncidentStab] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [propertyProt, setPropProt] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [envPres, setEnvPres] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState();
    const [canCommit, setCanCommit] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(true);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        var _a, _b, _c, _d, _e;
        if (indicator) {
            try {
                setName(indicator === null || indicator === void 0 ? void 0 : indicator.name);
                setRank((_a = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _a === void 0 ? void 0 : _a.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.RANK).weight);
                setLifeSafety((_b = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _b === void 0 ? void 0 : _b.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.LIFE_SAFETY).weight);
                setIncidentStab((_c = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _c === void 0 ? void 0 : _c.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.INCIDENT_STABILIZATION).weight);
                setPropProt((_d = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _d === void 0 ? void 0 : _d.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.PROPERTY_PROTECTION).weight);
                setEnvPres((_e = indicator === null || indicator === void 0 ? void 0 : indicator.weights) === null || _e === void 0 ? void 0 : _e.find(w => w.name === _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.ENVIRONMENT_PRESERVATION).weight);
            }
            catch (e) {
            }
        }
    }, [indicator]);
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setCanCommit(true);
        setError('');
        if (name) {
            const indicatorsNames = component.indicators.map(i => i.name.toLocaleLowerCase());
            if (indicator.isNew && indicatorsNames.includes(name.toLocaleLowerCase())) {
                setError(`Indicator: ${name} already exists`);
                setCanCommit(false);
                return;
            }
        }
    }, [name]);
    const getWeightByName = (w) => {
        switch (w.name) {
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.RANK:
                return rank;
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.LIFE_SAFETY:
                return lifeSafety;
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.INCIDENT_STABILIZATION:
                return incidentStab;
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.PROPERTY_PROTECTION:
                return propertyProt;
            case _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.ENVIRONMENT_PRESERVATION:
                return envPres;
        }
    };
    const onSaveEdits = () => __awaiter(void 0, void 0, void 0, function* () {
        setLoading(true);
        const updatedIndicator = Object.assign(Object.assign({}, indicator), { name: name, title: name, weights: indicator === null || indicator === void 0 ? void 0 : indicator.weights.map(w => {
                return Object.assign(Object.assign({}, w), { weight: getWeightByName(w) });
            }) });
        if (indicator.isNew) {
            const resp = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.createNewIndicator)(updatedIndicator, config, template.id, template.name);
            if (resp.errors) {
                setLoading(false);
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_12__.CLSSActionKeys.SET_ERRORS, resp.errors);
                return;
            }
        }
        else {
            const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.updateIndicator)(updatedIndicator, config);
            if (response.errors) {
                setLoading(false);
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_12__.CLSSActionKeys.SET_ERRORS, response.errors);
                return;
            }
        }
        setEditing(false);
        setLoading(false);
        onActionComplete(true);
    });
    const onCancelEdits = () => {
        setError('');
        setCanCommit(true);
        setEditing(false);
        onActionComplete(false);
        if (indicator.isNew) {
            onCancel();
        }
    };
    const onDeleteIndicator = () => __awaiter(void 0, void 0, void 0, function* () {
        if (confirm(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.DELETE_INDICATOR_CONFIRMATION) == true) {
            setLoading(true);
            const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.deleteIndicator)(indicator, config);
            if (response.errors) {
                (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_11__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_12__.CLSSActionKeys.SET_ERRORS, response.errors);
                return;
            }
            setLoading(false);
            onActionComplete(true);
        }
    });
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tr", { style: { position: 'relative' } },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `
                    .lifeline-component-table .indicator-name input {
                        font-size: 12px !important
                     }   
                     .jimu-numeric-input input{
                        min-width: 160px;
                     }                  
                    `),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data indicator-name", style: { textAlign: 'left' } }, isEditing ?
            (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("label", { style: { width: '100%' } },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.TextInput, { className: "indicator-name", title: name, value: name, onChange: (e) => setName(e.target.value), allowClear: true, type: "text" }))) :
            name),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, isEditing ?
            (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("label", null,
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.NumericInput, { max: 5, min: 1, onChange: (v) => setRank(v), value: rank }))) : rank),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, 'N/A'
        //    !isEditing ? (lifeSafety?.value): (<label><NumericInput onChange={onLifeSafetyChange} value={lifeSafety?.value}/></label>)
        ),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, 'N/A'
        //    !isEditing ? (incidentStab?.value): (<label><NumericInput onChange={onIncidentStabilizationChange} value={incidentStab?.value}/></label>)
        ),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, 'N/A'
        //    !isEditing ? (propertyProt?.value): (<label><NumericInput onChange={onPropertyProtectionChange} value={propertyProt?.value}/></label>)
        ),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }, 'N/A'
        //    !isEditing ? (envPres?.value): (<label><NumericInput onChange={onEnvironmentalPreservationChange} value={envPres?.value}/></label>)
        ),
        isEditable ?
            (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(TableRowCommand, { isInEditMode: isEditing, canSave: canCommit, onEdit: () => setEditing(true), onSave: onSaveEdits, onCancel: onCancelEdits, onDelete: onDeleteIndicator }))) : null,
        loading ? react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_loading__WEBPACK_IMPORTED_MODULE_6__["default"], null) : null));
};
const LifelineComponent = ({ lifeline, component, template, config, onActionComplete }) => {
    const [indicators, setIndicators] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState([]);
    const [error, setError] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState('');
    const [isEditable, setEditable] = react__WEBPACK_IMPORTED_MODULE_1__["default"].useState(false);
    const user = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.user;
    });
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        var _a, _b, _c;
        if (user) {
            if ((_a = user === null || user === void 0 ? void 0 : user.groups) === null || _a === void 0 ? void 0 : _a.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.CLSS_ADMIN)) {
                setEditable(true);
                return;
            }
            if (((_b = user === null || user === void 0 ? void 0 : user.groups) === null || _b === void 0 ? void 0 : _b.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.CLSS_EDITOR)) &&
                (template === null || template === void 0 ? void 0 : template.name) !== _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.BASELINE_TEMPLATE_NAME) {
                setEditable(true);
                return;
            }
            if (((_c = user === null || user === void 0 ? void 0 : user.groups) === null || _c === void 0 ? void 0 : _c.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.CLSS_FOLLOWERS)) &&
                (template === null || template === void 0 ? void 0 : template.name) !== _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.BASELINE_TEMPLATE_NAME) {
                setEditable(true);
                return;
            }
        }
        setEditable(false);
    }, [template, user]);
    // React.useEffect(() => {        
    //     if(user && template){
    //         if(!template.isActive){
    //            setEditable(false);
    //            return;
    //         }
    //         const isTemplateEditable = 
    //         (user?.groups?.includes(CLSS_ADMIN)) || 
    //         (template.name !== BASELINE_TEMPLATE_NAME && 
    //             user.groups?.includes(CLSS_EDITOR));
    //         setEditable(isTemplateEditable);
    //     }
    // }, [template, user])
    react__WEBPACK_IMPORTED_MODULE_1__["default"].useEffect(() => {
        setIndicators(component.indicators.orderBy('name'));
    }, [component]);
    const createNewIndicator = () => __awaiter(void 0, void 0, void 0, function* () {
        const weights = [
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.RANK,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.OTHER_WEIGHTS_SCALE_FACTOR,
                weight: 1
            },
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.LIFE_SAFETY,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.LIFE_SAFETY_SCALE_FACTOR,
                weight: 1
            },
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.PROPERTY_PROTECTION,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.OTHER_WEIGHTS_SCALE_FACTOR,
                weight: 1
            },
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.INCIDENT_STABILIZATION,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.OTHER_WEIGHTS_SCALE_FACTOR,
                weight: 1
            },
            {
                name: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.ENVIRONMENT_PRESERVATION,
                adjustedWeight: 0,
                indicatorId: '',
                scaleFactor: _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_8__.OTHER_WEIGHTS_SCALE_FACTOR,
                weight: 1
            }
        ];
        const existingIndicators = indicators || [];
        const newIndicator = {
            name: '',
            isBeingEdited: true,
            isNew: true,
            templateName: template.name,
            weights: weights,
            componentId: component.id,
            templateId: template.id,
            componentName: component.name,
            lifelineName: lifeline.name,
        };
        setIndicators([...existingIndicators, newIndicator]);
    });
    const onCancelIndicatorCreate = () => {
        setIndicators(indicators.filter(i => !i.isNew));
    };
    return (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "lifeline-component-container", style: {
            marginTop: isEditable ? '0.5em' : '1.8em'
        } },
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("style", null, `
               .lifeline-component-container{
                  display: flex;
                  flex-direction: column;
                  width: 100%;
                  margin-bottom: 0.5em;
               } 
               .component-label{
                font-size: 18px;
                color: #534c4c;
                font-weight: bold;
                padding: 0 0 0 1.2em;
                text-decoration: underline;
               }                     
               .component-details{
                 background-color: white;
                 width: 100%;
                 padding: 15px 0 0 0;
               }
               .lifeline-component-table{
                width: 100%;
               }    
               .lifeline-component-table .table-header-data{
                 display: flex;
                 width: 10em;
                 align-items: center;
                 flex-wrap:nowrap;
                 justify-content: center;
               } 
               .lifeline-component-table .table-header-data svg{
                 width: 40px;
               }         
               .lifeline-component-table .command{
                color: gray;
                cursor: pointer;
                width: 40px !important;
              }
              .lifeline-component-table td.data{
                font-size: 13px;               
                color: #534c4c;
                text-align: center;
                border-right: 1px solid white
              }
              .lifeline-component-table .tableBody td{
                color: #534c4c;
                text-align: center;
                font-size: 0.8rem;
                padding: .8em;
                font-weight: bold;
              }
              .lifeline-component-table .tableBody tr:nth-child(odd){
                background-color: #f0f0f0;
              }
              .add-new{
                text-align: right;
                margin: 10px 5px 0 0;
                font-weight: bold;
              }
              .add-new button{
                 font-weight: normal;
                 padding: 0.5em;
              }
              .table-header-data h6{
                margin: 0;
              }
            `),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Label, { check: true, className: "component-label" }, component.title),
        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "component-details" },
            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("table", { className: "lifeline-component-table table" },
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("thead", { style: { backgroundColor: '#c5c5c5' } },
                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tr", null,
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data", style: { width: '400px' } },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Indicator")),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Rank"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to your jurisdiction or hazard?(1=Most Important, 5=Least Important)" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Life Safety"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to Life Safety?" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Incident Stabilization"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to Incident Stabilization?" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Property Protection"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to Property Protection?" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" },
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "table-header-data" },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("h6", null, "Environmental Preservation"),
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_icons_filled_suggested_help__WEBPACK_IMPORTED_MODULE_4__.HelpFilled, { size: 20, title: "How important is the indicator to Environmental Preservation?" }))),
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { className: "data" }))),
                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tbody", { className: "tableBody" }, indicators.map((indicator) => {
                    return react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(EditableTableRow, { key: indicator.id, indicator: indicator, isEditable: isEditable, component: component, config: config, template: template, setError: setError, onCancel: onCancelIndicatorCreate, onActionComplete: onActionComplete });
                })),
                (!isEditable) ? null
                    : (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tfoot", null,
                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("tr", null,
                            react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("td", { colSpan: 8 },
                                react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement("div", { className: "add-new" },
                                    react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Button, { disabled: indicators === null || indicators === void 0 ? void 0 : indicators.some(i => i.isNew), onClick: () => createNewIndicator(), title: "Add new indicator", size: "default" },
                                        react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_0__.Icon, { icon: "<svg viewBox=\"0 0 16 16\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M7.5 0a.5.5 0 0 0-.5.5V7H.5a.5.5 0 0 0 0 1H7v6.5a.5.5 0 0 0 1 0V8h6.5a.5.5 0 0 0 0-1H8V.5a.5.5 0 0 0-.5-.5Z\" fill=\"#000\"></path></svg>", size: "m" }),
                                        "Add New Indicator"))))))),
            error ? (react__WEBPACK_IMPORTED_MODULE_1__["default"].createElement(_clss_error__WEBPACK_IMPORTED_MODULE_9__["default"], { error: error })) : null)));
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

/***/ "./your-extensions/widgets/clss-custom-components/clss-no-data.tsx":
/*!*************************************************************************!*\
  !*** ./your-extensions/widgets/clss-custom-components/clss-no-data.tsx ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");

const ClssNoData = ({ message }) => {
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { style: {
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
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("h3", null, message)));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (ClssNoData);


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

/***/ "./your-extensions/widgets/clss-template-detail/src/runtime/header.tsx":
/*!*****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-template-detail/src/runtime/header.tsx ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "DetailHeaderWidget": () => (/* binding */ DetailHeaderWidget)
/* harmony export */ });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "react");
/* harmony import */ var jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! jimu-icons/outlined/editor/close */ "./jimu-icons/outlined/editor/close.tsx");
/* harmony import */ var jimu_icons_outlined_editor_edit__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! jimu-icons/outlined/editor/edit */ "./jimu-icons/outlined/editor/edit.tsx");
/* harmony import */ var jimu_icons_filled_editor_save__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! jimu-icons/filled/editor/save */ "./jimu-icons/filled/editor/save.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../../../clss-custom-components/clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");
/* harmony import */ var _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../../../clss-application/src/extensions/constants */ "./your-extensions/widgets/clss-application/src/extensions/constants.ts");
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../../../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../../../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../clss-application/src/extensions/utils */ "./your-extensions/widgets/clss-application/src/extensions/utils.ts");
/* harmony import */ var _clss_custom_components_clss_dropdown__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../../../clss-custom-components/clss-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-dropdown.tsx");
/* harmony import */ var _clss_custom_components_clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ../../../clss-custom-components/clss-organizations-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-organizations-dropdown.tsx");
/* harmony import */ var _clss_custom_components_clss_hazards_dropdown__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! ../../../clss-custom-components/clss-hazards-dropdown */ "./your-extensions/widgets/clss-custom-components/clss-hazards-dropdown.tsx");
/* harmony import */ var _clss_custom_components_clss_assessments_list__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(/*! ../../../clss-custom-components/clss-assessments-list */ "./your-extensions/widgets/clss-custom-components/clss-assessments-list.tsx");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};















const { useSelector } = jimu_core__WEBPACK_IMPORTED_MODULE_7__.ReactRedux;
const DetailHeaderWidget = ({ template, config, organizations, hazards, onActionComplete, selectedNewHazard, selectedNewOrganization, toggleHazardModalVisibility, toggleOrganizationModalVisibility }) => {
    const [loading, setLoading] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(false);
    const [isEditing, setEditing] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(false);
    const [templateName, setTemplateName] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState('');
    const [selectedHazard, setSelectedHazard] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(null);
    const [selectedOrganization, setSelectedOrganization] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(null);
    const [allowToEdit, setAllowToEdit] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(false);
    const [status, setStatus] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState();
    const [statuses, setStatuses] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState([]);
    const [assessments, setAssessments] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState([]);
    const [isAssessmentsVisibility, setToggleAssessmentVisibility] = react__WEBPACK_IMPORTED_MODULE_0__["default"].useState(false);
    const user = useSelector((state) => {
        return state.clssState.user;
    });
    const templates = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.templates;
    });
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (selectedNewHazard) {
            setSelectedHazard(selectedNewHazard);
        }
    }, [selectedNewHazard]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (selectedNewOrganization) {
            setSelectedOrganization(selectedNewOrganization);
        }
    }, [selectedNewOrganization]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (config) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__.getAssessmentNames)(config, template === null || template === void 0 ? void 0 : template.name)
                .then((response) => {
                if (response.data) {
                    setAssessments(response.data);
                }
            });
        }
    }, [template]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (template) {
            const statusDomains = template.domains;
            setStatuses(statusDomains);
        }
    }, [template]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (template && statuses && statuses.length > 0) {
            const s = statuses.find(s => s.name === (template === null || template === void 0 ? void 0 : template.status.name));
            try {
                setStatus(s);
            }
            catch (e) {
                console.log(e);
            }
        }
    }, [template, statuses]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        var _a, _b, _c;
        if (user) {
            if ((_a = user === null || user === void 0 ? void 0 : user.groups) === null || _a === void 0 ? void 0 : _a.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.CLSS_ADMIN)) {
                setAllowToEdit(true);
                return;
            }
            if (((_b = user === null || user === void 0 ? void 0 : user.groups) === null || _b === void 0 ? void 0 : _b.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.CLSS_EDITOR)) &&
                (template === null || template === void 0 ? void 0 : template.name) !== _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.BASELINE_TEMPLATE_NAME) {
                setAllowToEdit(true);
                return;
            }
            if (((_c = user === null || user === void 0 ? void 0 : user.groups) === null || _c === void 0 ? void 0 : _c.includes(_clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.CLSS_FOLLOWERS)) &&
                (template === null || template === void 0 ? void 0 : template.name) !== _clss_application_src_extensions_constants__WEBPACK_IMPORTED_MODULE_6__.BASELINE_TEMPLATE_NAME) {
                setAllowToEdit(true);
                return;
            }
        }
        setAllowToEdit(false);
    }, [template, user]);
    react__WEBPACK_IMPORTED_MODULE_0__["default"].useEffect(() => {
        if (template) {
            setTemplateName(template === null || template === void 0 ? void 0 : template.name);
        }
    }, [template]);
    const onCancel = () => {
        setTemplateName(template.name);
        setSelectedHazard(hazards.find(h => h.name === template.hazardName));
        setSelectedOrganization(organizations.find(o => o.name === template.organizationName));
        setEditing(false);
        onActionComplete(false);
    };
    const getSelectedHazardData = () => {
        if (selectedHazard && selectedHazard.title !== '-None-') {
            return selectedHazard;
        }
    };
    const getSelectedOrgData = () => {
        if (selectedOrganization && selectedOrganization.title !== '-None-') {
            return selectedOrganization;
        }
    };
    const onSaveTemplateHeaderEdits = () => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        const _templates = templates.filter(t => t.id != template.id);
        if (_templates.some(t => t.name.toLowerCase() === templateName.toLowerCase().trim())) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_9__.CLSSActionKeys.SET_ERRORS, `Template: ${templateName} already exists`);
            return;
        }
        setLoading(true);
        const hazardData = getSelectedHazardData();
        const orgData = getSelectedOrgData();
        const updatedTemplate = Object.assign(Object.assign({}, template), { name: templateName, isSelected: template.isSelected, status: status, hazardId: hazardData ? hazardData.id : null, hazardName: hazardData ? hazardData.name : null, hazardType: hazardData ? (_a = hazardData.type) === null || _a === void 0 ? void 0 : _a.code : null, organizationType: orgData ? orgData.type : null, organizationName: orgData ? orgData.name : null, organizationId: orgData ? orgData.id : null });
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__.updateTemplateOrganizationAndHazard)(config, updatedTemplate, user.userName);
        setLoading(false);
        if (response.errors) {
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_8__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_9__.CLSSActionKeys.SET_ERRORS, response.errors);
            return;
        }
        setEditing(false);
        onActionComplete(true);
    });
    return (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: "details-content-header", style: {
            backgroundColor: config === null || config === void 0 ? void 0 : config.headerBackgroundColor
        } },
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("style", null, `      
                  .details-content-header{
                    display: flex;                    
                    flex-wrap: wrap;
                  }            
                  .editor-icon{                    
                    color: #534c4c;
                    cursor: pointer;
                    margin: 10px;
                  }
                  .details-content-header .editor-icon: hover{
                    opacity: .8
                  }
                  .details-content-header .save-cancel, 
                  .details-content-header .save-icon{
                    position: absolute;
                    right: 10px;
                    top: 10px;
                  }
                  .details-content-header .data-dropdown, 
                  .details-content-header .data-input{
                    width: 100%;
                    display: flex;
                    align-items: center;
                  }
                  .details-content-header .data-dropdown .jimu-dropdown{
                      width: 300px;
                  }
                  .details-content-header .data-dropdown-menu{
                    width: 300px;
                  }
                  .details-content-header .error{
                    color: red;
                    font-size: 15px;
                  }
                  .details-content-header .dropdown-item{
                      font-size: 1.3em;
                  }
                  .details-content-header .organization{
                    display: flex;
                    flex-direction: column;
                  }
                  .details-content-header .end-widget{
                      margin-bottom: 15px;
                  }
                  .details-content-header .data-input{
                      width: 30.7%
                  }
                  .details-content-header .title.template{
                    width: 142px;
                  }

                  .details-content-header td label,
                  .details-content-header td input{ 
                    font-size: 1.5em;
                  }
                  .details-content-header td label{
                    width: 165px;
                  }
                  .details-content-header td label.value{
                      font-weight: bold;
                      width: auto;
                  }
                  .details-content-header tr.td-under>td{
                    padding-bottom: 1em;
                  }
                  .details-content-header .template-input input{
                    padding-left: 10px;
                    height: 40px;
                    font-size: 16px;
                  }
                  .details-content-header .template-input span{
                      height: 40px !important;
                      width: 300px;
                  }
                  .action-icon {
                    color: gray;
                    cursor: pointer;
                  }
                `),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("table", { className: "template-detail-header-table", style: { marginRight: '10em' } },
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    " ",
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { check: true }, "Template Name: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.TextInput, { className: "template-input", onChange: (e) => setTemplateName(e.target.value), value: templateName })) :
                    (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true },
                        templateName,
                        " ")))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Organization: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: 'data-dropdown' },
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_organizations_dropdown__WEBPACK_IMPORTED_MODULE_12__.OrganizationsDropdown, { config: config, organizations: organizations, selectedOrganization: selectedOrganization, setOrganization: setSelectedOrganization, toggleNewOrganizationModal: toggleOrganizationModalVisibility, vertical: false }))) :
                    (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "txtOrganizationName", className: "value", check: true }, selectedOrganization ? selectedOrganization === null || selectedOrganization === void 0 ? void 0 : selectedOrganization.name : '-None-')))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    " ",
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Hazard: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: 'data-dropdown' },
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_hazards_dropdown__WEBPACK_IMPORTED_MODULE_13__.HazardsDropdown, { config: config, hazards: hazards, selectedHazard: selectedHazard, setHazard: setSelectedHazard, toggleNewHazardModal: toggleHazardModalVisibility, vertical: false }))) : (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "value", check: true }, selectedHazard && (selectedHazard === null || selectedHazard === void 0 ? void 0 : selectedHazard.title) !== '-None-' ? (selectedHazard.title + ` (${selectedHazard.type})`) : '-None-')))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Status: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: 'data-dropdown' },
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_dropdown__WEBPACK_IMPORTED_MODULE_11__.ClssDropdown, { items: statuses, item: status, menuWidth: '300px', deletable: false, setItem: setStatus }))) : (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "value", check: true }, status === null || status === void 0 ? void 0 : status.name))))),
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("table", { className: "template-detail-header-table" },
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    " ",
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { check: true }, "Author: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true }, template === null || template === void 0 ? void 0 :
                        template.creator,
                        " "))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Date Created: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true },
                        (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_10__.parseDate)(template === null || template === void 0 ? void 0 : template.createdDate),
                        " "))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Last Updated: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true },
                        (0,_clss_application_src_extensions_utils__WEBPACK_IMPORTED_MODULE_10__.parseDate)(template === null || template === void 0 ? void 0 : template.editedDate),
                        " ",
                        template.editor ? ' by ' + template.editor : '-'))),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("tr", { className: "td-under" },
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null,
                    " ",
                    react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { className: "title", check: true }, "Assessments: ")),
                react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("td", null, assessments && assessments.length > 0 ?
                    (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Button, { onClick: () => setToggleAssessmentVisibility(true), style: { fontSize: '1.5em',
                            padding: 0, fontWeight: 'bold' }, type: "link" },
                        "Click here to view the assessments (", assessments === null || assessments === void 0 ? void 0 :
                        assessments.length,
                        ")")) : react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_4__.Label, { "data-testid": "lblTemplateName", className: "value", check: true }, "-None-")))),
        allowToEdit && isEditing ? (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", { className: "save-cancel", style: { display: 'flex', flexDirection: 'column' } },
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_outlined_editor_close__WEBPACK_IMPORTED_MODULE_1__.CloseOutlined, { "data-testid": "btnCancelEdits", size: 25, className: 'editor-icon', style: { color: '#534c4c', fontWeight: 'bold' }, title: "Cancel Edits", onClick: () => onCancel() }),
            react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_filled_editor_save__WEBPACK_IMPORTED_MODULE_3__.SaveFilled, { size: 25, "data-testid": "btnSaveEdits", className: 'editor-icon', onClick: () => onSaveTemplateHeaderEdits(), style: { color: '#534c4c', fontWeight: 'bold' }, title: 'Save' }))) :
            (allowToEdit ?
                (react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(jimu_icons_outlined_editor_edit__WEBPACK_IMPORTED_MODULE_2__.EditOutlined, { "data-testid": "btnStartEditing", size: 30, className: 'editor-icon save-icon', onClick: () => setEditing(true), style: { color: '#534c4c' }, title: 'Edit' })) : null),
        (!template || loading) ? react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_5__["default"], null) : null,
        react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_clss_custom_components_clss_assessments_list__WEBPACK_IMPORTED_MODULE_14__.TemplateAssessmentView, { isVisible: isAssessmentsVisibility, toggle: setToggleAssessmentVisibility, assessments: assessments })));
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
/*!*****************************************************************************!*\
  !*** ./your-extensions/widgets/clss-template-detail/src/runtime/widget.tsx ***!
  \*****************************************************************************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var jimu_core__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! jimu-core */ "jimu-core");
/* harmony import */ var _clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../clss-custom-components/clss-loading */ "./your-extensions/widgets/clss-custom-components/clss-loading.tsx");
/* harmony import */ var _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../../clss-application/src/extensions/clss-store */ "./your-extensions/widgets/clss-application/src/extensions/clss-store.ts");
/* harmony import */ var _clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../../../clss-application/src/extensions/api */ "./your-extensions/widgets/clss-application/src/extensions/api.ts");
/* harmony import */ var _clss_custom_components_clss_errors_panel__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../../../clss-custom-components/clss-errors-panel */ "./your-extensions/widgets/clss-custom-components/clss-errors-panel.tsx");
/* harmony import */ var _header__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./header */ "./your-extensions/widgets/clss-template-detail/src/runtime/header.tsx");
/* harmony import */ var jimu_ui__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! jimu-ui */ "jimu-ui");
/* harmony import */ var _clss_custom_components_clss_lifeline_component__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../../../clss-custom-components/clss-lifeline-component */ "./your-extensions/widgets/clss-custom-components/clss-lifeline-component.tsx");
/* harmony import */ var _clss_custom_components_clss_add_organization__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-organization */ "./your-extensions/widgets/clss-custom-components/clss-add-organization.tsx");
/* harmony import */ var _clss_custom_components_clss_add_hazard__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../../../clss-custom-components/clss-add-hazard */ "./your-extensions/widgets/clss-custom-components/clss-add-hazard.tsx");
/* harmony import */ var _clss_custom_components_clss_no_data__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ../../../clss-custom-components/clss-no-data */ "./your-extensions/widgets/clss-custom-components/clss-no-data.tsx");
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
    const [loading, setLoading] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [config, setConfig] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [isAddOrganizationModalVisible, setAddOrganizationModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [isAddHazardModalVisible, setAddHazardModalVisibility] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(false);
    const [selectedHazard, setSelectedHazard] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const [selectedOrganization, setSelectedOrganization] = jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useState(null);
    const errors = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.errors;
    });
    const template = useSelector((state) => {
        var _a;
        return (_a = state === null || state === void 0 ? void 0 : state.clssState) === null || _a === void 0 ? void 0 : _a.templates.find(t => t.isSelected);
    });
    const credential = useSelector((state) => {
        var _a;
        return (_a = state.clssState) === null || _a === void 0 ? void 0 : _a.authenticate;
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
        if (credential) {
            setConfig(Object.assign(Object.assign({}, props.config), { credential: credential }));
        }
    }, [credential]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (template && organizations && organizations.length > 0) {
            setSelectedOrganization(organizations.find(o => o.name === template.organizationName));
        }
    }, [template, organizations]);
    jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.useEffect(() => {
        if (template && hazards && hazards.length > 0) {
            setSelectedHazard(hazards.find(h => h.name === template.hazardName));
        }
    }, [template, hazards]);
    const closeError = () => {
        (0,jimu_core__WEBPACK_IMPORTED_MODULE_0__.getAppStore)().dispatch({
            type: _clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__.CLSSActionKeys.SET_ERRORS,
            val: ''
        });
    };
    const loadTemplates = () => __awaiter(void 0, void 0, void 0, function* () {
        const selectedTemplate = template ? Object.assign({}, template) : null;
        const response = yield (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.getTemplates)(config);
        let fetchData = response.data;
        if (response.data) {
            if (selectedTemplate) {
                fetchData = response.data.map(t => {
                    return Object.assign(Object.assign({}, t), { isSelected: t.id === selectedTemplate.id });
                });
            }
            (0,_clss_application_src_extensions_api__WEBPACK_IMPORTED_MODULE_3__.dispatchAction)(_clss_application_src_extensions_clss_store__WEBPACK_IMPORTED_MODULE_2__.CLSSActionKeys.LOAD_TEMPLATES_ACTION, fetchData);
        }
        return response;
    });
    const onIndicatorActionComplete = (reload) => __awaiter(void 0, void 0, void 0, function* () {
        if (reload) {
            yield loadTemplates();
        }
    });
    if (loading) {
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_loading__WEBPACK_IMPORTED_MODULE_1__["default"], null);
    }
    if (template == null) {
        return jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_no_data__WEBPACK_IMPORTED_MODULE_10__["default"], { message: 'Select a template to view details' });
    }
    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "widget-template-detail", style: {
            backgroundColor: props.config.backgoundColor
        } },
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("style", null, `
          .widget-template-detail {
            width: 100%;
            height: 100%;
            padding: 20px;
            overflow: auto;
            position: relative;            
          }

          .error-panel {
            position: absolute;
            left: 0;
            top: 0;
            width: 100%;
            z-index: 999
          }
          
          .details-content{
            width: 100%;
            height: 100%; 
            display: flex;
            flex-direction: column;
            align-items: center;   
          }
         
          .details-content-header{
            border-radius: 10px 10px 0 0;
            padding: 30px 50px;
            width: 100%;
            position:relative;              
            margin-bottom: 10px;
          }
          
          .header-row{
            display: flex;   
            margin-bottom: 10px;           
          }
          .header-row label{
            font-size: 1.6em;
            color: #4d4949;
          }
          .header-row .value{
            font-weight: bold;
          }
          .header-row .title{
             width: 165px;
          }
          .details-content-data{
            height: 100%;
            margin-top: 20px;
            padding: 0;
          }
          .details-content-data-header{             
            height: 75px;
            width: 100%;
            background: #534c4c80;
            border-radius: 10px 10px 0 0;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 0 10px;
            text-align: center;
          }
          .details-content-data-header label{
            font-size: 1.6em;
            color: white;
          }
          .lifelines-tabs{
            width: 100%;             
          }
          .lifelines-tabs .tab-title{
            font-size: 15px;
            font-weight: bold;
            padding: 10px;
          }
          .lifelines-tabs .nav-item{
            height: 40px;
          }
          .lifeline-tab-content{
            padding: 10px;
            background-color: white;
          }
        `),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "details-content" },
            errors && !loading ? (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'error-panel' },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_errors_panel__WEBPACK_IMPORTED_MODULE_4__["default"], { close: closeError, errors: errors }))) : null,
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_header__WEBPACK_IMPORTED_MODULE_5__.DetailHeaderWidget, { template: template, organizations: organizations, hazards: hazards, onActionComplete: onIndicatorActionComplete, config: config, selectedNewHazard: selectedHazard, selectedNewOrganization: selectedOrganization, toggleHazardModalVisibility: setAddHazardModalVisibility, toggleOrganizationModalVisibility: setAddOrganizationModalVisibility }),
            jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: 'lifelines-tabs' },
                jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_6__.Tabs, { defaultValue: "tab-1", fill: true, type: "tabs" }, template === null || template === void 0 ? void 0 : template.lifelineTemplates.map(((lifeline) => {
                    var _a;
                    return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(jimu_ui__WEBPACK_IMPORTED_MODULE_6__.Tab, { id: lifeline === null || lifeline === void 0 ? void 0 : lifeline.id, key: lifeline === null || lifeline === void 0 ? void 0 : lifeline.id, title: lifeline.title },
                        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement("div", { className: "lifeline-tab-content" }, (_a = lifeline === null || lifeline === void 0 ? void 0 : lifeline.componentTemplates) === null || _a === void 0 ? void 0 : _a.map(((lifelineComp) => {
                            return (jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_lifeline_component__WEBPACK_IMPORTED_MODULE_7__.LifelineComponent, { key: lifelineComp.id, lifeline: lifeline, component: lifelineComp, template: template, config: config, onActionComplete: onIndicatorActionComplete }));
                        })))));
                }))))),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_organization__WEBPACK_IMPORTED_MODULE_8__.AddOrganizatonWidget, { propsConfig: props === null || props === void 0 ? void 0 : props.config, visible: isAddOrganizationModalVisible, setOrganization: setSelectedOrganization, toggle: setAddOrganizationModalVisibility }),
        jimu_core__WEBPACK_IMPORTED_MODULE_0__.React.createElement(_clss_custom_components_clss_add_hazard__WEBPACK_IMPORTED_MODULE_9__.AddHazardWidget, { props: props, visible: isAddHazardModalVisible, setHazard: setSelectedHazard, toggle: setAddHazardModalVisibility })));
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (Widget);

})();

/******/ 	return __webpack_exports__;
/******/ })()

			);
		}
	};
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid2lkZ2V0cy9jbHNzLXRlbXBsYXRlLWRldGFpbC9kaXN0L3J1bnRpbWUvd2lkZ2V0LmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQ0E7QUFDaUM7QUFDcUY7QUFDckU7QUFDTjtBQUN5QjtBQUNWO0FBQzFEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEtBQUs7QUFDTDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVksY0FBYztBQUMxQjtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUk7QUFDSjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSTtBQUNKO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGNBQWMsbUVBQVE7QUFDdEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVM7QUFDVDtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQixlQUFlO0FBQ2pDO0FBQ0E7QUFDQTtB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RkFBb0IsSUFDakIsV0FBVyxFQUFFLEtBQUssYUFBTCxLQUFLLHVCQUFMLEtBQUssQ0FBRSxNQUFNLEVBQzFCLE9BQU8sRUFBRSw2QkFBNkIsRUFDdEMsZUFBZSxFQUFFLHVCQUF1QixFQUN4QyxNQUFNLEVBQUUsaUNBQWlDLEdBQUc7UUFFaEQsMkRBQUMsb0ZBQWUsSUFDZCxLQUFLLEVBQUUsS0FBSyxFQUNaLE9BQU8sRUFBRSx1QkFBdUIsRUFDaEMsU0FBUyxFQUFFLGlCQUFpQixFQUM1QixNQUFNLEVBQUUsMkJBQTJCLEdBQUcsQ0FDcEMsQ0FDUDtBQUNILENBQUM7QUFDRCxpRUFBZSxNQUFNIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL1VzZXJTZXNzaW9uLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9mZWRlcmF0aW9uLXV0aWxzLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aC9kaXN0L2VzbS9mZXRjaC10b2tlbi5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgvZGlzdC9lc20vZ2VuZXJhdGUtdG9rZW4uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL2Rpc3QvZXNtL3ZhbGlkYXRlLWFwcC1hY2Nlc3MuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1hdXRoL25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL2Rpc3QvZXNtL2FkZC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vZGVsZXRlLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS9xdWVyeS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXIvZGlzdC9lc20vcXVlcnlSZWxhdGVkLmpzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9ub2RlX21vZHVsZXMvQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllci9kaXN0L2VzbS91cGRhdGUuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyL25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3JlcXVlc3QuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL0FyY0dJU1JlcXVlc3RFcnJvci5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvYXBwZW5kLWN1c3RvbS1wYXJhbXMuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL2NsZWFuLXVybC5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZGVjb2RlLXF1ZXJ5LXN0cmluZy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZW5jb2RlLWZvcm0tZGF0YS5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvZW5jb2RlLXF1ZXJ5LXN0cmluZy5qcyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vbm9kZV9tb2R1bGVzL0Blc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3QvZGlzdC9lc20vdXRpbHMvcHJvY2Vzcy1wYXJhbXMuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L2Rpc3QvZXNtL3V0aWxzL3dhcm4uanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL25vZGVfbW9kdWxlcy9AZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0L25vZGVfbW9kdWxlcy90c2xpYi90c2xpYi5lczYuanMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvc3ZnL2ZpbGxlZC9hcHBsaWNhdGlvbi9jaGVjay5zdmciLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvc3ZnL2ZpbGxlZC9lZGl0b3IvY2xvc2UtY2lyY2xlLnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvZmlsbGVkL2VkaXRvci9lZGl0LnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvZmlsbGVkL2VkaXRvci9zYXZlLnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvZmlsbGVkL3N1Z2dlc3RlZC9oZWxwLnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvb3V0bGluZWQvZWRpdG9yL2Nsb3NlLnN2ZyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9zdmcvb3V0bGluZWQvZWRpdG9yL2VkaXQuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9lZGl0b3IvcGx1cy1jaXJjbGUuc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL3N2Zy9vdXRsaW5lZC9lZGl0b3IvdHJhc2guc3ZnIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL2ZpbGxlZC9hcHBsaWNhdGlvbi9jaGVjay50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvZmlsbGVkL2VkaXRvci9jbG9zZS1jaXJjbGUudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL2ZpbGxlZC9lZGl0b3IvZWRpdC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvZmlsbGVkL2VkaXRvci9zYXZlLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1pY29ucy9maWxsZWQvc3VnZ2VzdGVkL2hlbHAudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL291dGxpbmVkL2VkaXRvci9jbG9zZS50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL2VkaXQudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi9qaW11LWljb25zL291dGxpbmVkL2VkaXRvci9wbHVzLWNpcmNsZS50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL2ppbXUtaWNvbnMvb3V0bGluZWQvZWRpdG9yL3RyYXNoLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGkudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXV0aC50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlLnRzIiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2NvbnN0YW50cy50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9lc3JpLWFwaS50cyIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9sb2dnZXIudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvdXRpbHMudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1hZGQtaGF6YXJkLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFkZC1vcmdhbml6YXRpb24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtYXNzZXNzbWVudHMtbGlzdC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1kcm9wZG93bi50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1lcnJvci50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1lcnJvcnMtcGFuZWwudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtaGF6YXJkcy1kcm9wZG93bi50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1saWZlbGluZS1jb21wb25lbnQudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtbG9hZGluZy50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1tb2RhbC50c3giLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1uby1kYXRhLnRzeCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4veW91ci1leHRlbnNpb25zL3dpZGdldHMvY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLW9yZ2FuaXphdGlvbnMtZHJvcGRvd24udHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvLi95b3VyLWV4dGVuc2lvbnMvd2lkZ2V0cy9jbHNzLXRlbXBsYXRlLWRldGFpbC9zcmMvcnVudGltZS9oZWFkZXIudHN4Iiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1hcmNnaXNcIiIsIndlYnBhY2s6Ly9leGItY2xpZW50L2V4dGVybmFsIHN5c3RlbSBcImppbXUtY29yZVwiIiwid2VicGFjazovL2V4Yi1jbGllbnQvZXh0ZXJuYWwgc3lzdGVtIFwiamltdS1jb3JlL3JlYWN0XCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC9leHRlcm5hbCBzeXN0ZW0gXCJqaW11LXVpXCIiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9jb21wYXQgZ2V0IGRlZmF1bHQgZXhwb3J0Iiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2RlZmluZSBwcm9wZXJ0eSBnZXR0ZXJzIiwid2VicGFjazovL2V4Yi1jbGllbnQvd2VicGFjay9ydW50aW1lL2hhc093blByb3BlcnR5IHNob3J0aGFuZCIsIndlYnBhY2s6Ly9leGItY2xpZW50L3dlYnBhY2svcnVudGltZS9tYWtlIG5hbWVzcGFjZSBvYmplY3QiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC93ZWJwYWNrL3J1bnRpbWUvcHVibGljUGF0aCIsIndlYnBhY2s6Ly9leGItY2xpZW50Ly4vamltdS1jb3JlL2xpYi9zZXQtcHVibGljLXBhdGgudHMiLCJ3ZWJwYWNrOi8vZXhiLWNsaWVudC8uL3lvdXItZXh0ZW5zaW9ucy93aWRnZXRzL2Nsc3MtdGVtcGxhdGUtZGV0YWlsL3NyYy9ydW50aW1lL3dpZGdldC50c3giXSwic291cmNlc0NvbnRlbnQiOlsiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTkgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIEFyY0dJU0F1dGhFcnJvciwgY2xlYW5VcmwsIGVuY29kZVF1ZXJ5U3RyaW5nLCBkZWNvZGVRdWVyeVN0cmluZywgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuaW1wb3J0IHsgZ2VuZXJhdGVUb2tlbiB9IGZyb20gXCIuL2dlbmVyYXRlLXRva2VuXCI7XG5pbXBvcnQgeyBmZXRjaFRva2VuIH0gZnJvbSBcIi4vZmV0Y2gtdG9rZW5cIjtcbmltcG9ydCB7IGNhblVzZU9ubGluZVRva2VuLCBpc0ZlZGVyYXRlZCB9IGZyb20gXCIuL2ZlZGVyYXRpb24tdXRpbHNcIjtcbmltcG9ydCB7IHZhbGlkYXRlQXBwQWNjZXNzIH0gZnJvbSBcIi4vdmFsaWRhdGUtYXBwLWFjY2Vzc1wiO1xuZnVuY3Rpb24gZGVmZXIoKSB7XG4gICAgdmFyIGRlZmVycmVkID0ge1xuICAgICAgICBwcm9taXNlOiBudWxsLFxuICAgICAgICByZXNvbHZlOiBudWxsLFxuICAgICAgICByZWplY3Q6IG51bGwsXG4gICAgfTtcbiAgICBkZWZlcnJlZC5wcm9taXNlID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICBkZWZlcnJlZC5yZXNvbHZlID0gcmVzb2x2ZTtcbiAgICAgICAgZGVmZXJyZWQucmVqZWN0ID0gcmVqZWN0O1xuICAgIH0pO1xuICAgIHJldHVybiBkZWZlcnJlZDtcbn1cbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IFVzZXJTZXNzaW9uIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aCc7XG4gKiBVc2VyU2Vzc2lvbi5iZWdpbk9BdXRoMih7XG4gKiAgIC8vIHJlZ2lzdGVyIGFuIGFwcCBvZiB5b3VyIG93biB0byBjcmVhdGUgYSB1bmlxdWUgY2xpZW50SWRcbiAqICAgY2xpZW50SWQ6IFwiYWJjMTIzXCIsXG4gKiAgIHJlZGlyZWN0VXJpOiAnaHR0cHM6Ly95b3VyYXBwLmNvbS9hdXRoZW50aWNhdGUuaHRtbCdcbiAqIH0pXG4gKiAgIC50aGVuKHNlc3Npb24pXG4gKiAvLyBvclxuICogbmV3IFVzZXJTZXNzaW9uKHtcbiAqICAgdXNlcm5hbWU6IFwianNtaXRoXCIsXG4gKiAgIHBhc3N3b3JkOiBcIjEyMzQ1NlwiXG4gKiB9KVxuICogLy8gb3JcbiAqIFVzZXJTZXNzaW9uLmRlc2VyaWFsaXplKGNhY2hlKVxuICogYGBgXG4gKiBVc2VkIHRvIGF1dGhlbnRpY2F0ZSBib3RoIEFyY0dJUyBPbmxpbmUgYW5kIEFyY0dJUyBFbnRlcnByaXNlIHVzZXJzLiBgVXNlclNlc3Npb25gIGluY2x1ZGVzIGhlbHBlciBtZXRob2RzIGZvciBbT0F1dGggMi4wXSgvYXJjZ2lzLXJlc3QtanMvZ3VpZGVzL2Jyb3dzZXItYXV0aGVudGljYXRpb24vKSBpbiBib3RoIGJyb3dzZXIgYW5kIHNlcnZlciBhcHBsaWNhdGlvbnMuXG4gKi9cbnZhciBVc2VyU2Vzc2lvbiA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBVc2VyU2Vzc2lvbihvcHRpb25zKSB7XG4gICAgICAgIHRoaXMuY2xpZW50SWQgPSBvcHRpb25zLmNsaWVudElkO1xuICAgICAgICB0aGlzLl9yZWZyZXNoVG9rZW4gPSBvcHRpb25zLnJlZnJlc2hUb2tlbjtcbiAgICAgICAgdGhpcy5fcmVmcmVzaFRva2VuRXhwaXJlcyA9IG9wdGlvbnMucmVmcmVzaFRva2VuRXhwaXJlcztcbiAgICAgICAgdGhpcy51c2VybmFtZSA9IG9wdGlvbnMudXNlcm5hbWU7XG4gICAgICAgIHRoaXMucGFzc3dvcmQgPSBvcHRpb25zLnBhc3N3b3JkO1xuICAgICAgICB0aGlzLl90b2tlbiA9IG9wdGlvbnMudG9rZW47XG4gICAgICAgIHRoaXMuX3Rva2VuRXhwaXJlcyA9IG9wdGlvbnMudG9rZW5FeHBpcmVzO1xuICAgICAgICB0aGlzLnBvcnRhbCA9IG9wdGlvbnMucG9ydGFsXG4gICAgICAgICAgICA/IGNsZWFuVXJsKG9wdGlvbnMucG9ydGFsKVxuICAgICAgICAgICAgOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgICAgIHRoaXMuc3NsID0gb3B0aW9ucy5zc2w7XG4gICAgICAgIHRoaXMucHJvdmlkZXIgPSBvcHRpb25zLnByb3ZpZGVyIHx8IFwiYXJjZ2lzXCI7XG4gICAgICAgIHRoaXMudG9rZW5EdXJhdGlvbiA9IG9wdGlvbnMudG9rZW5EdXJhdGlvbiB8fCAyMDE2MDtcbiAgICAgICAgdGhpcy5yZWRpcmVjdFVyaSA9IG9wdGlvbnMucmVkaXJlY3RVcmk7XG4gICAgICAgIHRoaXMucmVmcmVzaFRva2VuVFRMID0gb3B0aW9ucy5yZWZyZXNoVG9rZW5UVEwgfHwgMjAxNjA7XG4gICAgICAgIHRoaXMuc2VydmVyID0gb3B0aW9ucy5zZXJ2ZXI7XG4gICAgICAgIHRoaXMuZmVkZXJhdGVkU2VydmVycyA9IHt9O1xuICAgICAgICB0aGlzLnRydXN0ZWREb21haW5zID0gW107XG4gICAgICAgIC8vIGlmIGEgbm9uLWZlZGVyYXRlZCBzZXJ2ZXIgd2FzIHBhc3NlZCBleHBsaWNpdGx5LCBpdCBzaG91bGQgYmUgdHJ1c3RlZC5cbiAgICAgICAgaWYgKG9wdGlvbnMuc2VydmVyKSB7XG4gICAgICAgICAgICAvLyBpZiB0aGUgdXJsIGluY2x1ZGVzIG1vcmUgdGhhbiAnL2FyY2dpcy8nLCB0cmltIHRoZSByZXN0XG4gICAgICAgICAgICB2YXIgcm9vdCA9IHRoaXMuZ2V0U2VydmVyUm9vdFVybChvcHRpb25zLnNlcnZlcik7XG4gICAgICAgICAgICB0aGlzLmZlZGVyYXRlZFNlcnZlcnNbcm9vdF0gPSB7XG4gICAgICAgICAgICAgICAgdG9rZW46IG9wdGlvbnMudG9rZW4sXG4gICAgICAgICAgICAgICAgZXhwaXJlczogb3B0aW9ucy50b2tlbkV4cGlyZXMsXG4gICAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzID0ge307XG4gICAgfVxuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShVc2VyU2Vzc2lvbi5wcm90b3R5cGUsIFwidG9rZW5cIiwge1xuICAgICAgICAvKipcbiAgICAgICAgICogVGhlIGN1cnJlbnQgQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZSBgdG9rZW5gLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fdG9rZW47XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInRva2VuRXhwaXJlc1wiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgZXhwaXJhdGlvbiB0aW1lIG9mIHRoZSBjdXJyZW50IGB0b2tlbmAuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl90b2tlbkV4cGlyZXM7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoVXNlclNlc3Npb24ucHJvdG90eXBlLCBcInJlZnJlc2hUb2tlblwiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBUaGUgY3VycmVudCB0b2tlbiB0byBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlLlxuICAgICAgICAgKi9cbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcmVmcmVzaFRva2VuO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJyZWZyZXNoVG9rZW5FeHBpcmVzXCIsIHtcbiAgICAgICAgLyoqXG4gICAgICAgICAqIFRoZSBleHBpcmF0aW9uIHRpbWUgb2YgdGhlIGN1cnJlbnQgYHJlZnJlc2hUb2tlbmAuXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9yZWZyZXNoVG9rZW5FeHBpcmVzO1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiBmYWxzZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KFVzZXJTZXNzaW9uLnByb3RvdHlwZSwgXCJ0cnVzdGVkU2VydmVyc1wiLCB7XG4gICAgICAgIC8qKlxuICAgICAgICAgKiBEZXByZWNhdGVkLCB1c2UgYGZlZGVyYXRlZFNlcnZlcnNgIGluc3RlYWQuXG4gICAgICAgICAqXG4gICAgICAgICAqIEBkZXByZWNhdGVkXG4gICAgICAgICAqL1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiREVQUkVDQVRFRDogdXNlIGZlZGVyYXRlZFNlcnZlcnMgaW5zdGVhZFwiKTtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmZlZGVyYXRlZFNlcnZlcnM7XG4gICAgICAgIH0sXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICAvKipcbiAgICAgKiBCZWdpbnMgYSBuZXcgYnJvd3Nlci1iYXNlZCBPQXV0aCAyLjAgc2lnbiBpbi4gSWYgYG9wdGlvbnMucG9wdXBgIGlzIGB0cnVlYCB0aGVcbiAgICAgKiBhdXRoZW50aWNhdGlvbiB3aW5kb3cgd2lsbCBvcGVuIGluIGEgbmV3IHRhYi93aW5kb3cgYW5kIHRoZSBmdW5jdGlvbiB3aWxsIHJldHVyblxuICAgICAqIFByb21pc2UmbHQ7VXNlclNlc3Npb24mZ3Q7LiBPdGhlcndpc2UsIHRoZSB1c2VyIHdpbGwgYmUgcmVkaXJlY3RlZCB0byB0aGVcbiAgICAgKiBhdXRob3JpemF0aW9uIHBhZ2UgaW4gdGhlaXIgY3VycmVudCB0YWIvd2luZG93IGFuZCB0aGUgZnVuY3Rpb24gd2lsbCByZXR1cm4gYHVuZGVmaW5lZGAuXG4gICAgICpcbiAgICAgKiBAYnJvd3Nlck9ubHlcbiAgICAgKi9cbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIFVzZXJTZXNzaW9uLmJlZ2luT0F1dGgyID0gZnVuY3Rpb24gKG9wdGlvbnMsIHdpbikge1xuICAgICAgICBpZiAod2luID09PSB2b2lkIDApIHsgd2luID0gd2luZG93OyB9XG4gICAgICAgIGlmIChvcHRpb25zLmR1cmF0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkRFUFJFQ0FURUQ6ICdkdXJhdGlvbicgaXMgZGVwcmVjYXRlZCAtIHVzZSAnZXhwaXJhdGlvbicgaW5zdGVhZFwiKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7XG4gICAgICAgICAgICBwb3J0YWw6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHByb3ZpZGVyOiBcImFyY2dpc1wiLFxuICAgICAgICAgICAgZXhwaXJhdGlvbjogMjAxNjAsXG4gICAgICAgICAgICBwb3B1cDogdHJ1ZSxcbiAgICAgICAgICAgIHBvcHVwV2luZG93RmVhdHVyZXM6IFwiaGVpZ2h0PTQwMCx3aWR0aD02MDAsbWVudWJhcj1ubyxsb2NhdGlvbj15ZXMscmVzaXphYmxlPXllcyxzY3JvbGxiYXJzPXllcyxzdGF0dXM9eWVzXCIsXG4gICAgICAgICAgICBzdGF0ZTogb3B0aW9ucy5jbGllbnRJZCxcbiAgICAgICAgICAgIGxvY2FsZTogXCJcIixcbiAgICAgICAgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgcHJvdmlkZXIgPSBfYS5wcm92aWRlciwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgZXhwaXJhdGlvbiA9IF9hLmV4cGlyYXRpb24sIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmksIHBvcHVwID0gX2EucG9wdXAsIHBvcHVwV2luZG93RmVhdHVyZXMgPSBfYS5wb3B1cFdpbmRvd0ZlYXR1cmVzLCBzdGF0ZSA9IF9hLnN0YXRlLCBsb2NhbGUgPSBfYS5sb2NhbGUsIHBhcmFtcyA9IF9hLnBhcmFtcztcbiAgICAgICAgdmFyIHVybDtcbiAgICAgICAgaWYgKHByb3ZpZGVyID09PSBcImFyY2dpc1wiKSB7XG4gICAgICAgICAgICB1cmwgPSBwb3J0YWwgKyBcIi9vYXV0aDIvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImcmVzcG9uc2VfdHlwZT10b2tlbiZleHBpcmF0aW9uPVwiICsgKG9wdGlvbnMuZHVyYXRpb24gfHwgZXhwaXJhdGlvbikgKyBcIiZyZWRpcmVjdF91cmk9XCIgKyBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICsgXCImc3RhdGU9XCIgKyBzdGF0ZSArIFwiJmxvY2FsZT1cIiArIGxvY2FsZTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHVybCA9IHBvcnRhbCArIFwiL29hdXRoMi9zb2NpYWwvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImc29jaWFsTG9naW5Qcm92aWRlck5hbWU9XCIgKyBwcm92aWRlciArIFwiJmF1dG9BY2NvdW50Q3JlYXRlRm9yU29jaWFsPXRydWUmcmVzcG9uc2VfdHlwZT10b2tlbiZleHBpcmF0aW9uPVwiICsgKG9wdGlvbnMuZHVyYXRpb24gfHwgZXhwaXJhdGlvbikgKyBcIiZyZWRpcmVjdF91cmk9XCIgKyBlbmNvZGVVUklDb21wb25lbnQocmVkaXJlY3RVcmkpICsgXCImc3RhdGU9XCIgKyBzdGF0ZSArIFwiJmxvY2FsZT1cIiArIGxvY2FsZTtcbiAgICAgICAgfVxuICAgICAgICAvLyBhcHBlbmQgYWRkaXRpb25hbCBwYXJhbXNcbiAgICAgICAgaWYgKHBhcmFtcykge1xuICAgICAgICAgICAgdXJsID0gdXJsICsgXCImXCIgKyBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghcG9wdXApIHtcbiAgICAgICAgICAgIHdpbi5sb2NhdGlvbi5ocmVmID0gdXJsO1xuICAgICAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAgICAgfVxuICAgICAgICB2YXIgc2Vzc2lvbiA9IGRlZmVyKCk7XG4gICAgICAgIHdpbltcIl9fRVNSSV9SRVNUX0FVVEhfSEFORExFUl9cIiArIGNsaWVudElkXSA9IGZ1bmN0aW9uIChlcnJvclN0cmluZywgb2F1dGhJbmZvU3RyaW5nKSB7XG4gICAgICAgICAgICBpZiAoZXJyb3JTdHJpbmcpIHtcbiAgICAgICAgICAgICAgICB2YXIgZXJyb3IgPSBKU09OLnBhcnNlKGVycm9yU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uLnJlamVjdChuZXcgQXJjR0lTQXV0aEVycm9yKGVycm9yLmVycm9yTWVzc2FnZSwgZXJyb3IuZXJyb3IpKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAob2F1dGhJbmZvU3RyaW5nKSB7XG4gICAgICAgICAgICAgICAgdmFyIG9hdXRoSW5mbyA9IEpTT04ucGFyc2Uob2F1dGhJbmZvU3RyaW5nKTtcbiAgICAgICAgICAgICAgICBzZXNzaW9uLnJlc29sdmUobmV3IFVzZXJTZXNzaW9uKHtcbiAgICAgICAgICAgICAgICAgICAgY2xpZW50SWQ6IGNsaWVudElkLFxuICAgICAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICAgICAgc3NsOiBvYXV0aEluZm8uc3NsLFxuICAgICAgICAgICAgICAgICAgICB0b2tlbjogb2F1dGhJbmZvLnRva2VuLFxuICAgICAgICAgICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG5ldyBEYXRlKG9hdXRoSW5mby5leHBpcmVzKSxcbiAgICAgICAgICAgICAgICAgICAgdXNlcm5hbWU6IG9hdXRoSW5mby51c2VybmFtZSxcbiAgICAgICAgICAgICAgICB9KSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgICAgIHdpbi5vcGVuKHVybCwgXCJvYXV0aC13aW5kb3dcIiwgcG9wdXBXaW5kb3dGZWF0dXJlcyk7XG4gICAgICAgIHJldHVybiBzZXNzaW9uLnByb21pc2U7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBDb21wbGV0ZXMgYSBicm93c2VyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluLiBJZiBgb3B0aW9ucy5wb3B1cGAgaXMgYHRydWVgIHRoZSB1c2VyXG4gICAgICogd2lsbCBiZSByZXR1cm5lZCB0byB0aGUgcHJldmlvdXMgd2luZG93LiBPdGhlcndpc2UgYSBuZXcgYFVzZXJTZXNzaW9uYFxuICAgICAqIHdpbGwgYmUgcmV0dXJuZWQuIFlvdSBtdXN0IHBhc3MgdGhlIHNhbWUgdmFsdWVzIGZvciBgb3B0aW9ucy5wb3B1cGAgYW5kXG4gICAgICogYG9wdGlvbnMucG9ydGFsYCBhcyB5b3UgdXNlZCBpbiBgYmVnaW5PQXV0aDIoKWAuXG4gICAgICpcbiAgICAgKiBAYnJvd3Nlck9ubHlcbiAgICAgKi9cbiAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgIFVzZXJTZXNzaW9uLmNvbXBsZXRlT0F1dGgyID0gZnVuY3Rpb24gKG9wdGlvbnMsIHdpbikge1xuICAgICAgICBpZiAod2luID09PSB2b2lkIDApIHsgd2luID0gd2luZG93OyB9XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHsgcG9ydGFsOiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCIsIHBvcHVwOiB0cnVlIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIHBvcHVwID0gX2EucG9wdXA7XG4gICAgICAgIGZ1bmN0aW9uIGNvbXBsZXRlU2lnbkluKGVycm9yLCBvYXV0aEluZm8pIHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgdmFyIGhhbmRsZXJGbiA9IHZvaWQgMDtcbiAgICAgICAgICAgICAgICB2YXIgaGFuZGxlckZuTmFtZSA9IFwiX19FU1JJX1JFU1RfQVVUSF9IQU5ETEVSX1wiICsgY2xpZW50SWQ7XG4gICAgICAgICAgICAgICAgaWYgKHBvcHVwKSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIEd1YXJkIGIvYyBJRSBkb2VzIG5vdCBzdXBwb3J0IHdpbmRvdy5vcGVuZXJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHdpbi5vcGVuZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICh3aW4ub3BlbmVyLnBhcmVudCAmJiB3aW4ub3BlbmVyLnBhcmVudFtoYW5kbGVyRm5OYW1lXSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbiA9IHdpbi5vcGVuZXIucGFyZW50W2hhbmRsZXJGbk5hbWVdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgZWxzZSBpZiAod2luLm9wZW5lciAmJiB3aW4ub3BlbmVyW2hhbmRsZXJGbk5hbWVdKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgLy8gc3VwcG9ydCBwb3Atb3V0IG9hdXRoIGZyb20gd2l0aGluIGFuIGlmcmFtZVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbiA9IHdpbi5vcGVuZXJbaGFuZGxlckZuTmFtZV07XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvLyBJRVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKHdpbiAhPT0gd2luLnBhcmVudCAmJiB3aW4ucGFyZW50ICYmIHdpbi5wYXJlbnRbaGFuZGxlckZuTmFtZV0pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyRm4gPSB3aW4ucGFyZW50W2hhbmRsZXJGbk5hbWVdO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIC8vIGlmIHdlIGhhdmUgYSBoYW5kbGVyIGZuLCBjYWxsIGl0IGFuZCBjbG9zZSB0aGUgd2luZG93XG4gICAgICAgICAgICAgICAgICAgIGlmIChoYW5kbGVyRm4pIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXJGbihlcnJvciA/IEpTT04uc3RyaW5naWZ5KGVycm9yKSA6IHVuZGVmaW5lZCwgSlNPTi5zdHJpbmdpZnkob2F1dGhJbmZvKSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB3aW4uY2xvc2UoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IoXCJVbmFibGUgdG8gY29tcGxldGUgYXV0aGVudGljYXRpb24uIEl0J3MgcG9zc2libGUgeW91IHNwZWNpZmllZCBwb3B1cCBiYXNlZCBvQXV0aDIgYnV0IG5vIGhhbmRsZXIgZnJvbSBcXFwiYmVnaW5PQXV0aDIoKVxcXCIgcHJlc2VudC4gVGhpcyBnZW5lcmFsbHkgaGFwcGVucyBiZWNhdXNlIHRoZSBcXFwicG9wdXBcXFwiIG9wdGlvbiBkaWZmZXJzIGJldHdlZW4gXFxcImJlZ2luT0F1dGgyKClcXFwiIGFuZCBcXFwiY29tcGxldGVPQXV0aDIoKVxcXCIuXCIpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKGVycm9yKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEFyY0dJU0F1dGhFcnJvcihlcnJvci5lcnJvck1lc3NhZ2UsIGVycm9yLmVycm9yKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgICAgIGNsaWVudElkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICBzc2w6IG9hdXRoSW5mby5zc2wsXG4gICAgICAgICAgICAgICAgdG9rZW46IG9hdXRoSW5mby50b2tlbixcbiAgICAgICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG9hdXRoSW5mby5leHBpcmVzLFxuICAgICAgICAgICAgICAgIHVzZXJuYW1lOiBvYXV0aEluZm8udXNlcm5hbWUsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgcGFyYW1zID0gZGVjb2RlUXVlcnlTdHJpbmcod2luLmxvY2F0aW9uLmhhc2gpO1xuICAgICAgICBpZiAoIXBhcmFtcy5hY2Nlc3NfdG9rZW4pIHtcbiAgICAgICAgICAgIHZhciBlcnJvciA9IHZvaWQgMDtcbiAgICAgICAgICAgIHZhciBlcnJvck1lc3NhZ2UgPSBcIlVua25vd24gZXJyb3JcIjtcbiAgICAgICAgICAgIGlmIChwYXJhbXMuZXJyb3IpIHtcbiAgICAgICAgICAgICAgICBlcnJvciA9IHBhcmFtcy5lcnJvcjtcbiAgICAgICAgICAgICAgICBlcnJvck1lc3NhZ2UgPSBwYXJhbXMuZXJyb3JfZGVzY3JpcHRpb247XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gY29tcGxldGVTaWduSW4oeyBlcnJvcjogZXJyb3IsIGVycm9yTWVzc2FnZTogZXJyb3JNZXNzYWdlIH0pO1xuICAgICAgICB9XG4gICAgICAgIHZhciB0b2tlbiA9IHBhcmFtcy5hY2Nlc3NfdG9rZW47XG4gICAgICAgIHZhciBleHBpcmVzID0gbmV3IERhdGUoRGF0ZS5ub3coKSArIHBhcnNlSW50KHBhcmFtcy5leHBpcmVzX2luLCAxMCkgKiAxMDAwIC0gNjAgKiAxMDAwKTtcbiAgICAgICAgdmFyIHVzZXJuYW1lID0gcGFyYW1zLnVzZXJuYW1lO1xuICAgICAgICB2YXIgc3NsID0gcGFyYW1zLnNzbCA9PT0gXCJ0cnVlXCI7XG4gICAgICAgIHJldHVybiBjb21wbGV0ZVNpZ25Jbih1bmRlZmluZWQsIHtcbiAgICAgICAgICAgIHRva2VuOiB0b2tlbixcbiAgICAgICAgICAgIGV4cGlyZXM6IGV4cGlyZXMsXG4gICAgICAgICAgICBzc2w6IHNzbCxcbiAgICAgICAgICAgIHVzZXJuYW1lOiB1c2VybmFtZSxcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXF1ZXN0IHNlc3Npb24gaW5mb3JtYXRpb24gZnJvbSB0aGUgcGFyZW50IGFwcGxpY2F0aW9uXG4gICAgICpcbiAgICAgKiBXaGVuIGFuIGFwcGxpY2F0aW9uIGlzIGVtYmVkZGVkIGludG8gYW5vdGhlciBhcHBsaWNhdGlvbiB2aWEgYW4gSUZyYW1lLCB0aGUgZW1iZWRkZWQgYXBwIGNhblxuICAgICAqIHVzZSBgd2luZG93LnBvc3RNZXNzYWdlYCB0byByZXF1ZXN0IGNyZWRlbnRpYWxzIGZyb20gdGhlIGhvc3QgYXBwbGljYXRpb24uIFRoaXMgZnVuY3Rpb24gd3JhcHNcbiAgICAgKiB0aGF0IGJlaGF2aW9yLlxuICAgICAqXG4gICAgICogVGhlIEFyY0dJUyBBUEkgZm9yIEphdmFzY3JpcHQgaGFzIHRoaXMgYnVpbHQgaW50byB0aGUgSWRlbnRpdHkgTWFuYWdlciBhcyBvZiB0aGUgNC4xOSByZWxlYXNlLlxuICAgICAqXG4gICAgICogTm90ZTogVGhlIHBhcmVudCBhcHBsaWNhdGlvbiB3aWxsIG5vdCByZXNwb25kIGlmIHRoZSBlbWJlZGRlZCBhcHAncyBvcmlnaW4gaXMgbm90OlxuICAgICAqIC0gdGhlIHNhbWUgb3JpZ2luIGFzIHRoZSBwYXJlbnQgb3IgKi5hcmNnaXMuY29tIChKU0FQSSlcbiAgICAgKiAtIGluIHRoZSBsaXN0IG9mIHZhbGlkIGNoaWxkIG9yaWdpbnMgKFJFU1QtSlMpXG4gICAgICpcbiAgICAgKlxuICAgICAqIEBwYXJhbSBwYXJlbnRPcmlnaW4gb3JpZ2luIG9mIHRoZSBwYXJlbnQgZnJhbWUuIFBhc3NlZCBpbnRvIHRoZSBlbWJlZGRlZCBhcHBsaWNhdGlvbiBhcyBgcGFyZW50T3JpZ2luYCBxdWVyeSBwYXJhbVxuICAgICAqIEBicm93c2VyT25seVxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLmZyb21QYXJlbnQgPSBmdW5jdGlvbiAocGFyZW50T3JpZ2luLCB3aW4pIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQ6IG11c3QgcGFzcyBpbiBhIG1vY2t3aW5kb3cgZm9yIHRlc3RzIHNvIHdlIGNhbid0IGNvdmVyIHRoZSBvdGhlciBicmFuY2ggKi9cbiAgICAgICAgaWYgKCF3aW4gJiYgd2luZG93KSB7XG4gICAgICAgICAgICB3aW4gPSB3aW5kb3c7XG4gICAgICAgIH1cbiAgICAgICAgLy8gRGVjbGFyZSBoYW5kbGVyIG91dHNpZGUgb2YgcHJvbWlzZSBzY29wZSBzbyB3ZSBjYW4gZGV0YWNoIGl0XG4gICAgICAgIHZhciBoYW5kbGVyO1xuICAgICAgICAvLyByZXR1cm4gYSBwcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdoZW4gdGhlIGhhbmRsZXIgcmVjZWl2ZXNcbiAgICAgICAgLy8gc2Vzc2lvbiBpbmZvcm1hdGlvbiBmcm9tIHRoZSBjb3JyZWN0IG9yaWdpblxuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgLy8gY3JlYXRlIGFuIGV2ZW50IGhhbmRsZXIgdGhhdCBqdXN0IHdyYXBzIHRoZSBwYXJlbnRNZXNzYWdlSGFuZGxlclxuICAgICAgICAgICAgaGFuZGxlciA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICAgICAgICAgIC8vIGVuc3VyZSB3ZSBvbmx5IGxpc3RlbiB0byBldmVudHMgZnJvbSB0aGUgcGFyZW50XG4gICAgICAgICAgICAgICAgaWYgKGV2ZW50LnNvdXJjZSA9PT0gd2luLnBhcmVudCAmJiBldmVudC5kYXRhKSB7XG4gICAgICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzb2x2ZShVc2VyU2Vzc2lvbi5wYXJlbnRNZXNzYWdlSGFuZGxlcihldmVudCkpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICAvLyBhZGQgbGlzdGVuZXJcbiAgICAgICAgICAgIHdpbi5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCBoYW5kbGVyLCBmYWxzZSk7XG4gICAgICAgICAgICB3aW4ucGFyZW50LnBvc3RNZXNzYWdlKHsgdHlwZTogXCJhcmNnaXM6YXV0aDpyZXF1ZXN0Q3JlZGVudGlhbFwiIH0sIHBhcmVudE9yaWdpbik7XG4gICAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHNlc3Npb24pIHtcbiAgICAgICAgICAgIHdpbi5yZW1vdmVFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCBoYW5kbGVyLCBmYWxzZSk7XG4gICAgICAgICAgICByZXR1cm4gc2Vzc2lvbjtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBCZWdpbnMgYSBuZXcgc2VydmVyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluLiBUaGlzIHdpbGwgcmVkaXJlY3QgdGhlIHVzZXIgdG9cbiAgICAgKiB0aGUgQXJjR0lTIE9ubGluZSBvciBBcmNHSVMgRW50ZXJwcmlzZSBhdXRob3JpemF0aW9uIHBhZ2UuXG4gICAgICpcbiAgICAgKiBAbm9kZU9ubHlcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5hdXRob3JpemUgPSBmdW5jdGlvbiAob3B0aW9ucywgcmVzcG9uc2UpIHtcbiAgICAgICAgaWYgKG9wdGlvbnMuZHVyYXRpb24pIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiREVQUkVDQVRFRDogJ2R1cmF0aW9uJyBpcyBkZXByZWNhdGVkIC0gdXNlICdleHBpcmF0aW9uJyBpbnN0ZWFkXCIpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBfYSA9IF9fYXNzaWduKHsgcG9ydGFsOiBcImh0dHBzOi8vYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIiwgZXhwaXJhdGlvbjogMjAxNjAgfSwgb3B0aW9ucyksIHBvcnRhbCA9IF9hLnBvcnRhbCwgY2xpZW50SWQgPSBfYS5jbGllbnRJZCwgZXhwaXJhdGlvbiA9IF9hLmV4cGlyYXRpb24sIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmk7XG4gICAgICAgIHJlc3BvbnNlLndyaXRlSGVhZCgzMDEsIHtcbiAgICAgICAgICAgIExvY2F0aW9uOiBwb3J0YWwgKyBcIi9vYXV0aDIvYXV0aG9yaXplP2NsaWVudF9pZD1cIiArIGNsaWVudElkICsgXCImZXhwaXJhdGlvbj1cIiArIChvcHRpb25zLmR1cmF0aW9uIHx8IGV4cGlyYXRpb24pICsgXCImcmVzcG9uc2VfdHlwZT1jb2RlJnJlZGlyZWN0X3VyaT1cIiArIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSksXG4gICAgICAgIH0pO1xuICAgICAgICByZXNwb25zZS5lbmQoKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIENvbXBsZXRlcyB0aGUgc2VydmVyLWJhc2VkIE9BdXRoIDIuMCBzaWduIGluIHByb2Nlc3MgYnkgZXhjaGFuZ2luZyB0aGUgYGF1dGhvcml6YXRpb25Db2RlYFxuICAgICAqIGZvciBhIGBhY2Nlc3NfdG9rZW5gLlxuICAgICAqXG4gICAgICogQG5vZGVPbmx5XG4gICAgICovXG4gICAgVXNlclNlc3Npb24uZXhjaGFuZ2VBdXRob3JpemF0aW9uQ29kZSA9IGZ1bmN0aW9uIChvcHRpb25zLCBhdXRob3JpemF0aW9uQ29kZSkge1xuICAgICAgICB2YXIgX2EgPSBfX2Fzc2lnbih7XG4gICAgICAgICAgICBwb3J0YWw6IFwiaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogMjAxNjAsXG4gICAgICAgIH0sIG9wdGlvbnMpLCBwb3J0YWwgPSBfYS5wb3J0YWwsIGNsaWVudElkID0gX2EuY2xpZW50SWQsIHJlZGlyZWN0VXJpID0gX2EucmVkaXJlY3RVcmksIHJlZnJlc2hUb2tlblRUTCA9IF9hLnJlZnJlc2hUb2tlblRUTDtcbiAgICAgICAgcmV0dXJuIGZldGNoVG9rZW4ocG9ydGFsICsgXCIvb2F1dGgyL3Rva2VuXCIsIHtcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGdyYW50X3R5cGU6IFwiYXV0aG9yaXphdGlvbl9jb2RlXCIsXG4gICAgICAgICAgICAgICAgY2xpZW50X2lkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICByZWRpcmVjdF91cmk6IHJlZGlyZWN0VXJpLFxuICAgICAgICAgICAgICAgIGNvZGU6IGF1dGhvcml6YXRpb25Db2RlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgfSkudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgICAgIGNsaWVudElkOiBjbGllbnRJZCxcbiAgICAgICAgICAgICAgICBwb3J0YWw6IHBvcnRhbCxcbiAgICAgICAgICAgICAgICBzc2w6IHJlc3BvbnNlLnNzbCxcbiAgICAgICAgICAgICAgICByZWRpcmVjdFVyaTogcmVkaXJlY3RVcmksXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuOiByZXNwb25zZS5yZWZyZXNoVG9rZW4sXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuVFRMOiByZWZyZXNoVG9rZW5UVEwsXG4gICAgICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogbmV3IERhdGUoRGF0ZS5ub3coKSArIChyZWZyZXNoVG9rZW5UVEwgLSAxKSAqIDYwICogMTAwMCksXG4gICAgICAgICAgICAgICAgdG9rZW46IHJlc3BvbnNlLnRva2VuLFxuICAgICAgICAgICAgICAgIHRva2VuRXhwaXJlczogcmVzcG9uc2UuZXhwaXJlcyxcbiAgICAgICAgICAgICAgICB1c2VybmFtZTogcmVzcG9uc2UudXNlcm5hbWUsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBVc2VyU2Vzc2lvbi5kZXNlcmlhbGl6ZSA9IGZ1bmN0aW9uIChzdHIpIHtcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBKU09OLnBhcnNlKHN0cik7XG4gICAgICAgIHJldHVybiBuZXcgVXNlclNlc3Npb24oe1xuICAgICAgICAgICAgY2xpZW50SWQ6IG9wdGlvbnMuY2xpZW50SWQsXG4gICAgICAgICAgICByZWZyZXNoVG9rZW46IG9wdGlvbnMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogbmV3IERhdGUob3B0aW9ucy5yZWZyZXNoVG9rZW5FeHBpcmVzKSxcbiAgICAgICAgICAgIHVzZXJuYW1lOiBvcHRpb25zLnVzZXJuYW1lLFxuICAgICAgICAgICAgcGFzc3dvcmQ6IG9wdGlvbnMucGFzc3dvcmQsXG4gICAgICAgICAgICB0b2tlbjogb3B0aW9ucy50b2tlbixcbiAgICAgICAgICAgIHRva2VuRXhwaXJlczogbmV3IERhdGUob3B0aW9ucy50b2tlbkV4cGlyZXMpLFxuICAgICAgICAgICAgcG9ydGFsOiBvcHRpb25zLnBvcnRhbCxcbiAgICAgICAgICAgIHNzbDogb3B0aW9ucy5zc2wsXG4gICAgICAgICAgICB0b2tlbkR1cmF0aW9uOiBvcHRpb25zLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICByZWRpcmVjdFVyaTogb3B0aW9ucy5yZWRpcmVjdFVyaSxcbiAgICAgICAgICAgIHJlZnJlc2hUb2tlblRUTDogb3B0aW9ucy5yZWZyZXNoVG9rZW5UVEwsXG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogVHJhbnNsYXRlcyBhdXRoZW50aWNhdGlvbiBmcm9tIHRoZSBmb3JtYXQgdXNlZCBpbiB0aGUgW0FyY0dJUyBBUEkgZm9yIEphdmFTY3JpcHRdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL2phdmFzY3JpcHQvKS5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwoe1xuICAgICAqICAgdXNlcklkOiBcImpzbWl0aFwiLFxuICAgICAqICAgdG9rZW46IFwic2VjcmV0XCJcbiAgICAgKiB9KTtcbiAgICAgKiBgYGBcbiAgICAgKlxuICAgICAqIEByZXR1cm5zIFVzZXJTZXNzaW9uXG4gICAgICovXG4gICAgVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwgPSBmdW5jdGlvbiAoY3JlZGVudGlhbCkge1xuICAgICAgICAvLyBBdCBBcmNHSVMgT25saW5lIDkuMSwgY3JlZGVudGlhbHMgbm8gbG9uZ2VyIGluY2x1ZGUgdGhlIHNzbCBhbmQgZXhwaXJlcyBwcm9wZXJ0aWVzXG4gICAgICAgIC8vIEhlcmUsIHdlIHByb3ZpZGUgZGVmYXVsdCB2YWx1ZXMgZm9yIHRoZW0gdG8gY292ZXIgdGhpcyBjb25kaXRpb25cbiAgICAgICAgdmFyIHNzbCA9IHR5cGVvZiBjcmVkZW50aWFsLnNzbCAhPT0gXCJ1bmRlZmluZWRcIiA/IGNyZWRlbnRpYWwuc3NsIDogdHJ1ZTtcbiAgICAgICAgdmFyIGV4cGlyZXMgPSBjcmVkZW50aWFsLmV4cGlyZXMgfHwgRGF0ZS5ub3coKSArIDcyMDAwMDA7IC8qIDIgaG91cnMgKi9cbiAgICAgICAgcmV0dXJuIG5ldyBVc2VyU2Vzc2lvbih7XG4gICAgICAgICAgICBwb3J0YWw6IGNyZWRlbnRpYWwuc2VydmVyLmluY2x1ZGVzKFwic2hhcmluZy9yZXN0XCIpXG4gICAgICAgICAgICAgICAgPyBjcmVkZW50aWFsLnNlcnZlclxuICAgICAgICAgICAgICAgIDogY3JlZGVudGlhbC5zZXJ2ZXIgKyBcIi9zaGFyaW5nL3Jlc3RcIixcbiAgICAgICAgICAgIHNzbDogc3NsLFxuICAgICAgICAgICAgdG9rZW46IGNyZWRlbnRpYWwudG9rZW4sXG4gICAgICAgICAgICB1c2VybmFtZTogY3JlZGVudGlhbC51c2VySWQsXG4gICAgICAgICAgICB0b2tlbkV4cGlyZXM6IG5ldyBEYXRlKGV4cGlyZXMpLFxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEhhbmRsZSB0aGUgcmVzcG9uc2UgZnJvbSB0aGUgcGFyZW50XG4gICAgICogQHBhcmFtIGV2ZW50IERPTSBFdmVudFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnBhcmVudE1lc3NhZ2VIYW5kbGVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIGlmIChldmVudC5kYXRhLnR5cGUgPT09IFwiYXJjZ2lzOmF1dGg6Y3JlZGVudGlhbFwiKSB7XG4gICAgICAgICAgICByZXR1cm4gVXNlclNlc3Npb24uZnJvbUNyZWRlbnRpYWwoZXZlbnQuZGF0YS5jcmVkZW50aWFsKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZXZlbnQuZGF0YS50eXBlID09PSBcImFyY2dpczphdXRoOmVycm9yXCIpIHtcbiAgICAgICAgICAgIHZhciBlcnIgPSBuZXcgRXJyb3IoZXZlbnQuZGF0YS5lcnJvci5tZXNzYWdlKTtcbiAgICAgICAgICAgIGVyci5uYW1lID0gZXZlbnQuZGF0YS5lcnJvci5uYW1lO1xuICAgICAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiVW5rbm93biBtZXNzYWdlIHR5cGUuXCIpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGF1dGhlbnRpY2F0aW9uIGluIGEgZm9ybWF0IHVzZWFibGUgaW4gdGhlIFtBcmNHSVMgQVBJIGZvciBKYXZhU2NyaXB0XShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9qYXZhc2NyaXB0LykuXG4gICAgICpcbiAgICAgKiBgYGBqc1xuICAgICAqIGVzcmlJZC5yZWdpc3RlclRva2VuKHNlc3Npb24udG9DcmVkZW50aWFsKCkpO1xuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHJldHVybnMgSUNyZWRlbnRpYWxcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudG9DcmVkZW50aWFsID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgZXhwaXJlczogdGhpcy50b2tlbkV4cGlyZXMuZ2V0VGltZSgpLFxuICAgICAgICAgICAgc2VydmVyOiB0aGlzLnBvcnRhbCxcbiAgICAgICAgICAgIHNzbDogdGhpcy5zc2wsXG4gICAgICAgICAgICB0b2tlbjogdGhpcy50b2tlbixcbiAgICAgICAgICAgIHVzZXJJZDogdGhpcy51c2VybmFtZSxcbiAgICAgICAgfTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgaW5mb3JtYXRpb24gYWJvdXQgdGhlIGN1cnJlbnRseSBsb2dnZWQgaW4gW3VzZXJdKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy91c2VyLmh0bSkuIFN1YnNlcXVlbnQgY2FsbHMgd2lsbCAqbm90KiByZXN1bHQgaW4gYWRkaXRpb25hbCB3ZWIgdHJhZmZpYy5cbiAgICAgKlxuICAgICAqIGBgYGpzXG4gICAgICogc2Vzc2lvbi5nZXRVc2VyKClcbiAgICAgKiAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgKiAgICAgY29uc29sZS5sb2cocmVzcG9uc2Uucm9sZSk7IC8vIFwib3JnX2FkbWluXCJcbiAgICAgKiAgIH0pXG4gICAgICogYGBgXG4gICAgICpcbiAgICAgKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC4gTk9URTogYHJhd1Jlc3BvbnNlYCBpcyBub3Qgc3VwcG9ydGVkIGJ5IHRoaXMgb3BlcmF0aW9uLlxuICAgICAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkYXRhIGZyb20gdGhlIHJlc3BvbnNlLlxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRVc2VyID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3QpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVXNlclJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5fdXNlcikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLl91c2VyKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHZhciB1cmwgPSB0aGlzLnBvcnRhbCArIFwiL2NvbW11bml0eS9zZWxmXCI7XG4gICAgICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKF9fYXNzaWduKHsgaHR0cE1ldGhvZDogXCJHRVRcIiwgYXV0aGVudGljYXRpb246IHRoaXMgfSwgcmVxdWVzdE9wdGlvbnMpLCB7IHJhd1Jlc3BvbnNlOiBmYWxzZSB9KTtcbiAgICAgICAgICAgIHRoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdCA9IHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIF90aGlzLl91c2VyID0gcmVzcG9uc2U7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BlbmRpbmdVc2VyUmVxdWVzdCA9IG51bGw7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1VzZXJSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIGluZm9ybWF0aW9uIGFib3V0IHRoZSBjdXJyZW50bHkgbG9nZ2VkIGluIHVzZXIncyBbcG9ydGFsXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3VzZXJzLWdyb3Vwcy1hbmQtaXRlbXMvcG9ydGFsLXNlbGYuaHRtKS4gU3Vic2VxdWVudCBjYWxscyB3aWxsICpub3QqIHJlc3VsdCBpbiBhZGRpdGlvbmFsIHdlYiB0cmFmZmljLlxuICAgICAqXG4gICAgICogYGBganNcbiAgICAgKiBzZXNzaW9uLmdldFBvcnRhbCgpXG4gICAgICogICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICogICAgIGNvbnNvbGUubG9nKHBvcnRhbC5uYW1lKTsgLy8gXCJDaXR5IG9mIC4uLlwiXG4gICAgICogICB9KVxuICAgICAqIGBgYFxuICAgICAqXG4gICAgICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuIE5PVEU6IGByYXdSZXNwb25zZWAgaXMgbm90IHN1cHBvcnRlZCBieSB0aGlzIG9wZXJhdGlvbi5cbiAgICAgKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGF0YSBmcm9tIHRoZSByZXNwb25zZS5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0UG9ydGFsID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdQb3J0YWxSZXF1ZXN0O1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHRoaXMuX3BvcnRhbEluZm8pIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy5fcG9ydGFsSW5mbyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB2YXIgdXJsID0gdGhpcy5wb3J0YWwgKyBcIi9wb3J0YWxzL3NlbGZcIjtcbiAgICAgICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIkdFVFwiLCBhdXRoZW50aWNhdGlvbjogdGhpcyB9LCByZXF1ZXN0T3B0aW9ucyksIHsgcmF3UmVzcG9uc2U6IGZhbHNlIH0pO1xuICAgICAgICAgICAgdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3QgPSByZXF1ZXN0KHVybCwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5fcG9ydGFsSW5mbyA9IHJlc3BvbnNlO1xuICAgICAgICAgICAgICAgIF90aGlzLl9wZW5kaW5nUG9ydGFsUmVxdWVzdCA9IG51bGw7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5fcGVuZGluZ1BvcnRhbFJlcXVlc3Q7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgdGhlIHVzZXJuYW1lIGZvciB0aGUgY3VycmVudGx5IGxvZ2dlZCBpbiBbdXNlcl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC91c2Vycy1ncm91cHMtYW5kLWl0ZW1zL3VzZXIuaHRtKS4gU3Vic2VxdWVudCBjYWxscyB3aWxsICpub3QqIHJlc3VsdCBpbiBhZGRpdGlvbmFsIHdlYiB0cmFmZmljLiBUaGlzIGlzIGFsc28gdXNlZCBpbnRlcm5hbGx5IHdoZW4gYSB1c2VybmFtZSBpcyByZXF1aXJlZCBmb3Igc29tZSByZXF1ZXN0cyBidXQgaXMgbm90IHByZXNlbnQgaW4gdGhlIG9wdGlvbnMuXG4gICAgICpcbiAgICAgKiAgICAqIGBgYGpzXG4gICAgICogc2Vzc2lvbi5nZXRVc2VybmFtZSgpXG4gICAgICogICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICogICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTsgLy8gXCJjYXNleV9qb25lc1wiXG4gICAgICogICB9KVxuICAgICAqIGBgYFxuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5nZXRVc2VybmFtZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKHRoaXMudXNlcm5hbWUpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy51c2VybmFtZSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5fdXNlcikge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzLl91c2VyLnVzZXJuYW1lKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldFVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHVzZXIudXNlcm5hbWU7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLyoqXG4gICAgICogR2V0cyBhbiBhcHByb3ByaWF0ZSB0b2tlbiBmb3IgdGhlIGdpdmVuIFVSTC4gSWYgYHBvcnRhbGAgaXMgQXJjR0lTIE9ubGluZSBhbmRcbiAgICAgKiB0aGUgcmVxdWVzdCBpcyB0byBhbiBBcmNHSVMgT25saW5lIGRvbWFpbiBgdG9rZW5gIHdpbGwgYmUgdXNlZC4gSWYgdGhlIHJlcXVlc3RcbiAgICAgKiBpcyB0byB0aGUgY3VycmVudCBgcG9ydGFsYCB0aGUgY3VycmVudCBgdG9rZW5gIHdpbGwgYWxzbyBiZSB1c2VkLiBIb3dldmVyIGlmXG4gICAgICogdGhlIHJlcXVlc3QgaXMgdG8gYW4gdW5rbm93biBzZXJ2ZXIgd2Ugd2lsbCB2YWxpZGF0ZSB0aGUgc2VydmVyIHdpdGggYSByZXF1ZXN0XG4gICAgICogdG8gb3VyIGN1cnJlbnQgYHBvcnRhbGAuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFRva2VuID0gZnVuY3Rpb24gKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgaWYgKGNhblVzZU9ubGluZVRva2VuKHRoaXMucG9ydGFsLCB1cmwpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRGcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChuZXcgUmVnRXhwKHRoaXMucG9ydGFsLCBcImlcIikudGVzdCh1cmwpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5nZXRGcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmdldFRva2VuRm9yU2VydmVyKHVybCwgcmVxdWVzdE9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBHZXQgYXBwbGljYXRpb24gYWNjZXNzIGluZm9ybWF0aW9uIGZvciB0aGUgY3VycmVudCB1c2VyXG4gICAgICogc2VlIGB2YWxpZGF0ZUFwcEFjY2Vzc2AgZnVuY3Rpb24gZm9yIGRldGFpbHNcbiAgICAgKlxuICAgICAqIEBwYXJhbSBjbGllbnRJZCBhcHBsaWNhdGlvbiBjbGllbnQgaWRcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudmFsaWRhdGVBcHBBY2Nlc3MgPSBmdW5jdGlvbiAoY2xpZW50SWQpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW4odGhpcy5wb3J0YWwpLnRoZW4oZnVuY3Rpb24gKHRva2VuKSB7XG4gICAgICAgICAgICByZXR1cm4gdmFsaWRhdGVBcHBBY2Nlc3ModG9rZW4sIGNsaWVudElkKTtcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUudG9KU09OID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgY2xpZW50SWQ6IHRoaXMuY2xpZW50SWQsXG4gICAgICAgICAgICByZWZyZXNoVG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgcmVmcmVzaFRva2VuRXhwaXJlczogdGhpcy5yZWZyZXNoVG9rZW5FeHBpcmVzLFxuICAgICAgICAgICAgdXNlcm5hbWU6IHRoaXMudXNlcm5hbWUsXG4gICAgICAgICAgICBwYXNzd29yZDogdGhpcy5wYXNzd29yZCxcbiAgICAgICAgICAgIHRva2VuOiB0aGlzLnRva2VuLFxuICAgICAgICAgICAgdG9rZW5FeHBpcmVzOiB0aGlzLnRva2VuRXhwaXJlcyxcbiAgICAgICAgICAgIHBvcnRhbDogdGhpcy5wb3J0YWwsXG4gICAgICAgICAgICBzc2w6IHRoaXMuc3NsLFxuICAgICAgICAgICAgdG9rZW5EdXJhdGlvbjogdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgcmVkaXJlY3RVcmk6IHRoaXMucmVkaXJlY3RVcmksXG4gICAgICAgICAgICByZWZyZXNoVG9rZW5UVEw6IHRoaXMucmVmcmVzaFRva2VuVFRMLFxuICAgICAgICB9O1xuICAgIH07XG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnNlcmlhbGl6ZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHRoaXMpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRm9yIGEgXCJIb3N0XCIgYXBwIHRoYXQgZW1iZWRzIG90aGVyIHBsYXRmb3JtIGFwcHMgdmlhIGlmcmFtZXMsIGFmdGVyIGF1dGhlbnRpY2F0aW5nIHRoZSB1c2VyXG4gICAgICogYW5kIGNyZWF0aW5nIGEgVXNlclNlc3Npb24sIHRoZSBhcHAgY2FuIHRoZW4gZW5hYmxlIFwicG9zdCBtZXNzYWdlXCIgc3R5bGUgYXV0aGVudGljYXRpb24gYnkgY2FsbGluZ1xuICAgICAqIHRoaXMgbWV0aG9kLlxuICAgICAqXG4gICAgICogSW50ZXJuYWxseSB0aGlzIGFkZHMgYW4gZXZlbnQgbGlzdGVuZXIgb24gd2luZG93IGZvciB0aGUgYG1lc3NhZ2VgIGV2ZW50XG4gICAgICpcbiAgICAgKiBAcGFyYW0gdmFsaWRDaGlsZE9yaWdpbnMgQXJyYXkgb2Ygb3JpZ2lucyB0aGF0IGFyZSBhbGxvd2VkIHRvIHJlcXVlc3QgYXV0aGVudGljYXRpb24gZnJvbSB0aGUgaG9zdCBhcHBcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZW5hYmxlUG9zdE1lc3NhZ2VBdXRoID0gZnVuY3Rpb24gKHZhbGlkQ2hpbGRPcmlnaW5zLCB3aW4pIHtcbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIG5leHQ6IG11c3QgcGFzcyBpbiBhIG1vY2t3aW5kb3cgZm9yIHRlc3RzIHNvIHdlIGNhbid0IGNvdmVyIHRoZSBvdGhlciBicmFuY2ggKi9cbiAgICAgICAgaWYgKCF3aW4gJiYgd2luZG93KSB7XG4gICAgICAgICAgICB3aW4gPSB3aW5kb3c7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5faG9zdEhhbmRsZXIgPSB0aGlzLmNyZWF0ZVBvc3RNZXNzYWdlSGFuZGxlcih2YWxpZENoaWxkT3JpZ2lucyk7XG4gICAgICAgIHdpbi5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCB0aGlzLl9ob3N0SGFuZGxlciwgZmFsc2UpO1xuICAgIH07XG4gICAgLyoqXG4gICAgICogRm9yIGEgXCJIb3N0XCIgYXBwIHRoYXQgaGFzIGVtYmVkZGVkIG90aGVyIHBsYXRmb3JtIGFwcHMgdmlhIGlmcmFtZXMsIHdoZW4gdGhlIGhvc3QgbmVlZHNcbiAgICAgKiB0byB0cmFuc2l0aW9uIHJvdXRlcywgaXQgc2hvdWxkIGNhbGwgYFVzZXJTZXNzaW9uLmRpc2FibGVQb3N0TWVzc2FnZUF1dGgoKWAgdG8gcmVtb3ZlXG4gICAgICogdGhlIGV2ZW50IGxpc3RlbmVyIGFuZCBwcmV2ZW50IG1lbW9yeSBsZWFrc1xuICAgICAqL1xuICAgIFVzZXJTZXNzaW9uLnByb3RvdHlwZS5kaXNhYmxlUG9zdE1lc3NhZ2VBdXRoID0gZnVuY3Rpb24gKHdpbikge1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dDogbXVzdCBwYXNzIGluIGEgbW9ja3dpbmRvdyBmb3IgdGVzdHMgc28gd2UgY2FuJ3QgY292ZXIgdGhlIG90aGVyIGJyYW5jaCAqL1xuICAgICAgICBpZiAoIXdpbiAmJiB3aW5kb3cpIHtcbiAgICAgICAgICAgIHdpbiA9IHdpbmRvdztcbiAgICAgICAgfVxuICAgICAgICB3aW4ucmVtb3ZlRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgdGhpcy5faG9zdEhhbmRsZXIsIGZhbHNlKTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIE1hbnVhbGx5IHJlZnJlc2hlcyB0aGUgY3VycmVudCBgdG9rZW5gIGFuZCBgdG9rZW5FeHBpcmVzYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFNlc3Npb24gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgLy8gbWFrZSBzdXJlIHN1YnNlcXVlbnQgY2FsbHMgdG8gZ2V0VXNlcigpIGRvbid0IHJldHVybmVkIGNhY2hlZCBtZXRhZGF0YVxuICAgICAgICB0aGlzLl91c2VyID0gbnVsbDtcbiAgICAgICAgaWYgKHRoaXMudXNlcm5hbWUgJiYgdGhpcy5wYXNzd29yZCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFdpdGhVc2VybmFtZUFuZFBhc3N3b3JkKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5jbGllbnRJZCAmJiB0aGlzLnJlZnJlc2hUb2tlbikge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFdpdGhSZWZyZXNoVG9rZW4oKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEFyY0dJU0F1dGhFcnJvcihcIlVuYWJsZSB0byByZWZyZXNoIHRva2VuLlwiKSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBEZXRlcm1pbmVzIHRoZSByb290IG9mIHRoZSBBcmNHSVMgU2VydmVyIG9yIFBvcnRhbCBmb3IgYSBnaXZlbiBVUkwuXG4gICAgICpcbiAgICAgKiBAcGFyYW0gdXJsIHRoZSBVUmwgdG8gZGV0ZXJtaW5lIHRoZSByb290IHVybCBmb3IuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFNlcnZlclJvb3RVcmwgPSBmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgIHZhciByb290ID0gY2xlYW5VcmwodXJsKS5zcGxpdCgvXFwvcmVzdChcXC9hZG1pbik/XFwvc2VydmljZXMoPzpcXC98I3xcXD98JCkvKVswXTtcbiAgICAgICAgdmFyIF9hID0gcm9vdC5tYXRjaCgvKGh0dHBzPzpcXC9cXC8pKC4rKS8pLCBtYXRjaCA9IF9hWzBdLCBwcm90b2NvbCA9IF9hWzFdLCBkb21haW5BbmRQYXRoID0gX2FbMl07XG4gICAgICAgIHZhciBfYiA9IGRvbWFpbkFuZFBhdGguc3BsaXQoXCIvXCIpLCBkb21haW4gPSBfYlswXSwgcGF0aCA9IF9iLnNsaWNlKDEpO1xuICAgICAgICAvLyBvbmx5IHRoZSBkb21haW4gaXMgbG93ZXJjYXNlZCBiZWNhdXNlIGluIHNvbWUgY2FzZXMgYW4gb3JnIGlkIG1pZ2h0IGJlXG4gICAgICAgIC8vIGluIHRoZSBwYXRoIHdoaWNoIGNhbm5vdCBiZSBsb3dlcmNhc2VkLlxuICAgICAgICByZXR1cm4gXCJcIiArIHByb3RvY29sICsgZG9tYWluLnRvTG93ZXJDYXNlKCkgKyBcIi9cIiArIHBhdGguam9pbihcIi9cIik7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZXR1cm5zIHRoZSBwcm9wZXIgW2BjcmVkZW50aWFsc2BdIG9wdGlvbiBmb3IgYGZldGNoYCBmb3IgYSBnaXZlbiBkb21haW4uXG4gICAgICogU2VlIFt0cnVzdGVkIHNlcnZlcl0oaHR0cHM6Ly9lbnRlcnByaXNlLmFyY2dpcy5jb20vZW4vcG9ydGFsL2xhdGVzdC9hZG1pbmlzdGVyL3dpbmRvd3MvY29uZmlndXJlLXNlY3VyaXR5Lmh0bSNFU1JJX1NFQ1RJT04xXzcwQ0MxNTlCMzU0MDQ0MEFCMzI1QkU1RDg5REJFOTRBKS5cbiAgICAgKiBVc2VkIGludGVybmFsbHkgYnkgdW5kZXJseWluZyByZXF1ZXN0IG1ldGhvZHMgdG8gYWRkIHN1cHBvcnQgZm9yIHNwZWNpZmljIHNlY3VyaXR5IGNvbnNpZGVyYXRpb25zLlxuICAgICAqXG4gICAgICogQHBhcmFtIHVybCBUaGUgdXJsIG9mIHRoZSByZXF1ZXN0XG4gICAgICogQHJldHVybnMgXCJpbmNsdWRlXCIgb3IgXCJzYW1lLW9yaWdpblwiXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldERvbWFpbkNyZWRlbnRpYWxzID0gZnVuY3Rpb24gKHVybCkge1xuICAgICAgICBpZiAoIXRoaXMudHJ1c3RlZERvbWFpbnMgfHwgIXRoaXMudHJ1c3RlZERvbWFpbnMubGVuZ3RoKSB7XG4gICAgICAgICAgICByZXR1cm4gXCJzYW1lLW9yaWdpblwiO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzLnRydXN0ZWREb21haW5zLnNvbWUoZnVuY3Rpb24gKGRvbWFpbldpdGhQcm90b2NvbCkge1xuICAgICAgICAgICAgcmV0dXJuIHVybC5zdGFydHNXaXRoKGRvbWFpbldpdGhQcm90b2NvbCk7XG4gICAgICAgIH0pXG4gICAgICAgICAgICA/IFwiaW5jbHVkZVwiXG4gICAgICAgICAgICA6IFwic2FtZS1vcmlnaW5cIjtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybiBhIGZ1bmN0aW9uIHRoYXQgY2xvc2VzIG92ZXIgdGhlIHZhbGlkT3JpZ2lucyBhcnJheSBhbmRcbiAgICAgKiBjYW4gYmUgdXNlZCBhcyBhbiBldmVudCBoYW5kbGVyIGZvciB0aGUgYG1lc3NhZ2VgIGV2ZW50XG4gICAgICpcbiAgICAgKiBAcGFyYW0gdmFsaWRPcmlnaW5zIEFycmF5IG9mIHZhbGlkIG9yaWdpbnNcbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuY3JlYXRlUG9zdE1lc3NhZ2VIYW5kbGVyID0gZnVuY3Rpb24gKHZhbGlkT3JpZ2lucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICAvLyByZXR1cm4gYSBmdW5jdGlvbiB0aGF0IGNsb3NlcyBvdmVyIHRoZSB2YWxpZE9yaWdpbnMgYW5kXG4gICAgICAgIC8vIGhhcyBhY2Nlc3MgdG8gdGhlIGNyZWRlbnRpYWxcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICAgICAgLy8gVmVyaWZ5IHRoYXQgdGhlIG9yaWdpbiBpcyB2YWxpZFxuICAgICAgICAgICAgLy8gTm90ZTogZG8gbm90IHVzZSByZWdleCdzIGhlcmUuIHZhbGlkT3JpZ2lucyBpcyBhbiBhcnJheSBzbyB3ZSdyZSBjaGVja2luZyB0aGF0IHRoZSBldmVudCdzIG9yaWdpblxuICAgICAgICAgICAgLy8gaXMgaW4gdGhlIGFycmF5IHZpYSBleGFjdCBtYXRjaC4gTW9yZSBpbmZvIGFib3V0IGF2b2lkaW5nIHBvc3RNZXNzYWdlIHhzcyBpc3N1ZXMgaGVyZVxuICAgICAgICAgICAgLy8gaHR0cHM6Ly9qbGFqYXJhLmdpdGxhYi5pby93ZWIvMjAyMC8wNy8xNy9Eb21fWFNTX1Bvc3RNZXNzYWdlXzIuaHRtbCN0aXBzYnlwYXNzZXMtaW4tcG9zdG1lc3NhZ2UtdnVsbmVyYWJpbGl0aWVzXG4gICAgICAgICAgICB2YXIgaXNWYWxpZE9yaWdpbiA9IHZhbGlkT3JpZ2lucy5pbmRleE9mKGV2ZW50Lm9yaWdpbikgPiAtMTtcbiAgICAgICAgICAgIC8vIEpTQVBJIGhhbmRsZXMgdGhpcyBzbGlnaHRseSBkaWZmZXJlbnRseSAtIGluc3RlYWQgb2YgY2hlY2tpbmcgYSBsaXN0LCBpdCB3aWxsIHJlc3BvbmQgaWZcbiAgICAgICAgICAgIC8vIGV2ZW50Lm9yaWdpbiA9PT0gd2luZG93LmxvY2F0aW9uLm9yaWdpbiB8fCBldmVudC5vcmlnaW4uZW5kc1dpdGgoJy5hcmNnaXMuY29tJylcbiAgICAgICAgICAgIC8vIEZvciBIdWIsIGFuZCB0byBlbmFibGUgY3Jvc3MgZG9tYWluIGRlYnVnZ2luZyB3aXRoIHBvcnQncyBpbiB1cmxzLCB3ZSBhcmUgb3B0aW5nIHRvXG4gICAgICAgICAgICAvLyB1c2UgYSBsaXN0IG9mIHZhbGlkIG9yaWdpbnNcbiAgICAgICAgICAgIC8vIEVuc3VyZSB0aGUgbWVzc2FnZSB0eXBlIGlzIHNvbWV0aGluZyB3ZSB3YW50IHRvIGhhbmRsZVxuICAgICAgICAgICAgdmFyIGlzVmFsaWRUeXBlID0gZXZlbnQuZGF0YS50eXBlID09PSBcImFyY2dpczphdXRoOnJlcXVlc3RDcmVkZW50aWFsXCI7XG4gICAgICAgICAgICB2YXIgaXNUb2tlblZhbGlkID0gX3RoaXMudG9rZW5FeHBpcmVzLmdldFRpbWUoKSA+IERhdGUubm93KCk7XG4gICAgICAgICAgICBpZiAoaXNWYWxpZE9yaWdpbiAmJiBpc1ZhbGlkVHlwZSkge1xuICAgICAgICAgICAgICAgIHZhciBtc2cgPSB7fTtcbiAgICAgICAgICAgICAgICBpZiAoaXNUb2tlblZhbGlkKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciBjcmVkZW50aWFsID0gX3RoaXMudG9DcmVkZW50aWFsKCk7XG4gICAgICAgICAgICAgICAgICAgIC8vIGFyY2dpczphdXRoOmVycm9yIHdpdGgge25hbWU6IFwiXCIsIG1lc3NhZ2U6IFwiXCJ9XG4gICAgICAgICAgICAgICAgICAgIC8vIHRoZSBmb2xsb3dpbmcgbGluZSBhbGxvd3MgdXMgdG8gY29uZm9ybSB0byBvdXIgc3BlYyB3aXRob3V0IGNoYW5naW5nIG90aGVyIGRlcGVuZGVkLW9uIGZ1bmN0aW9uYWxpdHlcbiAgICAgICAgICAgICAgICAgICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvYmxvYi9tYXN0ZXIvcGFja2FnZXMvYXJjZ2lzLXJlc3QtYXV0aC9wb3N0LW1lc3NhZ2UtYXV0aC1zcGVjLm1kI2FyY2dpc2F1dGhjcmVkZW50aWFsXG4gICAgICAgICAgICAgICAgICAgIGNyZWRlbnRpYWwuc2VydmVyID0gY3JlZGVudGlhbC5zZXJ2ZXIucmVwbGFjZShcIi9zaGFyaW5nL3Jlc3RcIiwgXCJcIik7XG4gICAgICAgICAgICAgICAgICAgIG1zZyA9IHsgdHlwZTogXCJhcmNnaXM6YXV0aDpjcmVkZW50aWFsXCIsIGNyZWRlbnRpYWw6IGNyZWRlbnRpYWwgfTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIFJldHVybiBhbiBlcnJvclxuICAgICAgICAgICAgICAgICAgICBtc2cgPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0eXBlOiBcImFyY2dpczphdXRoOmVycm9yXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICBlcnJvcjoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5hbWU6IFwidG9rZW5FeHBpcmVkRXJyb3JcIixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBtZXNzYWdlOiBcIlNlc3Npb24gdG9rZW4gd2FzIGV4cGlyZWQsIGFuZCBub3QgcmV0dXJuZWQgdG8gdGhlIGNoaWxkIGFwcGxpY2F0aW9uXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBldmVudC5zb3VyY2UucG9zdE1lc3NhZ2UobXNnLCBldmVudC5vcmlnaW4pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgIH07XG4gICAgLyoqXG4gICAgICogVmFsaWRhdGVzIHRoYXQgYSBnaXZlbiBVUkwgaXMgcHJvcGVybHkgZmVkZXJhdGVkIHdpdGggb3VyIGN1cnJlbnQgYHBvcnRhbGAuXG4gICAgICogQXR0ZW1wdHMgdG8gdXNlIHRoZSBpbnRlcm5hbCBgZmVkZXJhdGVkU2VydmVyc2AgY2FjaGUgZmlyc3QuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmdldFRva2VuRm9yU2VydmVyID0gZnVuY3Rpb24gKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgLy8gcmVxdWVzdHMgdG8gL3Jlc3Qvc2VydmljZXMvIGFuZCAvcmVzdC9hZG1pbi9zZXJ2aWNlcy8gYXJlIGJvdGggdmFsaWRcbiAgICAgICAgLy8gRmVkZXJhdGVkIHNlcnZlcnMgbWF5IGhhdmUgaW5jb25zaXN0ZW50IGNhc2luZywgc28gbG93ZXJDYXNlIGl0XG4gICAgICAgIHZhciByb290ID0gdGhpcy5nZXRTZXJ2ZXJSb290VXJsKHVybCk7XG4gICAgICAgIHZhciBleGlzdGluZ1Rva2VuID0gdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdO1xuICAgICAgICBpZiAoZXhpc3RpbmdUb2tlbiAmJlxuICAgICAgICAgICAgZXhpc3RpbmdUb2tlbi5leHBpcmVzICYmXG4gICAgICAgICAgICBleGlzdGluZ1Rva2VuLmV4cGlyZXMuZ2V0VGltZSgpID4gRGF0ZS5ub3coKSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShleGlzdGluZ1Rva2VuLnRva2VuKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbcm9vdF0pIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XSA9IHRoaXMuZmV0Y2hBdXRob3JpemVkRG9tYWlucygpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIHJlcXVlc3Qocm9vdCArIFwiL3Jlc3QvaW5mb1wiLCB7XG4gICAgICAgICAgICAgICAgY3JlZGVudGlhbHM6IF90aGlzLmdldERvbWFpbkNyZWRlbnRpYWxzKHVybCksXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIGlmIChyZXNwb25zZS5vd25pbmdTeXN0ZW1VcmwpIHtcbiAgICAgICAgICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgICAgICAgICAqIGlmIHRoaXMgc2VydmVyIGlzIG5vdCBvd25lZCBieSB0aGlzIHBvcnRhbFxuICAgICAgICAgICAgICAgICAgICAgKiBiYWlsIG91dCB3aXRoIGFuIGVycm9yIHNpbmNlIHdlIGtub3cgd2Ugd29udFxuICAgICAgICAgICAgICAgICAgICAgKiBiZSBhYmxlIHRvIGdlbmVyYXRlIGEgdG9rZW5cbiAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgIGlmICghaXNGZWRlcmF0ZWQocmVzcG9uc2Uub3duaW5nU3lzdGVtVXJsLCBfdGhpcy5wb3J0YWwpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTQXV0aEVycm9yKHVybCArIFwiIGlzIG5vdCBmZWRlcmF0ZWQgd2l0aCBcIiArIF90aGlzLnBvcnRhbCArIFwiLlwiLCBcIk5PVF9GRURFUkFURURcIik7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAgICAgICAgICAgICAqIGlmIHRoZSBzZXJ2ZXIgaXMgZmVkZXJhdGVkLCB1c2UgdGhlIHJlbGV2YW50IHRva2VuIGVuZHBvaW50LlxuICAgICAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVxdWVzdChyZXNwb25zZS5vd25pbmdTeXN0ZW1VcmwgKyBcIi9zaGFyaW5nL3Jlc3QvaW5mb1wiLCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAocmVzcG9uc2UuYXV0aEluZm8gJiZcbiAgICAgICAgICAgICAgICAgICAgX3RoaXMuZmVkZXJhdGVkU2VydmVyc1tyb290XSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgICAgIC8qKlxuICAgICAgICAgICAgICAgICAgICAgKiBpZiBpdHMgYSBzdGFuZC1hbG9uZSBpbnN0YW5jZSBvZiBBcmNHSVMgU2VydmVyIHRoYXQgZG9lc24ndCBhZHZlcnRpc2VcbiAgICAgICAgICAgICAgICAgICAgICogZmVkZXJhdGlvbiwgYnV0IHRoZSByb290IHNlcnZlciB1cmwgaXMgcmVjb2duaXplZCwgdXNlIGl0cyBidWlsdCBpbiB0b2tlbiBlbmRwb2ludC5cbiAgICAgICAgICAgICAgICAgICAgICovXG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoe1xuICAgICAgICAgICAgICAgICAgICAgICAgYXV0aEluZm86IHJlc3BvbnNlLmF1dGhJbmZvLFxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IodXJsICsgXCIgaXMgbm90IGZlZGVyYXRlZCB3aXRoIGFueSBwb3J0YWwgYW5kIGlzIG5vdCBleHBsaWNpdGx5IHRydXN0ZWQuXCIsIFwiTk9UX0ZFREVSQVRFRFwiKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5hdXRoSW5mby50b2tlblNlcnZpY2VzVXJsO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAodG9rZW5TZXJ2aWNlc1VybCkge1xuICAgICAgICAgICAgICAgIC8vIGFuIGV4cGlyZWQgdG9rZW4gY2FudCBiZSB1c2VkIHRvIGdlbmVyYXRlIGEgbmV3IHRva2VuXG4gICAgICAgICAgICAgICAgaWYgKF90aGlzLnRva2VuICYmIF90aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBnZW5lcmF0ZVRva2VuKHRva2VuU2VydmljZXNVcmwsIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRva2VuOiBfdGhpcy50b2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZXJ2ZXJVcmw6IHVybCxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBleHBpcmF0aW9uOiBfdGhpcy50b2tlbkR1cmF0aW9uLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNsaWVudDogXCJyZWZlcmVyXCIsXG4gICAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgLy8gZ2VuZXJhdGUgYW4gZW50aXJlbHkgZnJlc2ggdG9rZW4gaWYgbmVjZXNzYXJ5XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZ2VuZXJhdGVUb2tlbih0b2tlblNlcnZpY2VzVXJsLCB7XG4gICAgICAgICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB1c2VybmFtZTogX3RoaXMudXNlcm5hbWUsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcGFzc3dvcmQ6IF90aGlzLnBhc3N3b3JkLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGV4cGlyYXRpb246IF90aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50OiBcInJlZmVyZXJcIixcbiAgICAgICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIH0pLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5mZWRlcmF0ZWRTZXJ2ZXJzW3Jvb3RdID0ge1xuICAgICAgICAgICAgICAgICAgICBleHBpcmVzOiBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKSxcbiAgICAgICAgICAgICAgICAgICAgdG9rZW46IHJlc3BvbnNlLnRva2VuLFxuICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgZGVsZXRlIF90aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UudG9rZW47XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1tyb290XTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJldHVybnMgYW4gdW5leHBpcmVkIHRva2VuIGZvciB0aGUgY3VycmVudCBgcG9ydGFsYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUuZ2V0RnJlc2hUb2tlbiA9IGZ1bmN0aW9uIChyZXF1ZXN0T3B0aW9ucykge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAodGhpcy50b2tlbiAmJiAhdGhpcy50b2tlbkV4cGlyZXMpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy50b2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMudG9rZW4gJiZcbiAgICAgICAgICAgIHRoaXMudG9rZW5FeHBpcmVzICYmXG4gICAgICAgICAgICB0aGlzLnRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPiBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMudG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy5fcGVuZGluZ1Rva2VuUmVxdWVzdHNbdGhpcy5wb3J0YWxdKSB7XG4gICAgICAgICAgICB0aGlzLl9wZW5kaW5nVG9rZW5SZXF1ZXN0c1t0aGlzLnBvcnRhbF0gPSB0aGlzLnJlZnJlc2hTZXNzaW9uKHJlcXVlc3RPcHRpb25zKS50aGVuKGZ1bmN0aW9uIChzZXNzaW9uKSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW190aGlzLnBvcnRhbF0gPSBudWxsO1xuICAgICAgICAgICAgICAgIHJldHVybiBzZXNzaW9uLnRva2VuO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMuX3BlbmRpbmdUb2tlblJlcXVlc3RzW3RoaXMucG9ydGFsXTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIFJlZnJlc2hlcyB0aGUgY3VycmVudCBgdG9rZW5gIGFuZCBgdG9rZW5FeHBpcmVzYCB3aXRoIGB1c2VybmFtZWAgYW5kXG4gICAgICogYHBhc3N3b3JkYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFdpdGhVc2VybmFtZUFuZFBhc3N3b3JkID0gZnVuY3Rpb24gKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICB1c2VybmFtZTogdGhpcy51c2VybmFtZSxcbiAgICAgICAgICAgICAgICBwYXNzd29yZDogdGhpcy5wYXNzd29yZCxcbiAgICAgICAgICAgICAgICBleHBpcmF0aW9uOiB0aGlzLnRva2VuRHVyYXRpb24sXG4gICAgICAgICAgICB9IH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIGdlbmVyYXRlVG9rZW4odGhpcy5wb3J0YWwgKyBcIi9nZW5lcmF0ZVRva2VuXCIsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShyZXNwb25zZS5leHBpcmVzKTtcbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBSZWZyZXNoZXMgdGhlIGN1cnJlbnQgYHRva2VuYCBhbmQgYHRva2VuRXhwaXJlc2Agd2l0aCBgcmVmcmVzaFRva2VuYC5cbiAgICAgKi9cbiAgICBVc2VyU2Vzc2lvbi5wcm90b3R5cGUucmVmcmVzaFdpdGhSZWZyZXNoVG9rZW4gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgaWYgKHRoaXMucmVmcmVzaFRva2VuICYmXG4gICAgICAgICAgICB0aGlzLnJlZnJlc2hUb2tlbkV4cGlyZXMgJiZcbiAgICAgICAgICAgIHRoaXMucmVmcmVzaFRva2VuRXhwaXJlcy5nZXRUaW1lKCkgPCBEYXRlLm5vdygpKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5yZWZyZXNoUmVmcmVzaFRva2VuKHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgb3B0aW9ucyA9IF9fYXNzaWduKHsgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgY2xpZW50X2lkOiB0aGlzLmNsaWVudElkLFxuICAgICAgICAgICAgICAgIHJlZnJlc2hfdG9rZW46IHRoaXMucmVmcmVzaFRva2VuLFxuICAgICAgICAgICAgICAgIGdyYW50X3R5cGU6IFwicmVmcmVzaF90b2tlblwiLFxuICAgICAgICAgICAgfSB9LCByZXF1ZXN0T3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBmZXRjaFRva2VuKHRoaXMucG9ydGFsICsgXCIvb2F1dGgyL3Rva2VuXCIsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICBfdGhpcy5fdG9rZW4gPSByZXNwb25zZS50b2tlbjtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbkV4cGlyZXMgPSByZXNwb25zZS5leHBpcmVzO1xuICAgICAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIC8qKlxuICAgICAqIEV4Y2hhbmdlcyBhbiB1bmV4cGlyZWQgYHJlZnJlc2hUb2tlbmAgZm9yIGEgbmV3IG9uZSwgYWxzbyB1cGRhdGVzIGB0b2tlbmAgYW5kXG4gICAgICogYHRva2VuRXhwaXJlc2AuXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLnJlZnJlc2hSZWZyZXNoVG9rZW4gPSBmdW5jdGlvbiAocmVxdWVzdE9wdGlvbnMpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbih7IHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGNsaWVudF9pZDogdGhpcy5jbGllbnRJZCxcbiAgICAgICAgICAgICAgICByZWZyZXNoX3Rva2VuOiB0aGlzLnJlZnJlc2hUb2tlbixcbiAgICAgICAgICAgICAgICByZWRpcmVjdF91cmk6IHRoaXMucmVkaXJlY3RVcmksXG4gICAgICAgICAgICAgICAgZ3JhbnRfdHlwZTogXCJleGNoYW5nZV9yZWZyZXNoX3Rva2VuXCIsXG4gICAgICAgICAgICB9IH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIGZldGNoVG9rZW4odGhpcy5wb3J0YWwgKyBcIi9vYXV0aDIvdG9rZW5cIiwgb3B0aW9ucykudGhlbihmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIF90aGlzLl90b2tlbiA9IHJlc3BvbnNlLnRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3Rva2VuRXhwaXJlcyA9IHJlc3BvbnNlLmV4cGlyZXM7XG4gICAgICAgICAgICBfdGhpcy5fcmVmcmVzaFRva2VuID0gcmVzcG9uc2UucmVmcmVzaFRva2VuO1xuICAgICAgICAgICAgX3RoaXMuX3JlZnJlc2hUb2tlbkV4cGlyZXMgPSBuZXcgRGF0ZShEYXRlLm5vdygpICsgKF90aGlzLnJlZnJlc2hUb2tlblRUTCAtIDEpICogNjAgKiAxMDAwKTtcbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICAvKipcbiAgICAgKiBlbnN1cmVzIHRoYXQgdGhlIGF1dGhvcml6ZWRDcm9zc09yaWdpbkRvbWFpbnMgYXJlIG9idGFpbmVkIGZyb20gdGhlIHBvcnRhbCBhbmQgY2FjaGVkXG4gICAgICogc28gd2UgY2FuIGNoZWNrIHRoZW0gbGF0ZXIuXG4gICAgICpcbiAgICAgKiBAcmV0dXJucyB0aGlzXG4gICAgICovXG4gICAgVXNlclNlc3Npb24ucHJvdG90eXBlLmZldGNoQXV0aG9yaXplZERvbWFpbnMgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIC8vIGlmIHRoaXMgdG9rZW4gaXMgZm9yIGEgc3BlY2lmaWMgc2VydmVyIG9yIHdlIGRvbid0IGhhdmUgYSBwb3J0YWxcbiAgICAgICAgLy8gZG9uJ3QgZ2V0IHRoZSBwb3J0YWwgaW5mbyBiZWNhdXNlIHdlIGNhbnQgZ2V0IHRoZSBhdXRob3JpemVkQ3Jvc3NPcmlnaW5Eb21haW5zXG4gICAgICAgIGlmICh0aGlzLnNlcnZlciB8fCAhdGhpcy5wb3J0YWwpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcyk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXMuZ2V0UG9ydGFsKCkudGhlbihmdW5jdGlvbiAocG9ydGFsSW5mbykge1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBTcGVjaWZpYyBkb21haW5zIGNhbiBiZSBjb25maWd1cmVkIGFzIHNlY3VyZS5lc3JpLmNvbSBvciBodHRwczovL3NlY3VyZS5lc3JpLmNvbSB0aGlzXG4gICAgICAgICAgICAgKiBub3JtYWxpemVzIHRvIGh0dHBzOi8vc2VjdXJlLmVzcmkuY29tIHNvIHdlIGNhbiB1c2Ugc3RhcnRzV2l0aCBsYXRlci5cbiAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgaWYgKHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWlucyAmJlxuICAgICAgICAgICAgICAgIHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWlucy5sZW5ndGgpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy50cnVzdGVkRG9tYWlucyA9IHBvcnRhbEluZm8uYXV0aG9yaXplZENyb3NzT3JpZ2luRG9tYWluc1xuICAgICAgICAgICAgICAgICAgICAuZmlsdGVyKGZ1bmN0aW9uIChkKSB7IHJldHVybiAhZC5zdGFydHNXaXRoKFwiaHR0cDovL1wiKTsgfSlcbiAgICAgICAgICAgICAgICAgICAgLm1hcChmdW5jdGlvbiAoZCkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoZC5zdGFydHNXaXRoKFwiaHR0cHM6Ly9cIikpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBkO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiaHR0cHM6Ly9cIiArIGQ7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBfdGhpcztcbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICByZXR1cm4gVXNlclNlc3Npb247XG59KCkpO1xuZXhwb3J0IHsgVXNlclNlc3Npb24gfTtcbi8vIyBzb3VyY2VNYXBwaW5nVVJMPVVzZXJTZXNzaW9uLmpzLm1hcCIsImltcG9ydCB7IGNsZWFuVXJsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogVXNlZCB0byB0ZXN0IGlmIGEgVVJMIGlzIGFuIEFyY0dJUyBPbmxpbmUgVVJMXG4gKi9cbnZhciBhcmNnaXNPbmxpbmVVcmxSZWdleCA9IC9eaHR0cHM/OlxcL1xcLyhcXFMrKVxcLmFyY2dpc1xcLmNvbS4rLztcbi8qKlxuICogVXNlZCB0byB0ZXN0IGlmIGEgVVJMIGlzIHByb2R1Y3Rpb24gQXJjR0lTIE9ubGluZSBQb3J0YWxcbiAqL1xudmFyIGFyY2dpc09ubGluZVBvcnRhbFJlZ2V4ID0gL15odHRwcz86XFwvXFwvKGRldnxkZXZleHR8cWF8cWFleHR8d3d3KVxcLmFyY2dpc1xcLmNvbVxcL3NoYXJpbmdcXC9yZXN0Ky87XG4vKipcbiAqIFVzZWQgdG8gdGVzdCBpZiBhIFVSTCBpcyBhbiBBcmNHSVMgT25saW5lIE9yZ2FuaXphdGlvbiBQb3J0YWxcbiAqL1xudmFyIGFyY2dpc09ubGluZU9yZ1BvcnRhbFJlZ2V4ID0gL15odHRwcz86XFwvXFwvKD86W2EtejAtOS1dK1xcLm1hcHMoZGV2fGRldmV4dHxxYXxxYWV4dCk/KT8uYXJjZ2lzXFwuY29tXFwvc2hhcmluZ1xcL3Jlc3QvO1xuZXhwb3J0IGZ1bmN0aW9uIGlzT25saW5lKHVybCkge1xuICAgIHJldHVybiBhcmNnaXNPbmxpbmVVcmxSZWdleC50ZXN0KHVybCk7XG59XG5leHBvcnQgZnVuY3Rpb24gbm9ybWFsaXplT25saW5lUG9ydGFsVXJsKHBvcnRhbFVybCkge1xuICAgIGlmICghYXJjZ2lzT25saW5lVXJsUmVnZXgudGVzdChwb3J0YWxVcmwpKSB7XG4gICAgICAgIHJldHVybiBwb3J0YWxVcmw7XG4gICAgfVxuICAgIHN3aXRjaCAoZ2V0T25saW5lRW52aXJvbm1lbnQocG9ydGFsVXJsKSkge1xuICAgICAgICBjYXNlIFwiZGV2XCI6XG4gICAgICAgICAgICByZXR1cm4gXCJodHRwczovL2RldmV4dC5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiO1xuICAgICAgICBjYXNlIFwicWFcIjpcbiAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vcWFleHQuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3RcIjtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHJldHVybiBcImh0dHBzOi8vd3d3LmFyY2dpcy5jb20vc2hhcmluZy9yZXN0XCI7XG4gICAgfVxufVxuZXhwb3J0IGZ1bmN0aW9uIGdldE9ubGluZUVudmlyb25tZW50KHVybCkge1xuICAgIGlmICghYXJjZ2lzT25saW5lVXJsUmVnZXgudGVzdCh1cmwpKSB7XG4gICAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICB2YXIgbWF0Y2ggPSB1cmwubWF0Y2goYXJjZ2lzT25saW5lVXJsUmVnZXgpO1xuICAgIHZhciBzdWJkb21haW4gPSBtYXRjaFsxXS5zcGxpdChcIi5cIikucG9wKCk7XG4gICAgaWYgKHN1YmRvbWFpbi5pbmNsdWRlcyhcImRldlwiKSkge1xuICAgICAgICByZXR1cm4gXCJkZXZcIjtcbiAgICB9XG4gICAgaWYgKHN1YmRvbWFpbi5pbmNsdWRlcyhcInFhXCIpKSB7XG4gICAgICAgIHJldHVybiBcInFhXCI7XG4gICAgfVxuICAgIHJldHVybiBcInByb2R1Y3Rpb25cIjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBpc0ZlZGVyYXRlZChvd25pbmdTeXN0ZW1VcmwsIHBvcnRhbFVybCkge1xuICAgIHZhciBub3JtYWxpemVkUG9ydGFsVXJsID0gY2xlYW5Vcmwobm9ybWFsaXplT25saW5lUG9ydGFsVXJsKHBvcnRhbFVybCkpLnJlcGxhY2UoL2h0dHBzPzpcXC9cXC8vLCBcIlwiKTtcbiAgICB2YXIgbm9ybWFsaXplZE93bmluZ1N5c3RlbVVybCA9IGNsZWFuVXJsKG93bmluZ1N5c3RlbVVybCkucmVwbGFjZSgvaHR0cHM/OlxcL1xcLy8sIFwiXCIpO1xuICAgIHJldHVybiBuZXcgUmVnRXhwKG5vcm1hbGl6ZWRPd25pbmdTeXN0ZW1VcmwsIFwiaVwiKS50ZXN0KG5vcm1hbGl6ZWRQb3J0YWxVcmwpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGNhblVzZU9ubGluZVRva2VuKHBvcnRhbFVybCwgcmVxdWVzdFVybCkge1xuICAgIHZhciBwb3J0YWxJc09ubGluZSA9IGlzT25saW5lKHBvcnRhbFVybCk7XG4gICAgdmFyIHJlcXVlc3RJc09ubGluZSA9IGlzT25saW5lKHJlcXVlc3RVcmwpO1xuICAgIHZhciBwb3J0YWxFbnYgPSBnZXRPbmxpbmVFbnZpcm9ubWVudChwb3J0YWxVcmwpO1xuICAgIHZhciByZXF1ZXN0RW52ID0gZ2V0T25saW5lRW52aXJvbm1lbnQocmVxdWVzdFVybCk7XG4gICAgaWYgKHBvcnRhbElzT25saW5lICYmIHJlcXVlc3RJc09ubGluZSAmJiBwb3J0YWxFbnYgPT09IHJlcXVlc3RFbnYpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIHJldHVybiBmYWxzZTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWZlZGVyYXRpb24tdXRpbHMuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHJlcXVlc3QgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuZXhwb3J0IGZ1bmN0aW9uIGZldGNoVG9rZW4odXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBvcHRpb25zID0gcmVxdWVzdE9wdGlvbnM7XG4gICAgLy8gd2UgZ2VuZXJhdGUgYSByZXNwb25zZSwgc28gd2UgY2FuJ3QgcmV0dXJuIHRoZSByYXcgcmVzcG9uc2VcbiAgICBvcHRpb25zLnJhd1Jlc3BvbnNlID0gZmFsc2U7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKS50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICB2YXIgciA9IHtcbiAgICAgICAgICAgIHRva2VuOiByZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICB1c2VybmFtZTogcmVzcG9uc2UudXNlcm5hbWUsXG4gICAgICAgICAgICBleHBpcmVzOiBuZXcgRGF0ZShcbiAgICAgICAgICAgIC8vIGNvbnZlcnQgc2Vjb25kcyBpbiByZXNwb25zZSB0byBtaWxsaXNlY29uZHMgYW5kIGFkZCB0aGUgdmFsdWUgdG8gdGhlIGN1cnJlbnQgdGltZSB0byBjYWxjdWxhdGUgYSBzdGF0aWMgZXhwaXJhdGlvbiB0aW1lc3RhbXBcbiAgICAgICAgICAgIERhdGUubm93KCkgKyAocmVzcG9uc2UuZXhwaXJlc19pbiAqIDEwMDAgLSAxMDAwKSksXG4gICAgICAgICAgICBzc2w6IHJlc3BvbnNlLnNzbCA9PT0gdHJ1ZVxuICAgICAgICB9O1xuICAgICAgICBpZiAocmVzcG9uc2UucmVmcmVzaF90b2tlbikge1xuICAgICAgICAgICAgci5yZWZyZXNoVG9rZW4gPSByZXNwb25zZS5yZWZyZXNoX3Rva2VuO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByO1xuICAgIH0pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZmV0Y2gtdG9rZW4uanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgcmVxdWVzdCwgTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVIsIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbmV4cG9ydCBmdW5jdGlvbiBnZW5lcmF0ZVRva2VuKHVybCwgcmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgb3B0aW9ucyA9IHJlcXVlc3RPcHRpb25zO1xuICAgIC8qIGlzdGFuYnVsIGlnbm9yZSBlbHNlICovXG4gICAgaWYgKHR5cGVvZiB3aW5kb3cgIT09IFwidW5kZWZpbmVkXCIgJiZcbiAgICAgICAgd2luZG93LmxvY2F0aW9uICYmXG4gICAgICAgIHdpbmRvdy5sb2NhdGlvbi5ob3N0KSB7XG4gICAgICAgIG9wdGlvbnMucGFyYW1zLnJlZmVyZXIgPSB3aW5kb3cubG9jYXRpb24uaG9zdDtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIG9wdGlvbnMucGFyYW1zLnJlZmVyZXIgPSBOT0RFSlNfREVGQVVMVF9SRUZFUkVSX0hFQURFUjtcbiAgICB9XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWdlbmVyYXRlLXRva2VuLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxOC0yMDIwIEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHJlcXVlc3QgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBWYWxpZGF0ZXMgdGhhdCB0aGUgdXNlciBoYXMgYWNjZXNzIHRvIHRoZSBhcHBsaWNhdGlvblxuICogYW5kIGlmIHRoZXkgdXNlciBzaG91bGQgYmUgcHJlc2VudGVkIGEgXCJWaWV3IE9ubHlcIiBtb2RlXG4gKlxuICogVGhpcyBpcyBvbmx5IG5lZWRlZC92YWxpZCBmb3IgRXNyaSBhcHBsaWNhdGlvbnMgdGhhdCBhcmUgXCJsaWNlbnNlZFwiXG4gKiBhbmQgc2hpcHBlZCBpbiBBcmNHSVMgT25saW5lIG9yIEFyY0dJUyBFbnRlcnByaXNlLiBNb3N0IGN1c3RvbSBhcHBsaWNhdGlvbnNcbiAqIHNob3VsZCBub3QgbmVlZCBvciB1c2UgdGhpcy5cbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgdmFsaWRhdGVBcHBBY2Nlc3MgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1hdXRoJztcbiAqXG4gKiByZXR1cm4gdmFsaWRhdGVBcHBBY2Nlc3MoJ3lvdXItdG9rZW4nLCAndGhlQ2xpZW50SWQnKVxuICogLnRoZW4oKHJlc3VsdCkgPT4ge1xuICogICAgaWYgKCFyZXN1bHQudmFsdWUpIHtcbiAqICAgICAgLy8gcmVkaXJlY3Qgb3Igc2hvdyBzb21lIG90aGVyIHVpXG4gKiAgICB9IGVsc2Uge1xuICogICAgICBpZiAocmVzdWx0LnZpZXdPbmx5VXNlclR5cGVBcHApIHtcbiAqICAgICAgICAvLyB1c2UgdGhpcyB0byBpbmZvcm0geW91ciBhcHAgdG8gc2hvdyBhIFwiVmlldyBPbmx5XCIgbW9kZVxuICogICAgICB9XG4gKiAgICB9XG4gKiB9KVxuICogLmNhdGNoKChlcnIpID0+IHtcbiAqICAvLyB0d28gcG9zc2libGUgZXJyb3JzXG4gKiAgLy8gaW52YWxpZCBjbGllbnRJZDoge1wiZXJyb3JcIjp7XCJjb2RlXCI6NDAwLFwibWVzc2FnZUNvZGVcIjpcIkdXTV8wMDA3XCIsXCJtZXNzYWdlXCI6XCJJbnZhbGlkIHJlcXVlc3RcIixcImRldGFpbHNcIjpbXX19XG4gKiAgLy8gaW52YWxpZCB0b2tlbjoge1wiZXJyb3JcIjp7XCJjb2RlXCI6NDk4LFwibWVzc2FnZVwiOlwiSW52YWxpZCB0b2tlbi5cIixcImRldGFpbHNcIjpbXX19XG4gKiB9KVxuICogYGBgXG4gKlxuICogTm90ZTogVGhpcyBpcyBvbmx5IHVzYWJsZSBieSBFc3JpIGFwcGxpY2F0aW9ucyBob3N0ZWQgb24gKmFyY2dpcy5jb20sICplc3JpLmNvbSBvciB3aXRoaW5cbiAqIGFuIEFyY0dJUyBFbnRlcnByaXNlIGluc3RhbGxhdGlvbi4gQ3VzdG9tIGFwcGxpY2F0aW9ucyBjYW4gbm90IHVzZSB0aGlzLlxuICpcbiAqIEBwYXJhbSB0b2tlbiBwbGF0Zm9ybSB0b2tlblxuICogQHBhcmFtIGNsaWVudElkIGFwcGxpY2F0aW9uIGNsaWVudCBpZFxuICogQHBhcmFtIHBvcnRhbCBPcHRpb25hbFxuICovXG5leHBvcnQgZnVuY3Rpb24gdmFsaWRhdGVBcHBBY2Nlc3ModG9rZW4sIGNsaWVudElkLCBwb3J0YWwpIHtcbiAgICBpZiAocG9ydGFsID09PSB2b2lkIDApIHsgcG9ydGFsID0gXCJodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdFwiOyB9XG4gICAgdmFyIHVybCA9IHBvcnRhbCArIFwiL29hdXRoMi92YWxpZGF0ZUFwcEFjY2Vzc1wiO1xuICAgIHZhciBybyA9IHtcbiAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICBmOiBcImpzb25cIixcbiAgICAgICAgICAgIGNsaWVudF9pZDogY2xpZW50SWQsXG4gICAgICAgICAgICB0b2tlbjogdG9rZW4sXG4gICAgICAgIH0sXG4gICAgfTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIHJvKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXZhbGlkYXRlLWFwcC1hY2Nlc3MuanMubWFwIiwiLyohICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXHJcbkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLlxyXG5cclxuUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XHJcbnB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZC5cclxuXHJcblRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEhcclxuUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZXHJcbkFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1IgQU5ZIFNQRUNJQUwsIERJUkVDVCxcclxuSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NXHJcbkxPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SXHJcbk9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1JcclxuUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cclxuKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogKi9cclxuLyogZ2xvYmFsIFJlZmxlY3QsIFByb21pc2UgKi9cclxuXHJcbnZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24oZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxyXG4gICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcclxuICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcclxuICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXh0ZW5kcyhkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG4gICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XHJcbiAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XHJcbn1cclxuXHJcbmV4cG9ydCB2YXIgX19hc3NpZ24gPSBmdW5jdGlvbigpIHtcclxuICAgIF9fYXNzaWduID0gT2JqZWN0LmFzc2lnbiB8fCBmdW5jdGlvbiBfX2Fzc2lnbih0KSB7XHJcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XHJcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XHJcbiAgICAgICAgICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSkgdFtwXSA9IHNbcF07XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3Jlc3QocywgZSkge1xyXG4gICAgdmFyIHQgPSB7fTtcclxuICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSAmJiBlLmluZGV4T2YocCkgPCAwKVxyXG4gICAgICAgIHRbcF0gPSBzW3BdO1xyXG4gICAgaWYgKHMgIT0gbnVsbCAmJiB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBwID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyhzKTsgaSA8IHAubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgaWYgKGUuaW5kZXhPZihwW2ldKSA8IDAgJiYgT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZS5jYWxsKHMsIHBbaV0pKVxyXG4gICAgICAgICAgICAgICAgdFtwW2ldXSA9IHNbcFtpXV07XHJcbiAgICAgICAgfVxyXG4gICAgcmV0dXJuIHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2RlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKSB7XHJcbiAgICB2YXIgYyA9IGFyZ3VtZW50cy5sZW5ndGgsIHIgPSBjIDwgMyA/IHRhcmdldCA6IGRlc2MgPT09IG51bGwgPyBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0YXJnZXQsIGtleSkgOiBkZXNjLCBkO1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0LmRlY29yYXRlID09PSBcImZ1bmN0aW9uXCIpIHIgPSBSZWZsZWN0LmRlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKTtcclxuICAgIGVsc2UgZm9yICh2YXIgaSA9IGRlY29yYXRvcnMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIGlmIChkID0gZGVjb3JhdG9yc1tpXSkgciA9IChjIDwgMyA/IGQocikgOiBjID4gMyA/IGQodGFyZ2V0LCBrZXksIHIpIDogZCh0YXJnZXQsIGtleSkpIHx8IHI7XHJcbiAgICByZXR1cm4gYyA+IDMgJiYgciAmJiBPYmplY3QuZGVmaW5lUHJvcGVydHkodGFyZ2V0LCBrZXksIHIpLCByO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19wYXJhbShwYXJhbUluZGV4LCBkZWNvcmF0b3IpIHtcclxuICAgIHJldHVybiBmdW5jdGlvbiAodGFyZ2V0LCBrZXkpIHsgZGVjb3JhdG9yKHRhcmdldCwga2V5LCBwYXJhbUluZGV4KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSkge1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0Lm1ldGFkYXRhID09PSBcImZ1bmN0aW9uXCIpIHJldHVybiBSZWZsZWN0Lm1ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXRlcih0aGlzQXJnLCBfYXJndW1lbnRzLCBQLCBnZW5lcmF0b3IpIHtcclxuICAgIGZ1bmN0aW9uIGFkb3B0KHZhbHVlKSB7IHJldHVybiB2YWx1ZSBpbnN0YW5jZW9mIFAgPyB2YWx1ZSA6IG5ldyBQKGZ1bmN0aW9uIChyZXNvbHZlKSB7IHJlc29sdmUodmFsdWUpOyB9KTsgfVxyXG4gICAgcmV0dXJuIG5ldyAoUCB8fCAoUCA9IFByb21pc2UpKShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XHJcbiAgICAgICAgZnVuY3Rpb24gZnVsZmlsbGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yLm5leHQodmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHJlamVjdGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yW1widGhyb3dcIl0odmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHN0ZXAocmVzdWx0KSB7IHJlc3VsdC5kb25lID8gcmVzb2x2ZShyZXN1bHQudmFsdWUpIDogYWRvcHQocmVzdWx0LnZhbHVlKS50aGVuKGZ1bGZpbGxlZCwgcmVqZWN0ZWQpOyB9XHJcbiAgICAgICAgc3RlcCgoZ2VuZXJhdG9yID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pKS5uZXh0KCkpO1xyXG4gICAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2dlbmVyYXRvcih0aGlzQXJnLCBib2R5KSB7XHJcbiAgICB2YXIgXyA9IHsgbGFiZWw6IDAsIHNlbnQ6IGZ1bmN0aW9uKCkgeyBpZiAodFswXSAmIDEpIHRocm93IHRbMV07IHJldHVybiB0WzFdOyB9LCB0cnlzOiBbXSwgb3BzOiBbXSB9LCBmLCB5LCB0LCBnO1xyXG4gICAgcmV0dXJuIGcgPSB7IG5leHQ6IHZlcmIoMCksIFwidGhyb3dcIjogdmVyYigxKSwgXCJyZXR1cm5cIjogdmVyYigyKSB9LCB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgKGdbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhpczsgfSksIGc7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgcmV0dXJuIGZ1bmN0aW9uICh2KSB7IHJldHVybiBzdGVwKFtuLCB2XSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAob3ApIHtcclxuICAgICAgICBpZiAoZikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy5cIik7XHJcbiAgICAgICAgd2hpbGUgKF8pIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChmID0gMSwgeSAmJiAodCA9IG9wWzBdICYgMiA/IHlbXCJyZXR1cm5cIl0gOiBvcFswXSA/IHlbXCJ0aHJvd1wiXSB8fCAoKHQgPSB5W1wicmV0dXJuXCJdKSAmJiB0LmNhbGwoeSksIDApIDogeS5uZXh0KSAmJiAhKHQgPSB0LmNhbGwoeSwgb3BbMV0pKS5kb25lKSByZXR1cm4gdDtcclxuICAgICAgICAgICAgaWYgKHkgPSAwLCB0KSBvcCA9IFtvcFswXSAmIDIsIHQudmFsdWVdO1xyXG4gICAgICAgICAgICBzd2l0Y2ggKG9wWzBdKSB7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDA6IGNhc2UgMTogdCA9IG9wOyBicmVhaztcclxuICAgICAgICAgICAgICAgIGNhc2UgNDogXy5sYWJlbCsrOyByZXR1cm4geyB2YWx1ZTogb3BbMV0sIGRvbmU6IGZhbHNlIH07XHJcbiAgICAgICAgICAgICAgICBjYXNlIDU6IF8ubGFiZWwrKzsgeSA9IG9wWzFdOyBvcCA9IFswXTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDc6IG9wID0gXy5vcHMucG9wKCk7IF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgIGlmICghKHQgPSBfLnRyeXMsIHQgPSB0Lmxlbmd0aCA+IDAgJiYgdFt0Lmxlbmd0aCAtIDFdKSAmJiAob3BbMF0gPT09IDYgfHwgb3BbMF0gPT09IDIpKSB7IF8gPSAwOyBjb250aW51ZTsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gMyAmJiAoIXQgfHwgKG9wWzFdID4gdFswXSAmJiBvcFsxXSA8IHRbM10pKSkgeyBfLmxhYmVsID0gb3BbMV07IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSA2ICYmIF8ubGFiZWwgPCB0WzFdKSB7IF8ubGFiZWwgPSB0WzFdOyB0ID0gb3A7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHQgJiYgXy5sYWJlbCA8IHRbMl0pIHsgXy5sYWJlbCA9IHRbMl07IF8ub3BzLnB1c2gob3ApOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0WzJdKSBfLm9wcy5wb3AoKTtcclxuICAgICAgICAgICAgICAgICAgICBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIG9wID0gYm9keS5jYWxsKHRoaXNBcmcsIF8pO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgb3AgPSBbNiwgZV07IHkgPSAwOyB9IGZpbmFsbHkgeyBmID0gdCA9IDA7IH1cclxuICAgICAgICBpZiAob3BbMF0gJiA1KSB0aHJvdyBvcFsxXTsgcmV0dXJuIHsgdmFsdWU6IG9wWzBdID8gb3BbMV0gOiB2b2lkIDAsIGRvbmU6IHRydWUgfTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY3JlYXRlQmluZGluZyhvLCBtLCBrLCBrMikge1xyXG4gICAgaWYgKGsyID09PSB1bmRlZmluZWQpIGsyID0gaztcclxuICAgIG9bazJdID0gbVtrXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXhwb3J0U3RhcihtLCBleHBvcnRzKSB7XHJcbiAgICBmb3IgKHZhciBwIGluIG0pIGlmIChwICE9PSBcImRlZmF1bHRcIiAmJiAhZXhwb3J0cy5oYXNPd25Qcm9wZXJ0eShwKSkgZXhwb3J0c1twXSA9IG1bcF07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3ZhbHVlcyhvKSB7XHJcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xyXG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XHJcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XHJcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xyXG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xyXG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XHJcbiAgICAgICAgfVxyXG4gICAgfTtcclxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVhZChvLCBuKSB7XHJcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XHJcbiAgICBpZiAoIW0pIHJldHVybiBvO1xyXG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xyXG4gICAgfVxyXG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XHJcbiAgICBmaW5hbGx5IHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZCgpIHtcclxuICAgIGZvciAodmFyIGFyID0gW10sIGkgPSAwOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKVxyXG4gICAgICAgIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkQXJyYXlzKCkge1xyXG4gICAgZm9yICh2YXIgcyA9IDAsIGkgPSAwLCBpbCA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBpbDsgaSsrKSBzICs9IGFyZ3VtZW50c1tpXS5sZW5ndGg7XHJcbiAgICBmb3IgKHZhciByID0gQXJyYXkocyksIGsgPSAwLCBpID0gMDsgaSA8IGlsOyBpKyspXHJcbiAgICAgICAgZm9yICh2YXIgYSA9IGFyZ3VtZW50c1tpXSwgaiA9IDAsIGpsID0gYS5sZW5ndGg7IGogPCBqbDsgaisrLCBrKyspXHJcbiAgICAgICAgICAgIHJba10gPSBhW2pdO1xyXG4gICAgcmV0dXJuIHI7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdCh2KSB7XHJcbiAgICByZXR1cm4gdGhpcyBpbnN0YW5jZW9mIF9fYXdhaXQgPyAodGhpcy52ID0gdiwgdGhpcykgOiBuZXcgX19hd2FpdCh2KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNHZW5lcmF0b3IodGhpc0FyZywgX2FyZ3VtZW50cywgZ2VuZXJhdG9yKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIGcgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSksIGksIHEgPSBbXTtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpZiAoZ1tuXSkgaVtuXSA9IGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAoYSwgYikgeyBxLnB1c2goW24sIHYsIGEsIGJdKSA+IDEgfHwgcmVzdW1lKG4sIHYpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gcmVzdW1lKG4sIHYpIHsgdHJ5IHsgc3RlcChnW25dKHYpKTsgfSBjYXRjaCAoZSkgeyBzZXR0bGUocVswXVszXSwgZSk7IH0gfVxyXG4gICAgZnVuY3Rpb24gc3RlcChyKSB7IHIudmFsdWUgaW5zdGFuY2VvZiBfX2F3YWl0ID8gUHJvbWlzZS5yZXNvbHZlKHIudmFsdWUudikudGhlbihmdWxmaWxsLCByZWplY3QpIDogc2V0dGxlKHFbMF1bMl0sIHIpOyB9XHJcbiAgICBmdW5jdGlvbiBmdWxmaWxsKHZhbHVlKSB7IHJlc3VtZShcIm5leHRcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiByZWplY3QodmFsdWUpIHsgcmVzdW1lKFwidGhyb3dcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUoZiwgdikgeyBpZiAoZih2KSwgcS5zaGlmdCgpLCBxLmxlbmd0aCkgcmVzdW1lKHFbMF1bMF0sIHFbMF1bMV0pOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jRGVsZWdhdG9yKG8pIHtcclxuICAgIHZhciBpLCBwO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiLCBmdW5jdGlvbiAoZSkgeyB0aHJvdyBlOyB9KSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobiwgZikgeyBpW25dID0gb1tuXSA/IGZ1bmN0aW9uICh2KSB7IHJldHVybiAocCA9ICFwKSA/IHsgdmFsdWU6IF9fYXdhaXQob1tuXSh2KSksIGRvbmU6IG4gPT09IFwicmV0dXJuXCIgfSA6IGYgPyBmKHYpIDogdjsgfSA6IGY7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNWYWx1ZXMobykge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBtID0gb1tTeW1ib2wuYXN5bmNJdGVyYXRvcl0sIGk7XHJcbiAgICByZXR1cm4gbSA/IG0uY2FsbChvKSA6IChvID0gdHlwZW9mIF9fdmFsdWVzID09PSBcImZ1bmN0aW9uXCIgPyBfX3ZhbHVlcyhvKSA6IG9bU3ltYm9sLml0ZXJhdG9yXSgpLCBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaSk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaVtuXSA9IG9bbl0gJiYgZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHsgdiA9IG9bbl0odiksIHNldHRsZShyZXNvbHZlLCByZWplY3QsIHYuZG9uZSwgdi52YWx1ZSk7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCBkLCB2KSB7IFByb21pc2UucmVzb2x2ZSh2KS50aGVuKGZ1bmN0aW9uKHYpIHsgcmVzb2x2ZSh7IHZhbHVlOiB2LCBkb25lOiBkIH0pOyB9LCByZWplY3QpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ha2VUZW1wbGF0ZU9iamVjdChjb29rZWQsIHJhdykge1xyXG4gICAgaWYgKE9iamVjdC5kZWZpbmVQcm9wZXJ0eSkgeyBPYmplY3QuZGVmaW5lUHJvcGVydHkoY29va2VkLCBcInJhd1wiLCB7IHZhbHVlOiByYXcgfSk7IH0gZWxzZSB7IGNvb2tlZC5yYXcgPSByYXc7IH1cclxuICAgIHJldHVybiBjb29rZWQ7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnRTdGFyKG1vZCkge1xyXG4gICAgaWYgKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgcmV0dXJuIG1vZDtcclxuICAgIHZhciByZXN1bHQgPSB7fTtcclxuICAgIGlmIChtb2QgIT0gbnVsbCkgZm9yICh2YXIgayBpbiBtb2QpIGlmIChPYmplY3QuaGFzT3duUHJvcGVydHkuY2FsbChtb2QsIGspKSByZXN1bHRba10gPSBtb2Rba107XHJcbiAgICByZXN1bHQuZGVmYXVsdCA9IG1vZDtcclxuICAgIHJldHVybiByZXN1bHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydERlZmF1bHQobW9kKSB7XHJcbiAgICByZXR1cm4gKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgPyBtb2QgOiB7IGRlZmF1bHQ6IG1vZCB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZEdldChyZWNlaXZlciwgcHJpdmF0ZU1hcCkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIGdldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHJldHVybiBwcml2YXRlTWFwLmdldChyZWNlaXZlcik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkU2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwLCB2YWx1ZSkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIHNldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHByaXZhdGVNYXAuc2V0KHJlY2VpdmVyLCB2YWx1ZSk7XHJcbiAgICByZXR1cm4gdmFsdWU7XHJcbn1cclxuIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduIH0gZnJvbSBcInRzbGliXCI7XG5pbXBvcnQgeyByZXF1ZXN0LCBjbGVhblVybCwgYXBwZW5kQ3VzdG9tUGFyYW1zIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXJlcXVlc3RcIjtcbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IGFkZEZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogYWRkRmVhdHVyZXMoe1xuICogICB1cmw6IFwiaHR0cHM6Ly9zYW1wbGVzZXJ2ZXI2LmFyY2dpc29ubGluZS5jb20vYXJjZ2lzL3Jlc3Qvc2VydmljZXMvU2VydmljZVJlcXVlc3QvRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgIGZlYXR1cmVzOiBbe1xuICogICAgIGdlb21ldHJ5OiB7IHg6IC0xMjAsIHk6IDQ1LCBzcGF0aWFsUmVmZXJlbmNlOiB7IHdraWQ6IDQzMjYgfSB9LFxuICogICAgIGF0dHJpYnV0ZXM6IHsgc3RhdHVzOiBcImFsaXZlXCIgfVxuICogICB9XVxuICogfSlcbiAqICAgLnRoZW4ocmVzcG9uc2UpXG4gKiBgYGBcbiAqIEFkZCBmZWF0dXJlcyByZXF1ZXN0LiBTZWUgdGhlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL2FkZC1mZWF0dXJlcy5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LlxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIGFkZEZlYXR1cmVzIHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gYWRkRmVhdHVyZXMocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgdXJsID0gY2xlYW5VcmwocmVxdWVzdE9wdGlvbnMudXJsKSArIFwiL2FkZEZlYXR1cmVzXCI7XG4gICAgLy8gZWRpdCBvcGVyYXRpb25zIGFyZSBQT1NUIG9ubHlcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1wiZmVhdHVyZXNcIiwgXCJnZGJWZXJzaW9uXCIsIFwicmV0dXJuRWRpdE1vbWVudFwiLCBcInJvbGxiYWNrT25GYWlsdXJlXCJdLCB7IHBhcmFtczogX19hc3NpZ24oe30sIHJlcXVlc3RPcHRpb25zLnBhcmFtcykgfSk7XG4gICAgcmV0dXJuIHJlcXVlc3QodXJsLCBvcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWFkZC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgZGVsZXRlRmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiBkZWxldGVGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwczovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9TZXJ2aWNlUmVxdWVzdC9GZWF0dXJlU2VydmVyLzBcIixcbiAqICAgb2JqZWN0SWRzOiBbMSwyLDNdXG4gKiB9KTtcbiAqIGBgYFxuICogRGVsZXRlIGZlYXR1cmVzIHJlcXVlc3QuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvZGVsZXRlLWZlYXR1cmVzLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIGRlbGV0ZUZlYXR1cmVzUmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdC5cbiAqIEByZXR1cm5zIEEgUHJvbWlzZSB0aGF0IHdpbGwgcmVzb2x2ZSB3aXRoIHRoZSBkZWxldGVGZWF0dXJlcyByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlbGV0ZUZlYXR1cmVzKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9kZWxldGVGZWF0dXJlc1wiO1xuICAgIC8vIGVkaXQgb3BlcmF0aW9ucyBQT1NUIG9ubHlcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1xuICAgICAgICBcIndoZXJlXCIsXG4gICAgICAgIFwib2JqZWN0SWRzXCIsXG4gICAgICAgIFwiZ2RiVmVyc2lvblwiLFxuICAgICAgICBcInJldHVybkVkaXRNb21lbnRcIixcbiAgICAgICAgXCJyb2xsYmFja09uRmFpbHVyZVwiXG4gICAgXSwgeyBwYXJhbXM6IF9fYXNzaWduKHt9LCByZXF1ZXN0T3B0aW9ucy5wYXJhbXMpIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KHVybCwgb3B0aW9ucyk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1kZWxldGUuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IHJlcXVlc3QsIGNsZWFuVXJsLCBhcHBlbmRDdXN0b21QYXJhbXMgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtcmVxdWVzdFwiO1xuLyoqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgZ2V0RmVhdHVyZSB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXInO1xuICogLy9cbiAqIGNvbnN0IHVybCA9IFwiaHR0cHM6Ly9zZXJ2aWNlcy5hcmNnaXMuY29tL1Y2WkhGcjZ6ZGdOWnVWRzAvYXJjZ2lzL3Jlc3Qvc2VydmljZXMvTGFuZHNjYXBlX1RyZWVzL0ZlYXR1cmVTZXJ2ZXIvMFwiO1xuICogLy9cbiAqIGdldEZlYXR1cmUoe1xuICogICB1cmwsXG4gKiAgIGlkOiA0MlxuICogfSkudGhlbihmZWF0dXJlID0+IHtcbiAqICBjb25zb2xlLmxvZyhmZWF0dXJlLmF0dHJpYnV0ZXMuRklEKTsgLy8gNDJcbiAqIH0pO1xuICogYGBgXG4gKiBHZXQgYSBmZWF0dXJlIGJ5IGlkLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0XG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZmVhdHVyZSBvciB0aGUgW3Jlc3BvbnNlXShodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvUmVzcG9uc2UpIGl0c2VsZiBpZiBgcmF3UmVzcG9uc2U6IHRydWVgIHdhcyBwYXNzZWQgaW4uXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRGZWF0dXJlKHJlcXVlc3RPcHRpb25zKSB7XG4gICAgdmFyIHVybCA9IGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9cIiArIHJlcXVlc3RPcHRpb25zLmlkO1xuICAgIC8vIGRlZmF1bHQgdG8gYSBHRVQgcmVxdWVzdFxuICAgIHZhciBvcHRpb25zID0gX19hc3NpZ24oeyBodHRwTWV0aG9kOiBcIkdFVFwiIH0sIHJlcXVlc3RPcHRpb25zKTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgIGlmIChvcHRpb25zLnJhd1Jlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmZlYXR1cmU7XG4gICAgfSk7XG59XG4vKipcbiAqIGBgYGpzXG4gKiBpbXBvcnQgeyBxdWVyeUZlYXR1cmVzIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcic7XG4gKiAvL1xuICogcXVlcnlGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwOi8vc2FtcGxlc2VydmVyNi5hcmNnaXNvbmxpbmUuY29tL2FyY2dpcy9yZXN0L3NlcnZpY2VzL0NlbnN1cy9NYXBTZXJ2ZXIvM1wiLFxuICogICB3aGVyZTogXCJTVEFURV9OQU1FID0gJ0FsYXNrYSdcIlxuICogfSlcbiAqICAgLnRoZW4ocmVzdWx0KVxuICogYGBgXG4gKiBRdWVyeSBhIGZlYXR1cmUgc2VydmljZS4gU2VlIFtSRVNUIERvY3VtZW50YXRpb25dKGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3Qvc2VydmljZXMtcmVmZXJlbmNlL3F1ZXJ5LWZlYXR1cmUtc2VydmljZS1sYXllci0uaHRtKSBmb3IgbW9yZSBpbmZvcm1hdGlvbi5cbiAqXG4gKiBAcGFyYW0gcmVxdWVzdE9wdGlvbnMgLSBPcHRpb25zIGZvciB0aGUgcmVxdWVzdFxuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIHF1ZXJ5IHJlc3BvbnNlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcXVlcnlGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciBxdWVyeU9wdGlvbnMgPSBhcHBlbmRDdXN0b21QYXJhbXMocmVxdWVzdE9wdGlvbnMsIFtcbiAgICAgICAgXCJ3aGVyZVwiLFxuICAgICAgICBcIm9iamVjdElkc1wiLFxuICAgICAgICBcInJlbGF0aW9uUGFyYW1cIixcbiAgICAgICAgXCJ0aW1lXCIsXG4gICAgICAgIFwiZGlzdGFuY2VcIixcbiAgICAgICAgXCJ1bml0c1wiLFxuICAgICAgICBcIm91dEZpZWxkc1wiLFxuICAgICAgICBcImdlb21ldHJ5XCIsXG4gICAgICAgIFwiZ2VvbWV0cnlUeXBlXCIsXG4gICAgICAgIFwic3BhdGlhbFJlbFwiLFxuICAgICAgICBcInJldHVybkdlb21ldHJ5XCIsXG4gICAgICAgIFwibWF4QWxsb3dhYmxlT2Zmc2V0XCIsXG4gICAgICAgIFwiZ2VvbWV0cnlQcmVjaXNpb25cIixcbiAgICAgICAgXCJpblNSXCIsXG4gICAgICAgIFwib3V0U1JcIixcbiAgICAgICAgXCJnZGJWZXJzaW9uXCIsXG4gICAgICAgIFwicmV0dXJuRGlzdGluY3RWYWx1ZXNcIixcbiAgICAgICAgXCJyZXR1cm5JZHNPbmx5XCIsXG4gICAgICAgIFwicmV0dXJuQ291bnRPbmx5XCIsXG4gICAgICAgIFwicmV0dXJuRXh0ZW50T25seVwiLFxuICAgICAgICBcIm9yZGVyQnlGaWVsZHNcIixcbiAgICAgICAgXCJncm91cEJ5RmllbGRzRm9yU3RhdGlzdGljc1wiLFxuICAgICAgICBcIm91dFN0YXRpc3RpY3NcIixcbiAgICAgICAgXCJyZXR1cm5aXCIsXG4gICAgICAgIFwicmV0dXJuTVwiLFxuICAgICAgICBcIm11bHRpcGF0Y2hPcHRpb25cIixcbiAgICAgICAgXCJyZXN1bHRPZmZzZXRcIixcbiAgICAgICAgXCJyZXN1bHRSZWNvcmRDb3VudFwiLFxuICAgICAgICBcInF1YW50aXphdGlvblBhcmFtZXRlcnNcIixcbiAgICAgICAgXCJyZXR1cm5DZW50cm9pZFwiLFxuICAgICAgICBcInJlc3VsdFR5cGVcIixcbiAgICAgICAgXCJoaXN0b3JpY01vbWVudFwiLFxuICAgICAgICBcInJldHVyblRydWVDdXJ2ZXNcIixcbiAgICAgICAgXCJzcWxGb3JtYXRcIixcbiAgICAgICAgXCJyZXR1cm5FeGNlZWRlZExpbWl0RmVhdHVyZXNcIixcbiAgICAgICAgXCJmXCJcbiAgICBdLCB7XG4gICAgICAgIGh0dHBNZXRob2Q6IFwiR0VUXCIsXG4gICAgICAgIHBhcmFtczogX19hc3NpZ24oeyBcbiAgICAgICAgICAgIC8vIHNldCBkZWZhdWx0IHF1ZXJ5IHBhcmFtZXRlcnNcbiAgICAgICAgICAgIHdoZXJlOiBcIjE9MVwiLCBvdXRGaWVsZHM6IFwiKlwiIH0sIHJlcXVlc3RPcHRpb25zLnBhcmFtcylcbiAgICB9KTtcbiAgICByZXR1cm4gcmVxdWVzdChjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvcXVlcnlcIiwgcXVlcnlPcHRpb25zKTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXF1ZXJ5LmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgcXVlcnlSZWxhdGVkIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtZmVhdHVyZS1sYXllcidcbiAqIC8vXG4gKiBxdWVyeVJlbGF0ZWQoe1xuICogIHVybDogXCJodHRwOi8vc2VydmljZXMubXlzZXJ2ZXIvT3JnSUQvQXJjR0lTL3Jlc3Qvc2VydmljZXMvUGV0cm9sZXVtL0tTUGV0cm8vRmVhdHVyZVNlcnZlci8wXCIsXG4gKiAgcmVsYXRpb25zaGlwSWQ6IDEsXG4gKiAgcGFyYW1zOiB7IHJldHVybkNvdW50T25seTogdHJ1ZSB9XG4gKiB9KVxuICogIC50aGVuKHJlc3BvbnNlKSAvLyByZXNwb25zZS5yZWxhdGVkUmVjb3Jkc1xuICogYGBgXG4gKiBRdWVyeSB0aGUgcmVsYXRlZCByZWNvcmRzIGZvciBhIGZlYXR1cmUgc2VydmljZS4gU2VlIHRoZSBbUkVTVCBEb2N1bWVudGF0aW9uXShodHRwczovL2RldmVsb3BlcnMuYXJjZ2lzLmNvbS9yZXN0L3NlcnZpY2VzLXJlZmVyZW5jZS9xdWVyeS1yZWxhdGVkLXJlY29yZHMtZmVhdHVyZS1zZXJ2aWNlLS5odG0pIGZvciBtb3JlIGluZm9ybWF0aW9uLlxuICpcbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9uc1xuICogQHJldHVybnMgQSBQcm9taXNlIHRoYXQgd2lsbCByZXNvbHZlIHdpdGggdGhlIHF1ZXJ5IHJlc3BvbnNlXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBxdWVyeVJlbGF0ZWQocmVxdWVzdE9wdGlvbnMpIHtcbiAgICB2YXIgb3B0aW9ucyA9IGFwcGVuZEN1c3RvbVBhcmFtcyhyZXF1ZXN0T3B0aW9ucywgW1wib2JqZWN0SWRzXCIsIFwicmVsYXRpb25zaGlwSWRcIiwgXCJkZWZpbml0aW9uRXhwcmVzc2lvblwiLCBcIm91dEZpZWxkc1wiXSwge1xuICAgICAgICBodHRwTWV0aG9kOiBcIkdFVFwiLFxuICAgICAgICBwYXJhbXM6IF9fYXNzaWduKHsgXG4gICAgICAgICAgICAvLyBzZXQgZGVmYXVsdCBxdWVyeSBwYXJhbWV0ZXJzXG4gICAgICAgICAgICBkZWZpbml0aW9uRXhwcmVzc2lvbjogXCIxPTFcIiwgb3V0RmllbGRzOiBcIipcIiwgcmVsYXRpb25zaGlwSWQ6IDAgfSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKVxuICAgIH0pO1xuICAgIHJldHVybiByZXF1ZXN0KGNsZWFuVXJsKHJlcXVlc3RPcHRpb25zLnVybCkgKyBcIi9xdWVyeVJlbGF0ZWRSZWNvcmRzXCIsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cXVlcnlSZWxhdGVkLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBfX2Fzc2lnbiB9IGZyb20gXCJ0c2xpYlwiO1xuaW1wb3J0IHsgcmVxdWVzdCwgY2xlYW5VcmwsIGFwcGVuZEN1c3RvbVBhcmFtcyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4vKipcbiAqXG4gKiBgYGBqc1xuICogaW1wb3J0IHsgdXBkYXRlRmVhdHVyZXMgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1mZWF0dXJlLWxheWVyJztcbiAqIC8vXG4gKiB1cGRhdGVGZWF0dXJlcyh7XG4gKiAgIHVybDogXCJodHRwczovL3NhbXBsZXNlcnZlcjYuYXJjZ2lzb25saW5lLmNvbS9hcmNnaXMvcmVzdC9zZXJ2aWNlcy9TZXJ2aWNlUmVxdWVzdC9GZWF0dXJlU2VydmVyLzBcIixcbiAqICAgZmVhdHVyZXM6IFt7XG4gKiAgICAgZ2VvbWV0cnk6IHsgeDogLTEyMCwgeTogNDUsIHNwYXRpYWxSZWZlcmVuY2U6IHsgd2tpZDogNDMyNiB9IH0sXG4gKiAgICAgYXR0cmlidXRlczogeyBzdGF0dXM6IFwiYWxpdmVcIiB9XG4gKiAgIH1dXG4gKiB9KTtcbiAqIGBgYFxuICogVXBkYXRlIGZlYXR1cmVzIHJlcXVlc3QuIFNlZSB0aGUgW1JFU1QgRG9jdW1lbnRhdGlvbl0oaHR0cHM6Ly9kZXZlbG9wZXJzLmFyY2dpcy5jb20vcmVzdC9zZXJ2aWNlcy1yZWZlcmVuY2UvdXBkYXRlLWZlYXR1cmVzLmh0bSkgZm9yIG1vcmUgaW5mb3JtYXRpb24uXG4gKlxuICogQHBhcmFtIHJlcXVlc3RPcHRpb25zIC0gT3B0aW9ucyBmb3IgdGhlIHJlcXVlc3QuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgdXBkYXRlRmVhdHVyZXMgcmVzcG9uc2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB1cGRhdGVGZWF0dXJlcyhyZXF1ZXN0T3B0aW9ucykge1xuICAgIHZhciB1cmwgPSBjbGVhblVybChyZXF1ZXN0T3B0aW9ucy51cmwpICsgXCIvdXBkYXRlRmVhdHVyZXNcIjtcbiAgICAvLyBlZGl0IG9wZXJhdGlvbnMgYXJlIFBPU1Qgb25seVxuICAgIHZhciBvcHRpb25zID0gYXBwZW5kQ3VzdG9tUGFyYW1zKHJlcXVlc3RPcHRpb25zLCBbXCJmZWF0dXJlc1wiLCBcImdkYlZlcnNpb25cIiwgXCJyZXR1cm5FZGl0TW9tZW50XCIsIFwicm9sbGJhY2tPbkZhaWx1cmVcIiwgXCJ0cnVlQ3VydmVDbGllbnRcIl0sIHsgcGFyYW1zOiBfX2Fzc2lnbih7fSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSB9KTtcbiAgICByZXR1cm4gcmVxdWVzdCh1cmwsIG9wdGlvbnMpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9dXBkYXRlLmpzLm1hcCIsIi8qISAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxyXG5Db3B5cmlnaHQgKGMpIE1pY3Jvc29mdCBDb3Jwb3JhdGlvbi5cclxuXHJcblBlcm1pc3Npb24gdG8gdXNlLCBjb3B5LCBtb2RpZnksIGFuZC9vciBkaXN0cmlidXRlIHRoaXMgc29mdHdhcmUgZm9yIGFueVxyXG5wdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQuXHJcblxyXG5USEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiIEFORCBUSEUgQVVUSE9SIERJU0NMQUlNUyBBTEwgV0FSUkFOVElFUyBXSVRIXHJcblJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWVxyXG5BTkQgRklUTkVTUy4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUiBCRSBMSUFCTEUgRk9SIEFOWSBTUEVDSUFMLCBESVJFQ1QsXHJcbklORElSRUNULCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgT1IgQU5ZIERBTUFHRVMgV0hBVFNPRVZFUiBSRVNVTFRJTkcgRlJPTVxyXG5MT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUlxyXG5PVEhFUiBUT1JUSU9VUyBBQ1RJT04sIEFSSVNJTkcgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgVVNFIE9SXHJcblBFUkZPUk1BTkNFIE9GIFRISVMgU09GVFdBUkUuXHJcbioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqICovXHJcbi8qIGdsb2JhbCBSZWZsZWN0LCBQcm9taXNlICovXHJcblxyXG52YXIgZXh0ZW5kU3RhdGljcyA9IGZ1bmN0aW9uKGQsIGIpIHtcclxuICAgIGV4dGVuZFN0YXRpY3MgPSBPYmplY3Quc2V0UHJvdG90eXBlT2YgfHxcclxuICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XHJcbiAgICAgICAgZnVuY3Rpb24gKGQsIGIpIHsgZm9yICh2YXIgcCBpbiBiKSBpZiAoYi5oYXNPd25Qcm9wZXJ0eShwKSkgZFtwXSA9IGJbcF07IH07XHJcbiAgICByZXR1cm4gZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxufTtcclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4dGVuZHMoZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcclxuICAgIGZ1bmN0aW9uIF9fKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gZDsgfVxyXG4gICAgZC5wcm90b3R5cGUgPSBiID09PSBudWxsID8gT2JqZWN0LmNyZWF0ZShiKSA6IChfXy5wcm90b3R5cGUgPSBiLnByb3RvdHlwZSwgbmV3IF9fKCkpO1xyXG59XHJcblxyXG5leHBvcnQgdmFyIF9fYXNzaWduID0gZnVuY3Rpb24oKSB7XHJcbiAgICBfX2Fzc2lnbiA9IE9iamVjdC5hc3NpZ24gfHwgZnVuY3Rpb24gX19hc3NpZ24odCkge1xyXG4gICAgICAgIGZvciAodmFyIHMsIGkgPSAxLCBuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IG47IGkrKykge1xyXG4gICAgICAgICAgICBzID0gYXJndW1lbnRzW2ldO1xyXG4gICAgICAgICAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkpIHRbcF0gPSBzW3BdO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gdDtcclxuICAgIH1cclxuICAgIHJldHVybiBfX2Fzc2lnbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19yZXN0KHMsIGUpIHtcclxuICAgIHZhciB0ID0ge307XHJcbiAgICBmb3IgKHZhciBwIGluIHMpIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocywgcCkgJiYgZS5pbmRleE9mKHApIDwgMClcclxuICAgICAgICB0W3BdID0gc1twXTtcclxuICAgIGlmIChzICE9IG51bGwgJiYgdHlwZW9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMgPT09IFwiZnVuY3Rpb25cIilcclxuICAgICAgICBmb3IgKHZhciBpID0gMCwgcCA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eVN5bWJvbHMocyk7IGkgPCBwLmxlbmd0aDsgaSsrKSB7XHJcbiAgICAgICAgICAgIGlmIChlLmluZGV4T2YocFtpXSkgPCAwICYmIE9iamVjdC5wcm90b3R5cGUucHJvcGVydHlJc0VudW1lcmFibGUuY2FsbChzLCBwW2ldKSlcclxuICAgICAgICAgICAgICAgIHRbcFtpXV0gPSBzW3BbaV1dO1xyXG4gICAgICAgIH1cclxuICAgIHJldHVybiB0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYykge1xyXG4gICAgdmFyIGMgPSBhcmd1bWVudHMubGVuZ3RoLCByID0gYyA8IDMgPyB0YXJnZXQgOiBkZXNjID09PSBudWxsID8gZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodGFyZ2V0LCBrZXkpIDogZGVzYywgZDtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5kZWNvcmF0ZSA9PT0gXCJmdW5jdGlvblwiKSByID0gUmVmbGVjdC5kZWNvcmF0ZShkZWNvcmF0b3JzLCB0YXJnZXQsIGtleSwgZGVzYyk7XHJcbiAgICBlbHNlIGZvciAodmFyIGkgPSBkZWNvcmF0b3JzLmxlbmd0aCAtIDE7IGkgPj0gMDsgaS0tKSBpZiAoZCA9IGRlY29yYXRvcnNbaV0pIHIgPSAoYyA8IDMgPyBkKHIpIDogYyA+IDMgPyBkKHRhcmdldCwga2V5LCByKSA6IGQodGFyZ2V0LCBrZXkpKSB8fCByO1xyXG4gICAgcmV0dXJuIGMgPiAzICYmIHIgJiYgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRhcmdldCwga2V5LCByKSwgcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcGFyYW0ocGFyYW1JbmRleCwgZGVjb3JhdG9yKSB7XHJcbiAgICByZXR1cm4gZnVuY3Rpb24gKHRhcmdldCwga2V5KSB7IGRlY29yYXRvcih0YXJnZXQsIGtleSwgcGFyYW1JbmRleCk7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fbWV0YWRhdGEobWV0YWRhdGFLZXksIG1ldGFkYXRhVmFsdWUpIHtcclxuICAgIGlmICh0eXBlb2YgUmVmbGVjdCA9PT0gXCJvYmplY3RcIiAmJiB0eXBlb2YgUmVmbGVjdC5tZXRhZGF0YSA9PT0gXCJmdW5jdGlvblwiKSByZXR1cm4gUmVmbGVjdC5tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2F3YWl0ZXIodGhpc0FyZywgX2FyZ3VtZW50cywgUCwgZ2VuZXJhdG9yKSB7XHJcbiAgICBmdW5jdGlvbiBhZG9wdCh2YWx1ZSkgeyByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBQID8gdmFsdWUgOiBuZXcgUChmdW5jdGlvbiAocmVzb2x2ZSkgeyByZXNvbHZlKHZhbHVlKTsgfSk7IH1cclxuICAgIHJldHVybiBuZXcgKFAgfHwgKFAgPSBQcm9taXNlKSkoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xyXG4gICAgICAgIGZ1bmN0aW9uIGZ1bGZpbGxlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvci5uZXh0KHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiByZWplY3RlZCh2YWx1ZSkgeyB0cnkgeyBzdGVwKGdlbmVyYXRvcltcInRocm93XCJdKHZhbHVlKSk7IH0gY2F0Y2ggKGUpIHsgcmVqZWN0KGUpOyB9IH1cclxuICAgICAgICBmdW5jdGlvbiBzdGVwKHJlc3VsdCkgeyByZXN1bHQuZG9uZSA/IHJlc29sdmUocmVzdWx0LnZhbHVlKSA6IGFkb3B0KHJlc3VsdC52YWx1ZSkudGhlbihmdWxmaWxsZWQsIHJlamVjdGVkKTsgfVxyXG4gICAgICAgIHN0ZXAoKGdlbmVyYXRvciA9IGdlbmVyYXRvci5hcHBseSh0aGlzQXJnLCBfYXJndW1lbnRzIHx8IFtdKSkubmV4dCgpKTtcclxuICAgIH0pO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19nZW5lcmF0b3IodGhpc0FyZywgYm9keSkge1xyXG4gICAgdmFyIF8gPSB7IGxhYmVsOiAwLCBzZW50OiBmdW5jdGlvbigpIHsgaWYgKHRbMF0gJiAxKSB0aHJvdyB0WzFdOyByZXR1cm4gdFsxXTsgfSwgdHJ5czogW10sIG9wczogW10gfSwgZiwgeSwgdCwgZztcclxuICAgIHJldHVybiBnID0geyBuZXh0OiB2ZXJiKDApLCBcInRocm93XCI6IHZlcmIoMSksIFwicmV0dXJuXCI6IHZlcmIoMikgfSwgdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIChnW1N5bWJvbC5pdGVyYXRvcl0gPSBmdW5jdGlvbigpIHsgcmV0dXJuIHRoaXM7IH0pLCBnO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IHJldHVybiBmdW5jdGlvbiAodikgeyByZXR1cm4gc3RlcChbbiwgdl0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzdGVwKG9wKSB7XHJcbiAgICAgICAgaWYgKGYpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJHZW5lcmF0b3IgaXMgYWxyZWFkeSBleGVjdXRpbmcuXCIpO1xyXG4gICAgICAgIHdoaWxlIChfKSB0cnkge1xyXG4gICAgICAgICAgICBpZiAoZiA9IDEsIHkgJiYgKHQgPSBvcFswXSAmIDIgPyB5W1wicmV0dXJuXCJdIDogb3BbMF0gPyB5W1widGhyb3dcIl0gfHwgKCh0ID0geVtcInJldHVyblwiXSkgJiYgdC5jYWxsKHkpLCAwKSA6IHkubmV4dCkgJiYgISh0ID0gdC5jYWxsKHksIG9wWzFdKSkuZG9uZSkgcmV0dXJuIHQ7XHJcbiAgICAgICAgICAgIGlmICh5ID0gMCwgdCkgb3AgPSBbb3BbMF0gJiAyLCB0LnZhbHVlXTtcclxuICAgICAgICAgICAgc3dpdGNoIChvcFswXSkge1xyXG4gICAgICAgICAgICAgICAgY2FzZSAwOiBjYXNlIDE6IHQgPSBvcDsgYnJlYWs7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDQ6IF8ubGFiZWwrKzsgcmV0dXJuIHsgdmFsdWU6IG9wWzFdLCBkb25lOiBmYWxzZSB9O1xyXG4gICAgICAgICAgICAgICAgY2FzZSA1OiBfLmxhYmVsKys7IHkgPSBvcFsxXTsgb3AgPSBbMF07IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgY2FzZSA3OiBvcCA9IF8ub3BzLnBvcCgpOyBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcclxuICAgICAgICAgICAgICAgICAgICBpZiAoISh0ID0gXy50cnlzLCB0ID0gdC5sZW5ndGggPiAwICYmIHRbdC5sZW5ndGggLSAxXSkgJiYgKG9wWzBdID09PSA2IHx8IG9wWzBdID09PSAyKSkgeyBfID0gMDsgY29udGludWU7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAob3BbMF0gPT09IDMgJiYgKCF0IHx8IChvcFsxXSA+IHRbMF0gJiYgb3BbMV0gPCB0WzNdKSkpIHsgXy5sYWJlbCA9IG9wWzFdOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gNiAmJiBfLmxhYmVsIDwgdFsxXSkgeyBfLmxhYmVsID0gdFsxXTsgdCA9IG9wOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0ICYmIF8ubGFiZWwgPCB0WzJdKSB7IF8ubGFiZWwgPSB0WzJdOyBfLm9wcy5wdXNoKG9wKTsgYnJlYWs7IH1cclxuICAgICAgICAgICAgICAgICAgICBpZiAodFsyXSkgXy5vcHMucG9wKCk7XHJcbiAgICAgICAgICAgICAgICAgICAgXy50cnlzLnBvcCgpOyBjb250aW51ZTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBvcCA9IGJvZHkuY2FsbCh0aGlzQXJnLCBfKTtcclxuICAgICAgICB9IGNhdGNoIChlKSB7IG9wID0gWzYsIGVdOyB5ID0gMDsgfSBmaW5hbGx5IHsgZiA9IHQgPSAwOyB9XHJcbiAgICAgICAgaWYgKG9wWzBdICYgNSkgdGhyb3cgb3BbMV07IHJldHVybiB7IHZhbHVlOiBvcFswXSA/IG9wWzFdIDogdm9pZCAwLCBkb25lOiB0cnVlIH07XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NyZWF0ZUJpbmRpbmcobywgbSwgaywgazIpIHtcclxuICAgIGlmIChrMiA9PT0gdW5kZWZpbmVkKSBrMiA9IGs7XHJcbiAgICBvW2syXSA9IG1ba107XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2V4cG9ydFN0YXIobSwgZXhwb3J0cykge1xyXG4gICAgZm9yICh2YXIgcCBpbiBtKSBpZiAocCAhPT0gXCJkZWZhdWx0XCIgJiYgIWV4cG9ydHMuaGFzT3duUHJvcGVydHkocCkpIGV4cG9ydHNbcF0gPSBtW3BdO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX192YWx1ZXMobykge1xyXG4gICAgdmFyIHMgPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgU3ltYm9sLml0ZXJhdG9yLCBtID0gcyAmJiBvW3NdLCBpID0gMDtcclxuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xyXG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xyXG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcclxuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcclxuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xyXG4gICAgICAgIH1cclxuICAgIH07XHJcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3JlYWQobywgbikge1xyXG4gICAgdmFyIG0gPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgb1tTeW1ib2wuaXRlcmF0b3JdO1xyXG4gICAgaWYgKCFtKSByZXR1cm4gbztcclxuICAgIHZhciBpID0gbS5jYWxsKG8pLCByLCBhciA9IFtdLCBlO1xyXG4gICAgdHJ5IHtcclxuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcclxuICAgIH1cclxuICAgIGNhdGNoIChlcnJvcikgeyBlID0geyBlcnJvcjogZXJyb3IgfTsgfVxyXG4gICAgZmluYWxseSB7XHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgaWYgKHIgJiYgIXIuZG9uZSAmJiAobSA9IGlbXCJyZXR1cm5cIl0pKSBtLmNhbGwoaSk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGZpbmFsbHkgeyBpZiAoZSkgdGhyb3cgZS5lcnJvcjsgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIGFyO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19zcHJlYWQoKSB7XHJcbiAgICBmb3IgKHZhciBhciA9IFtdLCBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKylcclxuICAgICAgICBhciA9IGFyLmNvbmNhdChfX3JlYWQoYXJndW1lbnRzW2ldKSk7XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZEFycmF5cygpIHtcclxuICAgIGZvciAodmFyIHMgPSAwLCBpID0gMCwgaWwgPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgaWw7IGkrKykgcyArPSBhcmd1bWVudHNbaV0ubGVuZ3RoO1xyXG4gICAgZm9yICh2YXIgciA9IEFycmF5KHMpLCBrID0gMCwgaSA9IDA7IGkgPCBpbDsgaSsrKVxyXG4gICAgICAgIGZvciAodmFyIGEgPSBhcmd1bWVudHNbaV0sIGogPSAwLCBqbCA9IGEubGVuZ3RoOyBqIDwgamw7IGorKywgaysrKVxyXG4gICAgICAgICAgICByW2tdID0gYVtqXTtcclxuICAgIHJldHVybiByO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXQodikge1xyXG4gICAgcmV0dXJuIHRoaXMgaW5zdGFuY2VvZiBfX2F3YWl0ID8gKHRoaXMudiA9IHYsIHRoaXMpIDogbmV3IF9fYXdhaXQodik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jR2VuZXJhdG9yKHRoaXNBcmcsIF9hcmd1bWVudHMsIGdlbmVyYXRvcikge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBnID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pLCBpLCBxID0gW107XHJcbiAgICByZXR1cm4gaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaWYgKGdbbl0pIGlbbl0gPSBmdW5jdGlvbiAodikgeyByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKGEsIGIpIHsgcS5wdXNoKFtuLCB2LCBhLCBiXSkgPiAxIHx8IHJlc3VtZShuLCB2KTsgfSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHJlc3VtZShuLCB2KSB7IHRyeSB7IHN0ZXAoZ1tuXSh2KSk7IH0gY2F0Y2ggKGUpIHsgc2V0dGxlKHFbMF1bM10sIGUpOyB9IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAocikgeyByLnZhbHVlIGluc3RhbmNlb2YgX19hd2FpdCA/IFByb21pc2UucmVzb2x2ZShyLnZhbHVlLnYpLnRoZW4oZnVsZmlsbCwgcmVqZWN0KSA6IHNldHRsZShxWzBdWzJdLCByKTsgfVxyXG4gICAgZnVuY3Rpb24gZnVsZmlsbCh2YWx1ZSkgeyByZXN1bWUoXCJuZXh0XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gcmVqZWN0KHZhbHVlKSB7IHJlc3VtZShcInRocm93XCIsIHZhbHVlKTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKGYsIHYpIHsgaWYgKGYodiksIHEuc2hpZnQoKSwgcS5sZW5ndGgpIHJlc3VtZShxWzBdWzBdLCBxWzBdWzFdKTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hc3luY0RlbGVnYXRvcihvKSB7XHJcbiAgICB2YXIgaSwgcDtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiwgZnVuY3Rpb24gKGUpIHsgdGhyb3cgZTsgfSksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4sIGYpIHsgaVtuXSA9IG9bbl0gPyBmdW5jdGlvbiAodikgeyByZXR1cm4gKHAgPSAhcCkgPyB7IHZhbHVlOiBfX2F3YWl0KG9bbl0odikpLCBkb25lOiBuID09PSBcInJldHVyblwiIH0gOiBmID8gZih2KSA6IHY7IH0gOiBmOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jVmFsdWVzKG8pIHtcclxuICAgIGlmICghU3ltYm9sLmFzeW5jSXRlcmF0b3IpIHRocm93IG5ldyBUeXBlRXJyb3IoXCJTeW1ib2wuYXN5bmNJdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XHJcbiAgICB2YXIgbSA9IG9bU3ltYm9sLmFzeW5jSXRlcmF0b3JdLCBpO1xyXG4gICAgcmV0dXJuIG0gPyBtLmNhbGwobykgOiAobyA9IHR5cGVvZiBfX3ZhbHVlcyA9PT0gXCJmdW5jdGlvblwiID8gX192YWx1ZXMobykgOiBvW1N5bWJvbC5pdGVyYXRvcl0oKSwgaSA9IHt9LCB2ZXJiKFwibmV4dFwiKSwgdmVyYihcInRocm93XCIpLCB2ZXJiKFwicmV0dXJuXCIpLCBpW1N5bWJvbC5hc3luY0l0ZXJhdG9yXSA9IGZ1bmN0aW9uICgpIHsgcmV0dXJuIHRoaXM7IH0sIGkpO1xyXG4gICAgZnVuY3Rpb24gdmVyYihuKSB7IGlbbl0gPSBvW25dICYmIGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7IHYgPSBvW25dKHYpLCBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCB2LmRvbmUsIHYudmFsdWUpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gc2V0dGxlKHJlc29sdmUsIHJlamVjdCwgZCwgdikgeyBQcm9taXNlLnJlc29sdmUodikudGhlbihmdW5jdGlvbih2KSB7IHJlc29sdmUoeyB2YWx1ZTogdiwgZG9uZTogZCB9KTsgfSwgcmVqZWN0KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tYWtlVGVtcGxhdGVPYmplY3QoY29va2VkLCByYXcpIHtcclxuICAgIGlmIChPYmplY3QuZGVmaW5lUHJvcGVydHkpIHsgT2JqZWN0LmRlZmluZVByb3BlcnR5KGNvb2tlZCwgXCJyYXdcIiwgeyB2YWx1ZTogcmF3IH0pOyB9IGVsc2UgeyBjb29rZWQucmF3ID0gcmF3OyB9XHJcbiAgICByZXR1cm4gY29va2VkO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9faW1wb3J0U3Rhcihtb2QpIHtcclxuICAgIGlmIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpIHJldHVybiBtb2Q7XHJcbiAgICB2YXIgcmVzdWx0ID0ge307XHJcbiAgICBpZiAobW9kICE9IG51bGwpIGZvciAodmFyIGsgaW4gbW9kKSBpZiAoT2JqZWN0Lmhhc093blByb3BlcnR5LmNhbGwobW9kLCBrKSkgcmVzdWx0W2tdID0gbW9kW2tdO1xyXG4gICAgcmVzdWx0LmRlZmF1bHQgPSBtb2Q7XHJcbiAgICByZXR1cm4gcmVzdWx0O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnREZWZhdWx0KG1vZCkge1xyXG4gICAgcmV0dXJuIChtb2QgJiYgbW9kLl9fZXNNb2R1bGUpID8gbW9kIDogeyBkZWZhdWx0OiBtb2QgfTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY2xhc3NQcml2YXRlRmllbGRHZXQocmVjZWl2ZXIsIHByaXZhdGVNYXApIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBnZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcHJpdmF0ZU1hcC5nZXQocmVjZWl2ZXIpO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZFNldChyZWNlaXZlciwgcHJpdmF0ZU1hcCwgdmFsdWUpIHtcclxuICAgIGlmICghcHJpdmF0ZU1hcC5oYXMocmVjZWl2ZXIpKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcImF0dGVtcHRlZCB0byBzZXQgcHJpdmF0ZSBmaWVsZCBvbiBub24taW5zdGFuY2VcIik7XHJcbiAgICB9XHJcbiAgICBwcml2YXRlTWFwLnNldChyZWNlaXZlciwgdmFsdWUpO1xyXG4gICAgcmV0dXJuIHZhbHVlO1xyXG59XHJcbiIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDE4IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IF9fYXNzaWduLCBfX2V4dGVuZHMgfSBmcm9tIFwidHNsaWJcIjtcbmltcG9ydCB7IGVuY29kZUZvcm1EYXRhIH0gZnJvbSBcIi4vdXRpbHMvZW5jb2RlLWZvcm0tZGF0YVwiO1xuaW1wb3J0IHsgZW5jb2RlUXVlcnlTdHJpbmcgfSBmcm9tIFwiLi91dGlscy9lbmNvZGUtcXVlcnktc3RyaW5nXCI7XG5pbXBvcnQgeyByZXF1aXJlc0Zvcm1EYXRhIH0gZnJvbSBcIi4vdXRpbHMvcHJvY2Vzcy1wYXJhbXNcIjtcbmltcG9ydCB7IEFyY0dJU1JlcXVlc3RFcnJvciB9IGZyb20gXCIuL3V0aWxzL0FyY0dJU1JlcXVlc3RFcnJvclwiO1xuaW1wb3J0IHsgd2FybiB9IGZyb20gXCIuL3V0aWxzL3dhcm5cIjtcbmV4cG9ydCB2YXIgTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVIgPSBcIkBlc3JpL2FyY2dpcy1yZXN0LWpzXCI7XG52YXIgREVGQVVMVF9BUkNHSVNfUkVRVUVTVF9PUFRJT05TID0ge1xuICAgIGh0dHBNZXRob2Q6IFwiUE9TVFwiLFxuICAgIHBhcmFtczoge1xuICAgICAgICBmOiBcImpzb25cIixcbiAgICB9LFxufTtcbi8qKlxuICogU2V0cyB0aGUgZGVmYXVsdCBvcHRpb25zIHRoYXQgd2lsbCBiZSBwYXNzZWQgaW4gKiphbGwgcmVxdWVzdHMgYWNyb3NzIGFsbCBgQGVzcmkvYXJjZ2lzLXJlc3QtanNgIG1vZHVsZXMqKi5cbiAqXG4gKlxuICogYGBganNcbiAqIGltcG9ydCB7IHNldERlZmF1bHRSZXF1ZXN0T3B0aW9ucyB9IGZyb20gXCJAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0XCI7XG4gKiBzZXREZWZhdWx0UmVxdWVzdE9wdGlvbnMoe1xuICogICBhdXRoZW50aWNhdGlvbjogdXNlclNlc3Npb24gLy8gYWxsIHJlcXVlc3RzIHdpbGwgdXNlIHRoaXMgc2Vzc2lvbiBieSBkZWZhdWx0XG4gKiB9KVxuICogYGBgXG4gKiBZb3Ugc2hvdWxkICoqbmV2ZXIqKiBzZXQgYSBkZWZhdWx0IGBhdXRoZW50aWNhdGlvbmAgd2hlbiB5b3UgYXJlIGluIGEgc2VydmVyIHNpZGUgZW52aXJvbm1lbnQgd2hlcmUgeW91IG1heSBiZSBoYW5kbGluZyByZXF1ZXN0cyBmb3IgbWFueSBkaWZmZXJlbnQgYXV0aGVudGljYXRlZCB1c2Vycy5cbiAqXG4gKiBAcGFyYW0gb3B0aW9ucyBUaGUgZGVmYXVsdCBvcHRpb25zIHRvIHBhc3Mgd2l0aCBldmVyeSByZXF1ZXN0LiBFeGlzdGluZyBkZWZhdWx0IHdpbGwgYmUgb3ZlcndyaXR0ZW4uXG4gKiBAcGFyYW0gaGlkZVdhcm5pbmdzIFNpbGVuY2Ugd2FybmluZ3MgYWJvdXQgc2V0dGluZyBkZWZhdWx0IGBhdXRoZW50aWNhdGlvbmAgaW4gc2hhcmVkIGVudmlyb25tZW50cy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHNldERlZmF1bHRSZXF1ZXN0T3B0aW9ucyhvcHRpb25zLCBoaWRlV2FybmluZ3MpIHtcbiAgICBpZiAob3B0aW9ucy5hdXRoZW50aWNhdGlvbiAmJiAhaGlkZVdhcm5pbmdzKSB7XG4gICAgICAgIHdhcm4oXCJZb3Ugc2hvdWxkIG5vdCBzZXQgYGF1dGhlbnRpY2F0aW9uYCBhcyBhIGRlZmF1bHQgaW4gYSBzaGFyZWQgZW52aXJvbm1lbnQgc3VjaCBhcyBhIHdlYiBzZXJ2ZXIgd2hpY2ggd2lsbCBwcm9jZXNzIG11bHRpcGxlIHVzZXJzIHJlcXVlc3RzLiBZb3UgY2FuIGNhbGwgYHNldERlZmF1bHRSZXF1ZXN0T3B0aW9uc2Agd2l0aCBgdHJ1ZWAgYXMgYSBzZWNvbmQgYXJndW1lbnQgdG8gZGlzYWJsZSB0aGlzIHdhcm5pbmcuXCIpO1xuICAgIH1cbiAgICBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMgPSBvcHRpb25zO1xufVxudmFyIEFyY0dJU0F1dGhFcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQXJjR0lTQXV0aEVycm9yLCBfc3VwZXIpO1xuICAgIC8qKlxuICAgICAqIENyZWF0ZSBhIG5ldyBgQXJjR0lTQXV0aEVycm9yYCAgb2JqZWN0LlxuICAgICAqXG4gICAgICogQHBhcmFtIG1lc3NhZ2UgLSBUaGUgZXJyb3IgbWVzc2FnZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gY29kZSAtIFRoZSBlcnJvciBjb2RlIGZyb20gdGhlIEFQSVxuICAgICAqIEBwYXJhbSByZXNwb25zZSAtIFRoZSBvcmlnaW5hbCByZXNwb25zZSBmcm9tIHRoZSBBUEkgdGhhdCBjYXVzZWQgdGhlIGVycm9yXG4gICAgICogQHBhcmFtIHVybCAtIFRoZSBvcmlnaW5hbCB1cmwgb2YgdGhlIHJlcXVlc3RcbiAgICAgKiBAcGFyYW0gb3B0aW9ucyAtIFRoZSBvcmlnaW5hbCBvcHRpb25zIG9mIHRoZSByZXF1ZXN0XG4gICAgICovXG4gICAgZnVuY3Rpb24gQXJjR0lTQXV0aEVycm9yKG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpIHtcbiAgICAgICAgaWYgKG1lc3NhZ2UgPT09IHZvaWQgMCkgeyBtZXNzYWdlID0gXCJBVVRIRU5USUNBVElPTl9FUlJPUlwiOyB9XG4gICAgICAgIGlmIChjb2RlID09PSB2b2lkIDApIHsgY29kZSA9IFwiQVVUSEVOVElDQVRJT05fRVJST1JfQ09ERVwiOyB9XG4gICAgICAgIHZhciBfdGhpcyA9IF9zdXBlci5jYWxsKHRoaXMsIG1lc3NhZ2UsIGNvZGUsIHJlc3BvbnNlLCB1cmwsIG9wdGlvbnMpIHx8IHRoaXM7XG4gICAgICAgIF90aGlzLm5hbWUgPSBcIkFyY0dJU0F1dGhFcnJvclwiO1xuICAgICAgICBfdGhpcy5tZXNzYWdlID1cbiAgICAgICAgICAgIGNvZGUgPT09IFwiQVVUSEVOVElDQVRJT05fRVJST1JfQ09ERVwiID8gbWVzc2FnZSA6IGNvZGUgKyBcIjogXCIgKyBtZXNzYWdlO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIEFyY0dJU0F1dGhFcnJvci5wcm90b3R5cGUucmV0cnkgPSBmdW5jdGlvbiAoZ2V0U2Vzc2lvbiwgcmV0cnlMaW1pdCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBpZiAocmV0cnlMaW1pdCA9PT0gdm9pZCAwKSB7IHJldHJ5TGltaXQgPSAzOyB9XG4gICAgICAgIHZhciB0cmllcyA9IDA7XG4gICAgICAgIHZhciByZXRyeVJlcXVlc3QgPSBmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgICAgICAgICBnZXRTZXNzaW9uKF90aGlzLnVybCwgX3RoaXMub3B0aW9ucylcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbiAoc2Vzc2lvbikge1xuICAgICAgICAgICAgICAgIHZhciBuZXdPcHRpb25zID0gX19hc3NpZ24oX19hc3NpZ24oe30sIF90aGlzLm9wdGlvbnMpLCB7IGF1dGhlbnRpY2F0aW9uOiBzZXNzaW9uIH0pO1xuICAgICAgICAgICAgICAgIHRyaWVzID0gdHJpZXMgKyAxO1xuICAgICAgICAgICAgICAgIHJldHVybiByZXF1ZXN0KF90aGlzLnVybCwgbmV3T3B0aW9ucyk7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgICAgIHJlc29sdmUocmVzcG9uc2UpO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKGUpIHtcbiAgICAgICAgICAgICAgICBpZiAoZS5uYW1lID09PSBcIkFyY0dJU0F1dGhFcnJvclwiICYmIHRyaWVzIDwgcmV0cnlMaW1pdCkge1xuICAgICAgICAgICAgICAgICAgICByZXRyeVJlcXVlc3QocmVzb2x2ZSwgcmVqZWN0KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoZS5uYW1lID09PSBcIkFyY0dJU0F1dGhFcnJvclwiICYmIHRyaWVzID49IHJldHJ5TGltaXQpIHtcbiAgICAgICAgICAgICAgICAgICAgcmVqZWN0KF90aGlzKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIHJlamVjdChlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcbiAgICAgICAgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICAgICAgICAgIHJldHJ5UmVxdWVzdChyZXNvbHZlLCByZWplY3QpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBBcmNHSVNBdXRoRXJyb3I7XG59KEFyY0dJU1JlcXVlc3RFcnJvcikpO1xuZXhwb3J0IHsgQXJjR0lTQXV0aEVycm9yIH07XG4vKipcbiAqIENoZWNrcyBmb3IgZXJyb3JzIGluIGEgSlNPTiByZXNwb25zZSBmcm9tIHRoZSBBcmNHSVMgUkVTVCBBUEkuIElmIHRoZXJlIGFyZSBubyBlcnJvcnMsIGl0IHdpbGwgcmV0dXJuIHRoZSBgZGF0YWAgcGFzc2VkIGluLiBJZiB0aGVyZSBpcyBhbiBlcnJvciwgaXQgd2lsbCB0aHJvdyBhbiBgQXJjR0lTUmVxdWVzdEVycm9yYCBvciBgQXJjR0lTQXV0aEVycm9yYC5cbiAqXG4gKiBAcGFyYW0gZGF0YSBUaGUgcmVzcG9uc2UgSlNPTiB0byBjaGVjayBmb3IgZXJyb3JzLlxuICogQHBhcmFtIHVybCBUaGUgdXJsIG9mIHRoZSBvcmlnaW5hbCByZXF1ZXN0XG4gKiBAcGFyYW0gcGFyYW1zIFRoZSBwYXJhbWV0ZXJzIG9mIHRoZSBvcmlnaW5hbCByZXF1ZXN0XG4gKiBAcGFyYW0gb3B0aW9ucyBUaGUgb3B0aW9ucyBvZiB0aGUgb3JpZ2luYWwgcmVxdWVzdFxuICogQHJldHVybnMgVGhlIGRhdGEgdGhhdCB3YXMgcGFzc2VkIGluIHRoZSBgZGF0YWAgcGFyYW1ldGVyXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjaGVja0ZvckVycm9ycyhyZXNwb25zZSwgdXJsLCBwYXJhbXMsIG9wdGlvbnMsIG9yaWdpbmFsQXV0aEVycm9yKSB7XG4gICAgLy8gdGhpcyBpcyBhbiBlcnJvciBtZXNzYWdlIGZyb20gYmlsbGluZy5hcmNnaXMuY29tIGJhY2tlbmRcbiAgICBpZiAocmVzcG9uc2UuY29kZSA+PSA0MDApIHtcbiAgICAgICAgdmFyIG1lc3NhZ2UgPSByZXNwb25zZS5tZXNzYWdlLCBjb2RlID0gcmVzcG9uc2UuY29kZTtcbiAgICAgICAgdGhyb3cgbmV3IEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICB9XG4gICAgLy8gZXJyb3IgZnJvbSBBcmNHSVMgT25saW5lIG9yIGFuIEFyY0dJUyBQb3J0YWwgb3Igc2VydmVyIGluc3RhbmNlLlxuICAgIGlmIChyZXNwb25zZS5lcnJvcikge1xuICAgICAgICB2YXIgX2EgPSByZXNwb25zZS5lcnJvciwgbWVzc2FnZSA9IF9hLm1lc3NhZ2UsIGNvZGUgPSBfYS5jb2RlLCBtZXNzYWdlQ29kZSA9IF9hLm1lc3NhZ2VDb2RlO1xuICAgICAgICB2YXIgZXJyb3JDb2RlID0gbWVzc2FnZUNvZGUgfHwgY29kZSB8fCBcIlVOS05PV05fRVJST1JfQ09ERVwiO1xuICAgICAgICBpZiAoY29kZSA9PT0gNDk4IHx8XG4gICAgICAgICAgICBjb2RlID09PSA0OTkgfHxcbiAgICAgICAgICAgIG1lc3NhZ2VDb2RlID09PSBcIkdXTV8wMDAzXCIgfHxcbiAgICAgICAgICAgIChjb2RlID09PSA0MDAgJiYgbWVzc2FnZSA9PT0gXCJVbmFibGUgdG8gZ2VuZXJhdGUgdG9rZW4uXCIpKSB7XG4gICAgICAgICAgICBpZiAob3JpZ2luYWxBdXRoRXJyb3IpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBvcmlnaW5hbEF1dGhFcnJvcjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBBcmNHSVNBdXRoRXJyb3IobWVzc2FnZSwgZXJyb3JDb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKG1lc3NhZ2UsIGVycm9yQ29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgfVxuICAgIC8vIGVycm9yIGZyb20gYSBzdGF0dXMgY2hlY2tcbiAgICBpZiAocmVzcG9uc2Uuc3RhdHVzID09PSBcImZhaWxlZFwiIHx8IHJlc3BvbnNlLnN0YXR1cyA9PT0gXCJmYWlsdXJlXCIpIHtcbiAgICAgICAgdmFyIG1lc3NhZ2UgPSB2b2lkIDA7XG4gICAgICAgIHZhciBjb2RlID0gXCJVTktOT1dOX0VSUk9SX0NPREVcIjtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIG1lc3NhZ2UgPSBKU09OLnBhcnNlKHJlc3BvbnNlLnN0YXR1c01lc3NhZ2UpLm1lc3NhZ2U7XG4gICAgICAgICAgICBjb2RlID0gSlNPTi5wYXJzZShyZXNwb25zZS5zdGF0dXNNZXNzYWdlKS5jb2RlO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICBtZXNzYWdlID0gcmVzcG9uc2Uuc3RhdHVzTWVzc2FnZSB8fCByZXNwb25zZS5tZXNzYWdlO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IG5ldyBBcmNHSVNSZXF1ZXN0RXJyb3IobWVzc2FnZSwgY29kZSwgcmVzcG9uc2UsIHVybCwgb3B0aW9ucyk7XG4gICAgfVxuICAgIHJldHVybiByZXNwb25zZTtcbn1cbi8qKlxuICogYGBganNcbiAqIGltcG9ydCB7IHJlcXVlc3QgfSBmcm9tICdAZXNyaS9hcmNnaXMtcmVzdC1yZXF1ZXN0JztcbiAqIC8vXG4gKiByZXF1ZXN0KCdodHRwczovL3d3dy5hcmNnaXMuY29tL3NoYXJpbmcvcmVzdCcpXG4gKiAgIC50aGVuKHJlc3BvbnNlKSAvLyByZXNwb25zZS5jdXJyZW50VmVyc2lvbiA9PT0gNS4yXG4gKiAvL1xuICogcmVxdWVzdCgnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3QnLCB7XG4gKiAgIGh0dHBNZXRob2Q6IFwiR0VUXCJcbiAqIH0pXG4gKiAvL1xuICogcmVxdWVzdCgnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbS9zaGFyaW5nL3Jlc3Qvc2VhcmNoJywge1xuICogICBwYXJhbXM6IHsgcTogJ3BhcmtzJyB9XG4gKiB9KVxuICogICAudGhlbihyZXNwb25zZSkgLy8gcmVzcG9uc2UudG90YWwgPT4gNzgzNzlcbiAqIGBgYFxuICogR2VuZXJpYyBtZXRob2QgZm9yIG1ha2luZyBIVFRQIHJlcXVlc3RzIHRvIEFyY0dJUyBSRVNUIEFQSSBlbmRwb2ludHMuXG4gKlxuICogQHBhcmFtIHVybCAtIFRoZSBVUkwgb2YgdGhlIEFyY0dJUyBSRVNUIEFQSSBlbmRwb2ludC5cbiAqIEBwYXJhbSByZXF1ZXN0T3B0aW9ucyAtIE9wdGlvbnMgZm9yIHRoZSByZXF1ZXN0LCBpbmNsdWRpbmcgcGFyYW1ldGVycyByZWxldmFudCB0byB0aGUgZW5kcG9pbnQuXG4gKiBAcmV0dXJucyBBIFByb21pc2UgdGhhdCB3aWxsIHJlc29sdmUgd2l0aCB0aGUgZGF0YSBmcm9tIHRoZSByZXNwb25zZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHJlcXVlc3QodXJsLCByZXF1ZXN0T3B0aW9ucykge1xuICAgIGlmIChyZXF1ZXN0T3B0aW9ucyA9PT0gdm9pZCAwKSB7IHJlcXVlc3RPcHRpb25zID0geyBwYXJhbXM6IHsgZjogXCJqc29uXCIgfSB9OyB9XG4gICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbihfX2Fzc2lnbih7IGh0dHBNZXRob2Q6IFwiUE9TVFwiIH0sIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUyksIHJlcXVlc3RPcHRpb25zKSwge1xuICAgICAgICBwYXJhbXM6IF9fYXNzaWduKF9fYXNzaWduKHt9LCBERUZBVUxUX0FSQ0dJU19SRVFVRVNUX09QVElPTlMucGFyYW1zKSwgcmVxdWVzdE9wdGlvbnMucGFyYW1zKSxcbiAgICAgICAgaGVhZGVyczogX19hc3NpZ24oX19hc3NpZ24oe30sIERFRkFVTFRfQVJDR0lTX1JFUVVFU1RfT1BUSU9OUy5oZWFkZXJzKSwgcmVxdWVzdE9wdGlvbnMuaGVhZGVycyksXG4gICAgfSk7XG4gICAgdmFyIG1pc3NpbmdHbG9iYWxzID0gW107XG4gICAgdmFyIHJlY29tbWVuZGVkUGFja2FnZXMgPSBbXTtcbiAgICAvLyBkb24ndCBjaGVjayBmb3IgYSBnbG9iYWwgZmV0Y2ggaWYgYSBjdXN0b20gaW1wbGVtZW50YXRpb24gd2FzIHBhc3NlZCB0aHJvdWdoXG4gICAgaWYgKCFvcHRpb25zLmZldGNoICYmIHR5cGVvZiBmZXRjaCAhPT0gXCJ1bmRlZmluZWRcIikge1xuICAgICAgICBvcHRpb25zLmZldGNoID0gZmV0Y2guYmluZChGdW5jdGlvbihcInJldHVybiB0aGlzXCIpKCkpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgbWlzc2luZ0dsb2JhbHMucHVzaChcImBmZXRjaGBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBub2RlLWZldGNoYFwiKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBQcm9taXNlID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgIG1pc3NpbmdHbG9iYWxzLnB1c2goXCJgUHJvbWlzZWBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBlczYtcHJvbWlzZWBcIik7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgRm9ybURhdGEgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgbWlzc2luZ0dsb2JhbHMucHVzaChcImBGb3JtRGF0YWBcIik7XG4gICAgICAgIHJlY29tbWVuZGVkUGFja2FnZXMucHVzaChcImBpc29tb3JwaGljLWZvcm0tZGF0YWBcIik7XG4gICAgfVxuICAgIGlmICghb3B0aW9ucy5mZXRjaCB8fFxuICAgICAgICB0eXBlb2YgUHJvbWlzZSA9PT0gXCJ1bmRlZmluZWRcIiB8fFxuICAgICAgICB0eXBlb2YgRm9ybURhdGEgPT09IFwidW5kZWZpbmVkXCIpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiYGFyY2dpcy1yZXN0LXJlcXVlc3RgIHJlcXVpcmVzIGEgYGZldGNoYCBpbXBsZW1lbnRhdGlvbiBhbmQgZ2xvYmFsIHZhcmlhYmxlcyBmb3IgYFByb21pc2VgIGFuZCBgRm9ybURhdGFgIHRvIGJlIHByZXNlbnQgaW4gdGhlIGdsb2JhbCBzY29wZS4gWW91IGFyZSBtaXNzaW5nIFwiICsgbWlzc2luZ0dsb2JhbHMuam9pbihcIiwgXCIpICsgXCIuIFdlIHJlY29tbWVuZCBpbnN0YWxsaW5nIHRoZSBcIiArIHJlY29tbWVuZGVkUGFja2FnZXMuam9pbihcIiwgXCIpICsgXCIgbW9kdWxlcyBhdCB0aGUgcm9vdCBvZiB5b3VyIGFwcGxpY2F0aW9uIHRvIGFkZCB0aGVzZSB0byB0aGUgZ2xvYmFsIHNjb3BlLiBTZWUgaHR0cHM6Ly9iaXQubHkvMktOd1dhSiBmb3IgbW9yZSBpbmZvLlwiKTtcbiAgICB9XG4gICAgdmFyIGh0dHBNZXRob2QgPSBvcHRpb25zLmh0dHBNZXRob2QsIGF1dGhlbnRpY2F0aW9uID0gb3B0aW9ucy5hdXRoZW50aWNhdGlvbiwgcmF3UmVzcG9uc2UgPSBvcHRpb25zLnJhd1Jlc3BvbnNlO1xuICAgIHZhciBwYXJhbXMgPSBfX2Fzc2lnbih7IGY6IFwianNvblwiIH0sIG9wdGlvbnMucGFyYW1zKTtcbiAgICB2YXIgb3JpZ2luYWxBdXRoRXJyb3IgPSBudWxsO1xuICAgIHZhciBmZXRjaE9wdGlvbnMgPSB7XG4gICAgICAgIG1ldGhvZDogaHR0cE1ldGhvZCxcbiAgICAgICAgLyogZW5zdXJlcyBiZWhhdmlvciBtaW1pY3MgWE1MSHR0cFJlcXVlc3QuXG4gICAgICAgIG5lZWRlZCB0byBzdXBwb3J0IHNlbmRpbmcgSVdBIGNvb2tpZXMgKi9cbiAgICAgICAgY3JlZGVudGlhbHM6IG9wdGlvbnMuY3JlZGVudGlhbHMgfHwgXCJzYW1lLW9yaWdpblwiLFxuICAgIH07XG4gICAgLy8gdGhlIC9vYXV0aDIvcGxhdGZvcm1TZWxmIHJvdXRlIHdpbGwgYWRkIFgtRXNyaS1BdXRoLUNsaWVudC1JZCBoZWFkZXJcbiAgICAvLyBhbmQgdGhhdCByZXF1ZXN0IG5lZWRzIHRvIHNlbmQgY29va2llcyBjcm9zcyBkb21haW5cbiAgICAvLyBzbyB3ZSBuZWVkIHRvIHNldCB0aGUgY3JlZGVudGlhbHMgdG8gXCJpbmNsdWRlXCJcbiAgICBpZiAob3B0aW9ucy5oZWFkZXJzICYmXG4gICAgICAgIG9wdGlvbnMuaGVhZGVyc1tcIlgtRXNyaS1BdXRoLUNsaWVudC1JZFwiXSAmJlxuICAgICAgICB1cmwuaW5kZXhPZihcIi9vYXV0aDIvcGxhdGZvcm1TZWxmXCIpID4gLTEpIHtcbiAgICAgICAgZmV0Y2hPcHRpb25zLmNyZWRlbnRpYWxzID0gXCJpbmNsdWRlXCI7XG4gICAgfVxuICAgIHJldHVybiAoYXV0aGVudGljYXRpb25cbiAgICAgICAgPyBhdXRoZW50aWNhdGlvbi5nZXRUb2tlbih1cmwsIHsgZmV0Y2g6IG9wdGlvbnMuZmV0Y2ggfSkuY2F0Y2goZnVuY3Rpb24gKGVycikge1xuICAgICAgICAgICAgLyoqXG4gICAgICAgICAgICAgKiBhcHBlbmQgb3JpZ2luYWwgcmVxdWVzdCB1cmwgYW5kIHJlcXVlc3RPcHRpb25zXG4gICAgICAgICAgICAgKiB0byB0aGUgZXJyb3IgdGhyb3duIGJ5IGdldFRva2VuKClcbiAgICAgICAgICAgICAqIHRvIGFzc2lzdCB3aXRoIHJldHJ5aW5nXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIGVyci51cmwgPSB1cmw7XG4gICAgICAgICAgICBlcnIub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgICAgICAgICAvKipcbiAgICAgICAgICAgICAqIGlmIGFuIGF0dGVtcHQgaXMgbWFkZSB0byB0YWxrIHRvIGFuIHVuZmVkZXJhdGVkIHNlcnZlclxuICAgICAgICAgICAgICogZmlyc3QgdHJ5IHRoZSByZXF1ZXN0IGFub255bW91c2x5LiBpZiBhICd0b2tlbiByZXF1aXJlZCdcbiAgICAgICAgICAgICAqIGVycm9yIGlzIHRocm93biwgdGhyb3cgdGhlIFVORkVERVJBVEVEIGVycm9yIHRoZW4uXG4gICAgICAgICAgICAgKi9cbiAgICAgICAgICAgIG9yaWdpbmFsQXV0aEVycm9yID0gZXJyO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShcIlwiKTtcbiAgICAgICAgfSlcbiAgICAgICAgOiBQcm9taXNlLnJlc29sdmUoXCJcIikpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uICh0b2tlbikge1xuICAgICAgICBpZiAodG9rZW4ubGVuZ3RoKSB7XG4gICAgICAgICAgICBwYXJhbXMudG9rZW4gPSB0b2tlbjtcbiAgICAgICAgfVxuICAgICAgICBpZiAoYXV0aGVudGljYXRpb24gJiYgYXV0aGVudGljYXRpb24uZ2V0RG9tYWluQ3JlZGVudGlhbHMpIHtcbiAgICAgICAgICAgIGZldGNoT3B0aW9ucy5jcmVkZW50aWFscyA9IGF1dGhlbnRpY2F0aW9uLmdldERvbWFpbkNyZWRlbnRpYWxzKHVybCk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gQ3VzdG9tIGhlYWRlcnMgdG8gYWRkIHRvIHJlcXVlc3QuIElSZXF1ZXN0T3B0aW9ucy5oZWFkZXJzIHdpdGggbWVyZ2Ugb3ZlciByZXF1ZXN0SGVhZGVycy5cbiAgICAgICAgdmFyIHJlcXVlc3RIZWFkZXJzID0ge307XG4gICAgICAgIGlmIChmZXRjaE9wdGlvbnMubWV0aG9kID09PSBcIkdFVFwiKSB7XG4gICAgICAgICAgICAvLyBQcmV2ZW50cyB0b2tlbiBmcm9tIGJlaW5nIHBhc3NlZCBpbiBxdWVyeSBwYXJhbXMgd2hlbiBoaWRlVG9rZW4gb3B0aW9uIGlzIHVzZWQuXG4gICAgICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgaWYgLSB3aW5kb3cgaXMgYWx3YXlzIGRlZmluZWQgaW4gYSBicm93c2VyLiBUZXN0IGNhc2UgaXMgY292ZXJlZCBieSBKYXNtaW5lIGluIG5vZGUgdGVzdCAqL1xuICAgICAgICAgICAgaWYgKHBhcmFtcy50b2tlbiAmJlxuICAgICAgICAgICAgICAgIG9wdGlvbnMuaGlkZVRva2VuICYmXG4gICAgICAgICAgICAgICAgLy8gU2hhcmluZyBBUEkgZG9lcyBub3Qgc3VwcG9ydCBwcmVmbGlnaHQgY2hlY2sgcmVxdWlyZWQgYnkgbW9kZXJuIGJyb3dzZXJzIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvR2xvc3NhcnkvUHJlZmxpZ2h0X3JlcXVlc3RcbiAgICAgICAgICAgICAgICB0eXBlb2Ygd2luZG93ID09PSBcInVuZGVmaW5lZFwiKSB7XG4gICAgICAgICAgICAgICAgcmVxdWVzdEhlYWRlcnNbXCJYLUVzcmktQXV0aG9yaXphdGlvblwiXSA9IFwiQmVhcmVyIFwiICsgcGFyYW1zLnRva2VuO1xuICAgICAgICAgICAgICAgIGRlbGV0ZSBwYXJhbXMudG9rZW47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBlbmNvZGUgdGhlIHBhcmFtZXRlcnMgaW50byB0aGUgcXVlcnkgc3RyaW5nXG4gICAgICAgICAgICB2YXIgcXVlcnlQYXJhbXMgPSBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpO1xuICAgICAgICAgICAgLy8gZG9udCBhcHBlbmQgYSAnPycgdW5sZXNzIHBhcmFtZXRlcnMgYXJlIGFjdHVhbGx5IHByZXNlbnRcbiAgICAgICAgICAgIHZhciB1cmxXaXRoUXVlcnlTdHJpbmcgPSBxdWVyeVBhcmFtcyA9PT0gXCJcIiA/IHVybCA6IHVybCArIFwiP1wiICsgZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgIC8vIFRoaXMgd291bGQgZXhjZWVkIHRoZSBtYXhpbXVtIGxlbmd0aCBmb3IgVVJMcyBzcGVjaWZpZWQgYnkgdGhlIGNvbnN1bWVyIGFuZCByZXF1aXJlcyBQT1NUXG4gICAgICAgICAgICAob3B0aW9ucy5tYXhVcmxMZW5ndGggJiZcbiAgICAgICAgICAgICAgICB1cmxXaXRoUXVlcnlTdHJpbmcubGVuZ3RoID4gb3B0aW9ucy5tYXhVcmxMZW5ndGgpIHx8XG4gICAgICAgICAgICAgICAgLy8gT3IgaWYgdGhlIGN1c3RvbWVyIHJlcXVpcmVzIHRoZSB0b2tlbiB0byBiZSBoaWRkZW4gYW5kIGl0IGhhcyBub3QgYWxyZWFkeSBiZWVuIGhpZGRlbiBpbiB0aGUgaGVhZGVyIChmb3IgYnJvd3NlcnMpXG4gICAgICAgICAgICAgICAgKHBhcmFtcy50b2tlbiAmJiBvcHRpb25zLmhpZGVUb2tlbikpIHtcbiAgICAgICAgICAgICAgICAvLyB0aGUgY29uc3VtZXIgc3BlY2lmaWVkIGEgbWF4aW11bSBsZW5ndGggZm9yIFVSTHNcbiAgICAgICAgICAgICAgICAvLyBhbmQgdGhpcyB3b3VsZCBleGNlZWQgaXQsIHNvIHVzZSBwb3N0IGluc3RlYWRcbiAgICAgICAgICAgICAgICBmZXRjaE9wdGlvbnMubWV0aG9kID0gXCJQT1NUXCI7XG4gICAgICAgICAgICAgICAgLy8gSWYgdGhlIHRva2VuIHdhcyBhbHJlYWR5IGFkZGVkIGFzIGEgQXV0aCBoZWFkZXIsIGFkZCB0aGUgdG9rZW4gYmFjayB0byBib2R5IHdpdGggb3RoZXIgcGFyYW1zIGluc3RlYWQgb2YgaGVhZGVyXG4gICAgICAgICAgICAgICAgaWYgKHRva2VuLmxlbmd0aCAmJiBvcHRpb25zLmhpZGVUb2tlbikge1xuICAgICAgICAgICAgICAgICAgICBwYXJhbXMudG9rZW4gPSB0b2tlbjtcbiAgICAgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIGV4aXN0aW5nIGhlYWRlciB0aGF0IHdhcyBhZGRlZCBiZWZvcmUgdXJsIHF1ZXJ5IGxlbmd0aCB3YXMgY2hlY2tlZFxuICAgICAgICAgICAgICAgICAgICBkZWxldGUgcmVxdWVzdEhlYWRlcnNbXCJYLUVzcmktQXV0aG9yaXphdGlvblwiXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAvLyBqdXN0IHVzZSBHRVRcbiAgICAgICAgICAgICAgICB1cmwgPSB1cmxXaXRoUXVlcnlTdHJpbmc7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgLyogdXBkYXRlUmVzb3VyY2VzIGN1cnJlbnRseSByZXF1aXJlcyBGb3JtRGF0YSBldmVuIHdoZW4gdGhlIGlucHV0IHBhcmFtZXRlcnMgZG9udCB3YXJyYW50IGl0LlxuICAgIGh0dHBzOi8vZGV2ZWxvcGVycy5hcmNnaXMuY29tL3Jlc3QvdXNlcnMtZ3JvdXBzLWFuZC1pdGVtcy91cGRhdGUtcmVzb3VyY2VzLmh0bVxuICAgICAgICBzZWUgaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvcHVsbC81MDAgZm9yIG1vcmUgaW5mby4gKi9cbiAgICAgICAgdmFyIGZvcmNlRm9ybURhdGEgPSBuZXcgUmVnRXhwKFwiL2l0ZW1zLy4rL3VwZGF0ZVJlc291cmNlc1wiKS50ZXN0KHVybCk7XG4gICAgICAgIGlmIChmZXRjaE9wdGlvbnMubWV0aG9kID09PSBcIlBPU1RcIikge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmJvZHkgPSBlbmNvZGVGb3JtRGF0YShwYXJhbXMsIGZvcmNlRm9ybURhdGEpO1xuICAgICAgICB9XG4gICAgICAgIC8vIE1peGluIGhlYWRlcnMgZnJvbSByZXF1ZXN0IG9wdGlvbnNcbiAgICAgICAgZmV0Y2hPcHRpb25zLmhlYWRlcnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7fSwgcmVxdWVzdEhlYWRlcnMpLCBvcHRpb25zLmhlYWRlcnMpO1xuICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAtIGthcm1hIHJlcG9ydHMgY292ZXJhZ2Ugb24gYnJvd3NlciB0ZXN0cyBvbmx5ICovXG4gICAgICAgIGlmICh0eXBlb2Ygd2luZG93ID09PSBcInVuZGVmaW5lZFwiICYmICFmZXRjaE9wdGlvbnMuaGVhZGVycy5yZWZlcmVyKSB7XG4gICAgICAgICAgICBmZXRjaE9wdGlvbnMuaGVhZGVycy5yZWZlcmVyID0gTk9ERUpTX0RFRkFVTFRfUkVGRVJFUl9IRUFERVI7XG4gICAgICAgIH1cbiAgICAgICAgLyogaXN0YW5idWwgaWdub3JlIGVsc2UgYmxvYiByZXNwb25zZXMgYXJlIGRpZmZpY3VsdCB0byBtYWtlIGNyb3NzIHBsYXRmb3JtIHdlIHdpbGwganVzdCBoYXZlIHRvIHRydXN0IHRoZSBpc29tb3JwaGljIGZldGNoIHdpbGwgZG8gaXRzIGpvYiAqL1xuICAgICAgICBpZiAoIXJlcXVpcmVzRm9ybURhdGEocGFyYW1zKSAmJiAhZm9yY2VGb3JtRGF0YSkge1xuICAgICAgICAgICAgZmV0Y2hPcHRpb25zLmhlYWRlcnNbXCJDb250ZW50LVR5cGVcIl0gPVxuICAgICAgICAgICAgICAgIFwiYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkXCI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIG9wdGlvbnMuZmV0Y2godXJsLCBmZXRjaE9wdGlvbnMpO1xuICAgIH0pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICBpZiAoIXJlc3BvbnNlLm9rKSB7XG4gICAgICAgICAgICAvLyBzZXJ2ZXIgcmVzcG9uZGVkIHcvIGFuIGFjdHVhbCBlcnJvciAoNDA0LCA1MDAsIGV0YylcbiAgICAgICAgICAgIHZhciBzdGF0dXNfMSA9IHJlc3BvbnNlLnN0YXR1cywgc3RhdHVzVGV4dCA9IHJlc3BvbnNlLnN0YXR1c1RleHQ7XG4gICAgICAgICAgICB0aHJvdyBuZXcgQXJjR0lTUmVxdWVzdEVycm9yKHN0YXR1c1RleHQsIFwiSFRUUCBcIiArIHN0YXR1c18xLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAocmF3UmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgfVxuICAgICAgICBzd2l0Y2ggKHBhcmFtcy5mKSB7XG4gICAgICAgICAgICBjYXNlIFwianNvblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICBjYXNlIFwiZ2VvanNvblwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5qc29uKCk7XG4gICAgICAgICAgICBjYXNlIFwiaHRtbFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS50ZXh0KCk7XG4gICAgICAgICAgICBjYXNlIFwidGV4dFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZS50ZXh0KCk7XG4gICAgICAgICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCBibG9iIHJlc3BvbnNlcyBhcmUgZGlmZmljdWx0IHRvIG1ha2UgY3Jvc3MgcGxhdGZvcm0gd2Ugd2lsbCBqdXN0IGhhdmUgdG8gdHJ1c3QgdGhhdCBpc29tb3JwaGljIGZldGNoIHdpbGwgZG8gaXRzIGpvYiAqL1xuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuYmxvYigpO1xuICAgICAgICB9XG4gICAgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKGRhdGEpIHtcbiAgICAgICAgaWYgKChwYXJhbXMuZiA9PT0gXCJqc29uXCIgfHwgcGFyYW1zLmYgPT09IFwiZ2VvanNvblwiKSAmJiAhcmF3UmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciByZXNwb25zZSA9IGNoZWNrRm9yRXJyb3JzKGRhdGEsIHVybCwgcGFyYW1zLCBvcHRpb25zLCBvcmlnaW5hbEF1dGhFcnJvcik7XG4gICAgICAgICAgICBpZiAob3JpZ2luYWxBdXRoRXJyb3IpIHtcbiAgICAgICAgICAgICAgICAvKiBJZiB0aGUgcmVxdWVzdCB3YXMgbWFkZSB0byBhbiB1bmZlZGVyYXRlZCBzZXJ2aWNlIHRoYXRcbiAgICAgICAgICAgICAgICBkaWRuJ3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvbiwgYWRkIHRoZSBiYXNlIHVybCBhbmQgYSBkdW1teSB0b2tlblxuICAgICAgICAgICAgICAgIHRvIHRoZSBsaXN0IG9mIHRydXN0ZWQgc2VydmVycyB0byBhdm9pZCBhbm90aGVyIGZlZGVyYXRpb24gY2hlY2tcbiAgICAgICAgICAgICAgICBpbiB0aGUgZXZlbnQgb2YgYSByZXBlYXQgcmVxdWVzdCAqL1xuICAgICAgICAgICAgICAgIHZhciB0cnVuY2F0ZWRVcmwgPSB1cmxcbiAgICAgICAgICAgICAgICAgICAgLnRvTG93ZXJDYXNlKClcbiAgICAgICAgICAgICAgICAgICAgLnNwbGl0KC9cXC9yZXN0KFxcL2FkbWluKT9cXC9zZXJ2aWNlc1xcLy8pWzBdO1xuICAgICAgICAgICAgICAgIG9wdGlvbnMuYXV0aGVudGljYXRpb24uZmVkZXJhdGVkU2VydmVyc1t0cnVuY2F0ZWRVcmxdID0ge1xuICAgICAgICAgICAgICAgICAgICB0b2tlbjogW10sXG4gICAgICAgICAgICAgICAgICAgIC8vIGRlZmF1bHQgdG8gMjQgaG91cnNcbiAgICAgICAgICAgICAgICAgICAgZXhwaXJlczogbmV3IERhdGUoRGF0ZS5ub3coKSArIDg2NDAwICogMTAwMCksXG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICBvcmlnaW5hbEF1dGhFcnJvciA9IG51bGw7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICByZXR1cm4gZGF0YTtcbiAgICAgICAgfVxuICAgIH0pO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9cmVxdWVzdC5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLy8gVHlwZVNjcmlwdCAyLjEgbm8gbG9uZ2VyIGFsbG93cyB5b3UgdG8gZXh0ZW5kIGJ1aWx0IGluIHR5cGVzLiBTZWUgaHR0cHM6Ly9naXRodWIuY29tL01pY3Jvc29mdC9UeXBlU2NyaXB0L2lzc3Vlcy8xMjc5MCNpc3N1ZWNvbW1lbnQtMjY1OTgxNDQyXG4vLyBhbmQgaHR0cHM6Ly9naXRodWIuY29tL01pY3Jvc29mdC9UeXBlU2NyaXB0LXdpa2kvYmxvYi9tYXN0ZXIvQnJlYWtpbmctQ2hhbmdlcy5tZCNleHRlbmRpbmctYnVpbHQtaW5zLWxpa2UtZXJyb3ItYXJyYXktYW5kLW1hcC1tYXktbm8tbG9uZ2VyLXdvcmtcbi8vXG4vLyBUaGlzIGNvZGUgaXMgZnJvbSBNRE4gaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvSmF2YVNjcmlwdC9SZWZlcmVuY2UvR2xvYmFsX09iamVjdHMvRXJyb3IjQ3VzdG9tX0Vycm9yX1R5cGVzLlxudmFyIEFyY0dJU1JlcXVlc3RFcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICAvKipcbiAgICAgKiBDcmVhdGUgYSBuZXcgYEFyY0dJU1JlcXVlc3RFcnJvcmAgIG9iamVjdC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSBtZXNzYWdlIC0gVGhlIGVycm9yIG1lc3NhZ2UgZnJvbSB0aGUgQVBJXG4gICAgICogQHBhcmFtIGNvZGUgLSBUaGUgZXJyb3IgY29kZSBmcm9tIHRoZSBBUElcbiAgICAgKiBAcGFyYW0gcmVzcG9uc2UgLSBUaGUgb3JpZ2luYWwgcmVzcG9uc2UgZnJvbSB0aGUgQVBJIHRoYXQgY2F1c2VkIHRoZSBlcnJvclxuICAgICAqIEBwYXJhbSB1cmwgLSBUaGUgb3JpZ2luYWwgdXJsIG9mIHRoZSByZXF1ZXN0XG4gICAgICogQHBhcmFtIG9wdGlvbnMgLSBUaGUgb3JpZ2luYWwgb3B0aW9ucyBhbmQgcGFyYW1ldGVycyBvZiB0aGUgcmVxdWVzdFxuICAgICAqL1xuICAgIGZ1bmN0aW9uIEFyY0dJU1JlcXVlc3RFcnJvcihtZXNzYWdlLCBjb2RlLCByZXNwb25zZSwgdXJsLCBvcHRpb25zKSB7XG4gICAgICAgIG1lc3NhZ2UgPSBtZXNzYWdlIHx8IFwiVU5LTk9XTl9FUlJPUlwiO1xuICAgICAgICBjb2RlID0gY29kZSB8fCBcIlVOS05PV05fRVJST1JfQ09ERVwiO1xuICAgICAgICB0aGlzLm5hbWUgPSBcIkFyY0dJU1JlcXVlc3RFcnJvclwiO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPVxuICAgICAgICAgICAgY29kZSA9PT0gXCJVTktOT1dOX0VSUk9SX0NPREVcIiA/IG1lc3NhZ2UgOiBjb2RlICsgXCI6IFwiICsgbWVzc2FnZTtcbiAgICAgICAgdGhpcy5vcmlnaW5hbE1lc3NhZ2UgPSBtZXNzYWdlO1xuICAgICAgICB0aGlzLmNvZGUgPSBjb2RlO1xuICAgICAgICB0aGlzLnJlc3BvbnNlID0gcmVzcG9uc2U7XG4gICAgICAgIHRoaXMudXJsID0gdXJsO1xuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgIH1cbiAgICByZXR1cm4gQXJjR0lTUmVxdWVzdEVycm9yO1xufSgpKTtcbmV4cG9ydCB7IEFyY0dJU1JlcXVlc3RFcnJvciB9O1xuQXJjR0lTUmVxdWVzdEVycm9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUoRXJyb3IucHJvdG90eXBlKTtcbkFyY0dJU1JlcXVlc3RFcnJvci5wcm90b3R5cGUuY29uc3RydWN0b3IgPSBBcmNHSVNSZXF1ZXN0RXJyb3I7XG4vLyMgc291cmNlTWFwcGluZ1VSTD1BcmNHSVNSZXF1ZXN0RXJyb3IuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3LTIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuaW1wb3J0IHsgX19hc3NpZ24gfSBmcm9tIFwidHNsaWJcIjtcbi8qKlxuICogSGVscGVyIGZvciBtZXRob2RzIHdpdGggbG90cyBvZiBmaXJzdCBvcmRlciByZXF1ZXN0IG9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIGFzIHJlcXVlc3QgcGFyYW1ldGVycy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFwcGVuZEN1c3RvbVBhcmFtcyhjdXN0b21PcHRpb25zLCBrZXlzLCBiYXNlT3B0aW9ucykge1xuICAgIHZhciByZXF1ZXN0T3B0aW9uc0tleXMgPSBbXG4gICAgICAgIFwicGFyYW1zXCIsXG4gICAgICAgIFwiaHR0cE1ldGhvZFwiLFxuICAgICAgICBcInJhd1Jlc3BvbnNlXCIsXG4gICAgICAgIFwiYXV0aGVudGljYXRpb25cIixcbiAgICAgICAgXCJwb3J0YWxcIixcbiAgICAgICAgXCJmZXRjaFwiLFxuICAgICAgICBcIm1heFVybExlbmd0aFwiLFxuICAgICAgICBcImhlYWRlcnNcIlxuICAgIF07XG4gICAgdmFyIG9wdGlvbnMgPSBfX2Fzc2lnbihfX2Fzc2lnbih7IHBhcmFtczoge30gfSwgYmFzZU9wdGlvbnMpLCBjdXN0b21PcHRpb25zKTtcbiAgICAvLyBtZXJnZSBhbGwga2V5cyBpbiBjdXN0b21PcHRpb25zIGludG8gb3B0aW9ucy5wYXJhbXNcbiAgICBvcHRpb25zLnBhcmFtcyA9IGtleXMucmVkdWNlKGZ1bmN0aW9uICh2YWx1ZSwga2V5KSB7XG4gICAgICAgIGlmIChjdXN0b21PcHRpb25zW2tleV0gfHwgdHlwZW9mIGN1c3RvbU9wdGlvbnNba2V5XSA9PT0gXCJib29sZWFuXCIpIHtcbiAgICAgICAgICAgIHZhbHVlW2tleV0gPSBjdXN0b21PcHRpb25zW2tleV07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHZhbHVlO1xuICAgIH0sIG9wdGlvbnMucGFyYW1zKTtcbiAgICAvLyBub3cgcmVtb3ZlIGFsbCBwcm9wZXJ0aWVzIGluIG9wdGlvbnMgdGhhdCBkb24ndCBleGlzdCBpbiBJUmVxdWVzdE9wdGlvbnNcbiAgICByZXR1cm4gcmVxdWVzdE9wdGlvbnNLZXlzLnJlZHVjZShmdW5jdGlvbiAodmFsdWUsIGtleSkge1xuICAgICAgICBpZiAob3B0aW9uc1trZXldKSB7XG4gICAgICAgICAgICB2YWx1ZVtrZXldID0gb3B0aW9uc1trZXldO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9LCB7fSk7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1hcHBlbmQtY3VzdG9tLXBhcmFtcy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTggRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLyoqXG4gKiBIZWxwZXIgbWV0aG9kIHRvIGVuc3VyZSB0aGF0IHVzZXIgc3VwcGxpZWQgdXJscyBkb24ndCBpbmNsdWRlIHdoaXRlc3BhY2Ugb3IgYSB0cmFpbGluZyBzbGFzaC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNsZWFuVXJsKHVybCkge1xuICAgIC8vIEd1YXJkIHNvIHdlIGRvbid0IHRyeSB0byB0cmltIHNvbWV0aGluZyB0aGF0J3Mgbm90IGEgc3RyaW5nXG4gICAgaWYgKHR5cGVvZiB1cmwgIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgcmV0dXJuIHVybDtcbiAgICB9XG4gICAgLy8gdHJpbSBsZWFkaW5nIGFuZCB0cmFpbGluZyBzcGFjZXMsIGJ1dCBub3Qgc3BhY2VzIGluc2lkZSB0aGUgdXJsXG4gICAgdXJsID0gdXJsLnRyaW0oKTtcbiAgICAvLyByZW1vdmUgdGhlIHRyYWlsaW5nIHNsYXNoIHRvIHRoZSB1cmwgaWYgb25lIHdhcyBpbmNsdWRlZFxuICAgIGlmICh1cmxbdXJsLmxlbmd0aCAtIDFdID09PSBcIi9cIikge1xuICAgICAgICB1cmwgPSB1cmwuc2xpY2UoMCwgLTEpO1xuICAgIH1cbiAgICByZXR1cm4gdXJsO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9Y2xlYW4tdXJsLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNy0yMDIwIEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVQYXJhbShwYXJhbSkge1xuICAgIHZhciBfYSA9IHBhcmFtLnNwbGl0KFwiPVwiKSwga2V5ID0gX2FbMF0sIHZhbHVlID0gX2FbMV07XG4gICAgcmV0dXJuIHsga2V5OiBkZWNvZGVVUklDb21wb25lbnQoa2V5KSwgdmFsdWU6IGRlY29kZVVSSUNvbXBvbmVudCh2YWx1ZSkgfTtcbn1cbi8qKlxuICogRGVjb2RlcyB0aGUgcGFzc2VkIHF1ZXJ5IHN0cmluZyBhcyBhbiBvYmplY3QuXG4gKlxuICogQHBhcmFtIHF1ZXJ5IEEgc3RyaW5nIHRvIGJlIGRlY29kZWQuXG4gKiBAcmV0dXJucyBBIGRlY29kZWQgcXVlcnkgcGFyYW0gb2JqZWN0LlxuICovXG5leHBvcnQgZnVuY3Rpb24gZGVjb2RlUXVlcnlTdHJpbmcocXVlcnkpIHtcbiAgICByZXR1cm4gcXVlcnlcbiAgICAgICAgLnJlcGxhY2UoL14jLywgXCJcIilcbiAgICAgICAgLnNwbGl0KFwiJlwiKVxuICAgICAgICAucmVkdWNlKGZ1bmN0aW9uIChhY2MsIGVudHJ5KSB7XG4gICAgICAgIHZhciBfYSA9IGRlY29kZVBhcmFtKGVudHJ5KSwga2V5ID0gX2Eua2V5LCB2YWx1ZSA9IF9hLnZhbHVlO1xuICAgICAgICBhY2Nba2V5XSA9IHZhbHVlO1xuICAgICAgICByZXR1cm4gYWNjO1xuICAgIH0sIHt9KTtcbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRlY29kZS1xdWVyeS1zdHJpbmcuanMubWFwIiwiLyogQ29weXJpZ2h0IChjKSAyMDE3IEVudmlyb25tZW50YWwgU3lzdGVtcyBSZXNlYXJjaCBJbnN0aXR1dGUsIEluYy5cbiAqIEFwYWNoZS0yLjAgKi9cbmltcG9ydCB7IHByb2Nlc3NQYXJhbXMsIHJlcXVpcmVzRm9ybURhdGEgfSBmcm9tIFwiLi9wcm9jZXNzLXBhcmFtc1wiO1xuaW1wb3J0IHsgZW5jb2RlUXVlcnlTdHJpbmcgfSBmcm9tIFwiLi9lbmNvZGUtcXVlcnktc3RyaW5nXCI7XG4vKipcbiAqIEVuY29kZXMgcGFyYW1ldGVycyBpbiBhIFtGb3JtRGF0YV0oaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvQVBJL0Zvcm1EYXRhKSBvYmplY3QgaW4gYnJvd3NlcnMgb3IgaW4gYSBbRm9ybURhdGFdKGh0dHBzOi8vZ2l0aHViLmNvbS9mb3JtLWRhdGEvZm9ybS1kYXRhKSBpbiBOb2RlLmpzXG4gKlxuICogQHBhcmFtIHBhcmFtcyBBbiBvYmplY3QgdG8gYmUgZW5jb2RlZC5cbiAqIEByZXR1cm5zIFRoZSBjb21wbGV0ZSBbRm9ybURhdGFdKGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9Gb3JtRGF0YSkgb2JqZWN0LlxuICovXG5leHBvcnQgZnVuY3Rpb24gZW5jb2RlRm9ybURhdGEocGFyYW1zLCBmb3JjZUZvcm1EYXRhKSB7XG4gICAgLy8gc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9Fc3JpL2FyY2dpcy1yZXN0LWpzL2lzc3Vlcy80OTkgZm9yIG1vcmUgaW5mby5cbiAgICB2YXIgdXNlRm9ybURhdGEgPSByZXF1aXJlc0Zvcm1EYXRhKHBhcmFtcykgfHwgZm9yY2VGb3JtRGF0YTtcbiAgICB2YXIgbmV3UGFyYW1zID0gcHJvY2Vzc1BhcmFtcyhwYXJhbXMpO1xuICAgIGlmICh1c2VGb3JtRGF0YSkge1xuICAgICAgICB2YXIgZm9ybURhdGFfMSA9IG5ldyBGb3JtRGF0YSgpO1xuICAgICAgICBPYmplY3Qua2V5cyhuZXdQYXJhbXMpLmZvckVhY2goZnVuY3Rpb24gKGtleSkge1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBCbG9iICE9PSBcInVuZGVmaW5lZFwiICYmIG5ld1BhcmFtc1trZXldIGluc3RhbmNlb2YgQmxvYikge1xuICAgICAgICAgICAgICAgIC8qIFRvIG5hbWUgdGhlIEJsb2I6XG4gICAgICAgICAgICAgICAgIDEuIGxvb2sgdG8gYW4gYWx0ZXJuYXRlIHJlcXVlc3QgcGFyYW1ldGVyIGNhbGxlZCAnZmlsZU5hbWUnXG4gICAgICAgICAgICAgICAgIDIuIHNlZSBpZiAnbmFtZScgaGFzIGJlZW4gdGFja2VkIG9udG8gdGhlIEJsb2IgbWFudWFsbHlcbiAgICAgICAgICAgICAgICAgMy4gaWYgYWxsIGVsc2UgZmFpbHMsIHVzZSB0aGUgcmVxdWVzdCBwYXJhbWV0ZXJcbiAgICAgICAgICAgICAgICAqL1xuICAgICAgICAgICAgICAgIHZhciBmaWxlbmFtZSA9IG5ld1BhcmFtc1tcImZpbGVOYW1lXCJdIHx8IG5ld1BhcmFtc1trZXldLm5hbWUgfHwga2V5O1xuICAgICAgICAgICAgICAgIGZvcm1EYXRhXzEuYXBwZW5kKGtleSwgbmV3UGFyYW1zW2tleV0sIGZpbGVuYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgIGZvcm1EYXRhXzEuYXBwZW5kKGtleSwgbmV3UGFyYW1zW2tleV0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIGZvcm1EYXRhXzE7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICByZXR1cm4gZW5jb2RlUXVlcnlTdHJpbmcocGFyYW1zKTtcbiAgICB9XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1lbmNvZGUtZm9ybS1kYXRhLmpzLm1hcCIsIi8qIENvcHlyaWdodCAoYykgMjAxNyBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG5pbXBvcnQgeyBwcm9jZXNzUGFyYW1zIH0gZnJvbSBcIi4vcHJvY2Vzcy1wYXJhbXNcIjtcbi8qKlxuICogRW5jb2RlcyBrZXlzIGFuZCBwYXJhbWV0ZXJzIGZvciB1c2UgaW4gYSBVUkwncyBxdWVyeSBzdHJpbmcuXG4gKlxuICogQHBhcmFtIGtleSBQYXJhbWV0ZXIncyBrZXlcbiAqIEBwYXJhbSB2YWx1ZSBQYXJhbWV0ZXIncyB2YWx1ZVxuICogQHJldHVybnMgUXVlcnkgc3RyaW5nIHdpdGgga2V5IGFuZCB2YWx1ZSBwYWlycyBzZXBhcmF0ZWQgYnkgXCImXCJcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVuY29kZVBhcmFtKGtleSwgdmFsdWUpIHtcbiAgICAvLyBGb3IgYXJyYXkgb2YgYXJyYXlzLCByZXBlYXQga2V5PXZhbHVlIGZvciBlYWNoIGVsZW1lbnQgb2YgY29udGFpbmluZyBhcnJheVxuICAgIGlmIChBcnJheS5pc0FycmF5KHZhbHVlKSAmJiB2YWx1ZVswXSAmJiBBcnJheS5pc0FycmF5KHZhbHVlWzBdKSkge1xuICAgICAgICByZXR1cm4gdmFsdWUubWFwKGZ1bmN0aW9uIChhcnJheUVsZW0pIHsgcmV0dXJuIGVuY29kZVBhcmFtKGtleSwgYXJyYXlFbGVtKTsgfSkuam9pbihcIiZcIik7XG4gICAgfVxuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQoa2V5KSArIFwiPVwiICsgZW5jb2RlVVJJQ29tcG9uZW50KHZhbHVlKTtcbn1cbi8qKlxuICogRW5jb2RlcyB0aGUgcGFzc2VkIG9iamVjdCBhcyBhIHF1ZXJ5IHN0cmluZy5cbiAqXG4gKiBAcGFyYW0gcGFyYW1zIEFuIG9iamVjdCB0byBiZSBlbmNvZGVkLlxuICogQHJldHVybnMgQW4gZW5jb2RlZCBxdWVyeSBzdHJpbmcuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbmNvZGVRdWVyeVN0cmluZyhwYXJhbXMpIHtcbiAgICB2YXIgbmV3UGFyYW1zID0gcHJvY2Vzc1BhcmFtcyhwYXJhbXMpO1xuICAgIHJldHVybiBPYmplY3Qua2V5cyhuZXdQYXJhbXMpXG4gICAgICAgIC5tYXAoZnVuY3Rpb24gKGtleSkge1xuICAgICAgICByZXR1cm4gZW5jb2RlUGFyYW0oa2V5LCBuZXdQYXJhbXNba2V5XSk7XG4gICAgfSlcbiAgICAgICAgLmpvaW4oXCImXCIpO1xufVxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZW5jb2RlLXF1ZXJ5LXN0cmluZy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTcgRW52aXJvbm1lbnRhbCBTeXN0ZW1zIFJlc2VhcmNoIEluc3RpdHV0ZSwgSW5jLlxuICogQXBhY2hlLTIuMCAqL1xuLyoqXG4gKiBDaGVja3MgcGFyYW1ldGVycyB0byBzZWUgaWYgd2Ugc2hvdWxkIHVzZSBGb3JtRGF0YSB0byBzZW5kIHRoZSByZXF1ZXN0XG4gKiBAcGFyYW0gcGFyYW1zIFRoZSBvYmplY3Qgd2hvc2Uga2V5cyB3aWxsIGJlIGVuY29kZWQuXG4gKiBAcmV0dXJuIEEgYm9vbGVhbiBpbmRpY2F0aW5nIGlmIEZvcm1EYXRhIHdpbGwgYmUgcmVxdWlyZWQuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByZXF1aXJlc0Zvcm1EYXRhKHBhcmFtcykge1xuICAgIHJldHVybiBPYmplY3Qua2V5cyhwYXJhbXMpLnNvbWUoZnVuY3Rpb24gKGtleSkge1xuICAgICAgICB2YXIgdmFsdWUgPSBwYXJhbXNba2V5XTtcbiAgICAgICAgaWYgKCF2YWx1ZSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIGlmICh2YWx1ZSAmJiB2YWx1ZS50b1BhcmFtKSB7XG4gICAgICAgICAgICB2YWx1ZSA9IHZhbHVlLnRvUGFyYW0oKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgdHlwZSA9IHZhbHVlLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIHN3aXRjaCAodHlwZSkge1xuICAgICAgICAgICAgY2FzZSBcIkFycmF5XCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIk9iamVjdFwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGNhc2UgXCJEYXRlXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIkZ1bmN0aW9uXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIkJvb2xlYW5cIjpcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICBjYXNlIFwiU3RyaW5nXCI6XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgY2FzZSBcIk51bWJlclwiOlxuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICB9KTtcbn1cbi8qKlxuICogQ29udmVydHMgcGFyYW1ldGVycyB0byB0aGUgcHJvcGVyIHJlcHJlc2VudGF0aW9uIHRvIHNlbmQgdG8gdGhlIEFyY0dJUyBSRVNUIEFQSS5cbiAqIEBwYXJhbSBwYXJhbXMgVGhlIG9iamVjdCB3aG9zZSBrZXlzIHdpbGwgYmUgZW5jb2RlZC5cbiAqIEByZXR1cm4gQSBuZXcgb2JqZWN0IHdpdGggcHJvcGVybHkgZW5jb2RlZCB2YWx1ZXMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBwcm9jZXNzUGFyYW1zKHBhcmFtcykge1xuICAgIHZhciBuZXdQYXJhbXMgPSB7fTtcbiAgICBPYmplY3Qua2V5cyhwYXJhbXMpLmZvckVhY2goZnVuY3Rpb24gKGtleSkge1xuICAgICAgICB2YXIgX2EsIF9iO1xuICAgICAgICB2YXIgcGFyYW0gPSBwYXJhbXNba2V5XTtcbiAgICAgICAgaWYgKHBhcmFtICYmIHBhcmFtLnRvUGFyYW0pIHtcbiAgICAgICAgICAgIHBhcmFtID0gcGFyYW0udG9QYXJhbSgpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghcGFyYW0gJiZcbiAgICAgICAgICAgIHBhcmFtICE9PSAwICYmXG4gICAgICAgICAgICB0eXBlb2YgcGFyYW0gIT09IFwiYm9vbGVhblwiICYmXG4gICAgICAgICAgICB0eXBlb2YgcGFyYW0gIT09IFwic3RyaW5nXCIpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB2YXIgdHlwZSA9IHBhcmFtLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIHZhciB2YWx1ZTtcbiAgICAgICAgLy8gcHJvcGVybHkgZW5jb2RlcyBvYmplY3RzLCBhcnJheXMgYW5kIGRhdGVzIGZvciBhcmNnaXMuY29tIGFuZCBvdGhlciBzZXJ2aWNlcy5cbiAgICAgICAgLy8gcG9ydGVkIGZyb20gaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvZXNyaS1sZWFmbGV0L2Jsb2IvbWFzdGVyL3NyYy9SZXF1ZXN0LmpzI0wyMi1MMzBcbiAgICAgICAgLy8gYWxzbyBzZWUgaHR0cHM6Ly9naXRodWIuY29tL0VzcmkvYXJjZ2lzLXJlc3QtanMvaXNzdWVzLzE4OlxuICAgICAgICAvLyBudWxsLCB1bmRlZmluZWQsIGZ1bmN0aW9uIGFyZSBleGNsdWRlZC4gSWYgeW91IHdhbnQgdG8gc2VuZCBhbiBlbXB0eSBrZXkgeW91IG5lZWQgdG8gc2VuZCBhbiBlbXB0eSBzdHJpbmcgXCJcIi5cbiAgICAgICAgc3dpdGNoICh0eXBlKSB7XG4gICAgICAgICAgICBjYXNlIFwiQXJyYXlcIjpcbiAgICAgICAgICAgICAgICAvLyBCYXNlZCBvbiB0aGUgZmlyc3QgZWxlbWVudCBvZiB0aGUgYXJyYXksIGNsYXNzaWZ5IGFycmF5IGFzIGFuIGFycmF5IG9mIGFycmF5cywgYW4gYXJyYXkgb2Ygb2JqZWN0c1xuICAgICAgICAgICAgICAgIC8vIHRvIGJlIHN0cmluZ2lmaWVkLCBvciBhbiBhcnJheSBvZiBub24tb2JqZWN0cyB0byBiZSBjb21tYS1zZXBhcmF0ZWRcbiAgICAgICAgICAgICAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tY2FzZS1kZWNsYXJhdGlvbnNcbiAgICAgICAgICAgICAgICB2YXIgZmlyc3RFbGVtZW50VHlwZSA9IChfYiA9IChfYSA9IHBhcmFtWzBdKSA9PT0gbnVsbCB8fCBfYSA9PT0gdm9pZCAwID8gdm9pZCAwIDogX2EuY29uc3RydWN0b3IpID09PSBudWxsIHx8IF9iID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYi5uYW1lO1xuICAgICAgICAgICAgICAgIHZhbHVlID1cbiAgICAgICAgICAgICAgICAgICAgZmlyc3RFbGVtZW50VHlwZSA9PT0gXCJBcnJheVwiID8gcGFyYW0gOiAvLyBwYXNzIHRocnUgYXJyYXkgb2YgYXJyYXlzXG4gICAgICAgICAgICAgICAgICAgICAgICBmaXJzdEVsZW1lbnRUeXBlID09PSBcIk9iamVjdFwiID8gSlNPTi5zdHJpbmdpZnkocGFyYW0pIDogLy8gc3RyaW5naWZ5IGFycmF5IG9mIG9iamVjdHNcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYXJhbS5qb2luKFwiLFwiKTsgLy8gam9pbiBvdGhlciB0eXBlcyBvZiBhcnJheSBlbGVtZW50c1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIk9iamVjdFwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gSlNPTi5zdHJpbmdpZnkocGFyYW0pO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSBcIkRhdGVcIjpcbiAgICAgICAgICAgICAgICB2YWx1ZSA9IHBhcmFtLnZhbHVlT2YoKTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJGdW5jdGlvblwiOlxuICAgICAgICAgICAgICAgIHZhbHVlID0gbnVsbDtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGNhc2UgXCJCb29sZWFuXCI6XG4gICAgICAgICAgICAgICAgdmFsdWUgPSBwYXJhbSArIFwiXCI7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgIHZhbHVlID0gcGFyYW07XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHZhbHVlIHx8IHZhbHVlID09PSAwIHx8IHR5cGVvZiB2YWx1ZSA9PT0gXCJzdHJpbmdcIiB8fCBBcnJheS5pc0FycmF5KHZhbHVlKSkge1xuICAgICAgICAgICAgbmV3UGFyYW1zW2tleV0gPSB2YWx1ZTtcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIHJldHVybiBuZXdQYXJhbXM7XG59XG4vLyMgc291cmNlTWFwcGluZ1VSTD1wcm9jZXNzLXBhcmFtcy5qcy5tYXAiLCIvKiBDb3B5cmlnaHQgKGMpIDIwMTctMjAxOCBFbnZpcm9ubWVudGFsIFN5c3RlbXMgUmVzZWFyY2ggSW5zdGl0dXRlLCBJbmMuXG4gKiBBcGFjaGUtMi4wICovXG4vKipcbiAqIE1ldGhvZCB1c2VkIGludGVybmFsbHkgdG8gc3VyZmFjZSBtZXNzYWdlcyB0byBkZXZlbG9wZXJzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gd2FybihtZXNzYWdlKSB7XG4gICAgaWYgKGNvbnNvbGUgJiYgY29uc29sZS53YXJuKSB7XG4gICAgICAgIGNvbnNvbGUud2Fybi5hcHBseShjb25zb2xlLCBbbWVzc2FnZV0pO1xuICAgIH1cbn1cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPXdhcm4uanMubWFwIiwiLyohICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqXHJcbkNvcHlyaWdodCAoYykgTWljcm9zb2Z0IENvcnBvcmF0aW9uLlxyXG5cclxuUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55XHJcbnB1cnBvc2Ugd2l0aCBvciB3aXRob3V0IGZlZSBpcyBoZXJlYnkgZ3JhbnRlZC5cclxuXHJcblRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEhcclxuUkVHQVJEIFRPIFRISVMgU09GVFdBUkUgSU5DTFVESU5HIEFMTCBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZXHJcbkFORCBGSVRORVNTLiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SIEJFIExJQUJMRSBGT1IgQU5ZIFNQRUNJQUwsIERJUkVDVCxcclxuSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NXHJcbkxPU1MgT0YgVVNFLCBEQVRBIE9SIFBST0ZJVFMsIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBORUdMSUdFTkNFIE9SXHJcbk9USEVSIFRPUlRJT1VTIEFDVElPTiwgQVJJU0lORyBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBVU0UgT1JcclxuUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS5cclxuKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKiogKi9cclxuLyogZ2xvYmFsIFJlZmxlY3QsIFByb21pc2UgKi9cclxuXHJcbnZhciBleHRlbmRTdGF0aWNzID0gZnVuY3Rpb24oZCwgYikge1xyXG4gICAgZXh0ZW5kU3RhdGljcyA9IE9iamVjdC5zZXRQcm90b3R5cGVPZiB8fFxyXG4gICAgICAgICh7IF9fcHJvdG9fXzogW10gfSBpbnN0YW5jZW9mIEFycmF5ICYmIGZ1bmN0aW9uIChkLCBiKSB7IGQuX19wcm90b19fID0gYjsgfSkgfHxcclxuICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcclxuICAgIHJldHVybiBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG59O1xyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXh0ZW5kcyhkLCBiKSB7XHJcbiAgICBleHRlbmRTdGF0aWNzKGQsIGIpO1xyXG4gICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XHJcbiAgICBkLnByb3RvdHlwZSA9IGIgPT09IG51bGwgPyBPYmplY3QuY3JlYXRlKGIpIDogKF9fLnByb3RvdHlwZSA9IGIucHJvdG90eXBlLCBuZXcgX18oKSk7XHJcbn1cclxuXHJcbmV4cG9ydCB2YXIgX19hc3NpZ24gPSBmdW5jdGlvbigpIHtcclxuICAgIF9fYXNzaWduID0gT2JqZWN0LmFzc2lnbiB8fCBmdW5jdGlvbiBfX2Fzc2lnbih0KSB7XHJcbiAgICAgICAgZm9yICh2YXIgcywgaSA9IDEsIG4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbjsgaSsrKSB7XHJcbiAgICAgICAgICAgIHMgPSBhcmd1bWVudHNbaV07XHJcbiAgICAgICAgICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSkgdFtwXSA9IHNbcF07XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiB0O1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIF9fYXNzaWduLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3Jlc3QocywgZSkge1xyXG4gICAgdmFyIHQgPSB7fTtcclxuICAgIGZvciAodmFyIHAgaW4gcykgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChzLCBwKSAmJiBlLmluZGV4T2YocCkgPCAwKVxyXG4gICAgICAgIHRbcF0gPSBzW3BdO1xyXG4gICAgaWYgKHMgIT0gbnVsbCAmJiB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyA9PT0gXCJmdW5jdGlvblwiKVxyXG4gICAgICAgIGZvciAodmFyIGkgPSAwLCBwID0gT2JqZWN0LmdldE93blByb3BlcnR5U3ltYm9scyhzKTsgaSA8IHAubGVuZ3RoOyBpKyspIHtcclxuICAgICAgICAgICAgaWYgKGUuaW5kZXhPZihwW2ldKSA8IDAgJiYgT2JqZWN0LnByb3RvdHlwZS5wcm9wZXJ0eUlzRW51bWVyYWJsZS5jYWxsKHMsIHBbaV0pKVxyXG4gICAgICAgICAgICAgICAgdFtwW2ldXSA9IHNbcFtpXV07XHJcbiAgICAgICAgfVxyXG4gICAgcmV0dXJuIHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2RlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKSB7XHJcbiAgICB2YXIgYyA9IGFyZ3VtZW50cy5sZW5ndGgsIHIgPSBjIDwgMyA/IHRhcmdldCA6IGRlc2MgPT09IG51bGwgPyBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih0YXJnZXQsIGtleSkgOiBkZXNjLCBkO1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0LmRlY29yYXRlID09PSBcImZ1bmN0aW9uXCIpIHIgPSBSZWZsZWN0LmRlY29yYXRlKGRlY29yYXRvcnMsIHRhcmdldCwga2V5LCBkZXNjKTtcclxuICAgIGVsc2UgZm9yICh2YXIgaSA9IGRlY29yYXRvcnMubGVuZ3RoIC0gMTsgaSA+PSAwOyBpLS0pIGlmIChkID0gZGVjb3JhdG9yc1tpXSkgciA9IChjIDwgMyA/IGQocikgOiBjID4gMyA/IGQodGFyZ2V0LCBrZXksIHIpIDogZCh0YXJnZXQsIGtleSkpIHx8IHI7XHJcbiAgICByZXR1cm4gYyA+IDMgJiYgciAmJiBPYmplY3QuZGVmaW5lUHJvcGVydHkodGFyZ2V0LCBrZXksIHIpLCByO1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19wYXJhbShwYXJhbUluZGV4LCBkZWNvcmF0b3IpIHtcclxuICAgIHJldHVybiBmdW5jdGlvbiAodGFyZ2V0LCBrZXkpIHsgZGVjb3JhdG9yKHRhcmdldCwga2V5LCBwYXJhbUluZGV4KTsgfVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19tZXRhZGF0YShtZXRhZGF0YUtleSwgbWV0YWRhdGFWYWx1ZSkge1xyXG4gICAgaWYgKHR5cGVvZiBSZWZsZWN0ID09PSBcIm9iamVjdFwiICYmIHR5cGVvZiBSZWZsZWN0Lm1ldGFkYXRhID09PSBcImZ1bmN0aW9uXCIpIHJldHVybiBSZWZsZWN0Lm1ldGFkYXRhKG1ldGFkYXRhS2V5LCBtZXRhZGF0YVZhbHVlKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXdhaXRlcih0aGlzQXJnLCBfYXJndW1lbnRzLCBQLCBnZW5lcmF0b3IpIHtcclxuICAgIGZ1bmN0aW9uIGFkb3B0KHZhbHVlKSB7IHJldHVybiB2YWx1ZSBpbnN0YW5jZW9mIFAgPyB2YWx1ZSA6IG5ldyBQKGZ1bmN0aW9uIChyZXNvbHZlKSB7IHJlc29sdmUodmFsdWUpOyB9KTsgfVxyXG4gICAgcmV0dXJuIG5ldyAoUCB8fCAoUCA9IFByb21pc2UpKShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XHJcbiAgICAgICAgZnVuY3Rpb24gZnVsZmlsbGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yLm5leHQodmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHJlamVjdGVkKHZhbHVlKSB7IHRyeSB7IHN0ZXAoZ2VuZXJhdG9yW1widGhyb3dcIl0odmFsdWUpKTsgfSBjYXRjaCAoZSkgeyByZWplY3QoZSk7IH0gfVxyXG4gICAgICAgIGZ1bmN0aW9uIHN0ZXAocmVzdWx0KSB7IHJlc3VsdC5kb25lID8gcmVzb2x2ZShyZXN1bHQudmFsdWUpIDogYWRvcHQocmVzdWx0LnZhbHVlKS50aGVuKGZ1bGZpbGxlZCwgcmVqZWN0ZWQpOyB9XHJcbiAgICAgICAgc3RlcCgoZ2VuZXJhdG9yID0gZ2VuZXJhdG9yLmFwcGx5KHRoaXNBcmcsIF9hcmd1bWVudHMgfHwgW10pKS5uZXh0KCkpO1xyXG4gICAgfSk7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2dlbmVyYXRvcih0aGlzQXJnLCBib2R5KSB7XHJcbiAgICB2YXIgXyA9IHsgbGFiZWw6IDAsIHNlbnQ6IGZ1bmN0aW9uKCkgeyBpZiAodFswXSAmIDEpIHRocm93IHRbMV07IHJldHVybiB0WzFdOyB9LCB0cnlzOiBbXSwgb3BzOiBbXSB9LCBmLCB5LCB0LCBnO1xyXG4gICAgcmV0dXJuIGcgPSB7IG5leHQ6IHZlcmIoMCksIFwidGhyb3dcIjogdmVyYigxKSwgXCJyZXR1cm5cIjogdmVyYigyKSB9LCB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgKGdbU3ltYm9sLml0ZXJhdG9yXSA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gdGhpczsgfSksIGc7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgcmV0dXJuIGZ1bmN0aW9uICh2KSB7IHJldHVybiBzdGVwKFtuLCB2XSk7IH07IH1cclxuICAgIGZ1bmN0aW9uIHN0ZXAob3ApIHtcclxuICAgICAgICBpZiAoZikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy5cIik7XHJcbiAgICAgICAgd2hpbGUgKF8pIHRyeSB7XHJcbiAgICAgICAgICAgIGlmIChmID0gMSwgeSAmJiAodCA9IG9wWzBdICYgMiA/IHlbXCJyZXR1cm5cIl0gOiBvcFswXSA/IHlbXCJ0aHJvd1wiXSB8fCAoKHQgPSB5W1wicmV0dXJuXCJdKSAmJiB0LmNhbGwoeSksIDApIDogeS5uZXh0KSAmJiAhKHQgPSB0LmNhbGwoeSwgb3BbMV0pKS5kb25lKSByZXR1cm4gdDtcclxuICAgICAgICAgICAgaWYgKHkgPSAwLCB0KSBvcCA9IFtvcFswXSAmIDIsIHQudmFsdWVdO1xyXG4gICAgICAgICAgICBzd2l0Y2ggKG9wWzBdKSB7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDA6IGNhc2UgMTogdCA9IG9wOyBicmVhaztcclxuICAgICAgICAgICAgICAgIGNhc2UgNDogXy5sYWJlbCsrOyByZXR1cm4geyB2YWx1ZTogb3BbMV0sIGRvbmU6IGZhbHNlIH07XHJcbiAgICAgICAgICAgICAgICBjYXNlIDU6IF8ubGFiZWwrKzsgeSA9IG9wWzFdOyBvcCA9IFswXTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBjYXNlIDc6IG9wID0gXy5vcHMucG9wKCk7IF8udHJ5cy5wb3AoKTsgY29udGludWU7XHJcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxyXG4gICAgICAgICAgICAgICAgICAgIGlmICghKHQgPSBfLnRyeXMsIHQgPSB0Lmxlbmd0aCA+IDAgJiYgdFt0Lmxlbmd0aCAtIDFdKSAmJiAob3BbMF0gPT09IDYgfHwgb3BbMF0gPT09IDIpKSB7IF8gPSAwOyBjb250aW51ZTsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmIChvcFswXSA9PT0gMyAmJiAoIXQgfHwgKG9wWzFdID4gdFswXSAmJiBvcFsxXSA8IHRbM10pKSkgeyBfLmxhYmVsID0gb3BbMV07IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKG9wWzBdID09PSA2ICYmIF8ubGFiZWwgPCB0WzFdKSB7IF8ubGFiZWwgPSB0WzFdOyB0ID0gb3A7IGJyZWFrOyB9XHJcbiAgICAgICAgICAgICAgICAgICAgaWYgKHQgJiYgXy5sYWJlbCA8IHRbMl0pIHsgXy5sYWJlbCA9IHRbMl07IF8ub3BzLnB1c2gob3ApOyBicmVhazsgfVxyXG4gICAgICAgICAgICAgICAgICAgIGlmICh0WzJdKSBfLm9wcy5wb3AoKTtcclxuICAgICAgICAgICAgICAgICAgICBfLnRyeXMucG9wKCk7IGNvbnRpbnVlO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIG9wID0gYm9keS5jYWxsKHRoaXNBcmcsIF8pO1xyXG4gICAgICAgIH0gY2F0Y2ggKGUpIHsgb3AgPSBbNiwgZV07IHkgPSAwOyB9IGZpbmFsbHkgeyBmID0gdCA9IDA7IH1cclxuICAgICAgICBpZiAob3BbMF0gJiA1KSB0aHJvdyBvcFsxXTsgcmV0dXJuIHsgdmFsdWU6IG9wWzBdID8gb3BbMV0gOiB2b2lkIDAsIGRvbmU6IHRydWUgfTtcclxuICAgIH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fY3JlYXRlQmluZGluZyhvLCBtLCBrLCBrMikge1xyXG4gICAgaWYgKGsyID09PSB1bmRlZmluZWQpIGsyID0gaztcclxuICAgIG9bazJdID0gbVtrXTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fZXhwb3J0U3RhcihtLCBleHBvcnRzKSB7XHJcbiAgICBmb3IgKHZhciBwIGluIG0pIGlmIChwICE9PSBcImRlZmF1bHRcIiAmJiAhZXhwb3J0cy5oYXNPd25Qcm9wZXJ0eShwKSkgZXhwb3J0c1twXSA9IG1bcF07XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3ZhbHVlcyhvKSB7XHJcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xyXG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XHJcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XHJcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xyXG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xyXG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XHJcbiAgICAgICAgfVxyXG4gICAgfTtcclxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fcmVhZChvLCBuKSB7XHJcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XHJcbiAgICBpZiAoIW0pIHJldHVybiBvO1xyXG4gICAgdmFyIGkgPSBtLmNhbGwobyksIHIsIGFyID0gW10sIGU7XHJcbiAgICB0cnkge1xyXG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xyXG4gICAgfVxyXG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XHJcbiAgICBmaW5hbGx5IHtcclxuICAgICAgICB0cnkge1xyXG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcclxuICAgICAgICB9XHJcbiAgICAgICAgZmluYWxseSB7IGlmIChlKSB0aHJvdyBlLmVycm9yOyB9XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYXI7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX3NwcmVhZCgpIHtcclxuICAgIGZvciAodmFyIGFyID0gW10sIGkgPSAwOyBpIDwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKVxyXG4gICAgICAgIGFyID0gYXIuY29uY2F0KF9fcmVhZChhcmd1bWVudHNbaV0pKTtcclxuICAgIHJldHVybiBhcjtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fc3ByZWFkQXJyYXlzKCkge1xyXG4gICAgZm9yICh2YXIgcyA9IDAsIGkgPSAwLCBpbCA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBpbDsgaSsrKSBzICs9IGFyZ3VtZW50c1tpXS5sZW5ndGg7XHJcbiAgICBmb3IgKHZhciByID0gQXJyYXkocyksIGsgPSAwLCBpID0gMDsgaSA8IGlsOyBpKyspXHJcbiAgICAgICAgZm9yICh2YXIgYSA9IGFyZ3VtZW50c1tpXSwgaiA9IDAsIGpsID0gYS5sZW5ndGg7IGogPCBqbDsgaisrLCBrKyspXHJcbiAgICAgICAgICAgIHJba10gPSBhW2pdO1xyXG4gICAgcmV0dXJuIHI7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19hd2FpdCh2KSB7XHJcbiAgICByZXR1cm4gdGhpcyBpbnN0YW5jZW9mIF9fYXdhaXQgPyAodGhpcy52ID0gdiwgdGhpcykgOiBuZXcgX19hd2FpdCh2KTtcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNHZW5lcmF0b3IodGhpc0FyZywgX2FyZ3VtZW50cywgZ2VuZXJhdG9yKSB7XHJcbiAgICBpZiAoIVN5bWJvbC5hc3luY0l0ZXJhdG9yKSB0aHJvdyBuZXcgVHlwZUVycm9yKFwiU3ltYm9sLmFzeW5jSXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xyXG4gICAgdmFyIGcgPSBnZW5lcmF0b3IuYXBwbHkodGhpc0FyZywgX2FyZ3VtZW50cyB8fCBbXSksIGksIHEgPSBbXTtcclxuICAgIHJldHVybiBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobikgeyBpZiAoZ1tuXSkgaVtuXSA9IGZ1bmN0aW9uICh2KSB7IHJldHVybiBuZXcgUHJvbWlzZShmdW5jdGlvbiAoYSwgYikgeyBxLnB1c2goW24sIHYsIGEsIGJdKSA+IDEgfHwgcmVzdW1lKG4sIHYpOyB9KTsgfTsgfVxyXG4gICAgZnVuY3Rpb24gcmVzdW1lKG4sIHYpIHsgdHJ5IHsgc3RlcChnW25dKHYpKTsgfSBjYXRjaCAoZSkgeyBzZXR0bGUocVswXVszXSwgZSk7IH0gfVxyXG4gICAgZnVuY3Rpb24gc3RlcChyKSB7IHIudmFsdWUgaW5zdGFuY2VvZiBfX2F3YWl0ID8gUHJvbWlzZS5yZXNvbHZlKHIudmFsdWUudikudGhlbihmdWxmaWxsLCByZWplY3QpIDogc2V0dGxlKHFbMF1bMl0sIHIpOyB9XHJcbiAgICBmdW5jdGlvbiBmdWxmaWxsKHZhbHVlKSB7IHJlc3VtZShcIm5leHRcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiByZWplY3QodmFsdWUpIHsgcmVzdW1lKFwidGhyb3dcIiwgdmFsdWUpOyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUoZiwgdikgeyBpZiAoZih2KSwgcS5zaGlmdCgpLCBxLmxlbmd0aCkgcmVzdW1lKHFbMF1bMF0sIHFbMF1bMV0pOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2FzeW5jRGVsZWdhdG9yKG8pIHtcclxuICAgIHZhciBpLCBwO1xyXG4gICAgcmV0dXJuIGkgPSB7fSwgdmVyYihcIm5leHRcIiksIHZlcmIoXCJ0aHJvd1wiLCBmdW5jdGlvbiAoZSkgeyB0aHJvdyBlOyB9KSwgdmVyYihcInJldHVyblwiKSwgaVtTeW1ib2wuaXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaTtcclxuICAgIGZ1bmN0aW9uIHZlcmIobiwgZikgeyBpW25dID0gb1tuXSA/IGZ1bmN0aW9uICh2KSB7IHJldHVybiAocCA9ICFwKSA/IHsgdmFsdWU6IF9fYXdhaXQob1tuXSh2KSksIGRvbmU6IG4gPT09IFwicmV0dXJuXCIgfSA6IGYgPyBmKHYpIDogdjsgfSA6IGY7IH1cclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIF9fYXN5bmNWYWx1ZXMobykge1xyXG4gICAgaWYgKCFTeW1ib2wuYXN5bmNJdGVyYXRvcikgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlN5bWJvbC5hc3luY0l0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcclxuICAgIHZhciBtID0gb1tTeW1ib2wuYXN5bmNJdGVyYXRvcl0sIGk7XHJcbiAgICByZXR1cm4gbSA/IG0uY2FsbChvKSA6IChvID0gdHlwZW9mIF9fdmFsdWVzID09PSBcImZ1bmN0aW9uXCIgPyBfX3ZhbHVlcyhvKSA6IG9bU3ltYm9sLml0ZXJhdG9yXSgpLCBpID0ge30sIHZlcmIoXCJuZXh0XCIpLCB2ZXJiKFwidGhyb3dcIiksIHZlcmIoXCJyZXR1cm5cIiksIGlbU3ltYm9sLmFzeW5jSXRlcmF0b3JdID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gdGhpczsgfSwgaSk7XHJcbiAgICBmdW5jdGlvbiB2ZXJiKG4pIHsgaVtuXSA9IG9bbl0gJiYgZnVuY3Rpb24gKHYpIHsgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHsgdiA9IG9bbl0odiksIHNldHRsZShyZXNvbHZlLCByZWplY3QsIHYuZG9uZSwgdi52YWx1ZSk7IH0pOyB9OyB9XHJcbiAgICBmdW5jdGlvbiBzZXR0bGUocmVzb2x2ZSwgcmVqZWN0LCBkLCB2KSB7IFByb21pc2UucmVzb2x2ZSh2KS50aGVuKGZ1bmN0aW9uKHYpIHsgcmVzb2x2ZSh7IHZhbHVlOiB2LCBkb25lOiBkIH0pOyB9LCByZWplY3QpOyB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX21ha2VUZW1wbGF0ZU9iamVjdChjb29rZWQsIHJhdykge1xyXG4gICAgaWYgKE9iamVjdC5kZWZpbmVQcm9wZXJ0eSkgeyBPYmplY3QuZGVmaW5lUHJvcGVydHkoY29va2VkLCBcInJhd1wiLCB7IHZhbHVlOiByYXcgfSk7IH0gZWxzZSB7IGNvb2tlZC5yYXcgPSByYXc7IH1cclxuICAgIHJldHVybiBjb29rZWQ7XHJcbn07XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19pbXBvcnRTdGFyKG1vZCkge1xyXG4gICAgaWYgKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgcmV0dXJuIG1vZDtcclxuICAgIHZhciByZXN1bHQgPSB7fTtcclxuICAgIGlmIChtb2QgIT0gbnVsbCkgZm9yICh2YXIgayBpbiBtb2QpIGlmIChPYmplY3QuaGFzT3duUHJvcGVydHkuY2FsbChtb2QsIGspKSByZXN1bHRba10gPSBtb2Rba107XHJcbiAgICByZXN1bHQuZGVmYXVsdCA9IG1vZDtcclxuICAgIHJldHVybiByZXN1bHQ7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2ltcG9ydERlZmF1bHQobW9kKSB7XHJcbiAgICByZXR1cm4gKG1vZCAmJiBtb2QuX19lc01vZHVsZSkgPyBtb2QgOiB7IGRlZmF1bHQ6IG1vZCB9O1xyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gX19jbGFzc1ByaXZhdGVGaWVsZEdldChyZWNlaXZlciwgcHJpdmF0ZU1hcCkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIGdldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHJldHVybiBwcml2YXRlTWFwLmdldChyZWNlaXZlcik7XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiBfX2NsYXNzUHJpdmF0ZUZpZWxkU2V0KHJlY2VpdmVyLCBwcml2YXRlTWFwLCB2YWx1ZSkge1xyXG4gICAgaWYgKCFwcml2YXRlTWFwLmhhcyhyZWNlaXZlcikpIHtcclxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiYXR0ZW1wdGVkIHRvIHNldCBwcml2YXRlIGZpZWxkIG9uIG5vbi1pbnN0YW5jZVwiKTtcclxuICAgIH1cclxuICAgIHByaXZhdGVNYXAuc2V0KHJlY2VpdmVyLCB2YWx1ZSk7XHJcbiAgICByZXR1cm4gdmFsdWU7XHJcbn1cclxuIiwibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGZpbGwtcnVsZT1cXFwiZXZlbm9kZFxcXCIgY2xpcC1ydWxlPVxcXCJldmVub2RkXFxcIiBkPVxcXCJNMTYgMi40NDMgNS44NTEgMTQgMCA4LjExNWwxLjQ1LTEuNTM4IDQuMzEgNC4zMzRMMTQuNDYzIDEgMTYgMi40NDNaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk0xNiA4QTggOCAwIDEgMSAwIDhhOCA4IDAgMCAxIDE2IDBabS01LjczNy0zLjM5NGEuOC44IDAgMCAxIDEuMTMxIDEuMTMxTDkuMTMyIDhsMi4yNjIgMi4yNjNhLjguOCAwIDAgMS0xLjEzMSAxLjEzMUw4IDkuMTMxbC0yLjI2MyAyLjI2M2EuOC44IDAgMCAxLTEuMTMtMS4xMzFMNi44NjggOCA0LjYwNiA1LjczN2EuOC44IDAgMSAxIDEuMTMxLTEuMTMxTDggNi44NjlsMi4yNjMtMi4yNjNaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk05Ljc5NSAxLjI4MmMuMzg3LS4zODcgMS4wMjgtLjM3NCAxLjQzMS4wM2wxLjQ2MiAxLjQ2MmMuNDA0LjQwMy40MTcgMS4wNDQuMDMgMS40MzFMNS40MTMgMTEuNTFsLTIuNjc0LjQ4YS42MzcuNjM3IDAgMCAxLS43My0uNzNsLjQ4LTIuNjczIDcuMzA2LTcuMzA1Wk0yIDEzYTEgMSAwIDEgMCAwIDJoMTJhMSAxIDAgMSAwIDAtMkgyWlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjwvc3ZnPlwiIiwibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGZpbGwtcnVsZT1cXFwiZXZlbm9kZFxcXCIgY2xpcC1ydWxlPVxcXCJldmVub2RkXFxcIiBkPVxcXCJNMSAzYTIgMiAwIDAgMSAyLTJoOC4wODZhMSAxIDAgMCAxIC43MDcuMjkzbDIuOTE0IDIuOTE0YTEgMSAwIDAgMSAuMjkzLjcwN1YxM2EyIDIgMCAwIDEtMiAySDNhMiAyIDAgMCAxLTItMlYzWm0xLjc1Ljc1YTEgMSAwIDAgMSAxLTFoNS44NzVhMSAxIDAgMCAxIDEgMXYxLjVhMSAxIDAgMCAxLTEgMUgzLjc1YTEgMSAwIDAgMS0xLTF2LTEuNVptNy44NzUgNi44NzVhMi42MjUgMi42MjUgMCAxIDEtNS4yNSAwIDIuNjI1IDIuNjI1IDAgMCAxIDUuMjUgMFpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBmaWxsLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGNsaXAtcnVsZT1cXFwiZXZlbm9kZFxcXCIgZD1cXFwiTTEgOGMwLTMuODUgMy4xNS03IDctN3M3IDMuMTUgNyA3LTMuMTUgNy03IDctNy0zLjE1LTctN1ptNy44NzUgNC4zNzVhLjg3NS44NzUgMCAxIDEtMS43NSAwIC44NzUuODc1IDAgMCAxIDEuNzUgMFptLS4wNjMtMi42NTZjLjEzMi0uNTcxLjQxNS0uOTE2Ljg0OC0xLjI5OS40MzMtLjM4My43MDEtLjcwOS43MDEtLjcwOS4zOS0uNDcyLjcwMS0xLjEwMi43MDEtMS44MTEgMC0xLjczMi0xLjQwMi0zLjE1LTMuMTE3LTMuMTUtMS4zNTcgMC0yLjUyLjkyOC0yLjk0NiAyLjE1Ny0uMDYuMTUyLS4wNi4yOTktLjA2LjI5OWEuNjQ4LjY0OCAwIDAgMCAuNjY4LjY5NGwuMS0uMDA2Yy40LS4wNDYuNjc5LS4yNzUuODI5LS42NS4wNzgtLjE2NC4xMDgtLjIwOC4xMjItLjIyOS4yODEtLjQxNi43NTQtLjY5IDEuMjg3LS42OS44NTggMCAxLjU1OS43MDkgMS41NTkgMS41NzUgMCAuNDcyLS4xNTYuODY2LS40NjggMS4xMDNsLS45MzUgMS4wMjNjLS41MDUuNDQ3LS44MDYgMS4wNDktLjkwMSAxLjcyMmEuNjE0LjYxNCAwIDAgMC0uMDA1LjA2NHYuMTE3YS43NDguNzQ4IDAgMCAwIC43NS42OTZsLjA5Mi0uMDA1Yy4zOTMtLjA0My43MTQtLjM1OC43NDMtLjc0bC4wMzItLjE2MVpcXFwiIGZpbGw9XFxcIiMwMDBcXFwiPjwvcGF0aD48L3N2Zz5cIiIsIm1vZHVsZS5leHBvcnRzID0gXCI8c3ZnIHZpZXdCb3g9XFxcIjAgMCAxNiAxNlxcXCIgZmlsbD1cXFwibm9uZVxcXCIgeG1sbnM9XFxcImh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnXFxcIj48cGF0aCBkPVxcXCJtOC43NDUgOCA2LjEgNi4xYS41MjcuNTI3IDAgMSAxLS43NDUuNzQ2TDggOC43NDZsLTYuMSA2LjFhLjUyNy41MjcgMCAxIDEtLjc0Ni0uNzQ2bDYuMS02LjEtNi4xLTYuMWEuNTI3LjUyNyAwIDAgMSAuNzQ2LS43NDZsNi4xIDYuMSA2LjEtNi4xYS41MjcuNTI3IDAgMCAxIC43NDYuNzQ2TDguNzQ2IDhaXFxcIiBmaWxsPVxcXCIjMDAwXFxcIj48L3BhdGg+PC9zdmc+XCIiLCJtb2R1bGUuZXhwb3J0cyA9IFwiPHN2ZyB2aWV3Qm94PVxcXCIwIDAgMTYgMTZcXFwiIGZpbGw9XFxcIm5vbmVcXFwiIHhtbG5zPVxcXCJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2Z1xcXCI+PHBhdGggZmlsbC1ydWxlPVxcXCJldmVub2RkXFxcIiBjbGlwLXJ1bGU9XFxcImV2ZW5vZGRcXFwiIGQ9XFxcIk0xMS4yMjYgMS4zMTJjLS40MDMtLjQwNC0xLjA0NC0uNDE3LTEuNDMxLS4wM0wyLjQ5IDguNTg3bC0uNDggMi42NzRhLjYzNy42MzcgMCAwIDAgLjczLjczbDIuNjczLS40OCA3LjMwNS03LjMwNmMuMzg3LS4zODcuMzc0LTEuMDI4LS4wMy0xLjQzMWwtMS40NjItMS40NjJabS04LjExMyA5LjU3NS4zMi0xLjc4MSA0Ljk5MS00Ljk5MiAxLjQ2MiAxLjQ2Mi00Ljk5MiA0Ljk5MS0xLjc4MS4zMlptNy40NzMtNi4wMTIgMS40MDItMS40LTEuNDYyLTEuNDYzLTEuNDAxIDEuNDAyIDEuNDYxIDEuNDYxWlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjxwYXRoIGQ9XFxcIk0xLjUgMTRhLjUuNSAwIDAgMCAwIDFoMTNhLjUuNSAwIDAgMCAwLTFoLTEzWlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjwvc3ZnPlwiIiwibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGZpbGwtcnVsZT1cXFwiZXZlbm9kZFxcXCIgY2xpcC1ydWxlPVxcXCJldmVub2RkXFxcIiBkPVxcXCJNMTQgOEE2IDYgMCAxIDEgMiA4YTYgNiAwIDAgMSAxMiAwWm0xIDBBNyA3IDAgMSAxIDEgOGE3IDcgMCAwIDEgMTQgMFpNNy41IDQuNWEuNS41IDAgMCAxIDEgMHYzaDNhLjUuNSAwIDAgMSAwIDFoLTN2M2EuNS41IDAgMCAxLTEgMHYtM2gtM2EuNS41IDAgMCAxIDAtMWgzdi0zWlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjwvc3ZnPlwiIiwibW9kdWxlLmV4cG9ydHMgPSBcIjxzdmcgdmlld0JveD1cXFwiMCAwIDE2IDE2XFxcIiBmaWxsPVxcXCJub25lXFxcIiB4bWxucz1cXFwiaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmdcXFwiPjxwYXRoIGQ9XFxcIk02IDYuNWEuNS41IDAgMCAxIDEgMHY2YS41LjUgMCAwIDEtMSAwdi02Wk05LjUgNmEuNS41IDAgMCAwLS41LjV2NmEuNS41IDAgMCAwIDEgMHYtNmEuNS41IDAgMCAwLS41LS41WlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjxwYXRoIGZpbGwtcnVsZT1cXFwiZXZlbm9kZFxcXCIgY2xpcC1ydWxlPVxcXCJldmVub2RkXFxcIiBkPVxcXCJNMTEgMEg1YTEgMSAwIDAgMC0xIDF2MkguNWEuNS41IDAgMCAwIDAgMWgxLjZsLjgxIDExLjFhMSAxIDAgMCAwIC45OTUuOWg4LjE5YTEgMSAwIDAgMCAuOTk1LS45TDEzLjkgNGgxLjZhLjUuNSAwIDAgMCAwLTFIMTJWMWExIDEgMCAwIDAtMS0xWm0wIDNWMUg1djJoNlptMS44OTUgMWgtOS43OWwuOCAxMWg4LjE5bC44LTExWlxcXCIgZmlsbD1cXFwiIzAwMFxcXCI+PC9wYXRoPjwvc3ZnPlwiIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9maWxsZWQvYXBwbGljYXRpb24vY2hlY2suc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IENoZWNrRmlsbGVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL2ZpbGxlZC9lZGl0b3IvY2xvc2UtY2lyY2xlLnN2ZydcclxuXHJcbmV4cG9ydCBjb25zdCBDbG9zZUNpcmNsZUZpbGxlZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9maWxsZWQvZWRpdG9yL2VkaXQuc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IEVkaXRGaWxsZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCB7IFJlYWN0LCBjbGFzc05hbWVzIH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyB0eXBlIFNWR0NvbXBvbmVudFByb3BzIH0gZnJvbSAnamltdS11aSdcclxuaW1wb3J0IHNyYyBmcm9tICcuLi8uLi9zdmcvZmlsbGVkL2VkaXRvci9zYXZlLnN2ZydcclxuXHJcbmV4cG9ydCBjb25zdCBTYXZlRmlsbGVkID0gKHByb3BzOiBTVkdDb21wb25lbnRQcm9wcykgPT4ge1xyXG4gIGNvbnN0IFNWRyA9IHdpbmRvdy5TVkdcclxuICBjb25zdCB7IGNsYXNzTmFtZSwgLi4ub3RoZXJzIH0gPSBwcm9wc1xyXG5cclxuICBjb25zdCBjbGFzc2VzID0gY2xhc3NOYW1lcygnamltdS1pY29uIGppbXUtaWNvbi1jb21wb25lbnQnLCBjbGFzc05hbWUpXHJcbiAgaWYgKCFTVkcpIHJldHVybiA8c3ZnIGNsYXNzTmFtZT17Y2xhc3Nlc30gey4uLm90aGVycyBhcyBhbnl9IC8+XHJcbiAgcmV0dXJuIDxTVkcgY2xhc3NOYW1lPXtjbGFzc2VzfSBzcmM9e3NyY30gey4uLm90aGVyc30gLz5cclxufVxyXG4iLCJpbXBvcnQgeyBSZWFjdCwgY2xhc3NOYW1lcyB9IGZyb20gJ2ppbXUtY29yZSdcclxuaW1wb3J0IHsgdHlwZSBTVkdDb21wb25lbnRQcm9wcyB9IGZyb20gJ2ppbXUtdWknXHJcbmltcG9ydCBzcmMgZnJvbSAnLi4vLi4vc3ZnL2ZpbGxlZC9zdWdnZXN0ZWQvaGVscC5zdmcnXHJcblxyXG5leHBvcnQgY29uc3QgSGVscEZpbGxlZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9vdXRsaW5lZC9lZGl0b3IvY2xvc2Uuc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IENsb3NlT3V0bGluZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCB7IFJlYWN0LCBjbGFzc05hbWVzIH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQgeyB0eXBlIFNWR0NvbXBvbmVudFByb3BzIH0gZnJvbSAnamltdS11aSdcclxuaW1wb3J0IHNyYyBmcm9tICcuLi8uLi9zdmcvb3V0bGluZWQvZWRpdG9yL2VkaXQuc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IEVkaXRPdXRsaW5lZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9vdXRsaW5lZC9lZGl0b3IvcGx1cy1jaXJjbGUuc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IFBsdXNDaXJjbGVPdXRsaW5lZCA9IChwcm9wczogU1ZHQ29tcG9uZW50UHJvcHMpID0+IHtcclxuICBjb25zdCBTVkcgPSB3aW5kb3cuU1ZHXHJcbiAgY29uc3QgeyBjbGFzc05hbWUsIC4uLm90aGVycyB9ID0gcHJvcHNcclxuXHJcbiAgY29uc3QgY2xhc3NlcyA9IGNsYXNzTmFtZXMoJ2ppbXUtaWNvbiBqaW11LWljb24tY29tcG9uZW50JywgY2xhc3NOYW1lKVxyXG4gIGlmICghU1ZHKSByZXR1cm4gPHN2ZyBjbGFzc05hbWU9e2NsYXNzZXN9IHsuLi5vdGhlcnMgYXMgYW55fSAvPlxyXG4gIHJldHVybiA8U1ZHIGNsYXNzTmFtZT17Y2xhc3Nlc30gc3JjPXtzcmN9IHsuLi5vdGhlcnN9IC8+XHJcbn1cclxuIiwiaW1wb3J0IHsgUmVhY3QsIGNsYXNzTmFtZXMgfSBmcm9tICdqaW11LWNvcmUnXHJcbmltcG9ydCB7IHR5cGUgU1ZHQ29tcG9uZW50UHJvcHMgfSBmcm9tICdqaW11LXVpJ1xyXG5pbXBvcnQgc3JjIGZyb20gJy4uLy4uL3N2Zy9vdXRsaW5lZC9lZGl0b3IvdHJhc2guc3ZnJ1xyXG5cclxuZXhwb3J0IGNvbnN0IFRyYXNoT3V0bGluZWQgPSAocHJvcHM6IFNWR0NvbXBvbmVudFByb3BzKSA9PiB7XHJcbiAgY29uc3QgU1ZHID0gd2luZG93LlNWR1xyXG4gIGNvbnN0IHsgY2xhc3NOYW1lLCAuLi5vdGhlcnMgfSA9IHByb3BzXHJcblxyXG4gIGNvbnN0IGNsYXNzZXMgPSBjbGFzc05hbWVzKCdqaW11LWljb24gamltdS1pY29uLWNvbXBvbmVudCcsIGNsYXNzTmFtZSlcclxuICBpZiAoIVNWRykgcmV0dXJuIDxzdmcgY2xhc3NOYW1lPXtjbGFzc2VzfSB7Li4ub3RoZXJzIGFzIGFueX0gLz5cclxuICByZXR1cm4gPFNWRyBjbGFzc05hbWU9e2NsYXNzZXN9IHNyYz17c3JjfSB7Li4ub3RoZXJzfSAvPlxyXG59XHJcbiIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIjtcclxuaW1wb3J0IHtcclxuICBBcHBXaWRnZXRDb25maWcsIEFzc2Vzc21lbnQsIFxyXG4gIENsc3NSZXNwb25zZSxcclxuICBDTFNTVGVtcGxhdGUsIFxyXG4gIENvbXBvbmVudFRlbXBsYXRlLCBcclxuICBIYXphcmQsXHJcbiAgSW5jaWRlbnQsXHJcbiAgSW5Db21tZW50LFxyXG4gIEluZGljYXRvckFzc2Vzc21lbnQsXHJcbiAgSW5kaWNhdG9yVGVtcGxhdGUsIEluZGljYXRvcldlaWdodCwgTGlmZWxpbmVTdGF0dXMsIExpZmVMaW5lVGVtcGxhdGUsXHJcbiAgT3JnYW5pemF0aW9uLCBTY2FsZUZhY3RvclxyXG59IGZyb20gXCIuL2RhdGEtZGVmaW5pdGlvbnNcIjtcclxuaW1wb3J0IHtcclxuICBBU1NFU1NNRU5UX1VSTF9FUlJPUiwgXHJcbiAgQkFTRUxJTkVfVEVNUExBVEVfTkFNRSwgXHJcbiAgQ09NUE9ORU5UX1VSTF9FUlJPUiwgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OLCBIQVpBUkRfVVJMX0VSUk9SLCBJTkNJREVOVF9TVEFCSUxJWkFUSU9OLCBJTkNJREVOVF9VUkxfRVJST1IsIElORElDQVRPUl9VUkxfRVJST1IsXHJcbiAgTElGRV9TQUZFVFksXHJcbiAgTElGRV9TQUZFVFlfU0NBTEVfRkFDVE9SLFxyXG4gIExJRkVMSU5FX1VSTF9FUlJPUiwgTUFYSU1VTV9XRUlHSFQsIE9SR0FOSVpBVElPTl9VUkxfRVJST1IsIE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SLCBcclxuICBQT1JUQUxfVVJMLCBcclxuICBQUk9QRVJUWV9QUk9URUNUSU9OLCBcclxuICBSQU5LLCBcclxuICBURU1QTEFURV9VUkxfRVJST1J9IGZyb20gXCIuL2NvbnN0YW50c1wiO1xyXG5pbXBvcnQgeyBnZXRBcHBTdG9yZSB9IGZyb20gXCJqaW11LWNvcmVcIjtcclxuaW1wb3J0IHtcclxuICBJRmVhdHVyZSwgSUZlYXR1cmVTZXQsIElGaWVsZH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXJcIjtcclxuaW1wb3J0IHsgcXVlcnlUYWJsZUZlYXR1cmVzLCBcclxuICAgdXBkYXRlVGFibGVGZWF0dXJlLCBkZWxldGVUYWJsZUZlYXR1cmVzLCBcclxuICAgIGFkZFRhYmxlRmVhdHVyZXMsIHVwZGF0ZVRhYmxlRmVhdHVyZXMsIHF1ZXJ5VGFibGVGZWF0dXJlU2V0IH0gZnJvbSBcIi4vZXNyaS1hcGlcIjtcclxuaW1wb3J0IHsgbG9nLCBMb2dUeXBlIH0gZnJvbSBcIi4vbG9nZ2VyXCI7XHJcbmltcG9ydCB7IElDb2RlZFZhbHVlIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXR5cGVzXCI7XHJcbmltcG9ydCB7IGNoZWNrQ3VycmVudFN0YXR1cywgc2lnbkluIH0gZnJvbSBcIi4vYXV0aFwiO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuL2Nsc3Mtc3RvcmVcIjtcclxuaW1wb3J0IHsgSUNyZWRlbnRpYWwgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aFwiO1xyXG5pbXBvcnQgeyBwYXJzZURhdGUgfSBmcm9tIFwiLi91dGlsc1wiO1xyXG5cclxuXHJcbi8vPT09PT09PT09PT09PT09PT09PT09PT09UFVCTElDPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxyXG5cclxuZXhwb3J0IGNvbnN0IGluaXRpYWxpemVBdXRoID0gYXN5bmMoYXBwSWQ6IHN0cmluZykgPT57ICAgXHJcbiAgY29uc29sZS5sb2coJ2luaXRpYWxpemVBdXRoIGNhbGxlZCcpXHJcbiAgbGV0IGNyZWQgPSBhd2FpdCBjaGVja0N1cnJlbnRTdGF0dXMoYXBwSWQsIFBPUlRBTF9VUkwpO1xyXG5cclxuICBpZighY3JlZCl7XHJcbiAgICBjcmVkID0gYXdhaXQgc2lnbkluKGFwcElkLCBQT1JUQUxfVVJMKTsgICAgXHJcbiAgfVxyXG5cclxuICBjb25zdCBjcmVkZW50aWFsID0ge1xyXG4gICAgZXhwaXJlczogY3JlZC5leHBpcmVzLFxyXG4gICAgc2VydmVyOiBjcmVkLnNlcnZlcixcclxuICAgIHNzbDogY3JlZC5zc2wsXHJcbiAgICB0b2tlbjogY3JlZC50b2tlbixcclxuICAgIHVzZXJJZDogY3JlZC51c2VySWRcclxuICB9IGFzIElDcmVkZW50aWFsXHJcblxyXG4gIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLkFVVEhFTlRJQ0FURV9BQ1RJT04sIGNyZWRlbnRpYWwpOyBcclxufVxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlTGlmZWxpbmVTdGF0dXMobGlmZWxpbmVTdGF0dXM6IExpZmVsaW5lU3RhdHVzLCBcclxuICBjb25maWc6IEFwcFdpZGdldENvbmZpZywgYXNzZXNzbWVudE9iamVjdElkOiBudW1iZXIsICB1c2VyOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgXHJcbiAgY29uc29sZS5sb2coJ2NhbGxlZCB1cGRhdGVMaWZlbGluZVN0YXR1cycpXHJcbiAgY2hlY2tQYXJhbShjb25maWcubGlmZWxpbmVTdGF0dXMsICdMaWZlbGluZSBTdGF0dXMgVVJMIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICBjb25zdCBhdHRyaWJ1dGVzID0ge1xyXG4gICAgT0JKRUNUSUQ6IGxpZmVsaW5lU3RhdHVzLm9iamVjdElkLFxyXG4gICAgU2NvcmU6IGxpZmVsaW5lU3RhdHVzLnNjb3JlLCBcclxuICAgIENvbG9yOiBsaWZlbGluZVN0YXR1cy5jb2xvciwgXHJcbiAgICBJc092ZXJyaWRlbjogbGlmZWxpbmVTdGF0dXMuaXNPdmVycmlkZW4sIFxyXG4gICAgT3ZlcnJpZGVuU2NvcmU6IGxpZmVsaW5lU3RhdHVzLm92ZXJyaWRlU2NvcmUsICBcclxuICAgIE92ZXJyaWRlbkNvbG9yOiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZW5Db2xvcixcclxuICAgIE92ZXJyaWRlbkJ5OiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZW5CeSwgIFxyXG4gICAgT3ZlcnJpZGVDb21tZW50OiBsaWZlbGluZVN0YXR1cy5vdmVycmlkZUNvbW1lbnQgXHJcbiAgfVxyXG4gIGxldCByZXNwb25zZSAgPSBhd2FpdCB1cGRhdGVUYWJsZUZlYXR1cmUoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBhdHRyaWJ1dGVzLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG5cclxuICAgIGNvbnN0IGlhRmVhdHVyZXMgPSBsaWZlbGluZVN0YXR1cy5pbmRpY2F0b3JBc3Nlc3NtZW50cy5tYXAoaSA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgT0JKRUNUSUQ6IGkub2JqZWN0SWQsXHJcbiAgICAgICAgICBzdGF0dXM6IGkuc3RhdHVzLFxyXG4gICAgICAgICAgQ29tbWVudHM6IGkuY29tbWVudHMgJiYgaS5jb21tZW50cy5sZW5ndGggPiAwID8gSlNPTi5zdHJpbmdpZnkoaS5jb21tZW50cyk6ICcnXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICB9KVxyXG5cclxuICAgIHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGlhRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuXHJcbiAgICAgIGNvbnN0IGFzc2Vzc0ZlYXR1cmUgPSB7XHJcbiAgICAgICAgT0JKRUNUSUQ6IGFzc2Vzc21lbnRPYmplY3RJZCxcclxuICAgICAgICBFZGl0ZWREYXRlOiBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcclxuICAgICAgICBFZGl0b3I6IHVzZXJcclxuICAgICAgfVxyXG4gICAgICByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcuYXNzZXNzbWVudHMsIGFzc2Vzc0ZlYXR1cmUsIGNvbmZpZylcclxuICAgICAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuICAgIH0gICAgXHJcbiAgfVxyXG4gIGxvZygnVXBkYXRpbmcgTGlmZWxpbmUgc2NvcmUgZmFpbGVkJywgTG9nVHlwZS5FUlJPUiwgJ3VwZGF0ZUxpZmVsaW5lU3RhdHVzJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ1VwZGF0aW5nIExpZmVsaW5lIHNjb3JlIGZhaWxlZCdcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wbGV0ZUFzc2Vzc21lbnQoYXNzZXNzbWVudDogQXNzZXNzbWVudCwgXHJcbiAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHVzZXJOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIGNoZWNrUGFyYW0oY29uZmlnLmFzc2Vzc21lbnRzLCAnTm8gQXNzZXNzbWVudCBVcmwgcHJvdmlkZWQnKTtcclxuXHJcbiAgIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZShjb25maWcuYXNzZXNzbWVudHMsIHtcclxuICAgICAgT0JKRUNUSUQ6IGFzc2Vzc21lbnQub2JqZWN0SWQsXHJcbiAgICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICAgIEVkaXRlZERhdGU6IG5ldyBEYXRlKCkuZ2V0VGltZSgpLFxyXG4gICAgICBJc0NvbXBsZXRlZDogMVxyXG4gICB9LCBjb25maWcpO1xyXG4gICBjb25zb2xlLmxvZyhyZXNwb25zZSk7XHJcbiAgIHJldHVybntcclxuICAgICBkYXRhOiByZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpXHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IHBhc3NEYXRhSW50ZWdyaXR5ID0gYXN5bmMgKHNlcnZpY2VVcmw6IHN0cmluZywgZmllbGRzOiBJRmllbGRbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpID0+IHtcclxuXHJcbiAgY2hlY2tQYXJhbShzZXJ2aWNlVXJsLCAnU2VydmljZSBVUkwgbm90IHByb3ZpZGVkJyk7XHJcblxyXG4gIC8vIHNlcnZpY2VVcmwgPSBgJHtzZXJ2aWNlVXJsfT9mPWpzb24mdG9rZW49JHt0b2tlbn1gO1xyXG4gIC8vIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2goc2VydmljZVVybCwge1xyXG4gIC8vICAgbWV0aG9kOiBcIkdFVFwiLFxyXG4gIC8vICAgaGVhZGVyczoge1xyXG4gIC8vICAgICAnY29udGVudC10eXBlJzogJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAvLyAgIH1cclxuICAvLyB9XHJcbiAgLy8gKTtcclxuICAvLyBjb25zdCBqc29uID0gYXdhaXQgcmVzcG9uc2UuanNvbigpO1xyXG5cclxuICAvLyBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhzZXJ2aWNlVXJsLCAnMT0xJywgY29uZmlnKTtcclxuXHJcbiAgLy8gY29uc3QgZGF0YUZpZWxkcyA9IGZlYXR1cmVzWzBdLiBhcyBJRmllbGRbXTtcclxuXHJcbiAgLy8gZGVidWdnZXI7XHJcbiAgLy8gaWYgKGZpZWxkcy5sZW5ndGggPiBkYXRhRmllbGRzLmxlbmd0aCkge1xyXG4gIC8vICAgdGhyb3cgbmV3IEVycm9yKCdOdW1iZXIgb2YgZmllbGRzIGRvIG5vdCBtYXRjaCBmb3IgJyArIHNlcnZpY2VVcmwpO1xyXG4gIC8vIH1cclxuXHJcbiAgLy8gY29uc3QgYWxsRmllbGRzR29vZCA9IGZpZWxkcy5ldmVyeShmID0+IHtcclxuICAvLyAgIGNvbnN0IGZvdW5kID0gZGF0YUZpZWxkcy5maW5kKGYxID0+IGYxLm5hbWUgPT09IGYubmFtZSAmJiBmMS50eXBlLnRvU3RyaW5nKCkgPT09IGYudHlwZS50b1N0cmluZygpICYmIGYxLmRvbWFpbiA9PSBmLmRvbWFpbik7XHJcbiAgLy8gICByZXR1cm4gZm91bmQ7XHJcbiAgLy8gfSk7XHJcblxyXG4gIC8vIGlmICghYWxsRmllbGRzR29vZCkge1xyXG4gIC8vICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIGZpZWxkcyBpbiB0aGUgZmVhdHVyZSBzZXJ2aWNlICcgKyBzZXJ2aWNlVXJsKVxyXG4gIC8vIH1cclxuICByZXR1cm4gdHJ1ZTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0SW5kaWNhdG9yRmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgSW5kaWNhdG9ycyBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0V2VpZ2h0c0ZlYXR1cmVzKHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IFdlaWdodHMgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldExpZmVsaW5lRmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgTGlmZWxpbmUgY2FsbGVkJyk7XHJcbiAgcmV0dXJuIGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0Q29tcG9uZW50RmVhdHVyZXMocXVlcnk6IHN0cmluZywgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElGZWF0dXJlW10+e1xyXG4gIGNvbnNvbGUubG9nKCdnZXQgQ29tcG9uZW50cyBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5jb21wb25lbnRzLCBxdWVyeSwgY29uZmlnKTtcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0VGVtcGxhdGVGZWF0dXJlU2V0KHF1ZXJ5OiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJRmVhdHVyZVNldD57XHJcbiAgY29uc29sZS5sb2coJ2dldCBUZW1wbGF0ZSBjYWxsZWQnKTtcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVTZXQoY29uZmlnLnRlbXBsYXRlcywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRUZW1wbGF0ZXMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHRlbXBsYXRlSWQ/OiBzdHJpbmcsIHF1ZXJ5U3RyaW5nPzpzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxDTFNTVGVtcGxhdGVbXT4+IHtcclxuXHJcbiAgY29uc3QgdGVtcGxhdGVVcmwgPSBjb25maWcudGVtcGxhdGVzO1xyXG4gIGNvbnN0IGxpZmVsaW5lVXJsID0gY29uZmlnLmxpZmVsaW5lcztcclxuICBjb25zdCBjb21wb25lbnRVcmwgPSBjb25maWcuY29tcG9uZW50cztcclxuXHJcbiAgdHJ5e1xyXG4gICAgY2hlY2tQYXJhbSh0ZW1wbGF0ZVVybCwgVEVNUExBVEVfVVJMX0VSUk9SKTtcclxuICAgIGNoZWNrUGFyYW0obGlmZWxpbmVVcmwsIExJRkVMSU5FX1VSTF9FUlJPUik7XHJcbiAgICBjaGVja1BhcmFtKGNvbXBvbmVudFVybCwgQ09NUE9ORU5UX1VSTF9FUlJPUik7XHJcblxyXG4gICAgY29uc3QgdGVtcFF1ZXJ5ID0gdGVtcGxhdGVJZCA/IGBHbG9iYWxJRD0nJHt0ZW1wbGF0ZUlkfWAgOihxdWVyeVN0cmluZyA/IHF1ZXJ5U3RyaW5nIDogJzE9MScgKTtcclxuXHJcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IFByb21pc2UuYWxsKFtcclxuICAgICAgZ2V0VGVtcGxhdGVGZWF0dXJlU2V0KHRlbXBRdWVyeSwgY29uZmlnKSxcclxuICAgICAgZ2V0TGlmZWxpbmVGZWF0dXJlcygnMT0xJywgY29uZmlnKSwgXHJcbiAgICAgIGdldENvbXBvbmVudEZlYXR1cmVzKCcxPTEnLCBjb25maWcpXSk7XHJcbiAgICBcclxuICAgIGNvbnN0IHRlbXBsYXRlRmVhdHVyZVNldCA9IHJlc3BvbnNlWzBdO1xyXG4gICAgY29uc3QgbGlmZWxpbmVGZWF0dXJlcyA9IHJlc3BvbnNlWzFdO1xyXG4gICAgY29uc3QgY29tcG9uZW50RmVhdHVyZXMgPSByZXNwb25zZVsyXTtcclxuXHJcbiAgICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlcyA9IGF3YWl0IGdldEluZGljYXRvckZlYXR1cmVzKCcxPTEnLCBjb25maWcpO1xyXG4gICAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSBhd2FpdCBnZXRXZWlnaHRzRmVhdHVyZXMoJzE9MScsIGNvbmZpZyk7XHJcblxyXG4gICAgY29uc3QgdGVtcGxhdGVzID0gYXdhaXQgUHJvbWlzZS5hbGwodGVtcGxhdGVGZWF0dXJlU2V0LmZlYXR1cmVzLm1hcChhc3luYyAodGVtcGxhdGVGZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgICBjb25zdCB0ZW1wbGF0ZUluZGljYXRvckZlYXR1cmVzID0gaW5kaWNhdG9yRmVhdHVyZXMuZmlsdGVyKGkgPT5pLmF0dHJpYnV0ZXMuVGVtcGxhdGVJRCA9PSB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgICAgICBcclxuICAgICAgcmV0dXJuIGF3YWl0IGdldFRlbXBsYXRlKHRlbXBsYXRlRmVhdHVyZSwgbGlmZWxpbmVGZWF0dXJlcywgY29tcG9uZW50RmVhdHVyZXMsIFxyXG4gICAgICAgIHRlbXBsYXRlSW5kaWNhdG9yRmVhdHVyZXMsIHdlaWdodEZlYXR1cmVzLCBcclxuICAgICAgICB0ZW1wbGF0ZUZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdTdGF0dXMnKS5kb21haW4uY29kZWRWYWx1ZXMpXHJcbiAgICB9KSk7XHJcblxyXG4gICAgaWYodGVtcGxhdGVzLmZpbHRlcih0ID0+IHQuaXNTZWxlY3RlZCkubGVuZ3RoID4gMSB8fCB0ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5pc1NlbGVjdGVkKS5sZW5ndGggPT0gMCl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdGVtcGxhdGVzLm1hcCh0ID0+IHtcclxuICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLnQsXHJcbiAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IHQubmFtZSA9PT0gQkFTRUxJTkVfVEVNUExBVEVfTkFNRVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBpZih0ZW1wbGF0ZXMubGVuZ3RoID09PSAxKXtcclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0ZW1wbGF0ZXMubWFwKHQgPT4ge1xyXG4gICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgaXNTZWxlY3RlZDogdHJ1ZVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRlbXBsYXRlc1xyXG4gICAgfVxyXG4gIH1cclxuICBjYXRjaChlKXsgXHJcbiAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2dldFRlbXBsYXRlcycpO1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiAnVGVtcGxhdGVzIHJlcXVlc3QgZmFpbGVkLidcclxuICAgIH1cclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBmdW5jdGlvbiB1c2VGZXRjaERhdGE8VD4odXJsOiBzdHJpbmcsIGNhbGxiYWNrQWRhcHRlcj86IEZ1bmN0aW9uKTogW1QsIEZ1bmN0aW9uLCBib29sZWFuLCBzdHJpbmddIHtcclxuICBjb25zdCBbZGF0YSwgc2V0RGF0YV0gPSBSZWFjdC51c2VTdGF0ZShudWxsKTtcclxuICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSBSZWFjdC51c2VTdGF0ZSh0cnVlKTtcclxuICBjb25zdCBbZXJyb3IsIHNldEVycm9yXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTtcclxuXHJcbiAgUmVhY3QudXNlRWZmZWN0KCgpID0+IHtcclxuICAgIGNvbnN0IGNvbnRyb2xsZXIgPSBuZXcgQWJvcnRDb250cm9sbGVyKCk7XHJcbiAgICByZXF1ZXN0RGF0YSh1cmwsIGNvbnRyb2xsZXIpXHJcbiAgICAgIC50aGVuKChkYXRhKSA9PiB7XHJcbiAgICAgICAgaWYgKGNhbGxiYWNrQWRhcHRlcikge1xyXG4gICAgICAgICAgc2V0RGF0YShjYWxsYmFja0FkYXB0ZXIoZGF0YSkpO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICBzZXREYXRhKGRhdGEpO1xyXG4gICAgICAgIH1cclxuICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgfSlcclxuICAgICAgLmNhdGNoKChlcnIpID0+IHtcclxuICAgICAgICBjb25zb2xlLmxvZyhlcnIpO1xyXG4gICAgICAgIHNldEVycm9yKGVycik7XHJcbiAgICAgIH0pXHJcbiAgICByZXR1cm4gKCkgPT4gY29udHJvbGxlci5hYm9ydCgpO1xyXG4gIH0sIFt1cmxdKVxyXG5cclxuICByZXR1cm4gW2RhdGEsIHNldERhdGEsIGxvYWRpbmcsIGVycm9yXVxyXG59XHJcblxyXG5leHBvcnQgZnVuY3Rpb24gZGlzcGF0Y2hBY3Rpb24odHlwZTogYW55LCB2YWw6IGFueSkge1xyXG4gIGdldEFwcFN0b3JlKCkuZGlzcGF0Y2goe1xyXG4gICAgdHlwZSxcclxuICAgIHZhbFxyXG4gIH0pO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0SW5jaWRlbnRzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxJbmNpZGVudFtdPiB7XHJcbiAgIFxyXG4gIGNvbnNvbGUubG9nKCdnZXQgaW5jaWRlbnRzIGNhbGxlZC4nKVxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluY2lkZW50cywgSU5DSURFTlRfVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluY2lkZW50cywgJzE9MScsIGNvbmZpZyk7XHJcblxyXG4gIGNvbnN0IHF1ZXJ5ID0gYEdsb2JhbElEIElOICgke2ZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5IYXphcmRJRCkubWFwKGlkID0+IGAnJHtpZH0nYCkuam9pbignLCcpfSlgO1xyXG4gIFxyXG4gIGNvbnN0IGhhemFyZEZlYXR1cmVzZXQgPSBhd2FpdCBnZXRIYXphcmRGZWF0dXJlcyhjb25maWcsIHF1ZXJ5LCAnZ2V0SW5jaWRlbnRzJyk7XHJcblxyXG4gIHJldHVybiBmZWF0dXJlcy5tYXAoKGY6IElGZWF0dXJlKSA9PntcclxuICAgICAgY29uc3QgaGYgPSBoYXphcmRGZWF0dXJlc2V0LmZlYXR1cmVzLmZpbmQoaCA9PiBoLmF0dHJpYnV0ZXMuR2xvYmFsSUQgPT0gZi5hdHRyaWJ1dGVzLkhhemFyZElEKVxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG9iamVjdElkOiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICBoYXphcmQ6IGhmID8ge1xyXG4gICAgICAgICAgb2JqZWN0SWQ6IGhmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgICBpZDogaGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICAgIG5hbWU6IGhmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICAgIHRpdGxlOiBoZi5hdHRyaWJ1dGVzLkRpc3BsYXlUaXRsZSB8fCBoZi5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGhmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICAgIHR5cGU6IGhmLmF0dHJpYnV0ZXMuVHlwZSxcclxuICAgICAgICAgIGRlc2NyaXB0aW9uOiBoZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgICAgZG9tYWluczogaGF6YXJkRmVhdHVyZXNldC5maWVsZHMuZmluZChmID0+IGYubmFtZSA9PT0gJ1R5cGUnKS5kb21haW4uY29kZWRWYWx1ZXNcclxuICAgICAgICB9IDogbnVsbCxcclxuICAgICAgICBkZXNjcmlwdGlvbjogZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgIHN0YXJ0RGF0ZTogTnVtYmVyKGYuYXR0cmlidXRlcy5TdGFydERhdGUpLFxyXG4gICAgICAgIGVuZERhdGU6IE51bWJlcihmLmF0dHJpYnV0ZXMuRW5kRGF0ZSlcclxuICAgICAgfSBhcyBJbmNpZGVudDtcclxuICB9KTtcclxuICByZXR1cm4gW107XHJcbn1cclxuXHJcbmFzeW5jIGZ1bmN0aW9uIGdldEhhemFyZEZlYXR1cmVzIChjb25maWc6IEFwcFdpZGdldENvbmZpZywgcXVlcnk6IHN0cmluZywgY2FsbGVyOiBzdHJpbmcpOiBQcm9taXNlPElGZWF0dXJlU2V0PiB7XHJcbiAgY29uc29sZS5sb2coJ2dldCBIYXphcmRzIGNhbGxlZCBieSAnK2NhbGxlcilcclxuICBjaGVja1BhcmFtKGNvbmZpZy5oYXphcmRzLCBIQVpBUkRfVVJMX0VSUk9SKTsgIFxyXG4gIHJldHVybiBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZVNldChjb25maWcuaGF6YXJkcywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZXRIYXphcmRzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBxdWVyeVN0cmluZzogc3RyaW5nLCBjYWxsZXI6IHN0cmluZyk6IFByb21pc2U8SGF6YXJkW10+IHtcclxuICBcclxuICBjb25zdCBmZWF0dXJlU2V0ID0gYXdhaXQgZ2V0SGF6YXJkRmVhdHVyZXMoY29uZmlnLCBxdWVyeVN0cmluZywgY2FsbGVyKTtcclxuICBpZighZmVhdHVyZVNldCB8fCBmZWF0dXJlU2V0LmZlYXR1cmVzLmxlbmd0aCA9PSAwKXtcclxuICAgIHJldHVybiBbXTtcclxuICB9XHJcbiAgcmV0dXJuIGZlYXR1cmVTZXQuZmVhdHVyZXMubWFwKChmOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgb2JqZWN0SWQ6IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgbmFtZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIHRpdGxlOiBmLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlIHx8IGYuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgdHlwZTogZi5hdHRyaWJ1dGVzLlR5cGUsXHJcbiAgICAgIGRlc2NyaXB0aW9uOiBmLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICAgIGRvbWFpbnM6IGZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdUeXBlJykuZG9tYWluLmNvZGVkVmFsdWVzXHJcbiAgICB9IGFzIEhhemFyZFxyXG4gIH0pXHJcbiAgcmV0dXJuIFtdO1xyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2V0T3JnYW5pemF0aW9ucyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgcXVlcnlTdHJpbmc6IHN0cmluZyk6IFByb21pc2U8T3JnYW5pemF0aW9uW10+IHtcclxuICBjb25zb2xlLmxvZygnZ2V0IE9yZ2FuaXphdGlvbnMgY2FsbGVkJylcclxuICBjaGVja1BhcmFtKGNvbmZpZy5vcmdhbml6YXRpb25zLCBPUkdBTklaQVRJT05fVVJMX0VSUk9SKTtcclxuXHJcbiAgY29uc3QgZmVhdHVyZVNldCA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlU2V0KGNvbmZpZy5vcmdhbml6YXRpb25zLCBxdWVyeVN0cmluZywgY29uZmlnKTtcclxuIFxyXG4gIGlmKGZlYXR1cmVTZXQgJiYgZmVhdHVyZVNldC5mZWF0dXJlcyAmJiBmZWF0dXJlU2V0LmZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgcmV0dXJuIGZlYXR1cmVTZXQuZmVhdHVyZXMubWFwKChmOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG9iamVjdElkOiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgaWQ6IGYuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICBuYW1lOiBmLmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICB0aXRsZTogZi5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgdHlwZTogZi5hdHRyaWJ1dGVzLlR5cGUsXHJcbiAgICAgICAgcGFyZW50SWQ6IGYuYXR0cmlidXRlcy5QYXJlbnRJRCxcclxuICAgICAgICBkZXNjcmlwdGlvbjogZi5hdHRyaWJ1dGVzLkRlc2NyaXB0aW9uLFxyXG4gICAgICAgIGRvbWFpbnM6IGZlYXR1cmVTZXQuZmllbGRzLmZpbmQoZiA9PiBmLm5hbWUgPT09ICdUeXBlJykuZG9tYWluLmNvZGVkVmFsdWVzXHJcbiAgICAgIH0gYXMgT3JnYW5pemF0aW9uXHJcbiAgICB9KVxyXG4gIH1cclxuICByZXR1cm4gW107XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjcmVhdGVOZXdUZW1wbGF0ZShjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGU6IENMU1NUZW1wbGF0ZSwgXHJcbiB1c2VyTmFtZTogc3RyaW5nLCBvcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbiwgaGF6YXJkOiBIYXphcmQpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG4gXHJcbiAgY2hlY2tQYXJhbShjb25maWcudGVtcGxhdGVzLCBURU1QTEFURV9VUkxfRVJST1IpO1xyXG4gIGNoZWNrUGFyYW0odGVtcGxhdGUsICdUZW1wbGF0ZSBkYXRhIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICBjb25zdCBjcmVhdGVEYXRlID0gbmV3IERhdGUoKS5nZXRUaW1lKCk7XHJcbiAgY29uc3QgdGVtcGxhdGVOYW1lID0gdGVtcGxhdGUubmFtZVswXS50b0xvY2FsZVVwcGVyQ2FzZSgpK3RlbXBsYXRlLm5hbWUuc3Vic3RyaW5nKDEpO1xyXG4gXHJcbiAgbGV0IGZlYXR1cmUgPSB7XHJcbiAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgIE9yZ2FuaXphdGlvbklEOiBvcmdhbml6YXRpb24gPyBvcmdhbml6YXRpb24uaWQgOiAgbnVsbCxcclxuICAgICAgT3JnYW5pemF0aW9uTmFtZTogb3JnYW5pemF0aW9uID8gb3JnYW5pemF0aW9uLm5hbWU6IG51bGwsXHJcbiAgICAgIE9yZ2FuaXphdGlvblR5cGU6IG9yZ2FuaXphdGlvbiA/IChvcmdhbml6YXRpb24udHlwZS5jb2RlID8gb3JnYW5pemF0aW9uLnR5cGUuY29kZTogb3JnYW5pemF0aW9uLnR5cGUgKTogbnVsbCxcclxuICAgICAgSGF6YXJkSUQ6ICBoYXphcmQgPyBoYXphcmQuaWQgOiBudWxsLFxyXG4gICAgICBIYXphcmROYW1lOiAgaGF6YXJkID8gaGF6YXJkLm5hbWUgOiBudWxsLFxyXG4gICAgICBIYXphcmRUeXBlOiAgaGF6YXJkID8gKGhhemFyZC50eXBlLmNvZGUgPyBoYXphcmQudHlwZS5jb2RlIDogaGF6YXJkLnR5cGUpIDogbnVsbCxcclxuICAgICAgTmFtZTogdGVtcGxhdGVOYW1lICxcclxuICAgICAgQ3JlYXRvcjogdXNlck5hbWUsXHJcbiAgICAgIENyZWF0ZWREYXRlOiBjcmVhdGVEYXRlLCAgICAgIFxyXG4gICAgICBTdGF0dXM6IDEsXHJcbiAgICAgIElzU2VsZWN0ZWQ6IDAsXHJcbiAgICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICAgIEVkaXRlZERhdGU6IGNyZWF0ZURhdGUgICAgIFxyXG4gICAgfVxyXG4gIH1cclxuICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy50ZW1wbGF0ZXMsIFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuICAgIFxyXG4gICAgY29uc3QgdGVtcGxhdGVJZCA9IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWQ7XHJcbiAgICAvL2NyZWF0ZSBuZXcgaW5kaWNhdG9ycyAgIFxyXG4gICAgY29uc3QgaW5kaWNhdG9ycyA9IGdldFRlbXBsYXRlSW5kaWNhdG9ycyh0ZW1wbGF0ZSk7XHJcbiAgICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlcyA9IGluZGljYXRvcnMubWFwKGluZGljYXRvciA9PiB7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgVGVtcGxhdGVJRDogdGVtcGxhdGVJZCwgIFxyXG4gICAgICAgICAgQ29tcG9uZW50SUQ6IGluZGljYXRvci5jb21wb25lbnRJZCxcclxuICAgICAgICAgIENvbXBvbmVudE5hbWU6IGluZGljYXRvci5jb21wb25lbnROYW1lLCAgXHJcbiAgICAgICAgICBOYW1lOiBpbmRpY2F0b3IubmFtZSwgICBcclxuICAgICAgICAgIFRlbXBsYXRlTmFtZTogdGVtcGxhdGVOYW1lLCBcclxuICAgICAgICAgIExpZmVsaW5lTmFtZTogaW5kaWNhdG9yLmxpZmVsaW5lTmFtZSAgICAgIFxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSlcclxuICAgIHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgaW5kaWNhdG9yRmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXtcclxuXHJcbiAgICAgIGNvbnN0IGdsb2JhbElkcyA9IGAoJHtyZXNwb25zZS5hZGRSZXN1bHRzLm1hcChyID0+IGAnJHtyLmdsb2JhbElkfSdgKS5qb2luKCcsJyl9KWA7XHJcbiAgICAgIGNvbnN0IHF1ZXJ5ID0gJ0dsb2JhbElEIElOICcrZ2xvYmFsSWRzOyAgICAgXHJcbiAgICAgIGNvbnN0IGFkZGVkSW5kaWNhdG9yRmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvcnMscXVlcnkgLCBjb25maWcpO1xyXG5cclxuICAgICAgIGxldCB3ZWlnaHRzRmVhdHVyZXMgPSBbXTtcclxuICAgICAgIGZvcihsZXQgZmVhdHVyZSBvZiBhZGRlZEluZGljYXRvckZlYXR1cmVzKXsgICBcclxuICAgICAgICAgY29uc3QgaW5jb21pbmdJbmRpY2F0b3IgPSBpbmRpY2F0b3JzLmZpbmQoaSA9PiBpLm5hbWUgPT09IGZlYXR1cmUuYXR0cmlidXRlcy5OYW1lKTtcclxuICAgICAgICAgaWYoaW5jb21pbmdJbmRpY2F0b3Ipe1xyXG4gICAgICAgICAgY29uc3Qgd2VpZ2h0RmVhdHVyZXMgPSBpbmNvbWluZ0luZGljYXRvci53ZWlnaHRzLm1hcCh3ID0+IHsgICAgICAgIFxyXG4gICAgICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgICAgICAgIEluZGljYXRvcklEOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsICBcclxuICAgICAgICAgICAgICAgIE5hbWU6IHcubmFtZSAsXHJcbiAgICAgICAgICAgICAgICBXZWlnaHQ6IHcud2VpZ2h0LCBcclxuICAgICAgICAgICAgICAgIFNjYWxlRmFjdG9yOiAwLCAgXHJcbiAgICAgICAgICAgICAgICBBZGp1c3RlZFdlaWdodCA6IDAsXHJcbiAgICAgICAgICAgICAgICBNYXhBZGp1c3RlZFdlaWdodDowXHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICAgIHdlaWdodHNGZWF0dXJlcyA9IHdlaWdodHNGZWF0dXJlcy5jb25jYXQod2VpZ2h0RmVhdHVyZXMpXHJcbiAgICAgICAgIH0gICAgICAgICAgICBcclxuICAgICAgIH1cclxuXHJcbiAgICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIHdlaWdodHNGZWF0dXJlcywgY29uZmlnKTtcclxuICAgICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgICAgfVxyXG4gICAgICAgfVxyXG4gICAgfVxyXG4gICAgLy8gY29uc3QgcHJvbWlzZXMgPSBpbmRpY2F0b3JzLm1hcChpbmRpY2F0b3IgPT4gY3JlYXRlTmV3SW5kaWNhdG9yKGluZGljYXRvciwgY29uZmlnLCB0ZW1wbGF0ZUlkLCB0ZW1wbGF0ZU5hbWUpKTtcclxuXHJcbiAgICAvLyBjb25zdCBwcm9taXNlUmVzcG9uc2UgPSBhd2FpdCBQcm9taXNlLmFsbChwcm9taXNlcyk7XHJcbiAgICAvLyBpZihwcm9taXNlUmVzcG9uc2UuZXZlcnkocCA9PiBwLmRhdGEpKXtcclxuICAgIC8vICAgcmV0dXJuIHtcclxuICAgIC8vICAgICBkYXRhOiB0cnVlXHJcbiAgICAvLyAgIH1cclxuICAgIC8vIH1cclxuICB9IFxyXG5cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnY3JlYXRlTmV3VGVtcGxhdGUnKVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdFcnJvciBvY2N1cnJlZCB3aGlsZSBjcmVhdGluZyB0aGUgbmV3IHRlbXBsYXRlJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZVRlbXBsYXRlT3JnYW5pemF0aW9uQW5kSGF6YXJkKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBcclxuICB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCB1c2VyTmFtZTogc3RyaW5nKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+IHtcclxuXHJcbiAgY2hlY2tQYXJhbSh0ZW1wbGF0ZSwgJ1RlbXBsYXRlIG5vdCBwcm92aWRlZCcpO1xyXG4gIGNoZWNrUGFyYW0oY29uZmlnLnRlbXBsYXRlcywgVEVNUExBVEVfVVJMX0VSUk9SKTsgXHJcblxyXG4gIGNvbnN0IGF0dHJpYnV0ZXMgPSB7XHJcbiAgICBPQkpFQ1RJRDogdGVtcGxhdGUub2JqZWN0SWQsXHJcbiAgICBPcmdhbml6YXRpb25JRDogdGVtcGxhdGUub3JnYW5pemF0aW9uSWQsXHJcbiAgICBIYXphcmRJRDogdGVtcGxhdGUuaGF6YXJkSWQsXHJcbiAgICBPcmdhbml6YXRpb25OYW1lOiB0ZW1wbGF0ZS5vcmdhbml6YXRpb25OYW1lLFxyXG4gICAgT3JnYW5pemF0aW9uVHlwZTogdGVtcGxhdGUub3JnYW5pemF0aW9uVHlwZSxcclxuICAgIEhhemFyZE5hbWU6IHRlbXBsYXRlLmhhemFyZE5hbWUsXHJcbiAgICBIYXphcmRUeXBlOiB0ZW1wbGF0ZS5oYXphcmRUeXBlLFxyXG4gICAgTmFtZTogdGVtcGxhdGUubmFtZSxcclxuICAgIEVkaXRvcjogdXNlck5hbWUsXHJcbiAgICBFZGl0ZWREYXRlOiBuZXcgRGF0ZSgpLmdldFRpbWUoKSxcclxuICAgIFN0YXR1czogdGVtcGxhdGUuc3RhdHVzLmNvZGUsXHJcbiAgICBJc1NlbGVjdGVkOiB0ZW1wbGF0ZS5pc1NlbGVjdGVkID8gMTogMFxyXG4gIH0gXHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy50ZW1wbGF0ZXMsIGF0dHJpYnV0ZXMsIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UudXBkYXRlUmVzdWx0cyAmJiByZXNwb25zZS51cGRhdGVSZXN1bHRzLmV2ZXJ5KHUgPT4gdS5zdWNjZXNzKSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICB9XHJcbiAgfVxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICd1cGRhdGVUZW1wbGF0ZU9yZ2FuaXphdGlvbkFuZEhhemFyZCcpXHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHVwZGF0aW5nIHRlbXBsYXRlLidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzZWxlY3RUZW1wbGF0ZShvYmplY3RJZDogbnVtYmVyLCBvYmplY3RJZHM6IG51bWJlcltdLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPFN0cmluZz4+IHtcclxuICBcclxuICAgIGNvbnNvbGUubG9nKCdzZWxlY3QgVGVtcGxhdGUgY2FsbGVkJylcclxuICAgIHRyeXtcclxuICAgICAgY2hlY2tQYXJhbShjb25maWcudGVtcGxhdGVzLCBURU1QTEFURV9VUkxfRVJST1IpO1xyXG5cclxuICAgICAgLy9sZXQgZmVhdHVyZXMgPSBhd2FpdCBnZXRUZW1wbGF0ZUZlYXR1cmVzKCcxPTEnLCBjb25maWcpLy8gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy50ZW1wbGF0ZXMsICcxPTEnLCBjb25maWcpXHJcbiAgICBcclxuICAgICAgY29uc3QgZmVhdHVyZXMgPSAgb2JqZWN0SWRzLm1hcChvaWQgPT4ge1xyXG4gICAgICAgIHJldHVybiB7ICAgICAgICAgIFxyXG4gICAgICAgICAgYXR0cmlidXRlczoge1xyXG4gICAgICAgICAgICBPQkpFQ1RJRDogb2lkLFxyXG4gICAgICAgICAgICBJc1NlbGVjdGVkOiBvaWQgPT09IG9iamVjdElkID8gMSA6IDBcclxuICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgIH0pXHJcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlcyhjb25maWcudGVtcGxhdGVzLCBmZWF0dXJlcywgY29uZmlnKVxyXG4gICAgICBpZihyZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGRhdGE6IHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHNbMF0uZ2xvYmFsSWRcclxuICAgICAgICAgfSBhcyBDbHNzUmVzcG9uc2U8U3RyaW5nPjtcclxuICAgICAgfVxyXG4gICAgfWNhdGNoKGUpIHtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdzZWxlY3RUZW1wbGF0ZScpO1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGVycm9yczogZVxyXG4gICAgICB9XHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBsb2FkU2NhbGVGYWN0b3JzKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8U2NhbGVGYWN0b3JbXT4+e1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5jb25zdGFudHMsICdSYXRpbmcgU2NhbGVzIHVybCBub3QgcHJvdmlkZWQnKTtcclxuXHJcbiAgdHJ5e1xyXG5cclxuICAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmNvbnN0YW50cywgJzE9MScsIGNvbmZpZyk7XHJcbiAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgIGNvbnN0IHNjYWxlcyA9ICBmZWF0dXJlcy5tYXAoZiA9PntcclxuICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgICB2YWx1ZTogZi5hdHRyaWJ1dGVzLlZhbHVlXHJcbiAgICAgICB9IGFzIFNjYWxlRmFjdG9yOyAgICAgICBcclxuICAgICB9KVxyXG5cclxuICAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiBzY2FsZXNcclxuICAgIH0gYXMgQ2xzc1Jlc3BvbnNlPFNjYWxlRmFjdG9yW10+XHJcbiAgIH1cclxuXHJcbiAgIGxvZygnRXJyb3Igb2NjdXJyZWQgd2hpbGUgcmVxdWVzdGluZyByYXRpbmcgc2NhbGVzJywgTG9nVHlwZS5FUlJPUiwgJ2xvYWRSYXRpbmdTY2FsZXMnKVxyXG4gICByZXR1cm4ge1xyXG4gICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHJlcXVlc3RpbmcgcmF0aW5nIHNjYWxlcydcclxuICAgfVxyXG4gIH0gY2F0Y2goZSl7XHJcbiAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdsb2FkUmF0aW5nU2NhbGVzJyk7ICAgIFxyXG4gIH0gIFxyXG4gICBcclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZU5ld0luZGljYXRvcihpbmRpY2F0b3I6IEluZGljYXRvclRlbXBsYXRlLCBjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGVJZDogc3RyaW5nLCB0ZW1wbGF0ZU5hbWU6IHN0cmluZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PiB7XHJcblxyXG4gIGNoZWNrUGFyYW0oY29uZmlnLmluZGljYXRvcnMsIElORElDQVRPUl9VUkxfRVJST1IpO1xyXG5cclxuICBjb25zdCBpbmRpY2F0b3JGZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBUZW1wbGF0ZUlEOiB0ZW1wbGF0ZUlkLCAgXHJcbiAgICAgIENvbXBvbmVudElEOiBpbmRpY2F0b3IuY29tcG9uZW50SWQsXHJcbiAgICAgIENvbXBvbmVudE5hbWU6IGluZGljYXRvci5jb21wb25lbnROYW1lLCAgXHJcbiAgICAgIE5hbWU6IGluZGljYXRvci5uYW1lLCAgIFxyXG4gICAgICBUZW1wbGF0ZU5hbWU6IHRlbXBsYXRlTmFtZSwgXHJcbiAgICAgIExpZmVsaW5lTmFtZTogaW5kaWNhdG9yLmxpZmVsaW5lTmFtZSAgICAgIFxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9ycywgW2luZGljYXRvckZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG5cclxuICAgIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gaW5kaWNhdG9yLndlaWdodHMubWFwKHcgPT4ge1xyXG4gICAgICAgXHJcbiAgICAgICByZXR1cm4ge1xyXG4gICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIEluZGljYXRvcklEOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkLCAgXHJcbiAgICAgICAgICBOYW1lOiB3Lm5hbWUgLFxyXG4gICAgICAgICAgV2VpZ2h0OiB3LndlaWdodCwgXHJcbiAgICAgICAgICBTY2FsZUZhY3RvcjogMCwgIFxyXG4gICAgICAgICAgQWRqdXN0ZWRXZWlnaHQgOiAwLFxyXG4gICAgICAgICAgTWF4QWRqdXN0ZWRXZWlnaHQ6MFxyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG4gICAgfSk7XHJcblxyXG4gICAgcmVzcG9uc2UgPSBhd2FpdCBhZGRUYWJsZUZlYXR1cmVzKGNvbmZpZy53ZWlnaHRzLCB3ZWlnaHRGZWF0dXJlcywgY29uZmlnKTtcclxuICAgIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgcmV0dXJuIHtcclxuICAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgICB9XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnY3JlYXRlTmV3SW5kaWNhdG9yJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ0Vycm9yIG9jY3VycmVkIHdoaWxlIHNhdmluZyB0aGUgaW5kaWNhdG9yLidcclxuICB9XHJcblxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdXBkYXRlSW5kaWNhdG9yTmFtZShjb25maWc6IEFwcFdpZGdldENvbmZpZywgaW5kaWNhdG9yVGVtcDpJbmRpY2F0b3JUZW1wbGF0ZSk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5ESUNBVE9SX1VSTF9FUlJPUik7XHJcblxyXG4gIGNvbnN0IGF0dHJpYnV0ZXMgPSB7XHJcbiAgICBPQkpFQ1RJRDogaW5kaWNhdG9yVGVtcC5vYmplY3RJZCxcclxuICAgIE5hbWU6IGluZGljYXRvclRlbXAubmFtZSxcclxuICAgIERpc3BsYXlUaXRsZTogaW5kaWNhdG9yVGVtcC5uYW1lLFxyXG4gICAgSXNBY3RpdmU6IDFcclxuICB9XHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy5pbmRpY2F0b3JzLCBhdHRyaWJ1dGVzLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeSh1ID0+IHUuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgfVxyXG4gIGxvZyhKU09OLnN0cmluZ2lmeShyZXNwb25zZSksIExvZ1R5cGUuRVJST1IsICd1cGRhdGVJbmRpY2F0b3JOYW1lJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgdXBkYXRpbmcgaW5kaWNhdG9yJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVwZGF0ZUluZGljYXRvcihpbmRpY2F0b3I6IEluZGljYXRvclRlbXBsYXRlLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPGJvb2xlYW4+PntcclxuICAgXHJcbiAgY2hlY2tQYXJhbShjb25maWcuaW5kaWNhdG9ycywgSU5DSURFTlRfVVJMX0VSUk9SKTtcclxuXHJcbiAgbGV0IGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBgTmFtZT0nJHtpbmRpY2F0b3IubmFtZX0nIEFORCBUZW1wbGF0ZU5hbWU9JyR7aW5kaWNhdG9yLnRlbXBsYXRlTmFtZX0nYCwgY29uZmlnKVxyXG4gXHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID4gMSl7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBlcnJvcnM6ICdBbiBpbmRpY2F0b3Igd2l0aCB0aGUgc2FtZSBuYW1lIGFscmVhZHkgZXhpc3RzJ1xyXG4gICAgfVxyXG4gIH1cclxuICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHVwZGF0ZUluZGljYXRvck5hbWUoY29uZmlnLCBpbmRpY2F0b3IpO1xyXG5cclxuICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiByZXNwb25zZS5lcnJvcnNcclxuICAgIH1cclxuICB9XHJcbiBcclxuICAgZmVhdHVyZXMgPSBpbmRpY2F0b3Iud2VpZ2h0cy5tYXAodyA9PiB7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGF0dHJpYnV0ZXM6IHtcclxuICAgICAgICAgIE9CSkVDVElEOiB3Lm9iamVjdElkLFxyXG4gICAgICAgICAgV2VpZ2h0OiBOdW1iZXIody53ZWlnaHQpLCBcclxuICAgICAgICAgIEFkanVzdGVkV2VpZ2h0OiBOdW1iZXIody53ZWlnaHQpICogdy5zY2FsZUZhY3RvclxyXG4gICAgICAgfVxyXG4gICAgIH1cclxuICAgfSk7XHJcblxyXG4gICBjb25zdCB1cGRhdGVSZXNwb25zZSA9IGF3YWl0IHVwZGF0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLndlaWdodHMsIGZlYXR1cmVzLCBjb25maWcpO1xyXG4gICBpZih1cGRhdGVSZXNwb25zZS51cGRhdGVSZXN1bHRzICYmIHVwZGF0ZVJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMuZXZlcnkodSA9PiB1LnN1Y2Nlc3MpKXtcclxuICAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gICB9XHJcblxyXG4gICBsb2coSlNPTi5zdHJpbmdpZnkodXBkYXRlUmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAndXBkYXRlSW5kaWNhdG9yJyk7XHJcbiAgIHJldHVybiB7XHJcbiAgICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgdXBkYXRpbmcgaW5kaWNhdG9yLidcclxuICAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVsZXRlSW5kaWNhdG9yKGluZGljYXRvclRlbXBsYXRlOiBJbmRpY2F0b3JUZW1wbGF0ZSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5pbmRpY2F0b3JzLCBJTkRJQ0FUT1JfVVJMX0VSUk9SKTtcclxuICBjaGVja1BhcmFtKGNvbmZpZy53ZWlnaHRzLCAnV2VpZ2h0cyBVUkwgbm90IHByb3ZpZGVkJyk7XHJcbiAgXHJcbiAgbGV0IHJlc3AgPSBhd2FpdCBkZWxldGVUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JzLCBbaW5kaWNhdG9yVGVtcGxhdGUub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gIGlmKHJlc3AuZGVsZXRlUmVzdWx0cyAmJiByZXNwLmRlbGV0ZVJlc3VsdHMuZXZlcnkoZCA9PiBkLnN1Y2Nlc3MpKXtcclxuICAgICBjb25zdCB3ZWlnaHRzT2JqZWN0SWRzID0gaW5kaWNhdG9yVGVtcGxhdGUud2VpZ2h0cy5tYXAodyA9PiB3Lm9iamVjdElkKTtcclxuICAgICByZXNwID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcud2VpZ2h0cywgd2VpZ2h0c09iamVjdElkcywgY29uZmlnKTtcclxuICAgICBpZihyZXNwLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcC5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgICB9XHJcbiAgICAgfVxyXG4gIH1cclxuXHJcbiAgbG9nKEpTT04uc3RyaW5naWZ5KHJlc3ApLCBMb2dUeXBlLkVSUk9SLCAnZGVsZXRlSW5kaWNhdG9yJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgZGVsZXRpbmcgdGhlIGluZGljYXRvcidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBhcmNoaXZlVGVtcGxhdGUob2JqZWN0SWQ6IG51bWJlciwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj4ge1xyXG4gXHJcbiAgY29uc3QgcmVzcG9uc2UgID0gYXdhaXQgdXBkYXRlVGFibGVGZWF0dXJlKGNvbmZpZy50ZW1wbGF0ZXMsIHtcclxuICAgIE9CSkVDVElEOiBvYmplY3RJZCxcclxuICAgIElzU2VsZWN0ZWQ6IDAsXHJcbiAgICBJc0FjdGl2ZTogMFxyXG4gIH0sIGNvbmZpZyk7XHJcbiAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xyXG4gIGlmKHJlc3BvbnNlLnVwZGF0ZVJlc3VsdHMgJiYgcmVzcG9uc2UudXBkYXRlUmVzdWx0cy5ldmVyeShlID0+IGUuc3VjY2Vzcykpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZGF0YTogdHJ1ZVxyXG4gICAgfVxyXG4gIH1cclxuICBsb2coSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpLCBMb2dUeXBlLkVSUk9SLCAnYXJjaGl2ZVRlbXBsYXRlJyk7XHJcbiAgcmV0dXJuIHtcclxuICAgIGVycm9yczogJ1RoZSB0ZW1wbGF0ZSBjYW5ub3QgYmUgYXJjaGl2ZWQuJ1xyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNhdmVPcmdhbml6YXRpb24oY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIG9yZ2FuaXphdGlvbjogT3JnYW5pemF0aW9uKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8T3JnYW5pemF0aW9uPj4ge1xyXG5cclxuICBjaGVja1BhcmFtKGNvbmZpZy5vcmdhbml6YXRpb25zLCBPUkdBTklaQVRJT05fVVJMX0VSUk9SKTtcclxuICBjaGVja1BhcmFtKG9yZ2FuaXphdGlvbiwgJ09yZ2FuaXphdGlvbiBvYmplY3Qgbm90IHByb3ZpZGVkJyk7XHJcbiBcclxuICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBOYW1lOiBvcmdhbml6YXRpb24ubmFtZSxcclxuICAgICAgVHlwZTogb3JnYW5pemF0aW9uLnR5cGU/LmNvZGUsXHJcbiAgICAgIERpc3BsYXlUaXRsZTogb3JnYW5pemF0aW9uLm5hbWUsXHJcbiAgICAgIFBhcmVudElEOiBvcmdhbml6YXRpb24/LnBhcmVudElkXHJcbiAgICB9XHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gIGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLm9yZ2FuaXphdGlvbnMsIFtmZWF0dXJlXSwgY29uZmlnKTtcclxuICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMuZXZlcnkociA9PiByLnN1Y2Nlc3MpKXsgXHJcbiAgICByZXR1cm4ge1xyXG4gICAgICBkYXRhOiB7XHJcbiAgICAgICAgLi4ub3JnYW5pemF0aW9uXHJcbiAgICAgIH0gYXMgT3JnYW5pemF0aW9uIC8vIChhd2FpdCBnZXRPcmdhbml6YXRpb25zKGNvbmZpZywgYEdsb2JhbElEPScke3Jlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWR9J2ApKVswXVxyXG4gICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiBKU09OLnN0cmluZ2lmeShyZXNwb25zZSlcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzYXZlSGF6YXJkKGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBoYXphcmQ6IEhhemFyZCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPEhhemFyZD4+IHtcclxuICBcclxuICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgYXR0cmlidXRlczoge1xyXG4gICAgICBOYW1lOiBoYXphcmQubmFtZSxcclxuICAgICAgRGlzcGxheVRpdGxlOiBoYXphcmQubmFtZSxcclxuICAgICAgVHlwZTogaGF6YXJkLnR5cGUuY29kZSxcclxuICAgICAgRGVzY3JpcHRpb246IGhhemFyZC5kZXNjcmlwdGlvblxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuaGF6YXJkcywgW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2VzcykpeyAgIFxyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHtcclxuICAgICAgICAgIC4uLmhhemFyZCxcclxuICAgICAgICAgIG9iamVjdElkOiByZXNwb25zZS5hZGRSZXN1bHRzWzBdLm9iamVjdElkLFxyXG4gICAgICAgICAgaWQ6IHJlc3BvbnNlLmFkZFJlc3VsdHNbMF0uZ2xvYmFsSWRcclxuICAgICAgICB9IGFzIEhhemFyZCAgXHJcbiAgICAgIH1cclxuICB9XHJcblxyXG4gIGxvZyhgRXJyb3Igb2NjdXJyZWQgd2hpbGUgc2F2aW5nIGhhemFyZC4gUmVzdGFydGluZyB0aGUgYXBwbGljYXRpb24gbWF5IGZpeCB0aGlzIGlzc3VlLmAsIExvZ1R5cGUuRVJST1IsICdzYXZlSGF6YXJkJylcclxuICByZXR1cm4ge1xyXG4gICAgZXJyb3JzOiAnRXJyb3Igb2NjdXJyZWQgd2hpbGUgc2F2aW5nIGhhemFyZC4gUmVzdGFydGluZyB0aGUgYXBwbGljYXRpb24gbWF5IGZpeCB0aGlzIGlzc3VlLidcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVJbmNpZGVudChpbmNpZGVudDogSW5jaWRlbnQsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5jaWRlbnRzLCBbaW5jaWRlbnQub2JqZWN0SWRdLCBjb25maWcpO1xyXG4gIGlmKHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcG9uc2UuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBkYXRhOiB0cnVlXHJcbiAgICAgfVxyXG4gIH1cclxuICByZXR1cm4ge1xyXG4gICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUhhemFyZChoYXphcmQ6IEhhemFyZCwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxib29sZWFuPj57XHJcbiAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaGF6YXJkcywgW2hhemFyZC5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgIGlmKHJlc3BvbnNlLmRlbGV0ZVJlc3VsdHMgJiYgcmVzcG9uc2UuZGVsZXRlUmVzdWx0cy5ldmVyeShkID0+IGQuc3VjY2Vzcykpe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IHRydWVcclxuICAgICAgfVxyXG4gICB9XHJcbiAgIHJldHVybiB7XHJcbiAgICBlcnJvcnM6IEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKVxyXG4gICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWxldGVPcmdhbml6YXRpb24ob3JnYW5pemF0aW9uOiBPcmdhbml6YXRpb24sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKTogUHJvbWlzZTxDbHNzUmVzcG9uc2U8Ym9vbGVhbj4+e1xyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcub3JnYW5pemF0aW9ucywgW29yZ2FuaXphdGlvbi5vYmplY3RJZF0sIGNvbmZpZyk7XHJcbiAgaWYocmVzcG9uc2UuZGVsZXRlUmVzdWx0cyAmJiByZXNwb25zZS5kZWxldGVSZXN1bHRzLmV2ZXJ5KGQgPT4gZC5zdWNjZXNzKSl7XHJcbiAgICAgcmV0dXJuIHtcclxuICAgICAgIGRhdGE6IHRydWVcclxuICAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgIGVycm9yczogSlNPTi5zdHJpbmdpZnkocmVzcG9uc2UpXHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY2hlY2tQYXJhbShwYXJhbTogYW55LCBlcnJvcjogc3RyaW5nKSB7XHJcbiAgaWYgKCFwYXJhbSB8fCBwYXJhbSA9PSBudWxsIHx8IHBhcmFtID09PSAnJyB8fCBwYXJhbSA9PSB1bmRlZmluZWQpIHtcclxuICAgIHRocm93IG5ldyBFcnJvcihlcnJvcilcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB0ZW1wbENsZWFuVXAoaW5kVXJsOiBzdHJpbmcsIGFsaWdVcmw6IHN0cmluZywgdG9rZW46IHN0cmluZykge1xyXG5cclxuXHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzYXZlTmV3QXNzZXNzbWVudChuZXdBc3Nlc3NtZW50OiBBc3Nlc3NtZW50LCB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCBcclxuICAgICAgICAgICAgICAgICAgY29uZmlnOiBBcHBXaWRnZXRDb25maWcsIHByZXZBc3Nlc3NtZW50PzogQXNzZXNzbWVudCk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHN0cmluZz4+eyAgICBcclxuICAgICAgXHJcbiAgICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBzYXZlQXNzZXNzbWVudChuZXdBc3Nlc3NtZW50LCBjb25maWcpO1xyXG4gICAgICBpZihyZXNwLmVycm9ycyl7XHJcbiAgICAgICAgbG9nKCdVbmFibGUgdG8gY3JlYXRlIHRoZSBhc3Nlc3NtZW50LicsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpO1xyXG5cclxuICAgICAgICByZXR1cm4ge1xyXG4gICAgICAgICAgZXJyb3JzOiAnVW5hYmxlIHRvIGNyZWF0ZSB0aGUgYXNzZXNzbWVudC4nXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcbiAgICAgXHJcbiAgICAgIHRyeXtcclxuXHJcbiAgICAgICAgY29uc3QgaW5kaWNhdG9ycyA9IGdldFRlbXBsYXRlSW5kaWNhdG9ycyh0ZW1wbGF0ZSk7XHJcbiAgICAgICAgaWYoIWluZGljYXRvcnMgfHwgaW5kaWNhdG9ycy5sZW5ndGggPT09IDApe1xyXG4gICAgICAgICAgbG9nKCdUZW1wbGF0ZSBpbmRpY2F0b3JzIG5vdCBmb3VuZCcsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpOyAgXHJcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1RlbXBsYXRlIGluZGljYXRvcnMgbm90IGZvdW5kLicpXHJcbiAgICAgICAgfSAgICAgIFxyXG4gIFxyXG4gICAgICAgIGNvbnN0IGxpZmVsaW5lU3RhdHVzRmVhdHVyZXMgPSB0ZW1wbGF0ZS5saWZlbGluZVRlbXBsYXRlcy5tYXAobHQgPT4ge1xyXG4gICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIGF0dHJpYnV0ZXM6IHsgXHJcbiAgICAgICAgICAgICAgQXNzZXNzbWVudElEIDogcmVzcC5kYXRhLFxyXG4gICAgICAgICAgICAgIFNjb3JlOiBudWxsLCBcclxuICAgICAgICAgICAgICBDb2xvcjogbnVsbCwgXHJcbiAgICAgICAgICAgICAgTGlmZWxpbmVJRDogbHQuaWQsIFxyXG4gICAgICAgICAgICAgIElzT3ZlcnJpZGVuOiAwLCBcclxuICAgICAgICAgICAgICBPdmVycmlkZW5TY29yZTogbnVsbCwgXHJcbiAgICAgICAgICAgICAgT3ZlcnJpZGVuQnk6IG51bGwsIFxyXG4gICAgICAgICAgICAgIE92ZXJyaWRlQ29tbWVudDogbnVsbCwgXHJcbiAgICAgICAgICAgICAgTGlmZWxpbmVOYW1lOiBsdC50aXRsZSwgXHJcbiAgICAgICAgICAgICAgVGVtcGxhdGVOYW1lOiB0ZW1wbGF0ZS5uYW1lXHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH1cclxuICAgICAgICB9KVxyXG4gICAgICAgIGxldCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBsaWZlbGluZVN0YXR1c0ZlYXR1cmVzLCBjb25maWcpO1xyXG4gICAgICAgIGlmKHJlc3BvbnNlICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cy5ldmVyeShyID0+IHIuc3VjY2Vzcykpe1xyXG4gICAgICAgICAgIGNvbnN0IHF1ZXJ5ID0gJ0dsb2JhbElEIElOICgnKyByZXNwb25zZS5hZGRSZXN1bHRzLm1hcChyID0+IGAnJHtyLmdsb2JhbElkfSdgKS5qb2luKCcsJykrXCIpXCI7XHJcbiAgICAgICAgICAgY29uc3QgbHNGZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIHF1ZXJ5LCBjb25maWcpO1xyXG4gICAgICAgICAgIFxyXG4gICAgICAgICAgIGNvbnN0IGluZGljYXRvckFzc2Vzc21lbnRGZWF0dXJlcyA9IGluZGljYXRvcnMubWFwKGkgPT4ge1xyXG4gICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgY29uc3QgbGlmZWxpbmVTdGF0dXNGZWF0dXJlID0gbHNGZWF0dXJlcy5maW5kKGxzID0+IFxyXG4gICAgICAgICAgICAgICAgbHMuYXR0cmlidXRlcy5MaWZlbGluZU5hbWUuc3BsaXQoL1snICcmXyxdKy8pLmpvaW4oJ18nKSAgPT09IGkubGlmZWxpbmVOYW1lKTtcclxuICAgICAgICAgICAgaWYoIWxpZmVsaW5lU3RhdHVzRmVhdHVyZSl7XHJcbiAgICAgICAgICAgICAgY29uc29sZS5sb2coYCR7aS5saWZlbGluZU5hbWV9IG5vdCBmb3VuZGApO1xyXG4gICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgJHtpLmxpZmVsaW5lTmFtZX0gbm90IGZvdW5kYCk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgICAgICAgICBMaWZlbGluZVN0YXR1c0lEIDogbGlmZWxpbmVTdGF0dXNGZWF0dXJlPyBsaWZlbGluZVN0YXR1c0ZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCA6ICcnLFxyXG4gICAgICAgICAgICAgICAgSW5kaWNhdG9ySUQ6IGkuaWQsICBcclxuICAgICAgICAgICAgICAgIFRlbXBsYXRlTmFtZTogaS50ZW1wbGF0ZU5hbWUsICBcclxuICAgICAgICAgICAgICAgIExpZmVsaW5lTmFtZTogaS5saWZlbGluZU5hbWUsICBcclxuICAgICAgICAgICAgICAgIENvbXBvbmVudE5hbWU6IGkuY29tcG9uZW50TmFtZSwgIFxyXG4gICAgICAgICAgICAgICAgSW5kaWNhdG9yTmFtZTogaS5uYW1lLFxyXG4gICAgICAgICAgICAgICAgQ29tbWVudHM6IFwiXCIsXHJcbiAgICAgICAgICAgICAgICBSYW5rOiBpLndlaWdodHMuZmluZCh3ID0+IHcubmFtZSA9PT0gUkFOSyk/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIExpZmVTYWZldHk6IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBMSUZFX1NBRkVUWSk/LndlaWdodCxcclxuICAgICAgICAgICAgICAgIFByb3BlcnR5UHJvdGVjdGlvbjogaS53ZWlnaHRzLmZpbmQodyA9PiB3Lm5hbWUgPT09IFBST1BFUlRZX1BST1RFQ1RJT04pPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBJbmNpZGVudFN0YWJpbGl6YXRpb246IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBJTkNJREVOVF9TVEFCSUxJWkFUSU9OKT8ud2VpZ2h0LFxyXG4gICAgICAgICAgICAgICAgRW52aXJvbm1lbnRQcmVzZXJ2YXRpb246IGkud2VpZ2h0cy5maW5kKHcgPT4gdy5uYW1lID09PSBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04pPy53ZWlnaHQsXHJcbiAgICAgICAgICAgICAgICBTdGF0dXM6IDQgLy91bmtub3duXHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgfSlcclxuICBcclxuICAgICAgICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgICAgICAgaWYocmVzcG9uc2UgJiYgcmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgZGF0YTogcmVzcC5kYXRhXHJcbiAgICAgICAgICAgIH0gXHJcbiAgICAgICAgICAgfWVsc2V7XHJcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcignRmFpbGVkIHRvIGFkZCBpbmRpY2F0b3IgYXNzZXNzbWVudCBmZWF0dXJlcycpO1xyXG4gICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgICAgZWxzZXtcclxuICAgICAgICAgIHRocm93IG5ldyBFcnJvcignRmFpbGVkIHRvIGFkZCBMaWZlbGluZSBTdGF0dXMgRmVhdHVyZXMnKTtcclxuICAgICAgICB9IFxyXG5cclxuICAgICAgfWNhdGNoKGUpe1xyXG4gICAgICAgIGF3YWl0IGNsZWFuVXBBc3Nlc3NtZW50RmFpbGVkRGF0YShyZXNwLmRhdGEsIGNvbmZpZyk7XHJcbiAgICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdzYXZlTmV3QXNzZXNzbWVudCcpXHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIGVycm9yczonRXJyb3Igb2NjdXJyZWQgd2hpbGUgY3JlYXRpbmcgQXNzZXNzbWVudC4nXHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBjbGVhblVwQXNzZXNzbWVudEZhaWxlZERhdGEoYXNzZXNzbWVudEdsb2JhbElkOiBzdHJpbmcsIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKXtcclxuICAgXHJcbiAgIGxldCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGBHbG9iYWxJRD0nJHthc3Nlc3NtZW50R2xvYmFsSWR9J2AsIGNvbmZpZyk7XHJcbiAgIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICAgIGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmFzc2Vzc21lbnRzLCBmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQpLCBjb25maWcpO1xyXG4gICB9XHJcblxyXG4gICBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIGBBc3Nlc3NtZW50SUQ9JyR7YXNzZXNzbWVudEdsb2JhbElkfSdgLCBjb25maWcpO1xyXG4gICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgIGF3YWl0IGRlbGV0ZVRhYmxlRmVhdHVyZXMoY29uZmlnLmxpZmVsaW5lU3RhdHVzLCBmZWF0dXJlcy5tYXAoZiA9PiBmLmF0dHJpYnV0ZXMuT0JKRUNUSUQpLCBjb25maWcpO1xyXG5cclxuICAgIGNvbnN0IHF1ZXJ5ID0gYExpZmVsaW5lU3RhdHVzSUQgSU4gKCR7ZmVhdHVyZXMubWFwKGYgPT4gZi5hdHRyaWJ1dGVzLkdsb2JhbElEKS5qb2luKCcsJyl9KWA7XHJcbiAgICBjb25zb2xlLmxvZygnZGVsZXRlIHF1ZXJpZXMnLCBxdWVyeSlcclxuICAgIGZlYXR1cmVzID0gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5pbmRpY2F0b3JBc3Nlc3NtZW50cywgcXVlcnksIGNvbmZpZyk7XHJcbiAgICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICAgYXdhaXQgZGVsZXRlVGFibGVGZWF0dXJlcyhjb25maWcuaW5kaWNhdG9yQXNzZXNzbWVudHMsIGZlYXR1cmVzLm1hcChmID0+IGYuYXR0cmlidXRlcy5PQkpFQ1RJRCksIGNvbmZpZyk7XHJcbiAgICB9XHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdldEFzc2Vzc21lbnROYW1lcyhjb25maWc6IEFwcFdpZGdldENvbmZpZywgdGVtcGxhdGVOYW1lOiBzdHJpbmcpOiBQcm9taXNlPENsc3NSZXNwb25zZTx7bmFtZTogc3RyaW5nLCBkYXRlOiBzdHJpbmd9W10+PntcclxuICBcclxuICBjb25zdCBmZWF0dXJlcyA9IGF3YWl0IHF1ZXJ5VGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsIGBUZW1wbGF0ZT0nJHt0ZW1wbGF0ZU5hbWV9J2AsIGNvbmZpZyk7XHJcbiAgaWYoZmVhdHVyZXMgJiYgZmVhdHVyZXMubGVuZ3RoID09PSAwKXtcclxuICAgIHJldHVybiB7XHJcbiAgICAgIGRhdGE6IFtdXHJcbiAgICB9XHJcbiAgfVxyXG4gIGlmKGZlYXR1cmVzICYmIGZlYXR1cmVzLmxlbmd0aCA+IDApe1xyXG4gICBcclxuICAgICBjb25zdCBhc3Nlc3MgPSAgZmVhdHVyZXMubWFwKGYgPT4ge1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIG5hbWU6IGYuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgICAgIGRhdGU6IHBhcnNlRGF0ZShOdW1iZXIoZi5hdHRyaWJ1dGVzLkNyZWF0ZWREYXRlKSlcclxuICAgICAgfVxyXG4gICAgIH0pO1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICBkYXRhOiBhc3Nlc3NcclxuICAgICB9XHJcbiAgfVxyXG4gIHJldHVybiB7XHJcbiAgICBlcnJvcnM6ICdSZXF1ZXN0IGZvciBhc3Nlc3NtZW50IG5hbWVzIGZhaWxlZC4nXHJcbiAgfVxyXG5cclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0QXNzZXNzbWVudEZlYXR1cmVzKGNvbmZpZykge1xyXG4gICBjb25zb2xlLmxvZygnZ2V0IEFzc2Vzc21lbnQgRmVhdHVyZXMgY2FsbGVkLicpO1xyXG4gICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5hc3Nlc3NtZW50cywgYDE9MWAsIGNvbmZpZyk7XHJcbn1cclxuXHJcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBsb2FkQWxsQXNzZXNzbWVudHMoY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPENsc3NSZXNwb25zZTxBc3Nlc3NtZW50W10+PntcclxuXHJcbiAgIHRyeXtcclxuICAgIGNvbnN0IGFzc2Vzc21lbnRGZWF0dXJlcyA9IGF3YWl0IGdldEFzc2Vzc21lbnRGZWF0dXJlcyhjb25maWcpO1xyXG4gICAgaWYoIWFzc2Vzc21lbnRGZWF0dXJlcyB8fCBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID09IDApe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IFtdXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIFxyXG4gICAgY29uc3QgbHNGZWF0dXJlcyA9IGF3YWl0IGdldExpZmVsaW5lU3RhdHVzRmVhdHVyZXMoY29uZmlnLCBgMT0xYCk7XHJcblxyXG4gICAgY29uc3QgcXVlcnkgPSBgTGlmZWxpbmVTdGF0dXNJRCBJTiAoJHtsc0ZlYXR1cmVzLm1hcChmID0+IGAnJHtmLmF0dHJpYnV0ZXMuR2xvYmFsSUR9J2ApLmpvaW4oJywnKX0pYFxyXG4gICAgXHJcbiAgICBjb25zdCBpbmRpY2F0b3JBc3Nlc3NtZW50cyA9IGF3YWl0IGdldEluZGljYXRvckFzc2Vzc21lbnRzKHF1ZXJ5LCBjb25maWcpO1xyXG5cclxuICAgIGlmKGFzc2Vzc21lbnRGZWF0dXJlcyAmJiBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID4gMCl7ICAgXHJcbiAgICAgIGNvbnN0IGFzc2Vzc21lbnRzID0gYXNzZXNzbWVudEZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuICAgICAgICBjb25zdCBhc3Nlc3NtZW50THNGZWF0dXJlcyA9IGxzRmVhdHVyZXMuZmlsdGVyKGwgPT5sLmF0dHJpYnV0ZXMuQXNzZXNzbWVudElEID09IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCkgICAgICAgIFxyXG4gICAgICAgIHJldHVybiBsb2FkQXNzZXNzbWVudChmZWF0dXJlLCBhc3Nlc3NtZW50THNGZWF0dXJlcywgaW5kaWNhdG9yQXNzZXNzbWVudHMpO1xyXG4gICAgICB9KTtcclxuXHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZGF0YTogYXNzZXNzbWVudHNcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmKGFzc2Vzc21lbnRGZWF0dXJlcyAmJiBhc3Nlc3NtZW50RmVhdHVyZXMubGVuZ3RoID09IDApe1xyXG4gICAgICByZXR1cm4ge1xyXG4gICAgICAgIGRhdGE6IFtdXHJcbiAgICAgIH0gIFxyXG4gICAgfVxyXG4gICB9Y2F0Y2goZSl7XHJcbiAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2xvYWRBbGxBc3Nlc3NtZW50cycpO1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiBlXHJcbiAgICB9XHJcbiAgIH1cclxufVxyXG5cclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNyZWF0ZUluY2lkZW50KGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnLCBpbmNpZGVudDogSW5jaWRlbnQpOiBQcm9taXNlPENsc3NSZXNwb25zZTx2b2lkPj57XHJcbiAgIFxyXG4gICAgdHJ5e1xyXG4gICAgICBjaGVja1BhcmFtKGNvbmZpZy5pbmNpZGVudHMsIElOQ0lERU5UX1VSTF9FUlJPUik7XHJcbiAgICAgIGNoZWNrUGFyYW0oaW5jaWRlbnQsICdJbmNpZGVudCBkYXRhIG5vdCBwcm92aWRlZCcpO1xyXG5cclxuICAgICAgY29uc3QgZmVhdHVyZXMgPSBbe1xyXG4gICAgICAgIGF0dHJpYnV0ZXMgOiB7XHJcbiAgICAgICAgICBIYXphcmRJRDogaW5jaWRlbnQuaGF6YXJkLmlkLFxyXG4gICAgICAgICAgTmFtZSA6IGluY2lkZW50Lm5hbWUsXHJcbiAgICAgICAgICBEZXNjcmlwdGlvbjogaW5jaWRlbnQuZGVzY3JpcHRpb24sXHJcbiAgICAgICAgICBTdGFydERhdGUgOiBTdHJpbmcoaW5jaWRlbnQuc3RhcnREYXRlKSxcclxuICAgICAgICAgIEVuZERhdGUgOiBTdHJpbmcoaW5jaWRlbnQuZW5kRGF0ZSlcclxuICAgICAgICB9XHJcbiAgICAgIH1dXHJcblxyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluY2lkZW50cywgZmVhdHVyZXMsIGNvbmZpZyk7XHJcblxyXG4gICAgICBpZihyZXNwb25zZS5hZGRSZXN1bHRzICYmIHJlc3BvbnNlLmFkZFJlc3VsdHMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgcmV0dXJue30gXHJcbiAgICAgIH1cclxuICAgICAgcmV0dXJuIHtcclxuICAgICAgICBlcnJvcnM6ICdJbmNpZGVudCBjb3VsZCBub3QgYmUgc2F2ZWQuJ1xyXG4gICAgICB9XHJcbiAgICB9Y2F0Y2goZSkge1xyXG4gICAgICBsb2coZSwgTG9nVHlwZS5FUlJPUiwgJ2NyZWF0ZUluY2lkZW50Jyk7XHJcbiAgICAgIHJldHVybiB7XHJcbiAgICAgICAgZXJyb3JzOiAnSW5jaWRlbnQgY291bGQgbm90IGJlIHNhdmVkLidcclxuICAgICAgfVxyXG4gICAgfVxyXG59XHJcblxyXG4vLz09PT09PT09PT09PT09PT09PT09UFJJVkFURT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XHJcblxyXG5jb25zdCByZXF1ZXN0RGF0YSA9IGFzeW5jICh1cmw6IHN0cmluZywgY29udHJvbGxlcj86IGFueSk6IFByb21pc2U8SUZlYXR1cmVTZXQ+ID0+IHtcclxuICBpZiAoIWNvbnRyb2xsZXIpIHtcclxuICAgIGNvbnRyb2xsZXIgPSBuZXcgQWJvcnRDb250cm9sbGVyKCk7XHJcbiAgfVxyXG4gIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZmV0Y2godXJsLCB7XHJcbiAgICBtZXRob2Q6IFwiR0VUXCIsXHJcbiAgICBoZWFkZXJzOiB7XHJcbiAgICAgICdjb250ZW50LXR5cGUnOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG4gICAgfSxcclxuICAgIHNpZ25hbDogY29udHJvbGxlci5zaWduYWxcclxuICB9XHJcbiAgKTtcclxuICByZXR1cm4gcmVzcG9uc2UuanNvbigpO1xyXG59XHJcblxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0VGVtcGxhdGUoXHJcbiAgdGVtcGxhdGVGZWF0dXJlOiBJRmVhdHVyZSwgXHJcbiAgbGlmZWxpbmVGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgY29tcG9uZW50RmVhdHVyZXM6IElGZWF0dXJlW10sIFxyXG4gIGluZGljYXRvcnNGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgd2VpZ2h0c0ZlYXR1cmVzOiBJRmVhdHVyZVtdLCBcclxuICB0ZW1wbGF0ZURvbWFpbnM6IElDb2RlZFZhbHVlW10pOiBQcm9taXNlPENMU1NUZW1wbGF0ZT57XHJcblxyXG4gIGNvbnN0IGluZGljYXRvckZlYXR1cmVzID0gaW5kaWNhdG9yc0ZlYXR1cmVzLmZpbHRlcihpID0+IGkuYXR0cmlidXRlcy5UZW1wbGF0ZUlEID0gYCcke3RlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEfSdgKS8vICBhd2FpdCBnZXRJbmRpY2F0b3JGZWF0dXJlcyhgVGVtcGxhdGVJRD0nJHt0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRH0nYCwgY29uZmlnKTtcclxuICBcclxuICAvL2NvbnN0IHF1ZXJ5ID0gaW5kaWNhdG9yRmVhdHVyZXMubWFwKGkgPT4gYEluZGljYXRvcklEPScke2kuYXR0cmlidXRlcy5HbG9iYWxJRC50b1VwcGVyQ2FzZSgpfSdgKS5qb2luKCcgT1IgJylcclxuICBcclxuICBjb25zdCBpbmRpY2F0b3JJZHMgPSBpbmRpY2F0b3JGZWF0dXJlcy5tYXAoaSA9PiBpLmF0dHJpYnV0ZXMuR2xvYmFsSUQpO1xyXG4gIGNvbnN0IHdlaWdodEZlYXR1cmVzID0gd2VpZ2h0c0ZlYXR1cmVzLmZpbHRlcih3ID0+IGluZGljYXRvcklkcy5pbmRleE9mKHcuYXR0cmlidXRlcy5JbmRpY2F0b3JJRCkpIC8vYXdhaXQgZ2V0V2VpZ2h0c0ZlYXR1cmVzKHF1ZXJ5LCBjb25maWcpO1xyXG4gIFxyXG4gIGNvbnN0IGluZGljYXRvclRlbXBsYXRlcyA9IGluZGljYXRvckZlYXR1cmVzLm1hcCgoZmVhdHVyZTogSUZlYXR1cmUpID0+IHtcclxuXHJcbiAgICAgY29uc3Qgd2VpZ2h0cyA9IHdlaWdodHNGZWF0dXJlc1xyXG4gICAgICAuZmlsdGVyKHcgPT4gdy5hdHRyaWJ1dGVzLkluZGljYXRvcklEPT09ZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKVxyXG4gICAgICAubWFwKHcgPT4ge1xyXG4gICAgICAgcmV0dXJuIHsgXHJcbiAgICAgICAgb2JqZWN0SWQ6IHcuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgICBuYW1lOiB3LmF0dHJpYnV0ZXMuTmFtZSxcclxuICAgICAgICB3ZWlnaHQ6IHcuYXR0cmlidXRlcy5XZWlnaHQsXHJcbiAgICAgICAgc2NhbGVGYWN0b3IgOiB3LmF0dHJpYnV0ZXMuU2NhbGVGYWN0b3IsIFxyXG4gICAgICAgIGFkanVzdGVkV2VpZ2h0OiB3LmF0dHJpYnV0ZXMuQWRqdXN0ZWRXZWlnaHQsXHJcbiAgICAgICAgbWF4QWRqdXN0ZWRXZWlnaHQ6IHcuYXR0cmlidXRlcy5NYXhBZGp1c3RlZFdlaWdodFxyXG4gICAgICAgfSBhcyBJbmRpY2F0b3JXZWlnaHRcclxuICAgICB9KVxyXG5cclxuICAgICByZXR1cm4ge1xyXG4gICAgICBvYmplY3RJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLk9CSkVDVElELFxyXG4gICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELCBcclxuICAgICAgbmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIHRlbXBsYXRlTmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlTmFtZSxcclxuICAgICAgd2VpZ2h0cyxcclxuICAgICAgY29tcG9uZW50SWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5Db21wb25lbnRJRCxcclxuICAgICAgdGVtcGxhdGVJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlSUQsICBcclxuICAgICAgY29tcG9uZW50TmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbXBvbmVudE5hbWUsXHJcbiAgICAgIGxpZmVsaW5lTmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lTmFtZVxyXG4gICAgIH0gYXMgSW5kaWNhdG9yVGVtcGxhdGVcclxuICB9KTtcclxuXHJcbiAgY29uc3QgY29tcG9uZW50VGVtcGxhdGVzID0gY29tcG9uZW50RmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgIHJldHVybiB7XHJcbiAgICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgICB0aXRsZTogZmVhdHVyZS5hdHRyaWJ1dGVzLkRpc3BsYXlOYW1lIHx8IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5VGl0bGUsXHJcbiAgICAgICAgbmFtZTogZmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgICAgbGlmZWxpbmVJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lSUQsXHJcbiAgICAgICAgaW5kaWNhdG9yczogKGluZGljYXRvclRlbXBsYXRlcy5maWx0ZXIoaSA9PiBpLmNvbXBvbmVudElkID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpIGFzIGFueSkub3JkZXJCeSgnbmFtZScpXHJcbiAgICAgfVxyXG4gIH0pO1xyXG5cclxuICBjb25zdCBsaWZlbGluZVRlbXBsYXRlcyA9IGxpZmVsaW5lRmVhdHVyZXMubWFwKChmZWF0dXJlOiBJRmVhdHVyZSkgPT4ge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgaWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5HbG9iYWxJRCxcclxuICAgICAgdGl0bGU6IGZlYXR1cmUuYXR0cmlidXRlcy5EaXNwbGF5TmFtZSB8fCBmZWF0dXJlLmF0dHJpYnV0ZXMuRGlzcGxheVRpdGxlLFxyXG4gICAgICBuYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTmFtZSwgICAgICBcclxuICAgICAgY29tcG9uZW50VGVtcGxhdGVzOiAoY29tcG9uZW50VGVtcGxhdGVzLmZpbHRlcihjID0+IGMubGlmZWxpbmVJZCA9PT0gZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElEKSBhcyBhbnkpLm9yZGVyQnkoJ3RpdGxlJylcclxuICAgIH0gYXMgTGlmZUxpbmVUZW1wbGF0ZTtcclxuICB9KTtcclxuXHJcbiAgY29uc3QgdGVtcGxhdGUgPSB7XHJcbiAgICAgIG9iamVjdElkOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgICAgaWQ6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICBpc1NlbGVjdGVkOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5Jc1NlbGVjdGVkID09IDEsXHJcbiAgICAgIHN0YXR1czoge1xyXG4gICAgICAgIGNvZGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLlN0YXR1cyxcclxuICAgICAgICBuYW1lOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5TdGF0dXMgPT09IDEgPyBcIkFjdGl2ZVwiOiAnQXJjaGl2ZWQnXHJcbiAgICAgIH0gYXMgSUNvZGVkVmFsdWUsXHJcbiAgICAgIG5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk5hbWUsXHJcbiAgICAgIGhhemFyZE5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZE5hbWUsXHJcbiAgICAgIGhhemFyZFR5cGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZFR5cGUsXHJcbiAgICAgIG9yZ2FuaXphdGlvbk5hbWU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvbk5hbWUsXHJcbiAgICAgIG9yZ2FuaXphdGlvblR5cGU6IHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvblR5cGUsIFxyXG4gICAgICBjcmVhdG9yOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5DcmVhdG9yLFxyXG4gICAgICBjcmVhdGVkRGF0ZTogTnVtYmVyKHRlbXBsYXRlRmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0ZWREYXRlKSxcclxuICAgICAgZWRpdG9yOiB0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5FZGl0b3IsXHJcbiAgICAgIGVkaXRlZERhdGU6IE51bWJlcih0ZW1wbGF0ZUZlYXR1cmUuYXR0cmlidXRlcy5FZGl0ZWREYXRlKSxcclxuICAgICAgbGlmZWxpbmVUZW1wbGF0ZXM6ICAobGlmZWxpbmVUZW1wbGF0ZXMgYXMgYW55KS5vcmRlckJ5KCd0aXRsZScpLFxyXG4gICAgICBkb21haW5zOiB0ZW1wbGF0ZURvbWFpbnNcclxuICB9IGFzIENMU1NUZW1wbGF0ZTtcclxuXHJcbiAgcmV0dXJuIHRlbXBsYXRlO1xyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBzYXZlQXNzZXNzbWVudChhc3Nlc3NtZW50OiBBc3Nlc3NtZW50LCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8Q2xzc1Jlc3BvbnNlPHN0cmluZz4+e1xyXG5cclxuICB0cnl7XHJcbiAgICBjb25zdCBmZWF0dXJlID0ge1xyXG4gICAgICBhdHRyaWJ1dGVzOiB7XHJcbiAgICAgICAgTmFtZSA6YXNzZXNzbWVudC5uYW1lLFxyXG4gICAgICAgIERlc2NyaXB0aW9uOiBhc3Nlc3NtZW50LmRlc2NyaXB0aW9uLFxyXG4gICAgICAgIEFzc2Vzc21lbnRUeXBlOiBhc3Nlc3NtZW50LmFzc2Vzc21lbnRUeXBlLCBcclxuICAgICAgICBPcmdhbml6YXRpb246IGFzc2Vzc21lbnQub3JnYW5pemF0aW9uLCBcclxuICAgICAgICBJbmNpZGVudDogYXNzZXNzbWVudC5pbmNpZGVudCwgXHJcbiAgICAgICAgSGF6YXJkOiBhc3Nlc3NtZW50LmhhemFyZCwgXHJcbiAgICAgICAgQ3JlYXRvcjogYXNzZXNzbWVudC5jcmVhdG9yLCBcclxuICAgICAgICBDcmVhdGVkRGF0ZTogYXNzZXNzbWVudC5jcmVhdGVkRGF0ZSwgXHJcbiAgICAgICAgRWRpdG9yOiBhc3Nlc3NtZW50LmVkaXRvciwgXHJcbiAgICAgICAgRWRpdGVkRGF0ZTogYXNzZXNzbWVudC5lZGl0ZWREYXRlLCBcclxuICAgICAgICBJc0NvbXBsZXRlZDogYXNzZXNzbWVudC5pc0NvbXBsZXRlZCwgXHJcbiAgICAgICAgSGF6YXJkVHlwZTogYXNzZXNzbWVudC5oYXphcmRUeXBlLFxyXG4gICAgICAgIE9yZ2FuaXphdGlvblR5cGU6YXNzZXNzbWVudC5vcmdhbml6YXRpb25UeXBlLFxyXG4gICAgICAgIFRlbXBsYXRlOiBhc3Nlc3NtZW50LnRlbXBsYXRlXHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcuYXNzZXNzbWVudHMsW2ZlYXR1cmVdLCBjb25maWcpO1xyXG4gICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KHIgPT4gci5zdWNjZXNzKSl7XHJcbiAgICAgIHJldHVybnsgZGF0YTogcmVzcG9uc2UuYWRkUmVzdWx0c1swXS5nbG9iYWxJZH1cclxuICAgIH1cclxuICAgIHJldHVybiB7XHJcbiAgICAgIGVycm9yczogIEpTT04uc3RyaW5naWZ5KHJlc3BvbnNlKSAgICBcclxuICAgIH1cclxuXHJcbiAgfWNhdGNoKGUpe1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgZXJyb3JzOiBlXHJcbiAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRJbmRpY2F0b3JBc3Nlc3NtZW50cyhxdWVyeTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SW5kaWNhdG9yQXNzZXNzbWVudFtdPntcclxuICBjb25zb2xlLmxvZygnZ2V0IEluZGljYXRvciBBc3Nlc3NtZW50cyBjYWxsZWQuJylcclxuXHJcbiAgY29uc3QgZmVhdHVyZXMgPSBhd2FpdCBxdWVyeVRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBxdWVyeSwgY29uZmlnKTtcclxuICBpZihmZWF0dXJlcyAmJiBmZWF0dXJlcy5sZW5ndGggPiAwKXtcclxuICAgICByZXR1cm4gZmVhdHVyZXMubWFwKGZlYXR1cmUgPT4geyAgICAgICAgXHJcbiAgICAgICAgcmV0dXJuIHtcclxuICAgICAgICAgIG9iamVjdElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgICAgICBpZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgICAgICAgaW5kaWNhdG9ySWQ6IGZlYXR1cmUuYXR0cmlidXRlcy5JbmRpY2F0b3JJRCxcclxuICAgICAgICAgIGluZGljYXRvcjogZmVhdHVyZS5hdHRyaWJ1dGVzLkluZGljYXRvck5hbWUsXHJcbiAgICAgICAgICB0ZW1wbGF0ZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlRlbXBsYXRlTmFtZSxcclxuICAgICAgICAgIGxpZmVsaW5lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lLFxyXG4gICAgICAgICAgY29tcG9uZW50OiBmZWF0dXJlLmF0dHJpYnV0ZXMuQ29tcG9uZW50TmFtZSwgICAgICAgICAgXHJcbiAgICAgICAgICBjb21tZW50czogcGFyc2VDb21tZW50KGZlYXR1cmUuYXR0cmlidXRlcy5Db21tZW50cyksICAgICAgICAgIFxyXG4gICAgICAgICAgbGlmZWxpbmVTdGF0dXNJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkxpZmVsaW5lU3RhdHVzSUQsXHJcbiAgICAgICAgICBlbnZpcm9ubWVudFByZXNlcnZhdGlvbjogZmVhdHVyZS5hdHRyaWJ1dGVzLkVudmlyb25tZW50UHJlc2VydmF0aW9uLFxyXG4gICAgICAgICAgaW5jaWRlbnRTdGFiaWxpemF0aW9uOiBmZWF0dXJlLmF0dHJpYnV0ZXMuSW5jaWRlbnRTdGFiaWxpemF0aW9uLFxyXG4gICAgICAgICAgcmFuazogZmVhdHVyZS5hdHRyaWJ1dGVzLlJhbmssXHJcbiAgICAgICAgICBsaWZlU2FmZXR5OiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZVNhZmV0eSxcclxuICAgICAgICAgIHByb3BlcnR5UHJvdGVjdGlvbjogZmVhdHVyZS5hdHRyaWJ1dGVzLlByb3BlcnR5UHJvdGVjdGlvbixcclxuICAgICAgICAgIHN0YXR1czogZmVhdHVyZS5hdHRyaWJ1dGVzLlN0YXR1c1xyXG4gICAgICAgIH0gYXMgSW5kaWNhdG9yQXNzZXNzbWVudDtcclxuICAgICB9KVxyXG4gIH1cclxuXHJcbn1cclxuXHJcbmZ1bmN0aW9uIHBhcnNlQ29tbWVudChjb21tZW50czogc3RyaW5nKXtcclxuICBpZighY29tbWVudHMgfHwgY29tbWVudHMgPT09IFwiXCIpe1xyXG4gICAgcmV0dXJuIFtdO1xyXG4gIH1cclxuICBsZXQgcGFyc2VkQ29tbWVudHMgPSBKU09OLnBhcnNlKGNvbW1lbnRzKSBhcyBJbkNvbW1lbnRbXTtcclxuICBcclxuICBpZihwYXJzZWRDb21tZW50cyAmJiBwYXJzZWRDb21tZW50cy5sZW5ndGggPiAwKXtcclxuICAgIHBhcnNlZENvbW1lbnRzLm1hcCgoY29tbWVudERhdGE6IEluQ29tbWVudCkgPT4ge1xyXG4gICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLmNvbW1lbnREYXRhLFxyXG4gICAgICAgICAgICBkYXRldGltZTogTnVtYmVyKGNvbW1lbnREYXRhLmRhdGV0aW1lKVxyXG4gICAgICAgIH0gYXMgSW5Db21tZW50XHJcbiAgICB9KTtcclxuICAgIHBhcnNlZENvbW1lbnRzID0gKHBhcnNlZENvbW1lbnRzIGFzIGFueSkub3JkZXJCeSgnZGF0ZXRpbWUnLCB0cnVlKTtcclxuICB9ZWxzZXtcclxuICAgIHBhcnNlZENvbW1lbnRzID0gW107XHJcbiAgfVxyXG4gIFxyXG4gIHJldHVybiBwYXJzZWRDb21tZW50cztcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gZ2V0TGlmZWxpbmVTdGF0dXNGZWF0dXJlcyhjb25maWcsIHF1ZXJ5KSB7XHJcbiAgY29uc29sZS5sb2coJ2dldCBMaWZlbGluZSBTdGF0dXMgY2FsbGVkJylcclxuICByZXR1cm4gYXdhaXQgcXVlcnlUYWJsZUZlYXR1cmVzKGNvbmZpZy5saWZlbGluZVN0YXR1cywgcXVlcnksIGNvbmZpZyk7XHJcbn1cclxuXHJcbmZ1bmN0aW9uIGxvYWRBc3Nlc3NtZW50KGFzc2Vzc21lbnRGZWF0dXJlOiBJRmVhdHVyZSwgbHNGZWF0dXJlczogSUZlYXR1cmVbXSwgXHJcbiAgaW5kaWNhdG9yQXNzZXNzbWVudHM6IEluZGljYXRvckFzc2Vzc21lbnRbXSk6IEFzc2Vzc21lbnR7ICAgXHJcblxyXG4gIGNvbnN0IGxpZmVsaW5lU3RhdHVzZXMgPSBsc0ZlYXR1cmVzLm1hcCgoZmVhdHVyZSkgPT4geyBcclxuICAgIHJldHVybiB7XHJcbiAgICAgIG9iamVjdElkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuT0JKRUNUSUQsXHJcbiAgICAgIGlkOiBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQsXHJcbiAgICAgIGFzc2Vzc21lbnRJZDogZmVhdHVyZS5hdHRyaWJ1dGVzLkFzc2Vzc21lbnRJRCxcclxuICAgICAgbGlmZWxpbmVOYW1lOiBmZWF0dXJlLmF0dHJpYnV0ZXMuTGlmZWxpbmVOYW1lLFxyXG4gICAgICBpbmRpY2F0b3JBc3Nlc3NtZW50czogaW5kaWNhdG9yQXNzZXNzbWVudHMuZmlsdGVyKGkgPT4gaS5saWZlbGluZVN0YXR1c0lkID09PSBmZWF0dXJlLmF0dHJpYnV0ZXMuR2xvYmFsSUQpLCAgICAgIFxyXG4gICAgICBzY29yZTogZmVhdHVyZS5hdHRyaWJ1dGVzLlNjb3JlLFxyXG4gICAgICBjb2xvcjogZmVhdHVyZS5hdHRyaWJ1dGVzLkNvbG9yLFxyXG4gICAgICBpc092ZXJyaWRlbjogZmVhdHVyZS5hdHRyaWJ1dGVzLklzT3ZlcnJpZGVuLFxyXG4gICAgICBvdmVycmlkZVNjb3JlOmZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5TY29yZSxcclxuICAgICAgb3ZlcnJpZGVuQnk6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5CeSxcclxuICAgICAgb3ZlcnJpZGVuQ29sb3I6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZW5Db2xvciwgICAgIFxyXG4gICAgICBvdmVycmlkZUNvbW1lbnQ6IGZlYXR1cmUuYXR0cmlidXRlcy5PdmVycmlkZUNvbW1lbnQgICAgICBcclxuICAgIH0gYXMgTGlmZWxpbmVTdGF0dXM7XHJcbiAgfSk7XHJcblxyXG4gIGNvbnN0IGFzc2Vzc21lbnQgPSB7XHJcbiAgICBvYmplY3RJZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5PQkpFQ1RJRCxcclxuICAgIGlkOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkdsb2JhbElELFxyXG4gICAgbmFtZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5OYW1lLFxyXG4gICAgYXNzZXNzbWVudFR5cGU6IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuQXNzZXNzbWVudFR5cGUsXHJcbiAgICBsaWZlbGluZVN0YXR1c2VzOiBsaWZlbGluZVN0YXR1c2VzLFxyXG4gICAgZGVzY3JpcHRpb246IGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuRGVzY3JpcHRpb24sXHJcbiAgICB0ZW1wbGF0ZTogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5UZW1wbGF0ZSxcclxuICAgIG9yZ2FuaXphdGlvbjogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Pcmdhbml6YXRpb24sXHJcbiAgICBvcmdhbml6YXRpb25UeXBlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLk9yZ2FuaXphdGlvblR5cGUsXHJcbiAgICBpbmNpZGVudDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5JbmNpZGVudCxcclxuICAgIGhhemFyZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5IYXphcmQsXHJcbiAgICBoYXphcmRUeXBlOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkhhemFyZFR5cGUsXHJcbiAgICBjcmVhdG9yOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkNyZWF0b3IsXHJcbiAgICBjcmVhdGVkRGF0ZTogTnVtYmVyKGFzc2Vzc21lbnRGZWF0dXJlLmF0dHJpYnV0ZXMuQ3JlYXRlZERhdGUpLFxyXG4gICAgZWRpdG9yOiBhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRvcixcclxuICAgIGVkaXRlZERhdGU6IE51bWJlcihhc3Nlc3NtZW50RmVhdHVyZS5hdHRyaWJ1dGVzLkVkaXRlZERhdGUpLFxyXG4gICAgaXNTZWxlY3RlZDogZmFsc2UsXHJcbiAgICBpc0NvbXBsZXRlZDogYXNzZXNzbWVudEZlYXR1cmUuYXR0cmlidXRlcy5Jc0NvbXBsZXRlZCxcclxuICB9IGFzIEFzc2Vzc21lbnRcclxuXHJcbiAgcmV0dXJuIGFzc2Vzc21lbnQ7ICBcclxufVxyXG5cclxuYXN5bmMgZnVuY3Rpb24gc2F2ZUxpZmVsaW5lU3RhdHVzKGxpZmVsaW5lU3RhdHVzRmVhdHVyZTogSUZlYXR1cmUsIGxzSW5kQXNzZXNzRmVhdHVyZXM6IElGZWF0dXJlW10sIGNvbmZpZyk6IFByb21pc2U8Ym9vbGVhbj57XHJcbiAgbGV0IHJlc3BvbnNlID0gYXdhaXQgYWRkVGFibGVGZWF0dXJlcyhjb25maWcubGlmZWxpbmVTdGF0dXMsIFtsaWZlbGluZVN0YXR1c0ZlYXR1cmVdLCBjb25maWcpXHJcbiAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KGUgPT4gZS5zdWNjZXNzKSl7XHJcbiAgICAgY29uc3QgZ2xvYmFsSWQgPSByZXNwb25zZS5hZGRSZXN1bHRzWzBdLmdsb2JhbElkO1xyXG5cclxuICAgICBjb25zdCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMgPSBsc0luZEFzc2Vzc0ZlYXR1cmVzLm1hcChpbmQgPT4ge1xyXG4gICAgICAgIGluZC5hdHRyaWJ1dGVzLkxpZmVsaW5lU3RhdHVzSUQgPSBnbG9iYWxJZFxyXG4gICAgICAgIHJldHVybiBpbmQ7XHJcbiAgICAgfSlcclxuICAgICByZXNwb25zZSA9IGF3YWl0IGFkZFRhYmxlRmVhdHVyZXMoY29uZmlnLmluZGljYXRvckFzc2Vzc21lbnRzLCBpbmRpY2F0b3JBc3Nlc3NtZW50RmVhdHVyZXMsIGNvbmZpZyk7XHJcbiAgICAgaWYocmVzcG9uc2UuYWRkUmVzdWx0cyAmJiByZXNwb25zZS5hZGRSZXN1bHRzLmV2ZXJ5KGUgPT4gZS5zdWNjZXNzKSl7XHJcbiAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICB9XHJcbiAgfVxyXG59XHJcblxyXG5mdW5jdGlvbiBnZXRUZW1wbGF0ZUluZGljYXRvcnModGVtcGxhdGU6IENMU1NUZW1wbGF0ZSk6IEluZGljYXRvclRlbXBsYXRlW10ge1xyXG4gIHJldHVybiBbXS5jb25jYXQuYXBwbHkoW10sIChbXS5jb25jYXQuYXBwbHkoW10sIFxyXG4gICB0ZW1wbGF0ZS5saWZlbGluZVRlbXBsYXRlcy5tYXAobCA9PiBsLmNvbXBvbmVudFRlbXBsYXRlcykpKVxyXG4gICAubWFwKChjOiBDb21wb25lbnRUZW1wbGF0ZSkgPT4gYy5pbmRpY2F0b3JzKSk7XHJcbn0iLCIvL0FkYXB0ZWQgZnJvbSAvL2h0dHBzOi8vZ2l0aHViLmNvbS9vZG9lL21hcC12dWUvYmxvYi9tYXN0ZXIvc3JjL2RhdGEvYXV0aC50c1xyXG5cclxuaW1wb3J0IHsgbG9hZEFyY0dJU0pTQVBJTW9kdWxlcyB9IGZyb20gXCJqaW11LWFyY2dpc1wiO1xyXG5cclxuLyoqXHJcbiAqIEF0dGVtcHQgdG8gc2lnbiBpbixcclxuICogZmlyc3QgY2hlY2sgY3VycmVudCBzdGF0dXNcclxuICogaWYgbm90IHNpZ25lZCBpbiwgdGhlbiBnbyB0aHJvdWdoXHJcbiAqIHN0ZXBzIHRvIGdldCBjcmVkZW50aWFsc1xyXG4gKi9cclxuZXhwb3J0IGNvbnN0IHNpZ25JbiA9IGFzeW5jIChhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykgPT4ge1xyXG4gICAgdHJ5IHtcclxuICAgICAgICByZXR1cm4gYXdhaXQgY2hlY2tDdXJyZW50U3RhdHVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcclxuICAgICAgICBjb25zb2xlLmxvZyhlcnJvcik7XHJcbiAgICAgICAgcmV0dXJuIGF3YWl0IGZldGNoQ3JlZGVudGlhbHMoYXBwSWQsIHBvcnRhbFVybCk7XHJcbiAgICB9XHJcbn07XHJcblxyXG4vKipcclxuICogU2lnbiB0aGUgdXNlciBvdXQsIGJ1dCBpZiB3ZSBjaGVja2VkIGNyZWRlbnRpYWxzXHJcbiAqIG1hbnVhbGx5LCBtYWtlIHN1cmUgdGhleSBhcmUgcmVnaXN0ZXJlZCB3aXRoXHJcbiAqIElkZW50aXR5TWFuYWdlciwgc28gaXQgY2FuIGRlc3Ryb3kgdGhlbSBwcm9wZXJseVxyXG4gKi9cclxuZXhwb3J0IGNvbnN0IHNpZ25PdXQgPSBhc3luYyAoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpID0+IHtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgYXdhaXQgc2lnbkluKGFwcElkLCBwb3J0YWxVcmwpO1xyXG5cclxuICAgIGRlbGV0ZSB3aW5kb3dbJ0lkZW50aXR5TWFuYWdlciddO1xyXG4gICAgZGVsZXRlIHdpbmRvd1snT0F1dGhJbmZvJ107XHJcbiAgICBJZGVudGl0eU1hbmFnZXIuZGVzdHJveUNyZWRlbnRpYWxzKCk7XHJcbiAgICBcclxufTtcclxuXHJcbi8qKlxyXG4gKiBHZXQgdGhlIGNyZWRlbnRpYWxzIGZvciB0aGUgcHJvdmlkZWQgcG9ydGFsXHJcbiAqL1xyXG5hc3luYyBmdW5jdGlvbiBmZXRjaENyZWRlbnRpYWxzKGFwcElkOiBzdHJpbmcsIHBvcnRhbFVybDogc3RyaW5nKXtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgY29uc3QgY3JlZGVudGlhbCA9IGF3YWl0IElkZW50aXR5TWFuYWdlci5nZXRDcmVkZW50aWFsKGAke3BvcnRhbFVybH0vc2hhcmluZ2AsIHtcclxuICAgICAgICBlcnJvcjogbnVsbCBhcyBhbnksXHJcbiAgICAgICAgb0F1dGhQb3B1cENvbmZpcm1hdGlvbjogZmFsc2UsXHJcbiAgICAgICAgdG9rZW46IG51bGwgYXMgYW55XHJcbiAgICB9KTtcclxuICAgIHJldHVybiBjcmVkZW50aWFsO1xyXG59O1xyXG5cclxuLyoqXHJcbiAqIEltcG9ydCBJZGVudGl0eSBNYW5hZ2VyLCBhbmQgT0F1dGhJbmZvXHJcbiAqL1xyXG5hc3luYyBmdW5jdGlvbiBsb2FkTW9kdWxlcyhhcHBJZDogc3RyaW5nLCBwb3J0YWxVcmw6IHN0cmluZykge1xyXG4gICAgbGV0IElkZW50aXR5TWFuYWdlciA9IHdpbmRvd1snSWRlbnRpdHlNYW5hZ2VyJ11cclxuICAgIGlmKCFJZGVudGl0eU1hbmFnZXIpe1xyXG4gICAgICAgIGNvbnN0IG1vZHVsZXMgPSBhd2FpdCBsb2FkQXJjR0lTSlNBUElNb2R1bGVzKFtcclxuICAgICAgICAgICAgJ2VzcmkvaWRlbnRpdHkvSWRlbnRpdHlNYW5hZ2VyJyxcclxuICAgICAgICAgICAgJ2VzcmkvaWRlbnRpdHkvT0F1dGhJbmZvJ10pO1xyXG5cclxuICAgICAgICAgICAgd2luZG93WydJZGVudGl0eU1hbmFnZXInXSA9IG1vZHVsZXNbMF07XHJcbiAgICAgICAgICAgIHdpbmRvd1snT0F1dGhJbmZvJ10gPSBtb2R1bGVzWzFdO1xyXG4gICAgICAgICAgICBcclxuICAgICAgICBJZGVudGl0eU1hbmFnZXIgPSBtb2R1bGVzWzBdO1xyXG4gICAgICAgIGNvbnN0IE9BdXRoSW5mbyA9IG1vZHVsZXNbMV07XHJcblxyXG4gICAgICAgIGNvbnN0IG9hdXRoSW5mbyA9IG5ldyBPQXV0aEluZm8oe1xyXG4gICAgICAgICAgICBhcHBJZCxcclxuICAgICAgICAgICAgcG9ydGFsVXJsLFxyXG4gICAgICAgICAgICBwb3B1cDogZmFsc2VcclxuICAgICAgICB9KTtcclxuICAgICAgICBJZGVudGl0eU1hbmFnZXIucmVnaXN0ZXJPQXV0aEluZm9zKFtvYXV0aEluZm9dKTsgICAgICAgIFxyXG4gICAgfVxyXG4gICAgcmV0dXJuIElkZW50aXR5TWFuYWdlcjtcclxufVxyXG5cclxuLyoqXHJcbiAqIENoZWNrIGN1cnJlbnQgbG9nZ2VkIGluIHN0YXR1cyBmb3IgY3VycmVudCBwb3J0YWxcclxuICovXHJcbmV4cG9ydCBjb25zdCBjaGVja0N1cnJlbnRTdGF0dXMgPSBhc3luYyAoYXBwSWQ6IHN0cmluZywgcG9ydGFsVXJsOiBzdHJpbmcpID0+IHtcclxuICAgIGNvbnN0IElkZW50aXR5TWFuYWdlciA9IGF3YWl0IGxvYWRNb2R1bGVzKGFwcElkLCBwb3J0YWxVcmwpO1xyXG4gICAgcmV0dXJuIElkZW50aXR5TWFuYWdlci5jaGVja1NpZ25JblN0YXR1cyhgJHtwb3J0YWxVcmx9L3NoYXJpbmdgKTtcclxufTsiLCJpbXBvcnQgeyBleHRlbnNpb25TcGVjLCBJbW11dGFibGVPYmplY3QsIElNU3RhdGUgfSBmcm9tICdqaW11LWNvcmUnO1xyXG5pbXBvcnQgeyBBc3Nlc3NtZW50LCBDTFNTX1N0YXRlLCBcclxuICBDTFNTVGVtcGxhdGUsIENsc3NVc2VyLCBIYXphcmQsIFxyXG4gIExpZmVsaW5lU3RhdHVzLCBPcmdhbml6YXRpb24sIFxyXG4gIFJhdGluZ1NjYWxlLCBTY2FsZUZhY3RvciB9IGZyb20gJy4vZGF0YS1kZWZpbml0aW9ucyc7XHJcbmltcG9ydCB7IElDb2RlZFZhbHVlIH0gZnJvbSAnQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXMnO1xyXG5pbXBvcnQgeyBJQ3JlZGVudGlhbCB9IGZyb20gJ0Blc3JpL2FyY2dpcy1yZXN0LWF1dGgnO1xyXG5cclxuXHJcbmV4cG9ydCBlbnVtIENMU1NBY3Rpb25LZXlzIHtcclxuICBBVVRIRU5USUNBVEVfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBhdXRoZW5pY2F0ZSBjcmVkZW50aWFscycsXHJcbiAgTE9BRF9IQVpBUkRTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBoYXphcmRzJyxcclxuICBMT0FEX0hBWkFSRF9UWVBFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgaGF6YXJkIHR5cGVzJyxcclxuICBMT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBsb2FkIG9yZ2FuaXphdGlvbnMnLFxyXG4gIExPQURfT1JHQU5JWkFUSU9OX1RZUEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCBvcmdhbml6YXRpb24gdHlwZXMnLFxyXG4gIExPQURfVEVNUExBVEVTX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gbG9hZCB0ZW1wbGF0ZXMnLFxyXG4gIExPQURfUFJJT1JJVElFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIGxvYWQgcHJpb3JpdGllcycsXHJcbiAgU0VMRUNUX1RFTVBMQVRFX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gc2VsZWN0IHRlbXBsYXRlJyxcclxuICBTRUFSQ0hfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBzZWFyY2ggZm9yIHRlbXBsYXRlJyxcclxuICBTSUdOX0lOX0FDVElPTiA9ICdbQ0xTUy1BUFBMSUNBVElPTl0gU2lnbiBpbicsXHJcbiAgU0lHTl9PVVRfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTaWduIG91dCcsXHJcbiAgU0VUX1VTRVJfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZXQgQ0xTUyBVc2VyJyxcclxuICBTRVRfSURFTlRJVFlfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZXQgSWRlbnRpdHknLFxyXG4gIFNFVF9FUlJPUlMgPSAnW0NMU1MtQVBQTElDQVRJT05dIFNldCBnbG9iYWwgZXJyb3JzJyxcclxuICBUT0dHTEVfSU5ESUNBVE9SX0VESVRJTkcgPSAnW0NMU1MtQVBQTElDQVRJT05dIFRvZ2dsZSBpbmRpY2F0b3IgZWRpdGluZycsICBcclxuICBTRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBTZWxlY3QgYSBsaWZlbGluZSBzdGF0dXMnLFxyXG4gIExPQURfQVNTRVNTTUVOVFNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBMb2FkIGFzc2Vzc21lbnRzJyxcclxuICBTRUxFQ1RfQVNTRVNTTUVOVF9BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIFNlbGVjdCBhc3Nlc3NtZW50JyxcclxuICBMT0FEX1JBVElOR1NDQUxFU19BQ1RJT04gPSAnW0NMU1MtQVBQTElDQVRJT05dIExvYWQgcmF0aW5nIHNjYWxlcycsXHJcbiAgTE9BRF9TQ0FMRUZBQ1RPUlNfQUNUSU9OID0gJ1tDTFNTLUFQUExJQ0FUSU9OXSBMb2FkIGNvbnN0YW50cydcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1NjYWxlRmFjdG9yc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1NDQUxFRkFDVE9SU19BQ1RJT04sXHJcbiAgdmFsOiBTY2FsZUZhY3RvcltdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9SYXRpbmdfU2NhbGVzX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLkxPQURfUkFUSU5HU0NBTEVTX0FDVElPTixcclxuICB2YWw6IFJhdGluZ1NjYWxlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWxlY3RfQXNzZXNzbWVudF9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfQVNTRVNTTUVOVF9BQ1RJT04sXHJcbiAgdmFsOiBBc3Nlc3NtZW50XHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Bc3Nlc3NtZW50c19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0FTU0VTU01FTlRTX0FDVElPTixcclxuICB2YWw6IEFzc2Vzc21lbnRbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfUHJpb3JpdGllc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX1BSSU9SSVRJRVNfQUNUSU9OLFxyXG4gIHZhbDogYW55W11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX0hhemFyZF9UeXBlc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRF9UWVBFU19BQ1RJT04sXHJcbiAgdmFsOiBJQ29kZWRWYWx1ZVtdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgTG9hZF9Pcmdhbml6YXRpb25fVHlwZXNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05fVFlQRVNfQUNUSU9OLFxyXG4gIHZhbDogSUNvZGVkVmFsdWVbXVxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNlbGVjdF9MaWZlbGluZVN0YXR1c19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUxFQ1RfTElGRUxJTkVTVEFUVVNfQUNUSU9OLFxyXG4gIHZhbDogTGlmZWxpbmVTdGF0dXNcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZXRfVG9nZ2xlX0luZGljYXRvcl9FZGl0aW5nX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlRPR0dMRV9JTkRJQ0FUT1JfRURJVElORyxcclxuICB2YWw6IHN0cmluZ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNldF9FcnJvcnNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUyxcclxuICB2YWw6IHN0cmluZ1xyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIExvYWRfSGF6YXJkc19BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRFNfQUNUSU9OLFxyXG4gIHZhbDogSGF6YXJkW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX09yZ2FuaXphdGlvbnNfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTixcclxuICB2YWw6IE9yZ2FuaXphdGlvbltdXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0SWRlbnRpdHlfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX0lERU5USVRZX0FDVElPTixcclxuICB2YWw6IENsc3NVc2VyXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2V0VXNlcl9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRVRfVVNFUl9BQ1RJT04sXHJcbiAgdmFsOiBDbHNzVXNlclxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNpZ25pbl9BY3Rpb25fVHlwZXtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TSUdOX0lOX0FDVElPTlxyXG59XHJcblxyXG5leHBvcnQgaW50ZXJmYWNlIFNpZ25vdXRfQWN0aW9uX1R5cGV7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0lHTl9PVVRfQUNUSU9OXHJcbn1cclxuXHJcbmV4cG9ydCBpbnRlcmZhY2UgU2VsZWN0X1RlbXBsYXRlX0FjdGlvbl9UeXBle1xyXG4gIHR5cGU6IENMU1NBY3Rpb25LZXlzLlNFTEVDVF9URU1QTEFURV9BQ1RJT04sXHJcbiAgdmFsOiBzdHJpbmdcclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBMb2FkX1RlbXBsYXRlc19BY3Rpb25fVHlwZSB7XHJcbiAgdHlwZTogQ0xTU0FjdGlvbktleXMuTE9BRF9URU1QTEFURVNfQUNUSU9OLFxyXG4gIHZhbDogQ0xTU1RlbXBsYXRlW11cclxufVxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBTZWFyY2hfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHtcclxuICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5TRUFSQ0hfQUNUSU9OLFxyXG4gIHZhbDogc3RyaW5nXHJcbn0gIFxyXG5cclxuZXhwb3J0IGludGVyZmFjZSBBdXRoZW50aWNhdGVfQWN0aW9uX1R5cGUge1xyXG4gICB0eXBlOiBDTFNTQWN0aW9uS2V5cy5BVVRIRU5USUNBVEVfQUNUSU9OLFxyXG4gICB2YWw6IElDcmVkZW50aWFsO1xyXG59XHJcblxyXG5cclxudHlwZSBBY3Rpb25UeXBlcyA9IFxyXG4gU2VsZWN0X1RlbXBsYXRlX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHwgXHJcbiBTZWFyY2hfVGVtcGxhdGVzX0FjdGlvbl9UeXBlIHwgXHJcbiBTaWduaW5fQWN0aW9uX1R5cGUgfFxyXG4gU2lnbm91dF9BY3Rpb25fVHlwZSB8XHJcbiBTZXRVc2VyX0FjdGlvbl9UeXBlIHwgXHJcbiBTZXRJZGVudGl0eV9BY3Rpb25fVHlwZSB8XHJcbiBMb2FkX0hhemFyZHNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Pcmdhbml6YXRpb25zX0FjdGlvbl9UeXBlIHxcclxuIFNldF9FcnJvcnNfQWN0aW9uX1R5cGUgfFxyXG4gU2V0X1RvZ2dsZV9JbmRpY2F0b3JfRWRpdGluZ19BY3Rpb25fVHlwZSB8XHJcbiBTZWxlY3RfTGlmZWxpbmVTdGF0dXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9IYXphcmRfVHlwZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Pcmdhbml6YXRpb25fVHlwZXNfQWN0aW9uX1R5cGUgfFxyXG4gTG9hZF9Qcmlvcml0aWVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfQXNzZXNzbWVudHNfQWN0aW9uX1R5cGUgfFxyXG4gU2VsZWN0X0Fzc2Vzc21lbnRfQWN0aW9uX1R5cGV8IFxyXG4gTG9hZF9SYXRpbmdfU2NhbGVzX0FjdGlvbl9UeXBlIHxcclxuIExvYWRfU2NhbGVGYWN0b3JzX0FjdGlvbl9UeXBlIHxcclxuIEF1dGhlbnRpY2F0ZV9BY3Rpb25fVHlwZSA7XHJcblxyXG50eXBlIElNTXlTdGF0ZSA9IEltbXV0YWJsZU9iamVjdDxDTFNTX1N0YXRlPjtcclxuXHJcbmRlY2xhcmUgbW9kdWxlICdqaW11LWNvcmUvbGliL3R5cGVzL3N0YXRlJ3tcclxuICBpbnRlcmZhY2UgU3RhdGV7XHJcbiAgICBjbHNzU3RhdGU/OiBJTU15U3RhdGVcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCBkZWZhdWx0IGNsYXNzIE15UmVkdXhTdG9yZUV4dGVuc2lvbiBpbXBsZW1lbnRzIGV4dGVuc2lvblNwZWMuUmVkdXhTdG9yZUV4dGVuc2lvbiB7XHJcbiAgaWQgPSAnY2xzcy1yZWR1eC1zdG9yZS1leHRlbnNpb24nO1xyXG4gXHJcbiAgZ2V0QWN0aW9ucygpIHtcclxuICAgIHJldHVybiBPYmplY3Qua2V5cyhDTFNTQWN0aW9uS2V5cykubWFwKGsgPT4gQ0xTU0FjdGlvbktleXNba10pO1xyXG4gIH1cclxuXHJcbiAgZ2V0SW5pdExvY2FsU3RhdGUoKSB7XHJcbiAgICByZXR1cm4ge1xyXG4gICAgICAgc2VsZWN0ZWRUZW1wbGF0ZTogbnVsbCxcclxuICAgICAgIHRlbXBsYXRlczogW10sXHJcbiAgICAgICBzZWFyY2hSZXN1bHRzOiBbXSxcclxuICAgICAgIHVzZXI6IG51bGwsXHJcbiAgICAgICBhdXRoOiBudWxsLFxyXG4gICAgICAgaWRlbnRpdHk6IG51bGwsICAgICAgIFxyXG4gICAgICAgbmV3VGVtcGxhdGVNb2RhbFZpc2libGU6IGZhbHNlLFxyXG4gICAgICAgaGF6YXJkczogW10sXHJcbiAgICAgICBvcmdhbml6YXRpb25zOiBbXSxcclxuICAgICAgIGVycm9yczogJycsXHJcbiAgICAgICBpc0luZGljYXRvckVkaXRpbmc6IGZhbHNlLFxyXG4gICAgICAgc2VsZWN0ZWRMaWZlbGluZVN0YXR1czogbnVsbCxcclxuICAgICAgIG9yZ2FuaXphdGlvblR5cGVzOiBbXSxcclxuICAgICAgIGhhemFyZFR5cGVzOiBbXSxcclxuICAgICAgIHByaW9yaXRpZXM6IFtdLFxyXG4gICAgICAgYXNzZXNzbWVudHM6IFtdLFxyXG4gICAgICAgcmF0aW5nU2NhbGVzOiBbXSxcclxuICAgICAgIHNjYWxlRmFjdG9yczogW10sXHJcbiAgICAgICBhdXRoZW50aWNhdGU6IG51bGxcclxuICAgIH0gYXMgQ0xTU19TdGF0ZTtcclxuICB9XHJcblxyXG4gIGdldFJlZHVjZXIoKSB7XHJcbiAgICByZXR1cm4gKGxvY2FsU3RhdGU6IElNTXlTdGF0ZSwgYWN0aW9uOiBBY3Rpb25UeXBlcywgYXBwU3RhdGU6IElNU3RhdGUpOiBJTU15U3RhdGUgPT4geyAgICAgIFxyXG4gICAgICBcclxuICAgICAgc3dpdGNoIChhY3Rpb24udHlwZSkge1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkFVVEhFTlRJQ0FURV9BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2F1dGhlbnRpY2F0ZScsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfU0NBTEVGQUNUT1JTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnc2NhbGVGYWN0b3JzJywgYWN0aW9uLnZhbCk7XHJcbiAgICAgICAgXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1JBVElOR1NDQUxFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3JhdGluZ1NjYWxlcycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFTEVDVF9BU1NFU1NNRU5UX0FDVElPTjpcclxuICAgICAgICAgIGNvbnN0IGFzc2Vzc21lbnRzID0gbG9jYWxTdGF0ZS5hc3Nlc3NtZW50cy5tYXAoYXNzZXNzID0+IHtcclxuICAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgLi4uYXNzZXNzLFxyXG4gICAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IGFzc2Vzcy5pZCA9PT0gYWN0aW9uLnZhbC5pZC50b0xvd2VyQ2FzZSgpXHJcbiAgICAgICAgICAgICB9XHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdhc3Nlc3NtZW50cycsIGFzc2Vzc21lbnRzKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX0FTU0VTU01FTlRTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnYXNzZXNzbWVudHMnLCBhY3Rpb24udmFsKTtcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX1BSSU9SSVRJRVNfQUNUSU9OOlxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdwcmlvcml0aWVzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VMRUNUX0xJRkVMSU5FU1RBVFVTX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnc2VsZWN0ZWRMaWZlbGluZVN0YXR1cycsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlRPR0dMRV9JTkRJQ0FUT1JfRURJVElORzpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaXNJbmRpY2F0b3JFZGl0aW5nJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUzpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnZXJyb3JzJywgYWN0aW9uLnZhbCk7XHJcblxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuTE9BRF9IQVpBUkRTX0FDVElPTjogIFxyXG4gICAgICAgICAgcmV0dXJuIGxvY2FsU3RhdGUuc2V0KCdoYXphcmRzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRF9UWVBFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ2hhemFyZFR5cGVzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTl9UWVBFU19BQ1RJT046XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ29yZ2FuaXphdGlvblR5cGVzJywgYWN0aW9uLnZhbClcclxuXHJcbiAgICAgICAgY2FzZSBDTFNTQWN0aW9uS2V5cy5MT0FEX09SR0FOSVpBVElPTlNfQUNUSU9OOlxyXG4gICAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ29yZ2FuaXphdGlvbnMnLCBhY3Rpb24udmFsKVxyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFVF9JREVOVElUWV9BQ1RJT046ICBcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgnaWRlbnRpdHknLCBhY3Rpb24udmFsKTtcclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLlNFVF9VU0VSX0FDVElPTjpcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgndXNlcicsIGFjdGlvbi52YWwpO1xyXG5cclxuICAgICAgICBjYXNlIENMU1NBY3Rpb25LZXlzLkxPQURfVEVNUExBVEVTX0FDVElPTjogICAgICAgICAgXHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZS5zZXQoJ3RlbXBsYXRlcycsIGFjdGlvbi52YWwpO1xyXG4gICAgICAgIFxyXG4gICAgICAgIGNhc2UgQ0xTU0FjdGlvbktleXMuU0VMRUNUX1RFTVBMQVRFX0FDVElPTjpcclxuICAgICAgICAgIGxldCB0ZW1wbGF0ZXMgPSBbLi4ubG9jYWxTdGF0ZS50ZW1wbGF0ZXNdLm1hcCh0ID0+IHtcclxuICAgICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgICAgLi4udCxcclxuICAgICAgICAgICAgICBpc1NlbGVjdGVkOiB0LmlkID09PSBhY3Rpb24udmFsXHJcbiAgICAgICAgICAgICB9IFxyXG4gICAgICAgICAgfSlcclxuICAgICAgICAgIHJldHVybiBsb2NhbFN0YXRlLnNldCgndGVtcGxhdGVzJywgdGVtcGxhdGVzKSAgICAgICAgICAgIFxyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICByZXR1cm4gbG9jYWxTdGF0ZTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgZ2V0U3RvcmVLZXkoKSB7XHJcbiAgICByZXR1cm4gJ2Nsc3NTdGF0ZSc7XHJcbiAgfVxyXG59IiwiZXhwb3J0IGNvbnN0IENMU1NfQURNSU4gPSAnQ0xTU19BZG1pbic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX0VESVRPUiA9ICdDTFNTX0VkaXRvcic7XHJcbmV4cG9ydCBjb25zdCBDTFNTX0FTU0VTU09SID0gJ0NMU1NfQXNzZXNzb3InO1xyXG5leHBvcnQgY29uc3QgQ0xTU19WSUVXRVIgPSAnQ0xTU19WaWV3ZXInO1xyXG5leHBvcnQgY29uc3QgQ0xTU19GT0xMT1dFUlMgPSAnQ0xTUyBGb2xsb3dlcnMnO1xyXG5cclxuZXhwb3J0IGNvbnN0IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUgPSAnQmFzZWxpbmUnO1xyXG5leHBvcnQgY29uc3QgVE9LRU5fRVJST1IgPSAnVG9rZW4gbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IFRFTVBMQVRFX1VSTF9FUlJPUiA9ICdUZW1wbGF0ZSBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBBU1NFU1NNRU5UX1VSTF9FUlJPUiA9ICdBc3Nlc3NtZW50IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IE9SR0FOSVpBVElPTl9VUkxfRVJST1IgPSAnT3JnYW5pemF0aW9uIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IEhBWkFSRF9VUkxfRVJST1IgPSAnSGF6YXJkIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9VUkxfRVJST1IgPSAnSW5kaWNhdG9yIEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IEFMSUdOTUVOVF9VUkxfRVJST1IgPSAnQWxpZ25tZW50cyBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBMSUZFTElORV9VUkxfRVJST1IgPSAnTGlmZWxpbmUgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgQ09NUE9ORU5UX1VSTF9FUlJPUiA9ICdDb21wb25lbnQgRmVhdHVyZUxheWVyIFVSTCBub3QgcHJvdmlkZWQnO1xyXG5leHBvcnQgY29uc3QgUFJJT1JJVFlfVVJMX0VSUk9SID0gJ1ByaW9yaXR5IEZlYXR1cmVMYXllciBVUkwgbm90IHByb3ZpZGVkJztcclxuZXhwb3J0IGNvbnN0IElOQ0lERU5UX1VSTF9FUlJPUiA9ICdJbmNpZGVudCBGZWF0dXJlTGF5ZXIgVVJMIG5vdCBwcm92aWRlZCc7XHJcbmV4cG9ydCBjb25zdCBTQVZJTkdfU0FNRV9BU19CQVNFTElORV9FUlJPUiA9ICdCYXNlbGluZSB0ZW1wbGF0ZSBjYW5ub3QgYmUgdXBkYXRlZC4gQ2hhbmdlIHRoZSB0ZW1wbGF0ZSBuYW1lIHRvIGNyZWF0ZSBhIG5ldyBvbmUuJ1xyXG5cclxuZXhwb3J0IGNvbnN0IFNUQUJJTElaSU5HX1NDQUxFX0ZBQ1RPUiA9ICdTdGFiaWxpemluZ19TY2FsZV9GYWN0b3InO1xyXG5leHBvcnQgY29uc3QgREVTVEFCSUxJWklOR19TQ0FMRV9GQUNUT1IgPSAnRGVzdGFiaWxpemluZ19TY2FsZV9GYWN0b3InO1xyXG5leHBvcnQgY29uc3QgVU5DSEFOR0VEX1NDQUxFX0ZBQ1RPUiA9ICdVbmNoYW5nZWRfSW5kaWNhdG9ycyc7XHJcbmV4cG9ydCBjb25zdCBERUZBVUxUX1BSSU9SSVRZX0xFVkVMUyA9IFwiRGVmYXVsdF9Qcmlvcml0eV9MZXZlbHNcIjtcclxuZXhwb3J0IGNvbnN0IFJBTksgPSAnSW1wb3J0YW5jZSBvZiBJbmRpY2F0b3InO1xyXG5leHBvcnQgY29uc3QgTElGRV9TQUZFVFkgPSAnTGlmZSBTYWZldHknO1xyXG5leHBvcnQgY29uc3QgSU5DSURFTlRfU1RBQklMSVpBVElPTiA9ICdJbmNpZGVudCBTdGFiaWxpemF0aW9uJztcclxuZXhwb3J0IGNvbnN0IFBST1BFUlRZX1BST1RFQ1RJT04gPSAnUHJvcGVydHkgUHJvdGVjdGlvbic7XHJcbmV4cG9ydCBjb25zdCBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04gPSAnRW52aXJvbm1lbnQgUHJlc2VydmF0aW9uJztcclxuXHJcbmV4cG9ydCBjb25zdCBMSUZFX1NBRkVUWV9TQ0FMRV9GQUNUT1IgPSAyMDA7XHJcbmV4cG9ydCBjb25zdCBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUiA9IDEwMDtcclxuZXhwb3J0IGNvbnN0IE1BWElNVU1fV0VJR0hUID0gNTtcclxuXHJcbmV4cG9ydCBlbnVtIFVwZGF0ZUFjdGlvbiB7XHJcbiAgICBIRUFERVIgPSAnaGVhZGVyJyxcclxuICAgIElORElDQVRPUl9OQU1FID0gJ0luZGljYXRvciBOYW1lJyxcclxuICAgIFBSSU9SSVRJRVMgPSAnSW5kaWNhdG9yIFByaW9yaXRpZXMnLFxyXG4gICAgTkVXX0lORElDQVRPUiA9ICdDcmVhdGUgTmV3IEluZGljYXRvcicsXHJcbiAgICBERUxFVEVfSU5ESUNBVE9SID0gJ0RlbGV0ZSBJbmRpY2F0b3InXHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBJTkNMVURFX0lORElDQVRPUiA9ICdJbXBhY3RlZCAtIFllcyBvciBObyc7XHJcbmV4cG9ydCBjb25zdCBJTkNMVURFX0lORElDQVRPUl9IRUxQID0gJ1llczogVGhlIGluZGljYXRvciB3aWxsIGJlIGNvbnNpZGVyZWQgaW4gdGhlIGFzc2Vzc21lbnQuXFxuTm86IFRoZSBpbmRpY2F0b3Igd2lsbCBub3QgYmUgY29uc2lkZXJlZC5cXG5Vbmtub3duOiBOb3Qgc3VyZSB0byBpbmNsdWRlIHRoZSBpbmRpY2F0b3IgaW4gYXNzZXNzbWVudC4nO1xyXG5cclxuZXhwb3J0IGNvbnN0IElORElDQVRPUl9TVEFUVVMgPSAnSW5kaWNhdG9yIEltcGFjdCBTdGF0dXMnO1xyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX1NUQVRVU19IRUxQID0gJ1N0YWJpbGl6aW5nOiBIYXMgdGhlIGluZGljYXRvciBiZWVuIGltcHJvdmVkIG9yIGltcHJvdmluZy5cXG5EZXN0YWJpbGl6aW5nOiBJcyB0aGUgaW5kaWNhdG9yIGRlZ3JhZGluZy5cXG5VbmNoYW5nZWQ6IE5vIHNpZ25pZmljYW50IGltcHJvdmVtZW50IHNpbmNlIHRoZSBsYXN0IGFzc2Vzc21lbnQuJztcclxuXHJcbmV4cG9ydCBjb25zdCBDT01NRU5UID0gJ0NvbW1lbnQnO1xyXG5leHBvcnQgY29uc3QgQ09NTUVOVF9IRUxQID0gJ1Byb3ZpZGUganVzdGlmaWNhdGlvbiBmb3IgdGhlIHNlbGVjdGVkIGluZGljYXRvciBzdGF0dXMuJztcclxuXHJcbmV4cG9ydCBjb25zdCBERUxFVEVfSU5ESUNBVE9SX0NPTkZJUk1BVElPTiA9ICdBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gZGVsZXRlIGluZGljYXRvcj8nO1xyXG5cclxuLy9DZWxsIFdlaWdodCA9ICBUcmVuZCAqICggKC0xKlJhbmspICsgNlxyXG5leHBvcnQgY29uc3QgQ1JJVElDQUwgPSAyNTtcclxuZXhwb3J0IGNvbnN0IENSSVRJQ0FMX0xPV0VSX0JPVU5EQVJZID0gMTIuNTtcclxuZXhwb3J0IGNvbnN0IE1PREVSQVRFX0xPV0VSX0JPVU5EQVJZID0gNS41O1xyXG5leHBvcnQgY29uc3QgTk9EQVRBX0NPTE9SID0gJyM5MTkzOTUnO1xyXG5leHBvcnQgY29uc3QgTk9EQVRBX1ZBTFVFID0gOTk5OTk5O1xyXG5leHBvcnQgY29uc3QgUkVEX0NPTE9SID0gJyNDNTIwMzgnO1xyXG5leHBvcnQgY29uc3QgWUVMTE9XX0NPTE9SID0gJyNGQkJBMTYnO1xyXG5leHBvcnQgY29uc3QgR1JFRU5fQ09MT1IgPSAnIzVFOUM0Mic7XHJcbmV4cG9ydCBjb25zdCBTQVZJTkdfVElNRVIgPSAxNTAwO1xyXG5leHBvcnQgY29uc3QgSU5ESUNBVE9SX0NPTU1FTlRfTEVOR1RIID0gMzAwO1xyXG5cclxuZXhwb3J0IGNvbnN0IFBPUlRBTF9VUkwgPSAnaHR0cHM6Ly93d3cuYXJjZ2lzLmNvbSc7XHJcblxyXG5leHBvcnQgY29uc3QgREVGQVVMVF9MSVNUSVRFTSA9IHtpZDogJzAwMCcsIG5hbWU6ICctTm9uZS0nLCB0aXRsZTogJy1Ob25lLSd9IGFzIGFueTtcclxuXHJcbmV4cG9ydCBjb25zdCBSQU5LX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIHlvdXIganVyaXNkaWN0aW9uIG9yIGhhemFyZD8nO1xyXG5leHBvcnQgY29uc3QgTElGRV9TQUZFVFlfTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gTGlmZSBTYWZldHk/JztcclxuZXhwb3J0IGNvbnN0IFBST1BFUlRZX1BST1RFQ1RJT05fTUVTU0FHRSA9ICdIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gUHJvcGVydHkgUHJvdGVjdGlvbj8nO1xyXG5leHBvcnQgY29uc3QgRU5WSVJPTk1FTlRfUFJFU0VSVkFUSU9OX01FU1NBR0UgPSAnSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIEVudmlyb25tZW50IFByZXNlcnZhdGlvbj8nO1xyXG5leHBvcnQgY29uc3QgSU5DSURFTlRfU1RBQklMSVpBVElPTl9NRVNTQUdFID0gJ0hvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBJbmNpZGVudCBTdGFiaWxpemF0aW9uPyc7XHJcblxyXG5leHBvcnQgY29uc3QgT1ZFUldSSVRFX1NDT1JFX01FU1NBR0UgPSAnQSBjb21wbGV0ZWQgYXNzZXNzbWVudCBjYW5ub3QgYmUgZWRpdGVkLiBBcmUgeW91IHN1cmUgeW91IHdhbnQgdG8gY29tcGxldGUgdGhpcyBhc3Nlc3NtZW50Pyc7XHJcblxyXG5leHBvcnQgY29uc3QgVVNFUl9CT1hfRUxFTUVOVF9JRCA9ICd1c2VyQm94RWxlbWVudCc7XHJcblxyXG5leHBvcnQgY29uc3QgREFUQV9MSUJSQVJZX1RJVExFID0gJ0RhdGEgTGlicmFyeSc7XHJcbmV4cG9ydCBjb25zdCBBTkFMWVNJU19SRVBPUlRJTkdfVElUTEUgPSAnQW5hbHlzaXMgJiBSZXBvcnRpbmcnO1xyXG5leHBvcnQgY29uc3QgREFUQV9MSUJSQVJZX1VSTCA9ICdodHRwczovL2V4cGVyaWVuY2UuYXJjZ2lzLmNvbS9leHBlcmllbmNlL2Y5NjExOTFjZDI1MTRhYmY4ZTQzNDg2YzZmZmJmMThiJztcclxuZXhwb3J0IGNvbnN0IEFOQUxZU0lTX1JFUE9SVElOR19VUkwgPSAnaHR0cHM6Ly9leHBlcmllbmNlLmFyY2dpcy5jb20vZXhwZXJpZW5jZS84YTc2MGE3MzkxMjU0NTMwYjJjYzljOTk1MmU3YWFkZCc7IiwiaW1wb3J0IHsgVXNlclNlc3Npb24gfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtYXV0aFwiO1xyXG5pbXBvcnQgeyBxdWVyeUZlYXR1cmVzLCBJUXVlcnlGZWF0dXJlc1Jlc3BvbnNlLCBcclxuICAgIElSZWxhdGVkUmVjb3JkR3JvdXAsIHF1ZXJ5UmVsYXRlZCwgdXBkYXRlRmVhdHVyZXMsIFxyXG4gICAgYWRkRmVhdHVyZXMsIGRlbGV0ZUZlYXR1cmVzIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LWZlYXR1cmUtbGF5ZXJcIjtcclxuaW1wb3J0IHsgSUZlYXR1cmVTZXQsIElGZWF0dXJlIH0gZnJvbSBcIkBlc3JpL2FyY2dpcy1yZXN0LXR5cGVzXCI7XHJcbmltcG9ydCB7IEFwcFdpZGdldENvbmZpZyB9IGZyb20gXCIuL2RhdGEtZGVmaW5pdGlvbnNcIjtcclxuaW1wb3J0IHsgbG9nLCBMb2dUeXBlIH0gZnJvbSBcIi4vbG9nZ2VyXCI7XHJcblxyXG5hc3luYyBmdW5jdGlvbiBnZXRBdXRoZW50aWNhdGlvbihjb25maWc6IEFwcFdpZGdldENvbmZpZykge1xyXG4gIHJldHVybiBVc2VyU2Vzc2lvbi5mcm9tQ3JlZGVudGlhbChjb25maWcuY3JlZGVudGlhbCk7XHJcbn1cclxuICBcclxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHF1ZXJ5VGFibGVGZWF0dXJlU2V0KHVybDogc3RyaW5nLCB3aGVyZTogc3RyaW5nLCBcclxuICBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVTZXQ+IHtcclxuICBcclxuICAgIHRyeXtcclxuXHJcbiAgICAgIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuICAgICAgcmV0dXJuIHF1ZXJ5RmVhdHVyZXMoeyB1cmwsIHdoZXJlLCBhdXRoZW50aWNhdGlvbiwgaGlkZVRva2VuOiB0cnVlIH0pXHJcbiAgICAgIC50aGVuKChyZXNwb25zZTogSVF1ZXJ5RmVhdHVyZXNSZXNwb25zZSkgPT4ge1xyXG4gICAgICAgIHJldHVybiByZXNwb25zZVxyXG4gICAgICB9KVxyXG5cclxuICAgIH1jYXRjaChlKXtcclxuICAgICAgbG9nKGUsIExvZ1R5cGUuRVJST1IsICdxdWVyeVRhYmxlRmVhdHVyZVNldCcpXHJcbiAgICB9ICAgIFxyXG59XHJcblxyXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcXVlcnlUYWJsZUZlYXR1cmVzKHVybDogc3RyaW5nLCB3aGVyZTogc3RyaW5nLCBjb25maWc6IEFwcFdpZGdldENvbmZpZyk6IFByb21pc2U8SUZlYXR1cmVbXT4ge1xyXG5cclxuIGNvbnN0IGF1dGhlbnRpY2F0aW9uID0gYXdhaXQgZ2V0QXV0aGVudGljYXRpb24oY29uZmlnKTtcclxuXHJcbiAgdHJ5e1xyXG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IHF1ZXJ5RmVhdHVyZXMoeyB1cmwsIHdoZXJlLCBhdXRoZW50aWNhdGlvbiwgIGh0dHBNZXRob2Q6J1BPU1QnLCBoaWRlVG9rZW46IHRydWUgfSlcclxuICAgICAgcmV0dXJuIChyZXNwb25zZSBhcyBJUXVlcnlGZWF0dXJlc1Jlc3BvbnNlKS5mZWF0dXJlcztcclxuICB9Y2F0Y2goZSl7XHJcbiAgICAgIGxvZyhlLCBMb2dUeXBlLkVSUk9SLCAncXVlcnlUYWJsZUZlYXR1cmVzJylcclxuICAgICAgbG9nKHVybCwgTG9nVHlwZS5XUk4sIHdoZXJlKTtcclxuICB9XHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gcXVlcnlSZWxhdGVkVGFibGVGZWF0dXJlcyhvYmplY3RJZHM6IG51bWJlcltdLFxyXG51cmw6IHN0cmluZywgcmVsYXRpb25zaGlwSWQ6IG51bWJlciwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpOiBQcm9taXNlPElSZWxhdGVkUmVjb3JkR3JvdXBbXT4ge1xyXG5cclxuY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBxdWVyeVJlbGF0ZWQoe1xyXG4gICAgb2JqZWN0SWRzLFxyXG4gICAgdXJsLCByZWxhdGlvbnNoaXBJZCxcclxuICAgIGF1dGhlbnRpY2F0aW9uLFxyXG4gICAgaGlkZVRva2VuOiB0cnVlXHJcbn0pO1xyXG5yZXR1cm4gcmVzcG9uc2UucmVsYXRlZFJlY29yZEdyb3VwcztcclxufVxyXG5cclxuZXhwb3J0ICBhc3luYyBmdW5jdGlvbiB1cGRhdGVUYWJsZUZlYXR1cmUodXJsOiBzdHJpbmcsIGF0dHJpYnV0ZXM6IGFueSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuICBjb25zdCBhdXRoZW50aWNhdGlvbiA9IGF3YWl0IGdldEF1dGhlbnRpY2F0aW9uKGNvbmZpZyk7XHJcblxyXG4gIHJldHVybiB1cGRhdGVGZWF0dXJlcyh7XHJcbiAgICAgIHVybCxcclxuICAgICAgYXV0aGVudGljYXRpb24sXHJcbiAgICAgIGZlYXR1cmVzOiBbe1xyXG4gICAgICBhdHRyaWJ1dGVzXHJcbiAgICAgIH1dLFxyXG4gICAgICByb2xsYmFja09uRmFpbHVyZTogdHJ1ZVxyXG4gIH0pXHJcbn1cclxuXHJcbmV4cG9ydCAgYXN5bmMgZnVuY3Rpb24gdXBkYXRlVGFibGVGZWF0dXJlcyh1cmw6IHN0cmluZywgZmVhdHVyZXM6IElGZWF0dXJlW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcbiAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpOyAgXHJcbiAgcmV0dXJuIHVwZGF0ZUZlYXR1cmVzKHtcclxuICAgICAgdXJsLFxyXG4gICAgICBhdXRoZW50aWNhdGlvbixcclxuICAgICAgZmVhdHVyZXNcclxuICB9KVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIGFkZFRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIGZlYXR1cmVzOiBhbnlbXSwgY29uZmlnOiBBcHBXaWRnZXRDb25maWcpIHtcclxuXHJcbiAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG5cclxuICB0cnl7XHJcbiAgICByZXR1cm4gYWRkRmVhdHVyZXMoeyB1cmwsIGZlYXR1cmVzLCBhdXRoZW50aWNhdGlvbiwgcm9sbGJhY2tPbkZhaWx1cmU6IHRydWUgfSk7XHJcbiAgfWNhdGNoKGUpe1xyXG4gICAgY29uc29sZS5sb2coZSk7XHJcbiAgfVxyXG59XHJcblxyXG5leHBvcnQgIGFzeW5jIGZ1bmN0aW9uIGRlbGV0ZVRhYmxlRmVhdHVyZXModXJsOiBzdHJpbmcsIG9iamVjdElkczogbnVtYmVyW10sIGNvbmZpZzogQXBwV2lkZ2V0Q29uZmlnKSB7XHJcblxyXG4gICAgY29uc3QgYXV0aGVudGljYXRpb24gPSBhd2FpdCBnZXRBdXRoZW50aWNhdGlvbihjb25maWcpO1xyXG4gICAgcmV0dXJuIGRlbGV0ZUZlYXR1cmVzKHsgdXJsLCBvYmplY3RJZHMsIGF1dGhlbnRpY2F0aW9uLCByb2xsYmFja09uRmFpbHVyZTogdHJ1ZSB9KTtcclxufSIsImV4cG9ydCBlbnVtIExvZ1R5cGUge1xyXG4gICAgSU5GTyA9ICdJbmZvcm1hdGlvbicsXHJcbiAgICBXUk4gPSAnV2FybmluZycsXHJcbiAgICBFUlJPUiA9ICdFcnJvcidcclxufVxyXG5cclxuZXhwb3J0IGZ1bmN0aW9uIGxvZyhtZXNzYWdlOiBzdHJpbmcsIHR5cGU/OiBMb2dUeXBlLCBmdW5jPzogc3RyaW5nKXtcclxuICAgIGlmKCF0eXBlKXtcclxuICAgICAgICB0eXBlID0gTG9nVHlwZS5JTkZPXHJcbiAgICB9XHJcblxyXG4gICAgaWYoZnVuYyl7XHJcbiAgICAgICAgZnVuYyA9IGAoJHtmdW5jfSlgO1xyXG4gICAgfVxyXG5cclxuICAgIG1lc3NhZ2UgPSBgWyR7bmV3IERhdGUoKS50b0xvY2FsZVN0cmluZygpfV06ICR7bWVzc2FnZX0gJHtmdW5jfWA7XHJcblxyXG4gICAgc3dpdGNoKHR5cGUpe1xyXG4gICAgICAgIGNhc2UgTG9nVHlwZS5JTkZPOlxyXG4gICAgICAgICAgICBjb25zb2xlLmxvZyhtZXNzYWdlKTtcclxuICAgICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgY2FzZSBMb2dUeXBlLldSTjpcclxuICAgICAgICAgICAgY29uc29sZS53YXJuKG1lc3NhZ2UpO1xyXG4gICAgICAgICAgICBicmVhaztcclxuICAgICAgICBjYXNlIExvZ1R5cGUuRVJST1I6XHJcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IobWVzc2FnZSk7XHJcbiAgICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGRlZmF1bHQ6XHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKG1lc3NhZ2UpO1xyXG4gICAgfVxyXG59IiwiXHJcbmV4cG9ydCBjb25zdCBzb3J0T2JqZWN0ID0gPFQ+KG9iajogVFtdLCBwcm9wOiBzdHJpbmcsIHJldmVyc2U/OmJvb2xlYW4pOiBUW10gPT4ge1xyXG4gICByZXR1cm4gb2JqLnNvcnQoKGE6VCwgYjpUKSA9PiB7XHJcbiAgICAgIGlmKGFbcHJvcF0gPiBiW3Byb3BdKXtcclxuICAgICAgICByZXR1cm4gcmV2ZXJzZSA/IC0xIDogMVxyXG4gICAgICB9XHJcbiAgICAgIGlmKGFbcHJvcF0gPCBiW3Byb3BdKXtcclxuICAgICAgICByZXR1cm4gcmV2ZXJzZSA/IDEgOiAtMVxyXG4gICAgICB9XHJcbiAgICAgIHJldHVybiAwO1xyXG4gIH0pO1xyXG59XHJcblxyXG5leHBvcnQgY29uc3QgY3JlYXRlR3VpZCA9ICgpID0+e1xyXG4gIHJldHVybiAneHh4eHh4eHgteHh4eC00eHh4LXl4eHgteHh4eHh4eHh4eHh4Jy5yZXBsYWNlKC9beHldL2csIGZ1bmN0aW9uKGMpIHtcclxuICAgIHZhciByID0gTWF0aC5yYW5kb20oKSAqIDE2IHwgMCwgdiA9IGMgPT0gJ3gnID8gciA6IChyICYgMHgzIHwgMHg4KTtcclxuICAgIHJldHVybiB2LnRvU3RyaW5nKDE2KTtcclxuICB9KTtcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IHBhcnNlRGF0ZSA9IChtaWxsaXNlY29uZHM6IG51bWJlcik6IHN0cmluZyA9PiB7XHJcbiAgaWYoIW1pbGxpc2Vjb25kcyl7XHJcbiAgICByZXR1cm5cclxuICB9XHJcbiAgIHJldHVybiBuZXcgRGF0ZShtaWxsaXNlY29uZHMpLnRvTG9jYWxlU3RyaW5nKCk7XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBzYXZlRGF0ZSA9IChkYXRlOiBzdHJpbmcpOiBudW1iZXIgPT4ge1xyXG4gICByZXR1cm4gbmV3IERhdGUoZGF0ZSkuZ2V0TWlsbGlzZWNvbmRzKCk7XHJcbn1cclxuXHJcblxyXG4vL1JlZmVyZW5jZTogaHR0cHM6Ly9zdGFja292ZXJmbG93LmNvbS9xdWVzdGlvbnMvNjE5NTMzNS9saW5lYXItcmVncmVzc2lvbi1pbi1qYXZhc2NyaXB0XHJcbi8vIGV4cG9ydCBjb25zdCBsaW5lYXJSZWdyZXNzaW9uID0gKHlWYWx1ZXM6IG51bWJlcltdLCB4VmFsdWVzOiBudW1iZXJbXSkgPT57XHJcbi8vICAgZGVidWdnZXI7XHJcbi8vICAgY29uc3QgeSA9IHlWYWx1ZXM7XHJcbi8vICAgY29uc3QgeCA9IHhWYWx1ZXM7XHJcblxyXG4vLyAgIHZhciBsciA9IHtzbG9wZTogTmFOLCBpbnRlcmNlcHQ6IE5hTiwgcjI6IE5hTn07XHJcbi8vICAgdmFyIG4gPSB5Lmxlbmd0aDtcclxuLy8gICB2YXIgc3VtX3ggPSAwO1xyXG4vLyAgIHZhciBzdW1feSA9IDA7XHJcbi8vICAgdmFyIHN1bV94eSA9IDA7XHJcbi8vICAgdmFyIHN1bV94eCA9IDA7XHJcbi8vICAgdmFyIHN1bV95eSA9IDA7XHJcblxyXG4vLyAgIGZvciAodmFyIGkgPSAwOyBpIDwgeS5sZW5ndGg7IGkrKykge1xyXG5cclxuLy8gICAgICAgc3VtX3ggKz0geFtpXTtcclxuLy8gICAgICAgc3VtX3kgKz0geVtpXTtcclxuLy8gICAgICAgc3VtX3h5ICs9ICh4W2ldKnlbaV0pO1xyXG4vLyAgICAgICBzdW1feHggKz0gKHhbaV0qeFtpXSk7XHJcbi8vICAgICAgIHN1bV95eSArPSAoeVtpXSp5W2ldKTtcclxuLy8gICB9IFxyXG5cclxuLy8gICBsci5zbG9wZSA9IChuICogc3VtX3h5IC0gc3VtX3ggKiBzdW1feSkgLyAobipzdW1feHggLSBzdW1feCAqIHN1bV94KTtcclxuLy8gICBsci5pbnRlcmNlcHQgPSAoc3VtX3kgLSBsci5zbG9wZSAqIHN1bV94KS9uO1xyXG4vLyAgIGxyLnIyID0gTWF0aC5wb3coKG4qc3VtX3h5IC0gc3VtX3gqc3VtX3kpL01hdGguc3FydCgobipzdW1feHgtc3VtX3gqc3VtX3gpKihuKnN1bV95eS1zdW1feSpzdW1feSkpLDIpO1xyXG4vLyAgIHJldHVybiBscjtcclxuLy8gfVxyXG5cclxuU3RyaW5nLnByb3RvdHlwZS50b1RpdGxlQ2FzZSA9IGZ1bmN0aW9uICgpIHtcclxuICByZXR1cm4gdGhpcy5yZXBsYWNlKC9cXHdcXFMqL2csIGZ1bmN0aW9uKHR4dCl7cmV0dXJuIHR4dC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIHR4dC5zdWJzdHIoMSkudG9Mb3dlckNhc2UoKTt9KTtcclxufTtcclxuXHJcbkFycmF5LnByb3RvdHlwZS5vcmRlckJ5ID0gZnVuY3Rpb248VD4ocHJvcCwgcmV2ZXJzZSkge1xyXG4gIHJldHVybiB0aGlzLnNvcnQoKGE6VCwgYjpUKSA9PiB7XHJcbiAgICBpZihhW3Byb3BdID4gYltwcm9wXSl7XHJcbiAgICAgIHJldHVybiByZXZlcnNlID8gLTEgOiAxXHJcbiAgICB9XHJcbiAgICBpZihhW3Byb3BdIDwgYltwcm9wXSl7XHJcbiAgICAgIHJldHVybiByZXZlcnNlID8gMSA6IC0xXHJcbiAgICB9XHJcbiAgICByZXR1cm4gMDtcclxuICB9KTtcclxufVxyXG5cclxuQXJyYXkucHJvdG90eXBlLmdyb3VwQnkgPSBmdW5jdGlvbihrZXkpIHtcclxuICByZXR1cm4gdGhpcy5yZWR1Y2UoZnVuY3Rpb24ocnYsIHgpIHtcclxuICAgIChydlt4W2tleV1dID0gcnZbeFtrZXldXSB8fCBbXSkucHVzaCh4KTtcclxuICAgIHJldHVybiBydjtcclxuICB9LCB7fSk7XHJcbn07XHJcbiIsImltcG9ydCB7IFRleHRJbnB1dCwgVGV4dEFyZWEgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBMYWJlbFxyXG4gICAgICB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIlxyXG5pbXBvcnQgeyBkaXNwYXRjaEFjdGlvbiwgIHNhdmVIYXphcmQgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9hcGlcIlxyXG5pbXBvcnQgeyBIYXphcmQgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9kYXRhLWRlZmluaXRpb25zXCJcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlXCJcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1kcm9wZG93blwiXHJcbmltcG9ydCB7IENsc3NNb2RhbCB9IGZyb20gXCIuL2Nsc3MtbW9kYWxcIjtcclxuaW1wb3J0IHsgUmVhY3RSZWR1eCB9IGZyb20gXCJqaW11LWNvcmVcIlxyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuZXhwb3J0IGNvbnN0IEFkZEhhemFyZFdpZGdldD0oe3Byb3BzLCB2aXNpYmxlLCB0b2dnbGUsIHNldEhhemFyZH06XHJcbiAgICB7cHJvcHM6IGFueSwgdmlzaWJsZTogYm9vbGVhbiwgdG9nZ2xlOiBhbnksIHNldEhhemFyZD86IGFueX0pID0+e1xyXG5cclxuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTsgICAgXHJcbiAgICBjb25zdCBbaXNWaXNpYmxlLCBzZXRWaXNpYmxlXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTsgXHJcbiAgICBjb25zdCBbbmFtZSwgc2V0TmFtZV0gPSBSZWFjdC51c2VTdGF0ZSgnJyk7ICAgXHJcbiAgICBjb25zdCBbZGVzY3JpcHRpb24sIHNldERlc2NyaXB0aW9uXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTsgXHJcbiAgICBjb25zdCBbaGF6YXJkVHlwZXMsIHNldEhhemFyZFR5cGVzXSA9IFJlYWN0LnVzZVN0YXRlPElDb2RlZFZhbHVlW10+KFtdKTtcclxuICAgIGNvbnN0IFtzZWxlY3RlZEhhemFyZFR5cGUsIHNldFNlbGVjdGVkSGF6YXJkVHlwZV0gPSBSZWFjdC51c2VTdGF0ZTxJQ29kZWRWYWx1ZT4obnVsbCk7XHJcbiAgICBjb25zdCBbY29uZmlnLCBzZXRDb25maWddID0gUmVhY3QudXNlU3RhdGUobnVsbClcclxuXHJcbiAgICBjb25zdCBjcmVkZW50aWFsID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5hdXRoZW50aWNhdGU7XHJcbiAgICB9KVxyXG5cclxuICAgIGNvbnN0IGhhemFyZHMgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgICAgIHJldHVybiBzdGF0ZS5jbHNzU3RhdGU/LmhhemFyZHMgYXMgSGF6YXJkW107XHJcbiAgICAgfSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgICAgIGlmKGNyZWRlbnRpYWwpe1xyXG4gICAgICAgICAgIHNldENvbmZpZyh7Li4uIHByb3BzLmNvbmZpZywgY3JlZGVudGlhbDpjcmVkZW50aWFsfSk7ICAgICAgICAgICAgXHJcbiAgICAgICAgfVxyXG4gICAgfSwgW2NyZWRlbnRpYWxdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgaWYoaGF6YXJkcyAmJiBoYXphcmRzLmxlbmd0aCA+IDApe1xyXG4gICAgICAgICAgICBjb25zdCB0eXBlcyA9IGhhemFyZHNbMV0uZG9tYWlucztcclxuICAgICAgICAgICAgKHR5cGVzIGFzIGFueSkub3JkZXJCeSgnbmFtZScpO1xyXG4gICAgICAgICAgICAgc2V0SGF6YXJkVHlwZXModHlwZXMpXHJcbjsgICAgICAgIH1cclxuICAgIH0sIFtoYXphcmRzXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgICBzZXRWaXNpYmxlKHZpc2libGUpO1xyXG4gICAgICAgIHNldE5hbWUoJycpO1xyXG4gICAgICAgIHNldERlc2NyaXB0aW9uKCcnKTtcclxuICAgICAgICBzZXRTZWxlY3RlZEhhemFyZFR5cGUobnVsbCk7XHJcbiAgICB9LCBbdmlzaWJsZV0pICAgXHJcblxyXG4gICAgY29uc3Qgc2F2ZU5ld0hhemFyZD1hc3luYyAoKT0+e1xyXG5cclxuICAgICAgICBjb25zdCBleGlzdCA9IGhhemFyZHMuZmluZChoID0+IGgubmFtZS50b0xvd2VyQ2FzZSgpID09PSBuYW1lLnRvTG93ZXJDYXNlKCkudHJpbSgpKTtcclxuICAgICAgICBpZihleGlzdCl7XHJcbiAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIGBIYXphcmQ6ICR7bmFtZX0gYWxyZWFkeSBleGlzdHNgKTtcclxuICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuXHJcbiAgICAgICAgc2V0TG9hZGluZyh0cnVlKTtcclxuXHJcbiAgICAgICAgdHJ5e1xyXG4gICAgICAgICAgICBsZXQgbmV3SGF6YXJkID0ge1xyXG4gICAgICAgICAgICAgICAgbmFtZSxcclxuICAgICAgICAgICAgICAgIHRpdGxlOiBuYW1lLFxyXG4gICAgICAgICAgICAgICAgdHlwZTogc2VsZWN0ZWRIYXphcmRUeXBlLFxyXG4gICAgICAgICAgICAgICAgZGVzY3JpcHRpb25cclxuICAgICAgICAgICAgfSBhcyBIYXphcmQ7XHJcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgc2F2ZUhhemFyZChjb25maWcsIG5ld0hhemFyZCk7XHJcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKHJlc3BvbnNlKTtcclxuICAgICAgICAgICAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFN0cmluZyhyZXNwb25zZS5lcnJvcnMpKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBcclxuICAgICAgICAgICAgbmV3SGF6YXJkID0gcmVzcG9uc2UuZGF0YTtcclxuICAgICAgICAgICAgbmV3SGF6YXJkLmRvbWFpbnMgPSBoYXphcmRzWzFdLmRvbWFpbnM7XHJcblxyXG4gICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5MT0FEX0hBWkFSRFNfQUNUSU9OLFxyXG4gICAgICAgICAgICAgICBbLi4uaGF6YXJkcywgbmV3SGF6YXJkXSlcclxuXHJcbiAgICAgICAgICAgIHNldEhhemFyZChuZXdIYXphcmQpO1xyXG4gICAgICAgICAgICB0b2dnbGUoZmFsc2UpO1xyXG4gICAgICAgIH1jYXRjaChlcnIpe1xyXG4gICAgICAgICAgIGNvbnNvbGUubG9nKGVycik7XHJcbiAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgZXJyLm1lc3NhZ2UpO1xyXG4gICAgICAgIH1maW5hbGx5e1xyXG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKTtcclxuICAgICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8Q2xzc01vZGFsIHRpdGxlPVwiQWRkIE5ldyBIYXphcmRcIlxyXG4gICAgICAgICAgICBkaXNhYmxlPXshKG5hbWUgJiYgc2VsZWN0ZWRIYXphcmRUeXBlKX0gIHNhdmU9e3NhdmVOZXdIYXphcmR9IFxyXG4gICAgICAgICAgICB0b2dnbGVWaXNpYmlsaXR5PXt0b2dnbGV9IHZpc2libGU9e2lzVmlzaWJsZX1cclxuICAgICAgICAgICAgbG9hZGluZz17bG9hZGluZ30+XHJcbiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImhhemFyZHNcIj5cclxuICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgICAgIDxMYWJlbCBjaGVjaz5IYXphcmQgTmFtZTxzcGFuIHN0eWxlPXt7Y29sb3I6ICdyZWQnfX0+Kjwvc3Bhbj48L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgICAgIDxUZXh0SW5wdXQgb25DaGFuZ2U9eyhlKT0+IHNldE5hbWUoZS50YXJnZXQudmFsdWUpfSBcclxuICAgICAgICAgICAgICAgICAgICB2YWx1ZT17bmFtZX0+PC9UZXh0SW5wdXQ+XHJcbiAgICAgICAgICAgICAgICA8L2Rpdj5cclxuXHJcbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+SGF6YXJkIFR5cGU8c3BhbiBzdHlsZT17e2NvbG9yOiAncmVkJ319Pio8L3NwYW4+PC9MYWJlbD5cclxuICAgICAgICAgICAgICAgICAgICA8Q2xzc0Ryb3Bkb3duIGl0ZW1zPXtoYXphcmRUeXBlc31cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGl0ZW09e3NlbGVjdGVkSGF6YXJkVHlwZX0gXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxldGFibGU9e2ZhbHNlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc2V0SXRlbT17c2V0U2VsZWN0ZWRIYXphcmRUeXBlfSAvPiBcclxuICAgICAgICAgICAgICAgIDwvZGl2PiAgICAgICBcclxuXHJcbiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2s+RGVzY3JpcHRpb24gb2YgSGF6YXJkIChPcHRpb25hbCk8L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgICAgIDxUZXh0QXJlYVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB2YWx1ZT17ZGVzY3JpcHRpb259XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSkgPT4gc2V0RGVzY3JpcHRpb24oZS50YXJnZXQudmFsdWUpfVxyXG4gICAgICAgICAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAgPC9kaXY+ICBcclxuICAgICAgICA8L0Nsc3NNb2RhbD5cclxuICAgIClcclxufSIsImltcG9ydCB7IFRleHRJbnB1dCwgQnV0dG9uLCBNb2RhbCwgTW9kYWxCb2R5LCBNb2RhbEZvb3RlciwgTW9kYWxIZWFkZXIgfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBMYWJlbCB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IHsgT3JnYW5pemF0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9uc1wiXHJcbmltcG9ydCB7IGRpc3BhdGNoQWN0aW9uLCBzYXZlT3JnYW5pemF0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpXCJcclxuaW1wb3J0IHsgQ0xTU0FjdGlvbktleXMgfSBmcm9tIFwiLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jbHNzLXN0b3JlXCJcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIlxyXG5pbXBvcnQgQ2xzc0xvYWRpbmcgZnJvbSBcIi4vY2xzcy1sb2FkaW5nXCJcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1kcm9wZG93blwiO1xyXG5pbXBvcnQgeyBSZWFjdFJlZHV4IH0gZnJvbSBcImppbXUtY29yZVwiXHJcbmltcG9ydCB7IENsc3NNb2RhbCB9IGZyb20gXCIuL2Nsc3MtbW9kYWxcIlxyXG5pbXBvcnQgeyBPcmdhbml6YXRpb25zRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLW9yZ2FuaXphdGlvbnMtZHJvcGRvd25cIlxyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuZXhwb3J0IGNvbnN0IEFkZE9yZ2FuaXphdG9uV2lkZ2V0PSh7cHJvcHNDb25maWcsIHZpc2libGUsIHRvZ2dsZSwgc2V0T3JnYW5pemF0aW9ufSkgPT57XHJcblxyXG4gICAgY29uc3QgW2xvYWRpbmcsIHNldExvYWRpbmddID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpOyAgICBcclxuICAgIGNvbnN0IFtpc1Zpc2libGUsIHNldFZpc2libGVdID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpOyBcclxuICAgIGNvbnN0IFtvcmdhbml6YXRpb25OYW1lLCBzZXRPcmdhbml6YXRpb25OYW1lXSA9IFJlYWN0LnVzZVN0YXRlKCcnKTsgICAgXHJcbiAgICBjb25zdCBbb3JnYW5pemF0aW9uVHlwZXMsIHNldE9yZ2FuaXphdGlvblR5cGVzXSA9IFJlYWN0LnVzZVN0YXRlPElDb2RlZFZhbHVlW10+KFtdKTtcclxuICAgIGNvbnN0IFtzZWxlY3RlZE9yZ2FuaXphdGlvblR5cGUsIHNldFNlbGVjdGVkT3JnYW5pemF0aW9uVHlwZV0gPSBSZWFjdC51c2VTdGF0ZTxJQ29kZWRWYWx1ZT4obnVsbCk7XHJcbiAgICBjb25zdCBbc2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb24sIHNldFNlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9uXSA9IFJlYWN0LnVzZVN0YXRlPE9yZ2FuaXphdGlvbj4obnVsbCk7XHJcbiAgICBjb25zdCBbY29uZmlnLCBzZXRDb25maWddID0gUmVhY3QudXNlU3RhdGUobnVsbCk7XHJcblxyXG4gICAgY29uc3Qgb3JnYW5pemF0aW9ucyA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICAgICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8ub3JnYW5pemF0aW9ucyBhcyBPcmdhbml6YXRpb25bXTtcclxuICAgICB9KVxyXG5cclxuICAgICBjb25zdCBjcmVkZW50aWFsID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5hdXRoZW50aWNhdGU7XHJcbiAgICB9KVxyXG4gICAgIFxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57IFxyXG4gICAgICAgIHNldFZpc2libGUodmlzaWJsZSk7XHJcbiAgICAgICAgc2V0T3JnYW5pemF0aW9uTmFtZSgnJyk7XHJcbiAgICAgICAgc2V0U2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlKG51bGwpO1xyXG4gICAgfSwgW3Zpc2libGVdKSAgIFxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgaWYoY3JlZGVudGlhbCl7XHJcbiAgICAgICAgICAgc2V0Q29uZmlnKHsuLi5wcm9wc0NvbmZpZywgY3JlZGVudGlhbH0pOyAgICAgICAgICAgIFxyXG4gICAgICAgIH1cclxuICAgIH0sIFtjcmVkZW50aWFsXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgICBpZihvcmdhbml6YXRpb25zICYmIG9yZ2FuaXphdGlvbnMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgY29uc3QgdHlwZXMgPSBvcmdhbml6YXRpb25zWzFdLmRvbWFpbnM7XHJcbiAgICAgICAgKHR5cGVzIGFzIGFueSk/Lm9yZGVyQnkoJ25hbWUnKTtcclxuICAgICAgICBzZXRPcmdhbml6YXRpb25UeXBlcyh0eXBlcyk7XHJcbiAgICAgIH1cclxuICAgIH0sIFtvcmdhbml6YXRpb25zXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgICBzZXRTZWxlY3RlZFBhcmVudE9yZ2FuaXphdGlvbihvcmdhbml6YXRpb25zWzBdKTtcclxuICAgIH0sIFtvcmdhbml6YXRpb25zXSlcclxuXHJcbiAgICBjb25zdCBzYXZlID0gYXN5bmMgKCkgPT4ge1xyXG4gICAgICAgIGNvbnN0IGV4aXN0cyA9IG9yZ2FuaXphdGlvbnMuZmluZChvID0+IG8ubmFtZSA9PT0gb3JnYW5pemF0aW9uTmFtZSk7XHJcbiAgICAgICAgaWYoZXhpc3RzKXtcclxuICAgICAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgYE9yZ2FuaXphdGlvbjogJHtvcmdhbml6YXRpb25OYW1lfSBhbHJlYWR5IGV4aXN0c2ApO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHNldExvYWRpbmcodHJ1ZSk7XHJcbiAgICAgICAgdHJ5e1xyXG4gICAgICAgICAgICBsZXQgbmV3T3JnYW5pemF0aW9uID0ge1xyXG4gICAgICAgICAgICAgICAgbmFtZTogb3JnYW5pemF0aW9uTmFtZSxcclxuICAgICAgICAgICAgICAgIHRpdGxlOiBvcmdhbml6YXRpb25OYW1lLFxyXG4gICAgICAgICAgICAgICAgdHlwZTogc2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlLFxyXG4gICAgICAgICAgICAgICAgcGFyZW50SWQ6IHNlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9uLmlkICE9PSAnMDAwJyA/IHNlbGVjdGVkUGFyZW50T3JnYW5pemF0aW9uLmlkIDogbnVsbFxyXG4gICAgICAgICAgICB9IGFzIE9yZ2FuaXphdGlvblxyXG5cclxuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBzYXZlT3JnYW5pemF0aW9uKGNvbmZpZywgbmV3T3JnYW5pemF0aW9uKTsgICAgICAgICAgICBcclxuICAgICAgICAgICAgY29uc29sZS5sb2cocmVzcG9uc2UpO1xyXG4gICAgICAgICAgICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFN0cmluZyhyZXNwb25zZS5lcnJvcnMpKVxyXG4gICAgICAgICAgICB9ICAgICAgICAgICAgXHJcblxyXG4gICAgICAgICAgICBuZXdPcmdhbml6YXRpb24gPSByZXNwb25zZS5kYXRhO1xyXG4gICAgICAgICAgICBuZXdPcmdhbml6YXRpb24uZG9tYWlucyA9IG9yZ2FuaXphdGlvbnNbMV0uZG9tYWlucztcclxuXHJcbiAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKFxyXG4gICAgICAgICAgICAgICAgQ0xTU0FjdGlvbktleXMuTE9BRF9PUkdBTklaQVRJT05TX0FDVElPTixcclxuICAgICAgICAgICAgICAgWy4uLm9yZ2FuaXphdGlvbnMsIG5ld09yZ2FuaXphdGlvbl0pO1xyXG4gICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgc2V0T3JnYW5pemF0aW9uKHJlc3BvbnNlLmRhdGEpXHJcbiAgICAgICAgICAgIHRvZ2dsZShmYWxzZSk7XHJcbiAgICAgICAgfWNhdGNoKGVycil7XHJcbiAgICAgICAgICAgY29uc29sZS5sb2coZXJyKTtcclxuICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCBlcnIubWVzc2FnZSk7XHJcbiAgICAgICAgfWZpbmFsbHl7XHJcbiAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4oICAgICAgICAgICBcclxuICAgICAgPENsc3NNb2RhbCB0aXRsZT1cIkFkZCBOZXcgT3JnYW5pemF0aW9uXCJcclxuICAgICAgICBkaXNhYmxlPXshKG9yZ2FuaXphdGlvbk5hbWUgJiYgc2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlKX0gIFxyXG4gICAgICAgIHNhdmU9e3NhdmV9IFxyXG4gICAgICAgIGxvYWRpbmc9e2xvYWRpbmd9XHJcbiAgICAgICAgdG9nZ2xlVmlzaWJpbGl0eT17dG9nZ2xlfSB2aXNpYmxlPXtpc1Zpc2libGV9PlxyXG4gICAgICAgICBcclxuICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJhZGQtb3JnYW5pemF0aW9uXCI+IFxyXG4gICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuYWRkLW9yZ2FuaXphdGlvbntcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtblxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cIm1vZGFsLWl0ZW1cIj4gICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPk9yZ2FuaXphdGlvbiBOYW1lPHNwYW4gc3R5bGU9e3tjb2xvcjogJ3JlZCd9fT4qPC9zcGFuPjwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICA8VGV4dElucHV0IGRhdGEtdGVzdGlkPVwidHh0T3JnYW5pemF0aW9uTmFtZVwiIHNpemU9XCJkZWZhdWx0XCJcclxuICAgICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KGUpPT4gc2V0T3JnYW5pemF0aW9uTmFtZShlLnRhcmdldC52YWx1ZSl9IFxyXG4gICAgICAgICAgICAgICAgICAgIHZhbHVlPXtvcmdhbml6YXRpb25OYW1lfT5cclxuICAgICAgICAgICAgICAgIDwvVGV4dElucHV0PlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuXHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPk9yZ2FuaXphdGlvbiBUeXBlPHNwYW4gc3R5bGU9e3tjb2xvcjogJ3JlZCd9fT4qPC9zcGFuPjwvTGFiZWw+ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICA8Q2xzc0Ryb3Bkb3duIGl0ZW1zPXtvcmdhbml6YXRpb25UeXBlc30gXHJcbiAgICAgICAgICAgICAgICAgICAgaXRlbT17c2VsZWN0ZWRPcmdhbml6YXRpb25UeXBlfSBcclxuICAgICAgICAgICAgICAgICAgICBkZWxldGFibGU9e2ZhbHNlfVxyXG4gICAgICAgICAgICAgICAgICAgIHNldEl0ZW09e3NldFNlbGVjdGVkT3JnYW5pemF0aW9uVHlwZX0vPlxyXG4gICAgICAgICAgICA8L2Rpdj5cclxuXHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwibW9kYWwtaXRlbVwiPlxyXG4gICAgICAgICAgICAgICAgPExhYmVsIGNoZWNrPk9yZ2FuaXphdGlvbidzIFBhcmVudCAoT3B0aW9uYWwpPC9MYWJlbD5cclxuICAgICAgICAgICAgICAgIDxPcmdhbml6YXRpb25zRHJvcGRvd24gXHJcbiAgICAgICAgICAgICAgICAgICAgY29uZmlnPXtjb25maWd9XHJcbiAgICAgICAgICAgICAgICAgICAgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWw9e251bGx9ICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICBvcmdhbml6YXRpb25zPXtvcmdhbml6YXRpb25zfSBcclxuICAgICAgICAgICAgICAgICAgICBzZWxlY3RlZE9yZ2FuaXphdGlvbj17c2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb259IFxyXG4gICAgICAgICAgICAgICAgICAgIHNldE9yZ2FuaXphdGlvbj17c2V0U2VsZWN0ZWRQYXJlbnRPcmdhbml6YXRpb259XHJcbiAgICAgICAgICAgICAgICAgICAgdmVydGljYWw9e2ZhbHNlfS8+ICBcclxuICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgIDwvZGl2PiAgICAgICAgICAgICAgICBcclxuICAgIFxyXG4gICAgICA8L0Nsc3NNb2RhbD5cclxuICAgIClcclxufSIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBDbHNzTW9kYWwgfSBmcm9tIFwiLi9jbHNzLW1vZGFsXCJcclxuXHJcbmV4cG9ydCBjb25zdCBUZW1wbGF0ZUFzc2Vzc21lbnRWaWV3ID0oe2Fzc2Vzc21lbnRzLCB0b2dnbGUsIGlzVmlzaWJsZX0pPT4ge1xyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8Q2xzc01vZGFsIHRpdGxlPVwiQXNzZXNzbWVudHMgY3JlYXRlZCB3aXRoIHRoaXMgdGVtcGxhdGVcIiAgXHJcbiAgICAgICAgdG9nZ2xlVmlzaWJpbGl0eT17dG9nZ2xlfSBcclxuICAgICAgICB2aXNpYmxlPXtpc1Zpc2libGV9XHJcbiAgICAgICAgaGlkZUZvb3Rlcj17dHJ1ZX0+XHJcbiAgICAgICAgPGRpdj5cclxuICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgICAgLmFzc2Vzc21lbnQtbGlzdCB0cjpudGgtY2hpbGQoMm4rMil7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGJhY2tncm91bmQ6I2VmZWZlZjtcclxuICAgICAgICAgICAgICAgICAgICAgfSAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgLmFzc2Vzc21lbnQtbGlzdCB0ZHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgIGxpbmUtaGVpZ2h0OiA1MHB4O1xyXG4gICAgICAgICAgICAgICAgICAgICB9ICAgICBcclxuICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgICA8dGFibGUgY2xhc3NOYW1lPVwiYXNzZXNzbWVudC1saXN0XCIgc3R5bGU9e3t3aWR0aDogJzEwMCUnfX0+ICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYXNzZXNzbWVudHM/Lm1hcCgoYSwgaSkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRyPjx0ZD57aSsxK1wiKSBcIn17YS5uYW1lfTxzcGFuIHN0eWxlPXt7Y29sb3I6ICdncmF5JywgbWFyZ2luTGVmdDogJy4yZW0nfX0+eyBcIiAgIChcIithLmRhdGUrXCIpXCJ9PC9zcGFuPjwvdGQ+PC90cj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgPC90YWJsZT4gXHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgPC9DbHNzTW9kYWw+XHJcbiAgICAgICBcclxuICAgIClcclxufSIsImltcG9ydCB7IERyb3Bkb3duLCBEcm9wZG93bkJ1dHRvbiwgRHJvcGRvd25NZW51LCBMYWJlbCB9IGZyb20gXCJqaW11LXVpXCI7XHJcbmltcG9ydCB7IFRyYXNoT3V0bGluZWQgfSBmcm9tICdqaW11LWljb25zL291dGxpbmVkL2VkaXRvci90cmFzaCc7XHJcbmltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5cclxuZXhwb3J0IGNvbnN0IENsc3NEcm9wZG93biA9ICh7aXRlbXMsIGl0ZW0sIGRlbGV0YWJsZSwgc2V0SXRlbSwgZGVsZXRlSXRlbSwgbWVudVdpZHRofTpcclxuICAgIHtpdGVtczogYW55W10sIGl0ZW06IGFueSwgZGVsZXRhYmxlOiBib29sZWFuLCBzZXRJdGVtOiBGdW5jdGlvbiwgXHJcbiAgICAgIGRlbGV0ZUl0ZW0/OiBGdW5jdGlvbiwgbWVudVdpZHRoPzogc3RyaW5nfSk9PiB7XHJcblxyXG4gICAgY29uc3QgYnV0dG9uRWxlbWVudCA9IFJlYWN0LnVzZVJlZjxIVE1MRWxlbWVudD4oKTtcclxuICAgIFxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpID0+e1xyXG4gICAgICAgaWYoaXRlbXMgJiYgaXRlbXMubGVuZ3RoID4gMCl7XHJcbiAgICAgICAgICBpZighaXRlbSl7XHJcbiAgICAgICAgICAgIHNldEl0ZW0oaXRlbXNbMF0pIFxyXG4gICAgICAgICAgfWVsc2V7XHJcbiAgICAgICAgICAgIHNldEl0ZW0oaXRlbSk7XHJcbiAgICAgICAgICB9ICAgICAgXHJcbiAgICAgICB9XHJcbiAgICB9LCBbaXRlbXNdKVxyXG5cclxuICAgIGNvbnN0IGl0ZW1DbGljayA9IChpdGVtKT0+eyAgICAgXHJcbiAgICAgICAgc2V0SXRlbShpdGVtKTsgICAgICAgIFxyXG4gICAgICAgIGlmKGJ1dHRvbkVsZW1lbnQgJiYgYnV0dG9uRWxlbWVudC5jdXJyZW50KXtcclxuICAgICAgICAgICAgYnV0dG9uRWxlbWVudC5jdXJyZW50LmNsaWNrKCk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHJlbW92ZUl0ZW0gPShpdGVtKSA9PntcclxuICAgICAgICBpZihjb25maXJtKCdSZW1vdmUgJysoaXRlbS50aXRsZSB8fCBpdGVtLm5hbWUpKSl7XHJcbiAgICAgICAgICAgIGRlbGV0ZUl0ZW0oaXRlbSk7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJjbHNzLWRyb3Bkb3duLWNvbnRhaW5lclwiIHN0eWxlPXt7d2lkdGg6ICcxMDAlJ319PlxyXG4gICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAuZHJvcGRvd24taXRlbS1jb250YWluZXJ7XHJcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA0NXB4O1xyXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlci1ib3R0b206IDFweCBzb2xpZCByZ2IoMjI3LCAyMjcsIDIyNyk7XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZHJvcGRvd24taXRlbS1jb250YWluZXI6aG92ZXJ7XHJcbiAgICAgICAgICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogcmdiKDIyNywgMjI3LCAyMjcpO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5qaW11LWRyb3Bkb3duLW1lbnV7XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDM1JTtcclxuICAgICAgICAgICAgICAgICAgICBtYXgtaGVpZ2h0OiA1MDBweDtcclxuICAgICAgICAgICAgICAgICAgICBvdmVyZmxvdzogYXV0bztcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuamltdS1kcm9wZG93bi1tZW51IC5kcm9wZG93bi1pdGVtLWNvbnRhaW5lcjpsYXN0LWNoaWxke1xyXG4gICAgICAgICAgICAgICAgICAgIGJvcmRlci1ib3R0b206IG5vbmU7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLm1vZGFsLWNvbnRlbnQgLmNsc3MtZHJvcGRvd24tY29udGFpbmVyIGJ1dHRvbntcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuY2xzcy1kcm9wZG93bi1jb250YWluZXIgLmppbXUtZHJvcGRvd257XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmNsb3NlLWJ1dHRvbntcclxuICAgICAgICAgICAgICAgICAgICBtYXJnaW46IDEwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6IGdyYXk7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgIC5tb2RhbC1jb250ZW50IC5jbHNzLWRyb3Bkb3duLWNvbnRhaW5lciBidXR0b24gc3BhbntcclxuICAgICAgICAgICAgICAgICAgICAgbGluZS1oZWlnaHQ6IDMwcHggIWltcG9ydGFudDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAuZHJvcGRvd24taXRlbS1jb250YWluZXIgbGFiZWx7XHJcbiAgICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiAxMDAlO1xyXG4gICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDEuMmVtO1xyXG4gICAgICAgICAgICAgICAgICAgIG1hcmdpbi1sZWZ0OiAxZW07XHJcbiAgICAgICAgICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3N0eWxlPlxyXG4gICAgICAgICAgICA8RHJvcGRvd24gIGFjdGl2ZUljb249XCJ0cnVlXCIgc2l6ZT1cImxnXCI+XHJcbiAgICAgICAgICAgICAgICA8RHJvcGRvd25CdXR0b24gY2xhc3NOYW1lPVwiZHJvcGRvd25CdXR0b25cIiByZWY9e2J1dHRvbkVsZW1lbnR9ICBzaXplPVwibGdcIiBzdHlsZT17e3RleHRBbGlnbjogJ2xlZnQnfX0+XHJcbiAgICAgICAgICAgICAgICAgICAge2l0ZW0/LnRpdGxlIHx8IGl0ZW0/Lm5hbWV9XHJcbiAgICAgICAgICAgICAgICA8L0Ryb3Bkb3duQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgPERyb3Bkb3duTWVudSBzdHlsZT17e3dpZHRoOiBtZW51V2lkdGggfHwgXCIzMCVcIn19PlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGl0ZW1zPy5tYXAoKGl0ZW0sIGlkeCkgPT4ge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBpZD17aXRlbT8ubmFtZSB8fCBpdGVtPy50aXRsZX0gY2xhc3NOYW1lPVwiZHJvcGRvd24taXRlbS1jb250YWluZXJcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2hlY2sgb25DbGljaz17KCkgPT4gaXRlbUNsaWNrKGl0ZW0pfT57aXRlbT8udGl0bGUgfHwgaXRlbT8ubmFtZX08L0xhYmVsPiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICgoaXRlbT8udGl0bGUgfHwgaXRlbT8ubmFtZSkgIT09ICctTm9uZS0nKSAmJiBkZWxldGFibGUgPyBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKDxUcmFzaE91dGxpbmVkIHRpdGxlPSdSZW1vdmUnIGNsYXNzTmFtZT1cImNsb3NlLWJ1dHRvblwiIHNpemU9ezIwfSBvbkNsaWNrPXsoKSA9PiByZW1vdmVJdGVtKGl0ZW0pfS8+KVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA6IG51bGxcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4gIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIDwvRHJvcGRvd25NZW51PlxyXG4gICAgICAgICAgICA8L0Ryb3Bkb3duPlxyXG4gICAgICAgIDwvZGl2PlxyXG4gICAgKVxyXG59IiwiaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiO1xyXG5cclxuY29uc3QgQ2xzc0Vycm9yID0gKHtlcnJvcn0pID0+IHtcclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPGgyIHN0eWxlPXt7Y29sb3I6ICdyZWQnLCBmb250U2l6ZTogJzE1cHgnfX0+e2Vycm9yfTwvaDI+XHJcbiAgICApXHJcbn1cclxuZXhwb3J0IGRlZmF1bHQgQ2xzc0Vycm9yOyIsImltcG9ydCB7IFJlYWN0IH0gZnJvbSAnamltdS1jb3JlJ1xyXG5pbXBvcnQge0J1dHRvbiwgTGFiZWx9IGZyb20gJ2ppbXUtdWknO1xyXG5pbXBvcnQgeyBDbG9zZUNpcmNsZUZpbGxlZCB9IGZyb20gJ2ppbXUtaWNvbnMvZmlsbGVkL2VkaXRvci9jbG9zZS1jaXJjbGUnXHJcbi8vY29uc3QgdXNlXHJcblxyXG5jb25zdCBDbHNzRXJyb3JzUGFuZWwgPSAoe2Nsb3NlLCBlcnJvcnN9KSA9PiB7ICBcclxuICByZXR1cm4gKCBcclxuICAgIDxkaXYgY2xhc3NOYW1lPSdqaW11LXdpZGdldCB3aWRnZXQtZXJyb3ItY29udGFpbmVyJz5cclxuICAgICAgIDxzdHlsZT5cclxuICAgICAgICB7YFxyXG4gICAgICAgICAgLndpZGdldC1lcnJvci1jb250YWluZXJ7XHJcbiAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgIGp1c3RpZnktY29udGVudDogY2VudGVyO1xyXG4gICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiAjZmZjNmNkO1xyXG4gICAgICAgICAgICBib3JkZXI6IDFweCBzb2xpZCByZWQ7XHJcbiAgICAgICAgICAgIGJveC1zaGFkb3c6IDFweCAxcHggMTJweCA0cHggIzVkNWM1YztcclxuICAgICAgICAgICAgcGFkZGluZzogMTBweCAyMHB4O1xyXG4gICAgICAgICAgICBib3JkZXItcmFkaXVzOiAwIDEwcHggMCAwO1xyXG4gICAgICAgICAgfSAgICAgXHJcbiAgICAgICAgICAuY2xvc2UtYnV0dG9ue1xyXG4gICAgICAgICAgICAgcG9zaXRpb246IGFic29sdXRlO1xyXG4gICAgICAgICAgICAgdG9wOiAwO1xyXG4gICAgICAgICAgICAgcmlnaHQ6IDA7XHJcbiAgICAgICAgICAgICBjb2xvcjogcmVkO1xyXG4gICAgICAgICAgICAgY3Vyc29yOiBwb2ludGVyO1xyXG4gICAgICAgICAgfSAgICAgXHJcbiAgICAgICAgYH1cclxuICAgICAgPC9zdHlsZT5cclxuICAgICAgPENsb3NlQ2lyY2xlRmlsbGVkIGNsYXNzTmFtZT0nY2xvc2UtYnV0dG9uJyBkYXRhLXRlc3RpZD1cImJ0bkNsb3NlRXJyb3JcIiBzaXplPXszMH1cclxuICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKSA9PiBjbG9zZSgpfSBzdHlsZT17e2NvbG9yOiAncmVkJ319IHRpdGxlPSdDbG9zZScvPlxyXG4gICAgPExhYmVsIHN0eWxlPXt7Y29sb3I6ICcjYTUwMDAwJywgXHJcbiAgICAgICAgZm9udFNpemU6ICcyMHB4J319IGNoZWNrIHNpemU9J2xnJz57ZXJyb3JzfTwvTGFiZWw+XHJcbiAgICAgPC9kaXY+XHJcbiAgKVxyXG59XHJcblxyXG5leHBvcnQgZGVmYXVsdCBDbHNzRXJyb3JzUGFuZWw7XHJcblxyXG4iLCJpbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4vY2xzcy1kcm9wZG93blwiXHJcbmltcG9ydCB7IEhhemFyZCB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnNcIlxyXG5pbXBvcnQgeyBCdXR0b24gfSBmcm9tIFwiamltdS11aVwiO1xyXG5pbXBvcnQgeyBQbHVzQ2lyY2xlT3V0bGluZWQgfSBmcm9tIFwiamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvcGx1cy1jaXJjbGVcIjtcclxuaW1wb3J0IHsgZGVsZXRlSGF6YXJkLCBkaXNwYXRjaEFjdGlvbiB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaVwiO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmVcIjtcclxuXHJcblxyXG5leHBvcnQgY29uc3QgSGF6YXJkc0Ryb3Bkb3duID0oe2NvbmZpZywgaGF6YXJkcywgc2VsZWN0ZWRIYXphcmQsIHNldEhhemFyZCwgdmVydGljYWwsIHRvZ2dsZU5ld0hhemFyZE1vZGFsfSk9PntcclxuXHJcbiAgICBjb25zdCBbbG9jYWxIYXphcmRzLCBzZXRMb2NhbEhhemFyZHNdID0gUmVhY3QudXNlU3RhdGU8SGF6YXJkW10+KFtdKTtcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgICBpZihoYXphcmRzKXsgICAgICAgICAgICBcclxuICAgICAgICAgICAgc2V0TG9jYWxIYXphcmRzKFsuLi5oYXphcmRzXSBhcyBIYXphcmRbXSlcclxuICAgICAgICB9XHJcbiAgICB9LCBbaGF6YXJkc10pXHJcblxyXG4gICAgY29uc3QgcmVtb3ZlSGF6YXJkID1hc3luYyAoaGF6YXJkOiBIYXphcmQpPT57ICAgICAgIFxyXG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlSGF6YXJkKGhhemFyZCwgY29uZmlnKTtcclxuICAgICAgIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICAgICAgY29uc29sZS5sb2cocmVzcG9uc2UuZXJyb3JzKTtcclxuICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCByZXNwb25zZS5lcnJvcnMpO1xyXG4gICAgICAgIHJldHVybjtcclxuICAgICAgIH1cclxuICAgICAgIGNvbnNvbGUubG9nKGAke2hhemFyZC50aXRsZX0gZGVsZXRlZGApO1xyXG4gICAgICAgc2V0TG9jYWxIYXphcmRzKFsuLi5sb2NhbEhhemFyZHMuZmlsdGVyKGggPT4gaC5pZCAhPT0gaGF6YXJkLmlkKV0pO1xyXG4gICAgfVxyXG4gICAgXHJcbiAgICByZXR1cm4gKFxyXG4gICAgICAgIDxkaXYgc3R5bGU9e3tkaXNwbGF5OiB2ZXJ0aWNhbCA/ICdibG9jayc6ICdmbGV4JyxcclxuICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcid9fT5cclxuICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgICAgLmFjdGlvbi1pY29uIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgY29sb3I6IGdyYXk7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgIDxDbHNzRHJvcGRvd24gaXRlbXM9e2xvY2FsSGF6YXJkc31cclxuICAgICAgICAgICAgICAgIGl0ZW09e3NlbGVjdGVkSGF6YXJkfSBcclxuICAgICAgICAgICAgICAgIGRlbGV0YWJsZT17dHJ1ZX1cclxuICAgICAgICAgICAgICAgIHNldEl0ZW09e3NldEhhemFyZH0gXHJcbiAgICAgICAgICAgICAgICBkZWxldGVJdGVtPXtyZW1vdmVIYXphcmR9Lz4gXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgdmVydGljYWw/IChcclxuICAgICAgICAgICAgICAgIDxCdXR0b24gZGF0YS10ZXN0aWQ9XCJidG5TaG93QWRkT3JnYW5pemF0aW9uXCIgIGNsYXNzTmFtZT1cIiBhZGQtbGlua1wiXHJcbiAgICAgICAgICAgICAgICAgICAgIHR5cGU9XCJsaW5rXCIgc3R5bGU9e3t0ZXh0QWxpZ246ICdsZWZ0J319XHJcbiAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCk9PiB0b2dnbGVOZXdIYXphcmRNb2RhbCh0cnVlKX0+XHJcbiAgICAgICAgICAgICAgICAgICAgQWRkIE5ldyBIYXphcmRcclxuICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICApOihcclxuICAgICAgICAgICAgICAgIDxQbHVzQ2lyY2xlT3V0bGluZWQgY2xhc3NOYW1lPVwiYWN0aW9uLWljb25cIiBcclxuICAgICAgICAgICAgICAgICAgICBkYXRhLXRlc3RpZD1cImJ0bkFkZE5ld0hhemFyZFwiIFxyXG4gICAgICAgICAgICAgICAgICAgIHRpdGxlPVwiQWRkIE5ldyBIYXphcmRcIiBzaXplPXszMH0gY29sb3I9eydncmF5J31cclxuICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKT0+IHRvZ2dsZU5ld0hhemFyZE1vZGFsKHRydWUpfS8+IFxyXG4gICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICB9ICAgXHJcbiAgICAgICAgICAgIHsvKiA8cD57c2VsZWN0ZWRIYXphcmQ/LmRlc2NyaXB0aW9ufTwvcD4gKi99XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgeyBCdXR0b24sIEljb24sIExhYmVsLCBOdW1lcmljSW5wdXQsIFRleHRJbnB1dCB9IGZyb20gXCJqaW11LXVpXCJcclxuaW1wb3J0IFJlYWN0IGZyb20gXCJyZWFjdFwiO1xyXG5pbXBvcnQgeyBUcmFzaE91dGxpbmVkIH0gZnJvbSAnamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvdHJhc2gnO1xyXG5pbXBvcnQgeyBFZGl0RmlsbGVkIH0gZnJvbSAnamltdS1pY29ucy9maWxsZWQvZWRpdG9yL2VkaXQnO1xyXG5pbXBvcnQgeyBIZWxwRmlsbGVkIH0gZnJvbSAnamltdS1pY29ucy9maWxsZWQvc3VnZ2VzdGVkL2hlbHAnXHJcbmltcG9ydCB7IENsb3NlT3V0bGluZWQgfSBmcm9tICdqaW11LWljb25zL291dGxpbmVkL2VkaXRvci9jbG9zZSc7XHJcbmltcG9ydCBDbHNzTG9hZGluZyBmcm9tIFwiLi9jbHNzLWxvYWRpbmdcIjtcclxuaW1wb3J0IHsgQ2hlY2tGaWxsZWQgfSBmcm9tICdqaW11LWljb25zL2ZpbGxlZC9hcHBsaWNhdGlvbi9jaGVjayc7XHJcbmltcG9ydCB7IENMU1NUZW1wbGF0ZSwgQ2xzc1VzZXIsIENvbXBvbmVudFRlbXBsYXRlLCBJbmRpY2F0b3JUZW1wbGF0ZSwgSW5kaWNhdG9yV2VpZ2h0LCBMaWZlTGluZVRlbXBsYXRlIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9uc1wiO1xyXG5pbXBvcnQgeyBSQU5LLCBMSUZFX1NBRkVUWSwgSU5DSURFTlRfU1RBQklMSVpBVElPTiwgUFJPUEVSVFlfUFJPVEVDVElPTiwgXHJcbiAgICBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04sIFxyXG4gICAgQkFTRUxJTkVfVEVNUExBVEVfTkFNRSxcclxuICAgIENMU1NfQURNSU4sXHJcbiAgICBDTFNTX0VESVRPUixcclxuICAgIERFTEVURV9JTkRJQ0FUT1JfQ09ORklSTUFUSU9OLFxyXG4gICAgT1RIRVJfV0VJR0hUU19TQ0FMRV9GQUNUT1IsXHJcbiAgICBMSUZFX1NBRkVUWV9TQ0FMRV9GQUNUT1IsXHJcbiAgICBDTFNTX0ZPTExPV0VSU30gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY29uc3RhbnRzXCI7XHJcbmltcG9ydCBDbHNzRXJyb3IgZnJvbSBcIi4vY2xzcy1lcnJvclwiO1xyXG5pbXBvcnQgeyBSZWFjdFJlZHV4IH0gZnJvbSBcImppbXUtY29yZVwiO1xyXG5pbXBvcnQgeyBjcmVhdGVOZXdJbmRpY2F0b3IsIGRlbGV0ZUluZGljYXRvciwgZGlzcGF0Y2hBY3Rpb24sIHVwZGF0ZUluZGljYXRvciB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaVwiO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmVcIjtcclxuY29uc3QgeyB1c2VTZWxlY3RvciB9ID0gUmVhY3RSZWR1eDtcclxuXHJcbmNvbnN0IFRhYmxlUm93Q29tbWFuZD0oe2lzSW5FZGl0TW9kZSwgb25FZGl0LCBvbkRlbGV0ZSwgb25TYXZlLCBvbkNhbmNlbCwgY2FuU2F2ZX06IFxyXG4gICAge2lzSW5FZGl0TW9kZTogYm9vbGVhbiwgXHJcbiAgICAgICAgb25FZGl0OiBGdW5jdGlvbiwgb25EZWxldGU6IEZ1bmN0aW9uLCBvblNhdmU6IEZ1bmN0aW9uLCBcclxuICAgICAgICBvbkNhbmNlbDogRnVuY3Rpb24sIGNhblNhdmU6IGJvb2xlYW59KT0+e1xyXG5cclxuICAgIHJldHVybihcclxuICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiPlxyXG4gICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImNvbW1hbmQtY29udGFpbmVyXCI+XHJcbiAgICAgICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jb21tYW5kLWNvbnRhaW5lcntcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jb21tYW5ke1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZmxleDogMVxyXG4gICAgICAgICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5lZGl0LWRlbGV0ZSwgLnNhdmUtY2FuY2Vse1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmbGV4LXdyYXA6IG5vd3JhcDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgPC9zdHlsZT5cclxuICAgICAgICAgICAgICAgIHsgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgIGlzSW5FZGl0TW9kZSA/XHJcbiAgICAgICAgICAgICAgICAgICAgKFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImVkaXQtZGVsZXRlXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8Q2hlY2tGaWxsZWQgc3R5bGU9e3twb2ludGVyRXZlbnRzOiAhY2FuU2F2ZSA/ICdub25lJyA6ICdhbGwnfX0gc2l6ZT17MjB9IGNsYXNzTmFtZT1cImNvbW1hbmRcIiB0aXRsZT1cIlNhdmUgRWRpdHNcIiBvbkNsaWNrPXsoKSA9PiBvblNhdmUoKX0vPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPENsb3NlT3V0bGluZWQgc2l6ZT17MjB9IGNsYXNzTmFtZT1cImNvbW1hbmRcIiB0aXRsZT1cIkNhbmNlbCBFZGl0c1wiIG9uQ2xpY2s9eygpID0+IG9uQ2FuY2VsKCl9Lz5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgICAgIDogKFxyXG4gICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiZWRpdC1kZWxldGVcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPEVkaXRGaWxsZWQgc2l6ZT17MjB9IGNsYXNzTmFtZT1cImNvbW1hbmRcIiB0aXRsZT1cIkVkaXRcIiBvbkNsaWNrPXsoKSA9PiBvbkVkaXQoKX0vPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8VHJhc2hPdXRsaW5lZCBzaXplPXsyMH0gY2xhc3NOYW1lPVwiY29tbWFuZFwiIHRpdGxlPVwiRGVsZXRlXCIgb25DbGljaz17KCkgPT4gb25EZWxldGUoKX0vPlxyXG4gICAgICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICAgIH0gICBcclxuICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICA8L3RkPiAgICAgICBcclxuICAgIClcclxufVxyXG5cclxuY29uc3QgRWRpdGFibGVUYWJsZVJvdz0oe2luZGljYXRvciwgaXNFZGl0YWJsZSwgY29tcG9uZW50LCBcclxuICAgIHRlbXBsYXRlLCBjb25maWcsIHNldEVycm9yLCBvbkFjdGlvbkNvbXBsZXRlLCBvbkNhbmNlbH06e1xyXG4gICAgaW5kaWNhdG9yOiBJbmRpY2F0b3JUZW1wbGF0ZSwgaXNFZGl0YWJsZTogYm9vbGVhbiwgXHJcbiAgICBjb21wb25lbnQ6IENvbXBvbmVudFRlbXBsYXRlLCB0ZW1wbGF0ZTogQ0xTU1RlbXBsYXRlLCBcclxuICAgIGNvbmZpZzogYW55LCBzZXRFcnJvcjogRnVuY3Rpb24sIG9uQWN0aW9uQ29tcGxldGU6IEZ1bmN0aW9uLCBvbkNhbmNlbDogRnVuY3Rpb259KT0+IHtcclxuXHJcbiAgICBjb25zdCBbaXNFZGl0aW5nLCBzZXRFZGl0aW5nXSA9IFJlYWN0LnVzZVN0YXRlKGluZGljYXRvci5pc0JlaW5nRWRpdGVkKTtcclxuICAgIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICAgIGNvbnN0IFtuYW1lLCBzZXROYW1lXSA9IFJlYWN0LnVzZVN0YXRlKCcnKVxyXG4gICAgY29uc3QgW3JhbmssIHNldFJhbmtdID0gUmVhY3QudXNlU3RhdGU8bnVtYmVyPigpOyAgICBcclxuICAgIGNvbnN0IFtsaWZlU2FmZXR5LCBzZXRMaWZlU2FmZXR5XSA9IFJlYWN0LnVzZVN0YXRlPG51bWJlcj4oKTtcclxuICAgIGNvbnN0IFtpbmNpZGVudFN0YWIsIHNldEluY2lkZW50U3RhYl0gPSBSZWFjdC51c2VTdGF0ZTxudW1iZXI+KCk7XHJcbiAgICBjb25zdCBbcHJvcGVydHlQcm90LCBzZXRQcm9wUHJvdF0gPSBSZWFjdC51c2VTdGF0ZTxudW1iZXI+KCk7XHJcbiAgICBjb25zdCBbZW52UHJlcywgc2V0RW52UHJlc10gPSBSZWFjdC51c2VTdGF0ZTxudW1iZXI+KCk7IFxyXG4gICAgY29uc3QgW2NhbkNvbW1pdCwgc2V0Q2FuQ29tbWl0XSA9IFJlYWN0LnVzZVN0YXRlKHRydWUpO1xyXG4gICAgICBcclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgaWYoaW5kaWNhdG9yKXtcclxuICAgICAgICAgICAgdHJ5e1xyXG4gICAgICAgICAgICAgICAgc2V0TmFtZShpbmRpY2F0b3I/Lm5hbWUpO1xyXG4gICAgICAgICAgICAgICAgc2V0UmFuayhpbmRpY2F0b3I/LndlaWdodHM/LmZpbmQodyA9PiB3Lm5hbWUgPT09IFJBTkspLndlaWdodCk7XHJcbiAgICAgICAgICAgICAgICBzZXRMaWZlU2FmZXR5KGluZGljYXRvcj8ud2VpZ2h0cz8uZmluZCh3ID0+IHcubmFtZSA9PT0gTElGRV9TQUZFVFkpLndlaWdodClcclxuICAgICAgICAgICAgICAgIHNldEluY2lkZW50U3RhYihpbmRpY2F0b3I/LndlaWdodHM/LmZpbmQodyA9PiB3Lm5hbWUgPT09IElOQ0lERU5UX1NUQUJJTElaQVRJT04pLndlaWdodClcclxuICAgICAgICAgICAgICAgIHNldFByb3BQcm90KGluZGljYXRvcj8ud2VpZ2h0cz8uZmluZCh3ID0+IHcubmFtZSA9PT0gUFJPUEVSVFlfUFJPVEVDVElPTikud2VpZ2h0KVxyXG4gICAgICAgICAgICAgICAgc2V0RW52UHJlcyhpbmRpY2F0b3I/LndlaWdodHM/LmZpbmQodyA9PiB3Lm5hbWUgPT09IEVOVklST05NRU5UX1BSRVNFUlZBVElPTikud2VpZ2h0KVxyXG4gICAgICAgICAgICB9Y2F0Y2goZSl7XHJcbiAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH0sIFtpbmRpY2F0b3JdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICAgIHNldENhbkNvbW1pdCh0cnVlKTtcclxuICAgICAgICBzZXRFcnJvcignJylcclxuICAgICAgICBpZihuYW1lKXtcclxuICAgICAgICAgICAgY29uc3QgaW5kaWNhdG9yc05hbWVzID0gY29tcG9uZW50LmluZGljYXRvcnMubWFwKGkgPT4gaS5uYW1lLnRvTG9jYWxlTG93ZXJDYXNlKCkpO1xyXG4gICAgICAgICAgICBpZihpbmRpY2F0b3IuaXNOZXcgJiYgaW5kaWNhdG9yc05hbWVzLmluY2x1ZGVzKG5hbWUudG9Mb2NhbGVMb3dlckNhc2UoKSkpe1xyXG4gICAgICAgICAgICAgICBzZXRFcnJvcihgSW5kaWNhdG9yOiAke25hbWV9IGFscmVhZHkgZXhpc3RzYCk7XHJcbiAgICAgICAgICAgICAgIHNldENhbkNvbW1pdChmYWxzZSk7XHJcbiAgICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgIH1cclxuICAgIH0sIFtuYW1lXSlcclxuXHJcbiAgICBjb25zdCBnZXRXZWlnaHRCeU5hbWU9KHc6IEluZGljYXRvcldlaWdodCk9PntcclxuICAgICAgICBzd2l0Y2gody5uYW1lKXtcclxuICAgICAgICAgICAgY2FzZSBSQU5LOlxyXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJhbms7XHJcbiAgICAgICAgICAgIGNhc2UgTElGRV9TQUZFVFk6XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gbGlmZVNhZmV0eVxyXG4gICAgICAgICAgICBjYXNlIElOQ0lERU5UX1NUQUJJTElaQVRJT046XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gaW5jaWRlbnRTdGFiO1xyXG4gICAgICAgICAgICBjYXNlIFBST1BFUlRZX1BST1RFQ1RJT046XHJcbiAgICAgICAgICAgICAgICByZXR1cm4gcHJvcGVydHlQcm90O1xyXG4gICAgICAgICAgICBjYXNlIEVOVklST05NRU5UX1BSRVNFUlZBVElPTjpcclxuICAgICAgICAgICAgICAgIHJldHVybiBlbnZQcmVzO1xyXG4gICAgICAgIH1cclxuICAgIH1cclxuICAgIFxyXG4gICAgY29uc3Qgb25TYXZlRWRpdHM9YXN5bmMgKCk9PntcclxuICAgICAgICBzZXRMb2FkaW5nKHRydWUpO1xyXG4gICAgICAgIGNvbnN0IHVwZGF0ZWRJbmRpY2F0b3IgPSB7XHJcbiAgICAgICAgICAgIC4uLmluZGljYXRvcixcclxuICAgICAgICAgICAgbmFtZTogbmFtZSxcclxuICAgICAgICAgICAgdGl0bGU6IG5hbWUsXHJcbiAgICAgICAgICAgIHdlaWdodHM6IGluZGljYXRvcj8ud2VpZ2h0cy5tYXAodyA9PiB7XHJcbiAgICAgICAgICAgICAgICByZXR1cm57XHJcbiAgICAgICAgICAgICAgICAgICAgLi4udyxcclxuICAgICAgICAgICAgICAgICAgICB3ZWlnaHQ6IGdldFdlaWdodEJ5TmFtZSh3KVxyXG4gICAgICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgfSlcclxuICAgICAgICB9XHJcbiAgICAgICBpZihpbmRpY2F0b3IuaXNOZXcpeyBcclxuICAgICAgICAgIGNvbnN0IHJlc3AgPSBhd2FpdCBjcmVhdGVOZXdJbmRpY2F0b3IodXBkYXRlZEluZGljYXRvciwgXHJcbiAgICAgICAgICAgIGNvbmZpZywgdGVtcGxhdGUuaWQsIHRlbXBsYXRlLm5hbWUpO1xyXG4gICAgICAgICAgaWYocmVzcC5lcnJvcnMpe1xyXG4gICAgICAgICAgICBzZXRMb2FkaW5nKGZhbHNlKVxyXG4gICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCByZXNwLmVycm9ycyk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgIH1cclxuICAgICAgIH1lbHNleyAgICAgICBcclxuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCB1cGRhdGVJbmRpY2F0b3IodXBkYXRlZEluZGljYXRvciwgY29uZmlnKTtcclxuICAgICAgICAgICAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgICAgICAgICAgICAgIHNldExvYWRpbmcoZmFsc2UpXHJcbiAgICAgICAgICAgICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5TRVRfRVJST1JTLCByZXNwb25zZS5lcnJvcnMpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHNldEVkaXRpbmcoZmFsc2UpO1xyXG4gICAgICAgIHNldExvYWRpbmcoZmFsc2UpO1xyXG4gICAgICAgIG9uQWN0aW9uQ29tcGxldGUodHJ1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3Qgb25DYW5jZWxFZGl0cz0oKT0+eyAgICBcclxuICAgICAgICAgc2V0RXJyb3IoJycpO1xyXG4gICAgICAgICBzZXRDYW5Db21taXQodHJ1ZSk7ICAgXHJcbiAgICAgICAgIHNldEVkaXRpbmcoZmFsc2UpXHJcbiAgICAgICAgIG9uQWN0aW9uQ29tcGxldGUoZmFsc2UpO1xyXG4gICAgICAgICBpZihpbmRpY2F0b3IuaXNOZXcpe1xyXG4gICAgICAgICAgICBvbkNhbmNlbCgpXHJcbiAgICAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBvbkRlbGV0ZUluZGljYXRvcj1hc3luYyAoKT0+e1xyXG5cclxuICAgICAgICBpZiAoY29uZmlybShERUxFVEVfSU5ESUNBVE9SX0NPTkZJUk1BVElPTikgPT0gdHJ1ZSkge1xyXG4gICAgICAgICAgICBcclxuICAgICAgICAgICAgc2V0TG9hZGluZyh0cnVlKTtcclxuXHJcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgZGVsZXRlSW5kaWNhdG9yKGluZGljYXRvciwgY29uZmlnKTtcclxuICAgICAgICAgICAgaWYocmVzcG9uc2UuZXJyb3JzKXtcclxuICAgICAgICAgICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIHJlc3BvbnNlLmVycm9ycyk7XHJcbiAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XHJcbiAgICAgICAgICAgIG9uQWN0aW9uQ29tcGxldGUodHJ1ZSk7ICAgICAgICAgICBcclxuICAgICAgICB9ICAgICAgICBcclxuICAgIH0gXHJcbiAgICBcclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPHRyIHN0eWxlPXt7cG9zaXRpb246ICdyZWxhdGl2ZSd9fT5cclxuICAgICAgICAgICAgPHN0eWxlPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgICAgICAubGlmZWxpbmUtY29tcG9uZW50LXRhYmxlIC5pbmRpY2F0b3ItbmFtZSBpbnB1dCB7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMTJweCAhaW1wb3J0YW50XHJcbiAgICAgICAgICAgICAgICAgICAgIH0gICBcclxuICAgICAgICAgICAgICAgICAgICAgLmppbXUtbnVtZXJpYy1pbnB1dCBpbnB1dHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgbWluLXdpZHRoOiAxNjBweDtcclxuICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC9zdHlsZT5cclxuICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGEgaW5kaWNhdG9yLW5hbWVcIiBzdHlsZT17e3RleHRBbGlnbjogJ2xlZnQnfX0+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgaXNFZGl0aW5nID8gXHJcbiAgICAgICAgICAgICAgICAgICAgKDxsYWJlbCBzdHlsZT17e3dpZHRoOiAnMTAwJSd9fT48VGV4dElucHV0IGNsYXNzTmFtZT1cImluZGljYXRvci1uYW1lXCIgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHRpdGxlPXtuYW1lfSB2YWx1ZT17bmFtZX0gb25DaGFuZ2U9eyhlKT0+IHNldE5hbWUoZS50YXJnZXQudmFsdWUpfSBcclxuICAgICAgICAgICAgICAgICAgICAgICAgYWxsb3dDbGVhciB0eXBlPVwidGV4dFwiLz48L2xhYmVsPik6XHJcbiAgICAgICAgICAgICAgICAgICAgbmFtZVxyXG4gICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICA8L3RkPlxyXG4gICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAgeyAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgIGlzRWRpdGluZyA/IFxyXG4gICAgICAgICAgICAgICAgICAgKDxsYWJlbD48TnVtZXJpY0lucHV0IFxyXG4gICAgICAgICAgICAgICAgICAgIG1heD17NX0gbWluPXsxfSBcclxuICAgICAgICAgICAgICAgICAgICBvbkNoYW5nZT17KHYpID0+IHNldFJhbmsodil9IHZhbHVlPXtyYW5rfVxyXG4gICAgICAgICAgICAgICAgICAgIC8+PC9sYWJlbD4pOnJhbmtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAnTi9BJ1xyXG4gICAgICAgICAgICAgICAgLy8gICAgIWlzRWRpdGluZyA/IChsaWZlU2FmZXR5Py52YWx1ZSk6ICg8bGFiZWw+PE51bWVyaWNJbnB1dCBvbkNoYW5nZT17b25MaWZlU2FmZXR5Q2hhbmdlfSB2YWx1ZT17bGlmZVNhZmV0eT8udmFsdWV9Lz48L2xhYmVsPilcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAnTi9BJ1xyXG4gICAgICAgICAgICAgICAgLy8gICAgIWlzRWRpdGluZyA/IChpbmNpZGVudFN0YWI/LnZhbHVlKTogKDxsYWJlbD48TnVtZXJpY0lucHV0IG9uQ2hhbmdlPXtvbkluY2lkZW50U3RhYmlsaXphdGlvbkNoYW5nZX0gdmFsdWU9e2luY2lkZW50U3RhYj8udmFsdWV9Lz48L2xhYmVsPilcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAnTi9BJ1xyXG4gICAgICAgICAgICAgICAgLy8gICAgIWlzRWRpdGluZyA/IChwcm9wZXJ0eVByb3Q/LnZhbHVlKTogKDxsYWJlbD48TnVtZXJpY0lucHV0IG9uQ2hhbmdlPXtvblByb3BlcnR5UHJvdGVjdGlvbkNoYW5nZX0gdmFsdWU9e3Byb3BlcnR5UHJvdD8udmFsdWV9Lz48L2xhYmVsPilcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAnTi9BJ1xyXG4gICAgICAgICAgICAgICAgLy8gICAgIWlzRWRpdGluZyA/IChlbnZQcmVzPy52YWx1ZSk6ICg8bGFiZWw+PE51bWVyaWNJbnB1dCBvbkNoYW5nZT17b25FbnZpcm9ubWVudGFsUHJlc2VydmF0aW9uQ2hhbmdlfSB2YWx1ZT17ZW52UHJlcz8udmFsdWV9Lz48L2xhYmVsPilcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICBpc0VkaXRhYmxlPyBcclxuICAgICAgICAgICAgICAgIChcclxuICAgICAgICAgICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8VGFibGVSb3dDb21tYW5kXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpc0luRWRpdE1vZGU9e2lzRWRpdGluZ30gXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjYW5TYXZlPXtjYW5Db21taXR9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkVkaXQ9eygpID0+c2V0RWRpdGluZyh0cnVlKX0gIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgb25TYXZlPXtvblNhdmVFZGl0c30gXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNhbmNlbD17b25DYW5jZWxFZGl0c31cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uRGVsZXRlPXtvbkRlbGV0ZUluZGljYXRvcn0vPiAgXHJcbiAgICAgICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICAgICk6IG51bGxcclxuICAgICAgICAgICAgfSAgIFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgIGxvYWRpbmcgPyA8Q2xzc0xvYWRpbmcvPiA6IG51bGwgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIH0gICAgICBcclxuICAgICAgICA8L3RyPlxyXG4gICAgKVxyXG59XHJcblxyXG5leHBvcnQgY29uc3QgTGlmZWxpbmVDb21wb25lbnQgPSAoXHJcbiAgICB7bGlmZWxpbmUsIGNvbXBvbmVudCwgdGVtcGxhdGUsIGNvbmZpZywgb25BY3Rpb25Db21wbGV0ZX06XHJcbiAgICB7bGlmZWxpbmU6IExpZmVMaW5lVGVtcGxhdGUsIGNvbXBvbmVudDogQ29tcG9uZW50VGVtcGxhdGUsIHRlbXBsYXRlOiBDTFNTVGVtcGxhdGUsIFxyXG4gICAgICAgIGNvbmZpZzogYW55LCBvbkFjdGlvbkNvbXBsZXRlOiBGdW5jdGlvbn0pID0+IHtcclxuXHJcbiAgICBjb25zdCBbaW5kaWNhdG9ycywgc2V0SW5kaWNhdG9yc109IFJlYWN0LnVzZVN0YXRlPEluZGljYXRvclRlbXBsYXRlW10+KFtdKTtcclxuICAgIGNvbnN0IFtlcnJvciwgc2V0RXJyb3JdID0gUmVhY3QudXNlU3RhdGUoJycpICAgIFxyXG4gICAgY29uc3QgW2lzRWRpdGFibGUsIHNldEVkaXRhYmxlXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKVxyXG4gICAgICBcclxuICAgIGNvbnN0IHVzZXIgPSAgdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHsgICBcclxuICAgICAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy51c2VyIGFzIENsc3NVc2VyO1xyXG4gICAgfSk7IFxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgICAgaWYodXNlcil7IFxyXG4gICAgICAgICAgaWYodXNlcj8uZ3JvdXBzPy5pbmNsdWRlcyhDTFNTX0FETUlOKSl7XHJcbiAgICAgICAgICAgIHNldEVkaXRhYmxlKHRydWUpO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICB9XHJcbiAgICBcclxuICAgICAgICAgIGlmKHVzZXI/Lmdyb3Vwcz8uaW5jbHVkZXMoQ0xTU19FRElUT1IpICYmIFxyXG4gICAgICAgICAgICAgIHRlbXBsYXRlPy5uYW1lICE9PSBCQVNFTElORV9URU1QTEFURV9OQU1FKXtcclxuICAgICAgICAgICAgICAgIHNldEVkaXRhYmxlKHRydWUpO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBpZih1c2VyPy5ncm91cHM/LmluY2x1ZGVzKENMU1NfRk9MTE9XRVJTKSAmJiBcclxuICAgICAgICAgICAgICAgIHRlbXBsYXRlPy5uYW1lICE9PSBCQVNFTElORV9URU1QTEFURV9OQU1FKXtcclxuICAgICAgICAgICAgICAgIHNldEVkaXRhYmxlKHRydWUpO1xyXG4gICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICB9XHJcbiAgICAgICAgc2V0RWRpdGFibGUoZmFsc2UpOyAgICAgIFxyXG4gICAgICB9LCBbdGVtcGxhdGUsIHVzZXJdKVxyXG4gICBcclxuICAgIC8vIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7ICAgICAgICBcclxuICAgIC8vICAgICBpZih1c2VyICYmIHRlbXBsYXRlKXtcclxuXHJcbiAgICAvLyAgICAgICAgIGlmKCF0ZW1wbGF0ZS5pc0FjdGl2ZSl7XHJcbiAgICAvLyAgICAgICAgICAgIHNldEVkaXRhYmxlKGZhbHNlKTtcclxuICAgIC8vICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgLy8gICAgICAgICB9XHJcblxyXG4gICAgLy8gICAgICAgICBjb25zdCBpc1RlbXBsYXRlRWRpdGFibGUgPSBcclxuICAgIC8vICAgICAgICAgKHVzZXI/Lmdyb3Vwcz8uaW5jbHVkZXMoQ0xTU19BRE1JTikpIHx8IFxyXG4gICAgLy8gICAgICAgICAodGVtcGxhdGUubmFtZSAhPT0gQkFTRUxJTkVfVEVNUExBVEVfTkFNRSAmJiBcclxuICAgIC8vICAgICAgICAgICAgIHVzZXIuZ3JvdXBzPy5pbmNsdWRlcyhDTFNTX0VESVRPUikpO1xyXG4gICAgLy8gICAgICAgICBzZXRFZGl0YWJsZShpc1RlbXBsYXRlRWRpdGFibGUpO1xyXG4gICAgLy8gICAgIH1cclxuICAgIC8vIH0sIFt0ZW1wbGF0ZSwgdXNlcl0pXHJcbiAgICBcclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+IHsgXHJcbiAgICAgICAgc2V0SW5kaWNhdG9ycygoY29tcG9uZW50LmluZGljYXRvcnMgYXMgYW55KS5vcmRlckJ5KCduYW1lJykpXHJcbiAgICB9LFtjb21wb25lbnRdKTsgIFxyXG4gICAgICAgXHJcbiAgICBjb25zdCBjcmVhdGVOZXdJbmRpY2F0b3I9IGFzeW5jICgpPT57XHJcblxyXG4gICAgICAgIGNvbnN0IHdlaWdodHMgPSBbXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIG5hbWU6IFJBTkssXHJcbiAgICAgICAgICAgICAgICBhZGp1c3RlZFdlaWdodDogMCxcclxuICAgICAgICAgICAgICAgIGluZGljYXRvcklkOiAnJyxcclxuICAgICAgICAgICAgICAgIHNjYWxlRmFjdG9yOiBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUixcclxuICAgICAgICAgICAgICAgIHdlaWdodDogMSAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9IGFzIEluZGljYXRvcldlaWdodCxcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgbmFtZTogTElGRV9TQUZFVFksXHJcbiAgICAgICAgICAgICAgICBhZGp1c3RlZFdlaWdodDogMCxcclxuICAgICAgICAgICAgICAgIGluZGljYXRvcklkOiAnJyxcclxuICAgICAgICAgICAgICAgIHNjYWxlRmFjdG9yOiBMSUZFX1NBRkVUWV9TQ0FMRV9GQUNUT1IsXHJcbiAgICAgICAgICAgICAgICB3ZWlnaHQ6IDEgICAgICAgICAgICBcclxuICAgICAgICAgICAgfSBhcyBJbmRpY2F0b3JXZWlnaHQsXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIG5hbWU6IFBST1BFUlRZX1BST1RFQ1RJT04sXHJcbiAgICAgICAgICAgICAgICBhZGp1c3RlZFdlaWdodDogMCxcclxuICAgICAgICAgICAgICAgIGluZGljYXRvcklkOiAnJyxcclxuICAgICAgICAgICAgICAgIHNjYWxlRmFjdG9yOiBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUixcclxuICAgICAgICAgICAgICAgIHdlaWdodDogMSAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9IGFzIEluZGljYXRvcldlaWdodCxcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgbmFtZTogSU5DSURFTlRfU1RBQklMSVpBVElPTixcclxuICAgICAgICAgICAgICAgIGFkanVzdGVkV2VpZ2h0OiAwLFxyXG4gICAgICAgICAgICAgICAgaW5kaWNhdG9ySWQ6ICcnLFxyXG4gICAgICAgICAgICAgICAgc2NhbGVGYWN0b3I6IE9USEVSX1dFSUdIVFNfU0NBTEVfRkFDVE9SLFxyXG4gICAgICAgICAgICAgICAgd2VpZ2h0OiAxICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIH0gYXMgSW5kaWNhdG9yV2VpZ2h0LFxyXG4gICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICBuYW1lOiBFTlZJUk9OTUVOVF9QUkVTRVJWQVRJT04sXHJcbiAgICAgICAgICAgICAgICBhZGp1c3RlZFdlaWdodDogMCxcclxuICAgICAgICAgICAgICAgIGluZGljYXRvcklkOiAnJyxcclxuICAgICAgICAgICAgICAgIHNjYWxlRmFjdG9yOiBPVEhFUl9XRUlHSFRTX1NDQUxFX0ZBQ1RPUixcclxuICAgICAgICAgICAgICAgIHdlaWdodDogMSAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9IGFzIEluZGljYXRvcldlaWdodFxyXG4gICAgICAgIF1cclxuXHJcbiAgICAgICAgY29uc3QgZXhpc3RpbmdJbmRpY2F0b3JzID0gaW5kaWNhdG9ycyAgfHwgW10gYXMgSW5kaWNhdG9yVGVtcGxhdGVbXVxyXG5cclxuICAgICAgICBjb25zdCBuZXdJbmRpY2F0b3IgPSB7XHJcbiAgICAgICAgICAgIG5hbWU6ICcnLFxyXG4gICAgICAgICAgICBpc0JlaW5nRWRpdGVkOiB0cnVlLFxyXG4gICAgICAgICAgICBpc05ldzogdHJ1ZSxcclxuICAgICAgICAgICAgdGVtcGxhdGVOYW1lOiB0ZW1wbGF0ZS5uYW1lLFxyXG4gICAgICAgICAgICB3ZWlnaHRzOiB3ZWlnaHRzLCAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBjb21wb25lbnRJZDogY29tcG9uZW50LmlkLFxyXG4gICAgICAgICAgICB0ZW1wbGF0ZUlkOiB0ZW1wbGF0ZS5pZCxcclxuICAgICAgICAgICAgY29tcG9uZW50TmFtZTogY29tcG9uZW50Lm5hbWUsXHJcbiAgICAgICAgICAgIGxpZmVsaW5lTmFtZTogbGlmZWxpbmUubmFtZSxcclxuICAgICAgICB9IGFzIEluZGljYXRvclRlbXBsYXRlO1xyXG4gICAgICAgIFxyXG4gICAgICAgIHNldEluZGljYXRvcnMoWy4uLmV4aXN0aW5nSW5kaWNhdG9ycywgbmV3SW5kaWNhdG9yXSk7IFxyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IG9uQ2FuY2VsSW5kaWNhdG9yQ3JlYXRlID0oKT0+e1xyXG4gICAgICAgIHNldEluZGljYXRvcnMoaW5kaWNhdG9ycy5maWx0ZXIoaSA9PiAhaS5pc05ldykpOyAgICAgICAgIFxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiAoXHJcbiAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJsaWZlbGluZS1jb21wb25lbnQtY29udGFpbmVyXCJcclxuICAgICAgICAgIHN0eWxlPXt7XHJcbiAgICAgICAgICAgIG1hcmdpblRvcDogaXNFZGl0YWJsZSA/ICcwLjVlbScgOiAnMS44ZW0nXHJcbiAgICAgICAgICB9fT5cclxuICAgICAgICAgICAgPHN0eWxlPntcclxuICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAubGlmZWxpbmUtY29tcG9uZW50LWNvbnRhaW5lcntcclxuICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgZmxleC1kaXJlY3Rpb246IGNvbHVtbjtcclxuICAgICAgICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgICAgICAgIG1hcmdpbi1ib3R0b206IDAuNWVtO1xyXG4gICAgICAgICAgICAgICB9IFxyXG4gICAgICAgICAgICAgICAuY29tcG9uZW50LWxhYmVse1xyXG4gICAgICAgICAgICAgICAgZm9udC1zaXplOiAxOHB4O1xyXG4gICAgICAgICAgICAgICAgY29sb3I6ICM1MzRjNGM7XHJcbiAgICAgICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDtcclxuICAgICAgICAgICAgICAgIHBhZGRpbmc6IDAgMCAwIDEuMmVtO1xyXG4gICAgICAgICAgICAgICAgdGV4dC1kZWNvcmF0aW9uOiB1bmRlcmxpbmU7XHJcbiAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgLmNvbXBvbmVudC1kZXRhaWxze1xyXG4gICAgICAgICAgICAgICAgIGJhY2tncm91bmQtY29sb3I6IHdoaXRlO1xyXG4gICAgICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgICAgIHBhZGRpbmc6IDE1cHggMCAwIDA7XHJcbiAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgLmxpZmVsaW5lLWNvbXBvbmVudC10YWJsZXtcclxuICAgICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgICB9ICAgIFxyXG4gICAgICAgICAgICAgICAubGlmZWxpbmUtY29tcG9uZW50LXRhYmxlIC50YWJsZS1oZWFkZXItZGF0YXtcclxuICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgIHdpZHRoOiAxMGVtO1xyXG4gICAgICAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgZmxleC13cmFwOm5vd3JhcDtcclxuICAgICAgICAgICAgICAgICBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgfSBcclxuICAgICAgICAgICAgICAgLmxpZmVsaW5lLWNvbXBvbmVudC10YWJsZSAudGFibGUtaGVhZGVyLWRhdGEgc3Zne1xyXG4gICAgICAgICAgICAgICAgIHdpZHRoOiA0MHB4O1xyXG4gICAgICAgICAgICAgICB9ICAgICAgICAgXHJcbiAgICAgICAgICAgICAgIC5saWZlbGluZS1jb21wb25lbnQtdGFibGUgLmNvbW1hbmR7XHJcbiAgICAgICAgICAgICAgICBjb2xvcjogZ3JheTtcclxuICAgICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgICAgIHdpZHRoOiA0MHB4ICFpbXBvcnRhbnQ7XHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgIC5saWZlbGluZS1jb21wb25lbnQtdGFibGUgdGQuZGF0YXtcclxuICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMTNweDsgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIGNvbG9yOiAjNTM0YzRjO1xyXG4gICAgICAgICAgICAgICAgdGV4dC1hbGlnbjogY2VudGVyO1xyXG4gICAgICAgICAgICAgICAgYm9yZGVyLXJpZ2h0OiAxcHggc29saWQgd2hpdGVcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgLmxpZmVsaW5lLWNvbXBvbmVudC10YWJsZSAudGFibGVCb2R5IHRke1xyXG4gICAgICAgICAgICAgICAgY29sb3I6ICM1MzRjNGM7XHJcbiAgICAgICAgICAgICAgICB0ZXh0LWFsaWduOiBjZW50ZXI7XHJcbiAgICAgICAgICAgICAgICBmb250LXNpemU6IDAuOHJlbTtcclxuICAgICAgICAgICAgICAgIHBhZGRpbmc6IC44ZW07XHJcbiAgICAgICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDtcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgLmxpZmVsaW5lLWNvbXBvbmVudC10YWJsZSAudGFibGVCb2R5IHRyOm50aC1jaGlsZChvZGQpe1xyXG4gICAgICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogI2YwZjBmMDtcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgLmFkZC1uZXd7XHJcbiAgICAgICAgICAgICAgICB0ZXh0LWFsaWduOiByaWdodDtcclxuICAgICAgICAgICAgICAgIG1hcmdpbjogMTBweCA1cHggMCAwO1xyXG4gICAgICAgICAgICAgICAgZm9udC13ZWlnaHQ6IGJvbGQ7XHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgIC5hZGQtbmV3IGJ1dHRvbntcclxuICAgICAgICAgICAgICAgICBmb250LXdlaWdodDogbm9ybWFsO1xyXG4gICAgICAgICAgICAgICAgIHBhZGRpbmc6IDAuNWVtO1xyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAudGFibGUtaGVhZGVyLWRhdGEgaDZ7XHJcbiAgICAgICAgICAgICAgICBtYXJnaW46IDA7XHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICBgXHJcbiAgICAgICAgICAgIH08L3N0eWxlPlxyXG4gICAgICAgICAgICA8TGFiZWwgY2hlY2sgY2xhc3NOYW1lPVwiY29tcG9uZW50LWxhYmVsXCI+XHJcbiAgICAgICAgICAgICAgIHtjb21wb25lbnQudGl0bGV9XHJcbiAgICAgICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiY29tcG9uZW50LWRldGFpbHNcIj5cclxuICAgICAgICAgICAgICAgIDx0YWJsZSBjbGFzc05hbWU9XCJsaWZlbGluZS1jb21wb25lbnQtdGFibGUgdGFibGVcIj5cclxuICAgICAgICAgICAgICAgICAgICA8dGhlYWQgc3R5bGU9e3tiYWNrZ3JvdW5kQ29sb3I6ICcjYzVjNWM1J319PiAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8dHI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8dGQgY2xhc3NOYW1lPVwiZGF0YVwiIHN0eWxlPXt7d2lkdGg6ICc0MDBweCd9fT5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aDY+SW5kaWNhdG9yPC9oNj48L3RkPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPHRkIGNsYXNzTmFtZT1cImRhdGFcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cInRhYmxlLWhlYWRlci1kYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxoNj5SYW5rPC9oNj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEhlbHBGaWxsZWQgc2l6ZT17MjB9IHRpdGxlPVwiSG93IGltcG9ydGFudCBpcyB0aGUgaW5kaWNhdG9yIHRvIHlvdXIganVyaXNkaWN0aW9uIG9yIGhhemFyZD8oMT1Nb3N0IEltcG9ydGFudCwgNT1MZWFzdCBJbXBvcnRhbnQpXCIvPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJ0YWJsZS1oZWFkZXItZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGg2PkxpZmUgU2FmZXR5PC9oNj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxIZWxwRmlsbGVkIHNpemU9ezIwfSB0aXRsZT1cIkhvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBMaWZlIFNhZmV0eT9cIi8+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJ0YWJsZS1oZWFkZXItZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aDY+SW5jaWRlbnQgU3RhYmlsaXphdGlvbjwvaDY+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxIZWxwRmlsbGVkIHNpemU9ezIwfSB0aXRsZT1cIkhvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBJbmNpZGVudCBTdGFiaWxpemF0aW9uP1wiLz5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cInRhYmxlLWhlYWRlci1kYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGg2PlByb3BlcnR5IFByb3RlY3Rpb248L2g2PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxIZWxwRmlsbGVkIHNpemU9ezIwfSB0aXRsZT1cIkhvdyBpbXBvcnRhbnQgaXMgdGhlIGluZGljYXRvciB0byBQcm9wZXJ0eSBQcm90ZWN0aW9uP1wiLz5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9XCJ0YWJsZS1oZWFkZXItZGF0YVwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8aDY+RW52aXJvbm1lbnRhbCBQcmVzZXJ2YXRpb248L2g2PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8SGVscEZpbGxlZCBzaXplPXsyMH0gdGl0bGU9XCJIb3cgaW1wb3J0YW50IGlzIHRoZSBpbmRpY2F0b3IgdG8gRW52aXJvbm1lbnRhbCBQcmVzZXJ2YXRpb24/XCIvPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBjbGFzc05hbWU9XCJkYXRhXCI+PC90ZD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPC90cj5cclxuICAgICAgICAgICAgICAgICAgICA8L3RoZWFkPlxyXG4gICAgICAgICAgICAgICAgICAgIDx0Ym9keSBjbGFzc05hbWU9XCJ0YWJsZUJvZHlcIj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgeyAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgaW5kaWNhdG9ycy5tYXAoKGluZGljYXRvcjogSW5kaWNhdG9yVGVtcGxhdGUpID0+e1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiA8RWRpdGFibGVUYWJsZVJvdyBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAga2V5PXtpbmRpY2F0b3IuaWR9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGluZGljYXRvcj17aW5kaWNhdG9yfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBpc0VkaXRhYmxlPXtpc0VkaXRhYmxlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb21wb25lbnQ9e2NvbXBvbmVudH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uZmlnPXtjb25maWd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRlbXBsYXRlPXt0ZW1wbGF0ZX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2V0RXJyb3I9e3NldEVycm9yfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvbkNhbmNlbD17b25DYW5jZWxJbmRpY2F0b3JDcmVhdGV9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG9uQWN0aW9uQ29tcGxldGU9e29uQWN0aW9uQ29tcGxldGV9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLz4gXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgIDwvdGJvZHk+XHJcbiAgICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAoIWlzRWRpdGFibGUpID8gbnVsbFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA6IChcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0Zm9vdD5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA8dHI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDx0ZCBjb2xTcGFuPXs4fT5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPVwiYWRkLW5ld1wiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBkaXNhYmxlZD17aW5kaWNhdG9ycz8uc29tZShpID0+aS5pc05ldyl9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCk9PmNyZWF0ZU5ld0luZGljYXRvcigpfSBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZT1cIkFkZCBuZXcgaW5kaWNhdG9yXCJcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzaXplPVwiZGVmYXVsdFwiPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDxJY29uIGljb249XCI8c3ZnIHZpZXdCb3g9JnF1b3Q7MCAwIDE2IDE2JnF1b3Q7IGZpbGw9JnF1b3Q7bm9uZSZxdW90OyB4bWxucz0mcXVvdDtodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyZxdW90Oz48cGF0aCBkPSZxdW90O003LjUgMGEuNS41IDAgMCAwLS41LjVWN0guNWEuNS41IDAgMCAwIDAgMUg3djYuNWEuNS41IDAgMCAwIDEgMFY4aDYuNWEuNS41IDAgMCAwIDAtMUg4Vi41YS41LjUgMCAwIDAtLjUtLjVaJnF1b3Q7IGZpbGw9JnF1b3Q7IzAwMCZxdW90Oz48L3BhdGg+PC9zdmc+XCJcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2l6ZT1cIm1cIi8+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQWRkIE5ldyBJbmRpY2F0b3JcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvdGQ+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPC90cj5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIDwvdGZvb3Q+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIDwvdGFibGU+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICBlcnJvciA/ICg8Q2xzc0Vycm9yIGVycm9yPXtlcnJvcn0vPik6IG51bGxcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICApXHJcbn0iLCJpbXBvcnQgeyBMb2FkaW5nIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuXHJcbmNvbnN0IENsc3NMb2FkaW5nID0oe21lc3NhZ2V9OnttZXNzYWdlPzpzdHJpbmd9KSA9PntcclxuICAgIHJldHVybiggICAgICAgIFxyXG4gICAgICAgIDxkaXZcclxuICAgICAgICAgICAgc3R5bGU9e3tcclxuICAgICAgICAgICAgICAgIGhlaWdodDogJzEwMCUnLFxyXG4gICAgICAgICAgICAgICAgd2lkdGg6ICcxMDAlJyxcclxuICAgICAgICAgICAgICAgIHBvc2l0aW9uOiAnYWJzb2x1dGUnLFxyXG4gICAgICAgICAgICAgICAgYmFja2dyb3VuZDogJ3JnYigwIDAgMCAvIDEzJSknLFxyXG4gICAgICAgICAgICAgICAgdG9wOiAwLCAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICBsZWZ0OiAwLFxyXG4gICAgICAgICAgICAgICAgekluZGV4OiA5OTk5OTksXHJcbiAgICAgICAgICAgICAgICBkaXNwbGF5OiAnZmxleCcsXHJcbiAgICAgICAgICAgICAgICBqdXN0aWZ5Q29udGVudDogJ2NlbnRlcicsXHJcbiAgICAgICAgICAgICAgICBhbGlnbkl0ZW1zOiAnY2VudGVyJ1xyXG4gICAgICAgICAgICB9fVxyXG4gICAgICAgICAgICA+XHJcbiAgICAgICAgICAgIDxMb2FkaW5nXHJcbiAgICAgICAgICAgICAgICBjbGFzc05hbWU9XCJcIlxyXG4gICAgICAgICAgICAgICAgdHlwZT1cIlNFQ09OREFSWVwiXHJcbiAgICAgICAgICAgIC8+XHJcbiAgICAgICAgICAgIDxoMz57bWVzc2FnZX08L2gzPlxyXG4gICAgICAgIDwvZGl2PlxyXG4gICAgKVxyXG59XHJcbmV4cG9ydCBkZWZhdWx0IENsc3NMb2FkaW5nOyIsIlxyXG5pbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuaW1wb3J0IHsgTW9kYWwsIE1vZGFsSGVhZGVyLCBNb2RhbEJvZHksIE1vZGFsRm9vdGVyLCBCdXR0b24gfSBmcm9tIFwiamltdS11aVwiXHJcbmltcG9ydCBDbHNzTG9hZGluZyBmcm9tIFwiLi9jbHNzLWxvYWRpbmdcIlxyXG5cclxuLy8gZXhwb3J0IGludGVyZmFjZSBNb2RhbFByb3BzIHtcclxuLy8gICAgIHRpdGxlOiBzdHJpbmc7XHJcbi8vICAgICB2aXNpYmxlOiBib29sZWFuO1xyXG4vLyAgICAgZGlzYWJsZTogYm9vbGVhbjtcclxuLy8gICAgIGNoaWxkcmVuOiBhbnk7XHJcbi8vICAgICB0b2dnbGVWaXNpYmlsaXR5OiBGdW5jdGlvbjtcclxuLy8gICAgIHNhdmU6IEZ1bmN0aW9uO1xyXG4vLyAgICAgY2FuY2VsOiBGdW5jdGlvbjtcclxuLy8gfVxyXG5cclxuZXhwb3J0IGNvbnN0IENsc3NNb2RhbCA9KHByb3BzKT0+e1xyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8TW9kYWwgaXNPcGVuPXtwcm9wcy52aXNpYmxlfSBjZW50ZXJlZD17dHJ1ZX0gY2xhc3NOYW1lPVwiY2xzcy1tb2RhbFwiPlxyXG4gICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAgICB7XHJcbiAgICAgICAgICAgICAgICAgICAgYFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAuY2xzcy1tb2RhbCAubW9kYWwtY29udGVudHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDEuM3JlbTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGZsZXgtZGlyZWN0aW9uOiBjb2x1bW5cclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIC5tb2RhbC10aXRsZXtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogMS4xZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgaW5wdXR7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBwYWRkaW5nLWxlZnQ6IDBweDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLmppbXUtaW5wdXQgc3BhbntcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhlaWdodDogNDBweDtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZvbnQtc2l6ZTogLjllbTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgbGFiZWx7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2xvcjogZ3JheTtcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLmppbXUtZHJvcGRvd24tYnV0dG9ue1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAxZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIC5jbHNzLW1vZGFsIC5tb2RhbC1pdGVte1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbWFyZ2luOiAxMHB4IDA7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH0gICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgdGV4dGFyZWF7XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDAuOGVtO1xyXG4gICAgICAgICAgICAgICAgICAgICAgICB9ICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgLmNsc3MtbW9kYWwgLnNwYWNlcntcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxZW07XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICBgXHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+XHJcbiAgICAgICAgICAgIDxNb2RhbEhlYWRlciB0b2dnbGU9eygpPT5wcm9wcy50b2dnbGVWaXNpYmlsaXR5KGZhbHNlKX0+XHJcbiAgICAgICAgICAgICAgICB7cHJvcHMudGl0bGV9XHJcbiAgICAgICAgICAgIDwvTW9kYWxIZWFkZXI+XHJcbiAgICAgICAgICAgIDxNb2RhbEJvZHk+XHJcbiAgICAgICAgICAgICAgICB7cHJvcHMuY2hpbGRyZW59ICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgPC9Nb2RhbEJvZHk+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgIHByb3BzLmhpZGVGb290ZXIgJiYgcHJvcHMuaGlkZUZvb3RlciA9PSB0cnVlID8gbnVsbCA6XHJcbiAgICAgICAgICAgICAgICAoXHJcbiAgICAgICAgICAgICAgICAgICAgPE1vZGFsRm9vdGVyID5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBvbkNsaWNrPXsoKSA9PiAocHJvcHMuY2FuY2VsID8gcHJvcHMuY2FuY2VsKCkgOiBwcm9wcy50b2dnbGVWaXNpYmlsaXR5KGZhbHNlKSl9PlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAge3Byb3BzLm5vQnV0dG9uVGl0bGUgfHwgJ0NhbmNlbCd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cInNwYWNlclwiLz5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBkYXRhLXRlc3RpZD1cImJ0blNhdmVcIiBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRpc2FibGVkPXtwcm9wcy5kaXNhYmxlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCkgPT4gcHJvcHMuc2F2ZSgpfT5cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHtwcm9wcy55ZXNCdXR0b25UaXRsZSB8fCAnU2F2ZSd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIDwvQnV0dG9uPlxyXG4gICAgICAgICAgICAgICAgICAgIDwvTW9kYWxGb290ZXI+XHJcbiAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgIH0gICAgICAgICAgICBcclxuICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgKHByb3BzLmxvYWRpbmcpID8gPENsc3NMb2FkaW5nLz4gOiBudWxsICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgPC9Nb2RhbD4gXHJcbiAgICApXHJcbn0iLCJpbXBvcnQgUmVhY3QgZnJvbSBcInJlYWN0XCJcclxuXHJcbmNvbnN0IENsc3NOb0RhdGEgPSh7bWVzc2FnZX06e21lc3NhZ2U6c3RyaW5nfSkgPT57XHJcbiAgICByZXR1cm4oICAgICAgICBcclxuICAgICAgICA8ZGl2XHJcbiAgICAgICAgICAgIHN0eWxlPXt7XHJcbiAgICAgICAgICAgICAgICBoZWlnaHQ6ICcxMDAlJyxcclxuICAgICAgICAgICAgICAgIHdpZHRoOiAnMTAwJScsXHJcbiAgICAgICAgICAgICAgICBwb3NpdGlvbjogJ2Fic29sdXRlJyxcclxuICAgICAgICAgICAgICAgIGJhY2tncm91bmQ6ICdyZ2IoMCAwIDAgLyAxMyUpJyxcclxuICAgICAgICAgICAgICAgIHRvcDogMCwgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgbGVmdDogMCxcclxuICAgICAgICAgICAgICAgIHpJbmRleDogOTk5OTk5LFxyXG4gICAgICAgICAgICAgICAgZGlzcGxheTogJ2ZsZXgnLFxyXG4gICAgICAgICAgICAgICAganVzdGlmeUNvbnRlbnQ6ICdjZW50ZXInLFxyXG4gICAgICAgICAgICAgICAgYWxpZ25JdGVtczogJ2NlbnRlcidcclxuICAgICAgICAgICAgfX1cclxuICAgICAgICAgICAgPiAgICAgICAgICAgIFxyXG4gICAgICAgICAgICA8aDM+e21lc3NhZ2V9PC9oMz5cclxuICAgICAgICA8L2Rpdj5cclxuICAgIClcclxufVxyXG5leHBvcnQgZGVmYXVsdCBDbHNzTm9EYXRhOyIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIlxyXG5pbXBvcnQgeyBDbHNzRHJvcGRvd24gfSBmcm9tIFwiLi9jbHNzLWRyb3Bkb3duXCJcclxuaW1wb3J0IHsgQnV0dG9uIH0gZnJvbSBcImppbXUtdWlcIlxyXG5pbXBvcnQgeyBQbHVzQ2lyY2xlT3V0bGluZWQgfSBmcm9tIFwiamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvcGx1cy1jaXJjbGVcIlxyXG5pbXBvcnQgeyBkZWxldGVPcmdhbml6YXRpb24sIGRpc3BhdGNoQWN0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpXCJcclxuaW1wb3J0IHsgT3JnYW5pemF0aW9uIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9uc1wiXHJcbmltcG9ydCB7IENMU1NBY3Rpb25LZXlzIH0gZnJvbSBcIi4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZVwiXHJcblxyXG5cclxuZXhwb3J0IGNvbnN0IE9yZ2FuaXphdGlvbnNEcm9wZG93biA9KHtjb25maWcsIG9yZ2FuaXphdGlvbnMsIHNlbGVjdGVkT3JnYW5pemF0aW9uLCBcclxuICAgIHNldE9yZ2FuaXphdGlvbiwgdmVydGljYWwsIHRvZ2dsZU5ld09yZ2FuaXphdGlvbk1vZGFsfSk9PntcclxuXHJcbiAgICBjb25zdCBbbG9jYWxPcmdhbml6YXRpb25zLCBzZXRMb2NhbE9yZ2FuaXphdGlvbnNdID0gUmVhY3QudXNlU3RhdGU8T3JnYW5pemF0aW9uW10+KFtdKTtcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgICBpZihvcmdhbml6YXRpb25zKXsgXHJcbiAgICAgICAgICAgIHNldExvY2FsT3JnYW5pemF0aW9ucyhbLi4ub3JnYW5pemF0aW9uc10gYXMgT3JnYW5pemF0aW9uW10pXHJcbiAgICAgICAgfVxyXG4gICAgfSwgW29yZ2FuaXphdGlvbnNdKVxyXG4gICAgXHJcbiAgICBjb25zdCByZW1vdmVPcmdhbml6YXRpb24gPWFzeW5jIChvcmdhbml6YXRpb246IE9yZ2FuaXphdGlvbik9PntcclxuICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBkZWxldGVPcmdhbml6YXRpb24ob3JnYW5pemF0aW9uLCBjb25maWcpO1xyXG4gICAgICBpZihyZXNwb25zZS5lcnJvcnMpe1xyXG4gICAgICAgY29uc29sZS5sb2cocmVzcG9uc2UuZXJyb3JzKTtcclxuICAgICAgIGRpc3BhdGNoQWN0aW9uKENMU1NBY3Rpb25LZXlzLlNFVF9FUlJPUlMsIHJlc3BvbnNlLmVycm9ycyk7XHJcbiAgICAgICByZXR1cm47XHJcbiAgICAgIH1cclxuICAgICAgY29uc29sZS5sb2coYCR7b3JnYW5pemF0aW9uLnRpdGxlfSBkZWxldGVkYClcclxuICAgICAgc2V0TG9jYWxPcmdhbml6YXRpb25zKFsuLi5sb2NhbE9yZ2FuaXphdGlvbnMuZmlsdGVyKG8gPT4gby5pZCAhPT0gb3JnYW5pemF0aW9uLmlkKV0pO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIChcclxuICAgICAgICA8ZGl2IHN0eWxlPXt7ZGlzcGxheTogdmVydGljYWwgPyAnYmxvY2snOiAnZmxleCcsXHJcbiAgICAgICAgICAgIGFsaWduSXRlbXM6ICdjZW50ZXInfX0+XHJcbiAgICAgICAgICAgICA8Q2xzc0Ryb3Bkb3duIGl0ZW1zPXtsb2NhbE9yZ2FuaXphdGlvbnN9XHJcbiAgICAgICAgICAgICAgICBpdGVtPXtzZWxlY3RlZE9yZ2FuaXphdGlvbn0gXHJcbiAgICAgICAgICAgICAgICBkZWxldGFibGU9e3RydWV9XHJcbiAgICAgICAgICAgICAgICBzZXRJdGVtPXtzZXRPcmdhbml6YXRpb259IFxyXG4gICAgICAgICAgICAgICAgZGVsZXRlSXRlbT17cmVtb3ZlT3JnYW5pemF0aW9ufS8+XHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWwgPyAoXHJcbiAgICAgICAgICAgICAgICB2ZXJ0aWNhbD8gKFxyXG4gICAgICAgICAgICAgICAgICAgIDxCdXR0b24gZGF0YS10ZXN0aWQ9XCJidG5TaG93QWRkT3JnYW5pemF0aW9uXCIgIGNsYXNzTmFtZT1cIiBhZGQtbGlua1wiXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICB0eXBlPVwibGlua1wiIHN0eWxlPXt7dGV4dEFsaWduOiAnbGVmdCd9fVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKT0+IHRvZ2dsZU5ld09yZ2FuaXphdGlvbk1vZGFsKHRydWUpfT5cclxuICAgICAgICAgICAgICAgICAgICAgICAgQWRkIE5ldyBPcmdhbml6YXRpb25cclxuICAgICAgICAgICAgICAgICAgICA8L0J1dHRvbj5cclxuICAgICAgICAgICAgICAgICAgICk6KFxyXG4gICAgICAgICAgICAgICAgICAgIDxQbHVzQ2lyY2xlT3V0bGluZWQgY2xhc3NOYW1lPVwiYWN0aW9uLWljb25cIiBcclxuICAgICAgICAgICAgICAgICAgICAgICAgZGF0YS10ZXN0aWQ9XCJidG5BZGROZXdPcmdhbml6YXRpb25cIiBcclxuICAgICAgICAgICAgICAgICAgICAgICAgdGl0bGU9XCJBZGQgTmV3IE9yZ2FuaXphdGlvblwiIHNpemU9ezMwfSBjb2xvcj17J2dyYXknfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICBvbkNsaWNrPXsoKT0+IHRvZ2dsZU5ld09yZ2FuaXphdGlvbk1vZGFsKHRydWUpfS8+ICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICApOiBudWxsXHJcbiAgICAgICAgICAgIH0gICBcclxuICAgICAgICA8L2Rpdj5cclxuICAgIClcclxufSIsImltcG9ydCBSZWFjdCBmcm9tIFwicmVhY3RcIjtcclxuaW1wb3J0IHsgQ2xvc2VPdXRsaW5lZCB9IGZyb20gXCJqaW11LWljb25zL291dGxpbmVkL2VkaXRvci9jbG9zZVwiO1xyXG5pbXBvcnQgeyBFZGl0T3V0bGluZWQgfSBmcm9tIFwiamltdS1pY29ucy9vdXRsaW5lZC9lZGl0b3IvZWRpdFwiO1xyXG5pbXBvcnQgeyBTYXZlRmlsbGVkIH0gZnJvbSAnamltdS1pY29ucy9maWxsZWQvZWRpdG9yL3NhdmUnXHJcbmltcG9ydCB7IFxyXG4gIEJ1dHRvbixcclxuICBMYWJlbCxUZXh0SW5wdXRcclxuICAgfSBmcm9tIFwiamltdS11aVwiO1xyXG5pbXBvcnQgQ2xzc0xvYWRpbmcgZnJvbSBcIi4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1sb2FkaW5nXCI7XHJcbmltcG9ydCB7IENMU1NUZW1wbGF0ZSwgXHJcbiAgQ2xzc1VzZXIsIEhhemFyZCwgXHJcbiAgT3JnYW5pemF0aW9uIH0gZnJvbSBcIi4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvZGF0YS1kZWZpbml0aW9uc1wiO1xyXG5pbXBvcnQgeyBCQVNFTElORV9URU1QTEFURV9OQU1FLCBcclxuICBDTFNTX0FETUlOLCBDTFNTX0VESVRPUiwgQ0xTU19GT0xMT1dFUlMgfSBmcm9tIFwiLi4vLi4vLi4vY2xzcy1hcHBsaWNhdGlvbi9zcmMvZXh0ZW5zaW9ucy9jb25zdGFudHNcIjtcclxuaW1wb3J0IHsgUmVhY3RSZWR1eCB9IGZyb20gXCJqaW11LWNvcmVcIjtcclxuaW1wb3J0IHsgZGlzcGF0Y2hBY3Rpb24sIFxyXG4gIGdldEFzc2Vzc21lbnROYW1lcyxcclxuICB1cGRhdGVUZW1wbGF0ZU9yZ2FuaXphdGlvbkFuZEhhemFyZCB9IGZyb20gXCIuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2FwaVwiO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gXCIuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2Nsc3Mtc3RvcmVcIjtcclxuaW1wb3J0IHsgcGFyc2VEYXRlIH0gZnJvbSBcIi4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvdXRpbHNcIjtcclxuaW1wb3J0IHsgSUNvZGVkVmFsdWUgfSBmcm9tIFwiQGVzcmkvYXJjZ2lzLXJlc3QtdHlwZXNcIjtcclxuaW1wb3J0IHsgQ2xzc0Ryb3Bkb3duIH0gZnJvbSBcIi4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1kcm9wZG93blwiO1xyXG5pbXBvcnQgeyBPcmdhbml6YXRpb25zRHJvcGRvd24gfSBmcm9tIFwiLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLW9yZ2FuaXphdGlvbnMtZHJvcGRvd25cIjtcclxuaW1wb3J0IHsgSGF6YXJkc0Ryb3Bkb3duIH0gZnJvbSBcIi4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1oYXphcmRzLWRyb3Bkb3duXCI7XHJcbmltcG9ydCB7IFRlbXBsYXRlQXNzZXNzbWVudFZpZXcgfSBmcm9tIFwiLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWFzc2Vzc21lbnRzLWxpc3RcIjtcclxuY29uc3QgeyB1c2VTZWxlY3RvciB9ID0gUmVhY3RSZWR1eDtcclxuXHJcbmV4cG9ydCBjb25zdCBEZXRhaWxIZWFkZXJXaWRnZXQgPShcclxuICB7dGVtcGxhdGUsIGNvbmZpZywgb3JnYW5pemF0aW9ucywgaGF6YXJkcywgb25BY3Rpb25Db21wbGV0ZSwgXHJcbiAgICBzZWxlY3RlZE5ld0hhemFyZCwgc2VsZWN0ZWROZXdPcmdhbml6YXRpb24sXHJcbiAgICB0b2dnbGVIYXphcmRNb2RhbFZpc2liaWxpdHksIFxyXG4gICAgdG9nZ2xlT3JnYW5pemF0aW9uTW9kYWxWaXNpYmlsaXR5fSk9PntcclxuXHJcbiAgICBjb25zdCBbbG9hZGluZywgc2V0TG9hZGluZ10gPSBSZWFjdC51c2VTdGF0ZShmYWxzZSk7XHJcbiAgICBjb25zdCBbaXNFZGl0aW5nLCBzZXRFZGl0aW5nXSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICAgIGNvbnN0IFt0ZW1wbGF0ZU5hbWUsIHNldFRlbXBsYXRlTmFtZV0gPSBSZWFjdC51c2VTdGF0ZSgnJyk7XHJcbiAgICBjb25zdCBbc2VsZWN0ZWRIYXphcmQsIHNldFNlbGVjdGVkSGF6YXJkXT0gUmVhY3QudXNlU3RhdGU8SGF6YXJkPihudWxsKTtcclxuICAgIGNvbnN0IFtzZWxlY3RlZE9yZ2FuaXphdGlvbiwgc2V0U2VsZWN0ZWRPcmdhbml6YXRpb25dPVJlYWN0LnVzZVN0YXRlPE9yZ2FuaXphdGlvbj4obnVsbCk7XHJcbiAgICBjb25zdCBbYWxsb3dUb0VkaXQsIHNldEFsbG93VG9FZGl0XSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICAgIGNvbnN0IFtzdGF0dXMsIHNldFN0YXR1c109UmVhY3QudXNlU3RhdGU8YW55PigpO1xyXG4gICAgY29uc3QgW3N0YXR1c2VzLCBzZXRTdGF0dXNlc10gPSBSZWFjdC51c2VTdGF0ZTxJQ29kZWRWYWx1ZVtdPihbXSlcclxuICAgIGNvbnN0IFthc3Nlc3NtZW50cywgc2V0QXNzZXNzbWVudHNdPVJlYWN0LnVzZVN0YXRlPGFueVtdPihbXSlcclxuICAgIGNvbnN0IFtpc0Fzc2Vzc21lbnRzVmlzaWJpbGl0eSwgc2V0VG9nZ2xlQXNzZXNzbWVudFZpc2liaWxpdHldPVJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICAgXHJcbiAgICBjb25zdCB1c2VyID0gdXNlU2VsZWN0b3IoKHN0YXRlOiBhbnkpID0+IHtcclxuICAgICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZS51c2VyIGFzIENsc3NVc2VyO1xyXG4gICAgfSlcclxuXHJcbiAgICBjb25zdCB0ZW1wbGF0ZXMgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8udGVtcGxhdGVzIGFzIENMU1NUZW1wbGF0ZVtdO1xyXG4gICAgfSlcclxuICAgIFxyXG4gICAgXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgICBpZihzZWxlY3RlZE5ld0hhemFyZCl7ICAgICAgICBcclxuICAgICAgICBzZXRTZWxlY3RlZEhhemFyZChzZWxlY3RlZE5ld0hhemFyZClcclxuICAgICAgfVxyXG4gICAgfSwgW3NlbGVjdGVkTmV3SGF6YXJkXSlcclxuXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgICBpZihzZWxlY3RlZE5ld09yZ2FuaXphdGlvbil7XHJcbiAgICAgICAgc2V0U2VsZWN0ZWRPcmdhbml6YXRpb24oc2VsZWN0ZWROZXdPcmdhbml6YXRpb24pXHJcbiAgICAgIH1cclxuICAgIH0sIFtzZWxlY3RlZE5ld09yZ2FuaXphdGlvbl0pXHJcbiAgICAgXHJcbiAgICBSZWFjdC51c2VFZmZlY3QoKCk9PntcclxuICAgICAgaWYoY29uZmlnKXtcclxuICAgICAgICBnZXRBc3Nlc3NtZW50TmFtZXMoY29uZmlnLCB0ZW1wbGF0ZT8ubmFtZSlcclxuICAgICAgICAudGhlbigocmVzcG9uc2UpID0+IHtcclxuICAgICAgICAgIGlmKHJlc3BvbnNlLmRhdGEpe1xyXG4gICAgICAgICAgICBzZXRBc3Nlc3NtZW50cyhyZXNwb25zZS5kYXRhKVxyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH0pXHJcbiAgICAgIH1cclxuICAgIH0sIFt0ZW1wbGF0ZV0pXHJcblxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT57XHJcbiAgICAgIGlmKHRlbXBsYXRlKXtcclxuICAgICAgICBjb25zdCBzdGF0dXNEb21haW5zID0gICh0ZW1wbGF0ZSBhcyBDTFNTVGVtcGxhdGUpLmRvbWFpbnM7XHJcbiAgICAgICAgc2V0U3RhdHVzZXMoc3RhdHVzRG9tYWlucyk7XHJcbiAgICAgIH1cclxuICAgIH0sIFt0ZW1wbGF0ZV0pICBcclxuICAgIFxyXG4gICAgUmVhY3QudXNlRWZmZWN0KCgpPT4ge1xyXG4gICAgICBpZih0ZW1wbGF0ZSAmJiBzdGF0dXNlcyAmJiBzdGF0dXNlcy5sZW5ndGggPiAwKXsgICBcclxuICAgICAgICBjb25zdCBzID0gc3RhdHVzZXMuZmluZChzID0+IHMubmFtZSA9PT0gdGVtcGxhdGU/LnN0YXR1cy5uYW1lKTtcclxuICAgICAgICB0cnl7XHJcbiAgICAgICAgICBzZXRTdGF0dXMocyk7XHJcbiAgICAgICAgfWNhdGNoKGUpe1xyXG4gICAgICAgICAgY29uc29sZS5sb2coZSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9ICAgICBcclxuICAgIH0sIFt0ZW1wbGF0ZSwgc3RhdHVzZXNdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICAgIGlmKHVzZXIpeyBcclxuICAgICAgICBpZih1c2VyPy5ncm91cHM/LmluY2x1ZGVzKENMU1NfQURNSU4pKXtcclxuICAgICAgICAgIHNldEFsbG93VG9FZGl0KHRydWUpO1xyXG4gICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgIH1cclxuICBcclxuICAgICAgICBpZih1c2VyPy5ncm91cHM/LmluY2x1ZGVzKENMU1NfRURJVE9SKSAmJiBcclxuICAgICAgICAgICAgdGVtcGxhdGU/Lm5hbWUgIT09IEJBU0VMSU5FX1RFTVBMQVRFX05BTUUpe1xyXG4gICAgICAgICAgc2V0QWxsb3dUb0VkaXQodHJ1ZSk7XHJcbiAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG4gICAgICAgIFxyXG4gICAgICAgIGlmKHVzZXI/Lmdyb3Vwcz8uaW5jbHVkZXMoQ0xTU19GT0xMT1dFUlMpICYmIFxyXG4gICAgICAgICAgICB0ZW1wbGF0ZT8ubmFtZSAhPT0gQkFTRUxJTkVfVEVNUExBVEVfTkFNRSl7XHJcbiAgICAgICAgICAgc2V0QWxsb3dUb0VkaXQodHJ1ZSk7XHJcbiAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgfVxyXG4gICAgICBzZXRBbGxvd1RvRWRpdChmYWxzZSk7ICAgICAgXHJcbiAgICB9LCBbdGVtcGxhdGUsIHVzZXJdKVxyXG5cclxuICAgIFJlYWN0LnVzZUVmZmVjdCgoKT0+e1xyXG4gICAgICBpZih0ZW1wbGF0ZSl7XHJcbiAgICAgICAgc2V0VGVtcGxhdGVOYW1lKHRlbXBsYXRlPy5uYW1lKTtcclxuICAgICAgfVxyXG4gICAgfSwgW3RlbXBsYXRlXSkgICBcclxuICAgIFxyXG4gICAgY29uc3Qgb25DYW5jZWwgPSgpID0+e1xyXG4gICAgICBzZXRUZW1wbGF0ZU5hbWUodGVtcGxhdGUubmFtZSk7IFxyXG4gICAgICBzZXRTZWxlY3RlZEhhemFyZChoYXphcmRzLmZpbmQoaCA9PiBoLm5hbWUgPT09IHRlbXBsYXRlLmhhemFyZE5hbWUpKTtcclxuICAgICAgc2V0U2VsZWN0ZWRPcmdhbml6YXRpb24ob3JnYW5pemF0aW9ucy5maW5kKG8gPT4gby5uYW1lID09PSB0ZW1wbGF0ZS5vcmdhbml6YXRpb25OYW1lKSk7IFxyXG4gICAgICBzZXRFZGl0aW5nKGZhbHNlKTtcclxuICAgICAgb25BY3Rpb25Db21wbGV0ZShmYWxzZSk7XHJcbiAgICB9XHJcbiAgIFxyXG4gICAgY29uc3QgZ2V0U2VsZWN0ZWRIYXphcmREYXRhID0oKSA9PiB7XHJcbiAgICAgIGlmKHNlbGVjdGVkSGF6YXJkICYmIHNlbGVjdGVkSGF6YXJkLnRpdGxlICE9PSAnLU5vbmUtJyl7XHJcbiAgICAgICAgcmV0dXJuIHNlbGVjdGVkSGF6YXJkXHJcbiAgICAgIH0gICAgICAgXHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgZ2V0U2VsZWN0ZWRPcmdEYXRhID0gKCk9PiB7XHJcbiAgICAgIGlmKHNlbGVjdGVkT3JnYW5pemF0aW9uICYmIHNlbGVjdGVkT3JnYW5pemF0aW9uLnRpdGxlICE9PSAnLU5vbmUtJyl7XHJcbiAgICAgICAgcmV0dXJuIHNlbGVjdGVkT3JnYW5pemF0aW9uXHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBvblNhdmVUZW1wbGF0ZUhlYWRlckVkaXRzPSBhc3luYygpPT57ICBcclxuXHJcbiAgICAgIGNvbnN0IF90ZW1wbGF0ZXMgPSB0ZW1wbGF0ZXMuZmlsdGVyKHQgPT4gdC5pZCAhPSB0ZW1wbGF0ZS5pZCk7XHJcblxyXG4gICAgICBpZihfdGVtcGxhdGVzLnNvbWUodCA9PiB0Lm5hbWUudG9Mb3dlckNhc2UoKSA9PT0gdGVtcGxhdGVOYW1lLnRvTG93ZXJDYXNlKCkudHJpbSgpKSl7XHJcbiAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgYFRlbXBsYXRlOiAke3RlbXBsYXRlTmFtZX0gYWxyZWFkeSBleGlzdHNgKTtcclxuICAgICAgICByZXR1cm47XHJcbiAgICAgIH1cclxuICAgICBcclxuICAgICAgc2V0TG9hZGluZyh0cnVlKTtcclxuXHJcbiAgICAgIGNvbnN0IGhhemFyZERhdGEgPSBnZXRTZWxlY3RlZEhhemFyZERhdGEoKTtcclxuICAgICAgY29uc3Qgb3JnRGF0YSA9IGdldFNlbGVjdGVkT3JnRGF0YSgpO1xyXG5cclxuICAgICAgY29uc3QgdXBkYXRlZFRlbXBsYXRlID0ge1xyXG4gICAgICAgIC4uLnRlbXBsYXRlLFxyXG4gICAgICAgIG5hbWU6IHRlbXBsYXRlTmFtZSxcclxuICAgICAgICBpc1NlbGVjdGVkOiB0ZW1wbGF0ZS5pc1NlbGVjdGVkLFxyXG4gICAgICAgIHN0YXR1czogc3RhdHVzLFxyXG4gICAgICAgIGhhemFyZElkOiBoYXphcmREYXRhPyBoYXphcmREYXRhLmlkOiBudWxsLFxyXG4gICAgICAgIGhhemFyZE5hbWU6IGhhemFyZERhdGE/IGhhemFyZERhdGEubmFtZTogbnVsbCxcclxuICAgICAgICBoYXphcmRUeXBlOiBoYXphcmREYXRhPyBoYXphcmREYXRhLnR5cGU/LmNvZGU6IG51bGwsXHJcbiAgICAgICAgb3JnYW5pemF0aW9uVHlwZTogb3JnRGF0YT8gb3JnRGF0YS50eXBlOiBudWxsLFxyXG4gICAgICAgIG9yZ2FuaXphdGlvbk5hbWU6IG9yZ0RhdGE/IG9yZ0RhdGEubmFtZTogIG51bGwsICAgICAgICBcclxuICAgICAgICBvcmdhbml6YXRpb25JZDogb3JnRGF0YT8gb3JnRGF0YS5pZDogIG51bGwsXHJcbiAgICAgIH0gYXMgQ0xTU1RlbXBsYXRlO1xyXG5cclxuICAgICAgY29uc3QgcmVzcG9uc2UgPSAgYXdhaXQgdXBkYXRlVGVtcGxhdGVPcmdhbml6YXRpb25BbmRIYXphcmQoXHJcbiAgICAgICAgY29uZmlnLCB1cGRhdGVkVGVtcGxhdGUsIHVzZXIudXNlck5hbWVcclxuICAgICAgKTsgIFxyXG5cclxuICAgICAgc2V0TG9hZGluZyhmYWxzZSk7XHJcbiAgICAgIGlmKHJlc3BvbnNlLmVycm9ycyl7XHJcbiAgICAgICAgZGlzcGF0Y2hBY3Rpb24oQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUywgcmVzcG9uc2UuZXJyb3JzKTsgICAgICAgIFxyXG4gICAgICAgIHJldHVybjtcclxuICAgICAgfVxyXG4gICAgICBzZXRFZGl0aW5nKGZhbHNlKTtcclxuICAgICAgb25BY3Rpb25Db21wbGV0ZSh0cnVlKSAgIFxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiAoICAgIFxyXG4gICAgICA8ZGl2IGNsYXNzTmFtZT1cImRldGFpbHMtY29udGVudC1oZWFkZXJcIiBzdHlsZT17e1xyXG4gICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBjb25maWc/LmhlYWRlckJhY2tncm91bmRDb2xvclxyXG4gICAgICAgIH19PlxyXG4gICAgICAgICAgICA8c3R5bGU+XHJcbiAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgYCAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlcntcclxuICAgICAgICAgICAgICAgICAgICBkaXNwbGF5OiBmbGV4OyAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgZmxleC13cmFwOiB3cmFwO1xyXG4gICAgICAgICAgICAgICAgICB9ICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgIC5lZGl0b3ItaWNvbnsgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgIGNvbG9yOiAjNTM0YzRjO1xyXG4gICAgICAgICAgICAgICAgICAgIGN1cnNvcjogcG9pbnRlcjtcclxuICAgICAgICAgICAgICAgICAgICBtYXJnaW46IDEwcHg7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLmVkaXRvci1pY29uOiBob3ZlcntcclxuICAgICAgICAgICAgICAgICAgICBvcGFjaXR5OiAuOFxyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5zYXZlLWNhbmNlbCwgXHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5zYXZlLWljb257XHJcbiAgICAgICAgICAgICAgICAgICAgcG9zaXRpb246IGFic29sdXRlO1xyXG4gICAgICAgICAgICAgICAgICAgIHJpZ2h0OiAxMHB4O1xyXG4gICAgICAgICAgICAgICAgICAgIHRvcDogMTBweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciAuZGF0YS1kcm9wZG93biwgXHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5kYXRhLWlucHV0e1xyXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICAgICAgICAgIGRpc3BsYXk6IGZsZXg7XHJcbiAgICAgICAgICAgICAgICAgICAgYWxpZ24taXRlbXM6IGNlbnRlcjtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciAuZGF0YS1kcm9wZG93biAuamltdS1kcm9wZG93bntcclxuICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAzMDBweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciAuZGF0YS1kcm9wZG93bi1tZW51e1xyXG4gICAgICAgICAgICAgICAgICAgIHdpZHRoOiAzMDBweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciAuZXJyb3J7XHJcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6IHJlZDtcclxuICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDE1cHg7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLmRyb3Bkb3duLWl0ZW17XHJcbiAgICAgICAgICAgICAgICAgICAgICBmb250LXNpemU6IDEuM2VtO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5vcmdhbml6YXRpb257XHJcbiAgICAgICAgICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC5lbmQtd2lkZ2V0e1xyXG4gICAgICAgICAgICAgICAgICAgICAgbWFyZ2luLWJvdHRvbTogMTVweDtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciAuZGF0YS1pbnB1dHtcclxuICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiAzMC43JVxyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC50aXRsZS50ZW1wbGF0ZXtcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTQycHg7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIHRkIGxhYmVsLFxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciB0ZCBpbnB1dHsgXHJcbiAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAxLjVlbTtcclxuICAgICAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICAgICAgICAuZGV0YWlscy1jb250ZW50LWhlYWRlciB0ZCBsYWJlbHtcclxuICAgICAgICAgICAgICAgICAgICB3aWR0aDogMTY1cHg7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgdGQgbGFiZWwudmFsdWV7XHJcbiAgICAgICAgICAgICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDtcclxuICAgICAgICAgICAgICAgICAgICAgIHdpZHRoOiBhdXRvO1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIHRyLnRkLXVuZGVyPnRke1xyXG4gICAgICAgICAgICAgICAgICAgIHBhZGRpbmctYm90dG9tOiAxZW07XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmRldGFpbHMtY29udGVudC1oZWFkZXIgLnRlbXBsYXRlLWlucHV0IGlucHV0e1xyXG4gICAgICAgICAgICAgICAgICAgIHBhZGRpbmctbGVmdDogMTBweDtcclxuICAgICAgICAgICAgICAgICAgICBoZWlnaHQ6IDQwcHg7XHJcbiAgICAgICAgICAgICAgICAgICAgZm9udC1zaXplOiAxNnB4O1xyXG4gICAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVyIC50ZW1wbGF0ZS1pbnB1dCBzcGFue1xyXG4gICAgICAgICAgICAgICAgICAgICAgaGVpZ2h0OiA0MHB4ICFpbXBvcnRhbnQ7XHJcbiAgICAgICAgICAgICAgICAgICAgICB3aWR0aDogMzAwcHg7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgLmFjdGlvbi1pY29uIHtcclxuICAgICAgICAgICAgICAgICAgICBjb2xvcjogZ3JheTtcclxuICAgICAgICAgICAgICAgICAgICBjdXJzb3I6IHBvaW50ZXI7XHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgIGBcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIDwvc3R5bGU+IFxyXG5cclxuICAgICAgICAgICAgPHRhYmxlIGNsYXNzTmFtZT1cInRlbXBsYXRlLWRldGFpbC1oZWFkZXItdGFibGVcIiBcclxuICAgICAgICAgICAgc3R5bGU9e3ttYXJnaW5SaWdodDogJzEwZW0nfX0+XHJcbiAgICAgICAgICAgICAgPHRyIGNsYXNzTmFtZT1cInRkLXVuZGVyXCI+XHJcbiAgICAgICAgICAgICAgICA8dGQ+IDxMYWJlbCBjaGVjaz5UZW1wbGF0ZSBOYW1lOiA8L0xhYmVsPjwvdGQ+XHJcbiAgICAgICAgICAgICAgICA8dGQ+XHJcbiAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgIGlzRWRpdGluZyA/IChcclxuICAgICAgICAgICAgICAgICAgICAgIDxUZXh0SW5wdXQgY2xhc3NOYW1lPVwidGVtcGxhdGUtaW5wdXRcIlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIG9uQ2hhbmdlPXsoZSk9PiBzZXRUZW1wbGF0ZU5hbWUoZS50YXJnZXQudmFsdWUpfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHZhbHVlPXt0ZW1wbGF0ZU5hbWV9PjwvVGV4dElucHV0PlxyXG4gICAgICAgICAgICAgICAgICAgICAgKSA6XHJcbiAgICAgICAgICAgICAgICAgICAgICAoPExhYmVsIGRhdGEtdGVzdGlkPVwibGJsVGVtcGxhdGVOYW1lXCIgY2xhc3NOYW1lPVwidmFsdWVcIiBjaGVjaz57dGVtcGxhdGVOYW1lfSA8L0xhYmVsPilcclxuICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICAgIDx0ciBjbGFzc05hbWU9XCJ0ZC11bmRlclwiPlxyXG4gICAgICAgICAgICAgICAgPHRkPjxMYWJlbCBjbGFzc05hbWU9XCJ0aXRsZVwiIGNoZWNrPk9yZ2FuaXphdGlvbjogPC9MYWJlbD48L3RkPlxyXG4gICAgICAgICAgICAgICAgPHRkPlxyXG4gICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGlzRWRpdGluZyA/IChcclxuICAgICAgICAgICAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPSdkYXRhLWRyb3Bkb3duJz5cclxuICAgICAgICAgICAgICAgICAgICAgICAgPE9yZ2FuaXphdGlvbnNEcm9wZG93blxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGNvbmZpZz17Y29uZmlnfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIG9yZ2FuaXphdGlvbnM9e29yZ2FuaXphdGlvbnN9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgc2VsZWN0ZWRPcmdhbml6YXRpb249e3NlbGVjdGVkT3JnYW5pemF0aW9ufVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHNldE9yZ2FuaXphdGlvbj17c2V0U2VsZWN0ZWRPcmdhbml6YXRpb259XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgdG9nZ2xlTmV3T3JnYW5pemF0aW9uTW9kYWw9e3RvZ2dsZU9yZ2FuaXphdGlvbk1vZGFsVmlzaWJpbGl0eX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICB2ZXJ0aWNhbD17ZmFsc2V9Lz5cclxuICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICAgICAgICAgICk6XHJcbiAgICAgICAgICAgICAgICAgICggICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgPExhYmVsIGRhdGEtdGVzdGlkPVwidHh0T3JnYW5pemF0aW9uTmFtZVwiIGNsYXNzTmFtZT1cInZhbHVlXCIgY2hlY2s+e1xyXG4gICAgICAgICAgICAgICAgICAgICAgc2VsZWN0ZWRPcmdhbml6YXRpb24gPyBzZWxlY3RlZE9yZ2FuaXphdGlvbj8ubmFtZSA6ICAnLU5vbmUtJ1xyXG4gICAgICAgICAgICAgICAgICAgIH08L0xhYmVsPlxyXG4gICAgICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICB9IFxyXG4gICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICAgIDx0ciBjbGFzc05hbWU9XCJ0ZC11bmRlclwiPlxyXG4gICAgICAgICAgICAgICAgPHRkPiA8TGFiZWwgY2xhc3NOYW1lPVwidGl0bGVcIiBjaGVjaz5IYXphcmQ6IDwvTGFiZWw+PC90ZD5cclxuICAgICAgICAgICAgICAgIDx0ZD5cclxuICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgaXNFZGl0aW5nID8gKFxyXG4gICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9J2RhdGEtZHJvcGRvd24nPiAgXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICA8SGF6YXJkc0Ryb3Bkb3duXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbmZpZz17Y29uZmlnfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgaGF6YXJkcz17aGF6YXJkc31cclxuICAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkSGF6YXJkPXtzZWxlY3RlZEhhemFyZH1cclxuICAgICAgICAgICAgICAgICAgICAgICAgIHNldEhhemFyZD17c2V0U2VsZWN0ZWRIYXphcmR9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICB0b2dnbGVOZXdIYXphcmRNb2RhbD17dG9nZ2xlSGF6YXJkTW9kYWxWaXNpYmlsaXR5fVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgdmVydGljYWw9e2ZhbHNlfS8+ICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgIDwvZGl2PlxyXG4gICAgICAgICAgICAgICAgICAgICk6IChcclxuICAgICAgICAgICAgICAgICAgICAgICAgPExhYmVsIGNsYXNzTmFtZT1cInZhbHVlXCIgY2hlY2s+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkSGF6YXJkICYmIHNlbGVjdGVkSGF6YXJkPy50aXRsZSAhPT0gJy1Ob25lLScgPyAoc2VsZWN0ZWRIYXphcmQudGl0bGUrIGAgKCR7c2VsZWN0ZWRIYXphcmQudHlwZX0pYCk6ICctTm9uZS0nXHJcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgICAgIDwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgIH0gIFxyXG4gICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICAgIDx0ciBjbGFzc05hbWU9XCJ0ZC11bmRlclwiPiAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgIDx0ZD48TGFiZWwgY2xhc3NOYW1lPVwidGl0bGVcIiBjaGVjaz5TdGF0dXM6IDwvTGFiZWw+PC90ZD5cclxuICAgICAgICAgICAgICAgIDx0ZD5cclxuICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgIGlzRWRpdGluZyA/IChcclxuICAgICAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzc05hbWU9J2RhdGEtZHJvcGRvd24nPlxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIDxDbHNzRHJvcGRvd24gaXRlbXM9e3N0YXR1c2VzfSBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGl0ZW09e3N0YXR1c30gXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBtZW51V2lkdGg9eyczMDBweCd9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBkZWxldGFibGU9e2ZhbHNlfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgc2V0SXRlbT17c2V0U3RhdHVzfS8+ICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAgICAgICAgICApOiAoXHJcbiAgICAgICAgICAgICAgICAgICAgICA8TGFiZWwgY2xhc3NOYW1lPVwidmFsdWVcIiBjaGVjaz57c3RhdHVzPy5uYW1lfTwvTGFiZWw+XHJcbiAgICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgICB9ICBcclxuICAgICAgICAgICAgICAgIDwvdGQ+XHJcbiAgICAgICAgICAgICAgPC90cj5cclxuICAgICAgICAgICAgPC90YWJsZT4gICAgICAgICBcclxuXHJcbiAgICAgICAgICAgIDx0YWJsZSBjbGFzc05hbWU9XCJ0ZW1wbGF0ZS1kZXRhaWwtaGVhZGVyLXRhYmxlXCI+XHJcbiAgICAgICAgICAgICAgPHRyIGNsYXNzTmFtZT1cInRkLXVuZGVyXCI+XHJcbiAgICAgICAgICAgICAgICA8dGQ+IDxMYWJlbCBjaGVjaz5BdXRob3I6IDwvTGFiZWw+PC90ZD5cclxuICAgICAgICAgICAgICAgIDx0ZD5cclxuICAgICAgICAgICAgICAgICAgICA8TGFiZWwgZGF0YS10ZXN0aWQ9XCJsYmxUZW1wbGF0ZU5hbWVcIiBcclxuICAgICAgICAgICAgICAgICAgICBjbGFzc05hbWU9XCJ2YWx1ZVwiIGNoZWNrPnt0ZW1wbGF0ZT8uY3JlYXRvcn0gPC9MYWJlbD4gICAgIFxyXG4gICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICAgIDx0ciBjbGFzc05hbWU9XCJ0ZC11bmRlclwiPlxyXG4gICAgICAgICAgICAgICAgPHRkPjxMYWJlbCBjbGFzc05hbWU9XCJ0aXRsZVwiIGNoZWNrPkRhdGUgQ3JlYXRlZDogPC9MYWJlbD48L3RkPlxyXG4gICAgICAgICAgICAgICAgPHRkPlxyXG4gICAgICAgICAgICAgICAgICAgPExhYmVsIGRhdGEtdGVzdGlkPVwibGJsVGVtcGxhdGVOYW1lXCIgXHJcbiAgICAgICAgICAgICAgICAgICBjbGFzc05hbWU9XCJ2YWx1ZVwiIGNoZWNrPntwYXJzZURhdGUodGVtcGxhdGU/LmNyZWF0ZWREYXRlKX0gPC9MYWJlbD4gICAgIFxyXG4gICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICAgIDx0ciBjbGFzc05hbWU9XCJ0ZC11bmRlclwiPlxyXG4gICAgICAgICAgICAgICAgPHRkPjxMYWJlbCBjbGFzc05hbWU9XCJ0aXRsZVwiIGNoZWNrPkxhc3QgVXBkYXRlZDogPC9MYWJlbD48L3RkPlxyXG4gICAgICAgICAgICAgICAgPHRkPlxyXG4gICAgICAgICAgICAgICAgICAgPExhYmVsIGRhdGEtdGVzdGlkPVwibGJsVGVtcGxhdGVOYW1lXCIgXHJcbiAgICAgICAgICAgICAgICAgICBjbGFzc05hbWU9XCJ2YWx1ZVwiIGNoZWNrPntwYXJzZURhdGUodGVtcGxhdGU/LmVkaXRlZERhdGUpfSB7dGVtcGxhdGUuZWRpdG9yID8gJyBieSAnICsgdGVtcGxhdGUuZWRpdG9yOiAnLSd9PC9MYWJlbD4gICAgIFxyXG4gICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICAgIDx0ciBjbGFzc05hbWU9XCJ0ZC11bmRlclwiPlxyXG4gICAgICAgICAgICAgICAgPHRkPiA8TGFiZWwgY2xhc3NOYW1lPVwidGl0bGVcIiBjaGVjaz5Bc3Nlc3NtZW50czogPC9MYWJlbD48L3RkPlxyXG4gICAgICAgICAgICAgICAgPHRkPiBcclxuICAgICAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgICAgICBhc3Nlc3NtZW50cyAmJiBhc3Nlc3NtZW50cy5sZW5ndGggPiAwID9cclxuICAgICAgICAgICAgICAgICAgICAgKFxyXG4gICAgICAgICAgICAgICAgICAgICAgPEJ1dHRvbiBvbkNsaWNrPXsoKT0+IHNldFRvZ2dsZUFzc2Vzc21lbnRWaXNpYmlsaXR5KHRydWUpfSBzdHlsZT17e2ZvbnRTaXplOiAnMS41ZW0nLCBcclxuICAgICAgICAgICAgICAgIHBhZGRpbmc6MCwgZm9udFdlaWdodDogJ2JvbGQnfX0gdHlwZT1cImxpbmtcIj5DbGljayBoZXJlIHRvIHZpZXcgdGhlIGFzc2Vzc21lbnRzICh7YXNzZXNzbWVudHM/Lmxlbmd0aH0pPC9CdXR0b24+XHJcbiAgICAgICAgICAgICAgICAgICAgICk6IDxMYWJlbCBkYXRhLXRlc3RpZD1cImxibFRlbXBsYXRlTmFtZVwiIFxyXG4gICAgICAgICAgICAgICAgICAgICBjbGFzc05hbWU9XCJ2YWx1ZVwiIGNoZWNrPi1Ob25lLTwvTGFiZWw+ICAgXHJcbiAgICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgICAgICAgPC90ZD5cclxuICAgICAgICAgICAgICA8L3RyPlxyXG4gICAgICAgICAgICA8L3RhYmxlPiBcclxuXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICBhbGxvd1RvRWRpdCAmJiBpc0VkaXRpbmcgPyAoXHJcbiAgICAgICAgICAgICAgICA8ZGl2ICBjbGFzc05hbWU9XCJzYXZlLWNhbmNlbFwiIHN0eWxlPXt7ZGlzcGxheTogJ2ZsZXgnLCBmbGV4RGlyZWN0aW9uOiAnY29sdW1uJ319PlxyXG4gICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgPENsb3NlT3V0bGluZWQgZGF0YS10ZXN0aWQ9XCJidG5DYW5jZWxFZGl0c1wiIHNpemU9ezI1fSBjbGFzc05hbWU9J2VkaXRvci1pY29uJyBcclxuICAgICAgICAgICAgICAgICAgICBzdHlsZT17e2NvbG9yOiAnIzUzNGM0YycsIGZvbnRXZWlnaHQ6ICdib2xkJ319IFxyXG4gICAgICAgICAgICAgICAgICAgIHRpdGxlPVwiQ2FuY2VsIEVkaXRzXCIgb25DbGljaz17KCkgPT4gb25DYW5jZWwoKX0vPlxyXG5cclxuICAgICAgICAgICAgICAgICAgPFNhdmVGaWxsZWQgc2l6ZT17MjV9IGRhdGEtdGVzdGlkPVwiYnRuU2F2ZUVkaXRzXCIgY2xhc3NOYW1lPSdlZGl0b3ItaWNvbicgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgb25DbGljaz17KCkgPT4gb25TYXZlVGVtcGxhdGVIZWFkZXJFZGl0cygpfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHN0eWxlPXt7Y29sb3I6ICcjNTM0YzRjJywgZm9udFdlaWdodDogJ2JvbGQnfX0gdGl0bGU9J1NhdmUnLz5cclxuICAgICAgICAgICAgICAgIDwvZGl2PiAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgKSA6XHJcbiAgICAgICAgICAgICAgKFxyXG4gICAgICAgICAgICAgICAgYWxsb3dUb0VkaXQgP1xyXG4gICAgICAgICAgICAgICAgKFxyXG4gICAgICAgICAgICAgICAgICA8RWRpdE91dGxpbmVkIGRhdGEtdGVzdGlkPVwiYnRuU3RhcnRFZGl0aW5nXCIgc2l6ZT17MzB9IGNsYXNzTmFtZT0nZWRpdG9yLWljb24gc2F2ZS1pY29uJyBcclxuICAgICAgICAgICAgICAgICAgb25DbGljaz17KCkgPT4gc2V0RWRpdGluZyh0cnVlKX1cclxuICAgICAgICAgICAgICAgICAgc3R5bGU9e3tjb2xvcjogJyM1MzRjNGMnfX0gdGl0bGU9J0VkaXQnLz5cclxuICAgICAgICAgICAgICAgICk6IG51bGxcclxuICAgICAgICAgICAgICApICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgfSAgXHJcbiAgICAgICAgICAgIHtcclxuICAgICAgICAgICAgICAoIXRlbXBsYXRlIHx8IGxvYWRpbmcpID8gPENsc3NMb2FkaW5nLz4gOiBudWxsICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICA8VGVtcGxhdGVBc3Nlc3NtZW50Vmlld1xyXG4gICAgICAgICAgICAgIGlzVmlzaWJsZT17aXNBc3Nlc3NtZW50c1Zpc2liaWxpdHl9XHJcbiAgICAgICAgICAgICAgdG9nZ2xlPXtzZXRUb2dnbGVBc3Nlc3NtZW50VmlzaWJpbGl0eX1cclxuICAgICAgICAgICAgICBhc3Nlc3NtZW50cz17YXNzZXNzbWVudHN9Lz5cclxuICAgICAgPC9kaXY+ICAgICAgXHJcbiAgICApXHJcbn0iLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV9hcmNnaXNfXzsiLCJtb2R1bGUuZXhwb3J0cyA9IF9fV0VCUEFDS19FWFRFUk5BTF9NT0RVTEVfamltdV9jb3JlX187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX3JlYWN0X187IiwibW9kdWxlLmV4cG9ydHMgPSBfX1dFQlBBQ0tfRVhURVJOQUxfTU9EVUxFX2ppbXVfdWlfXzsiLCIvLyBUaGUgbW9kdWxlIGNhY2hlXG52YXIgX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fID0ge307XG5cbi8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG5mdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuXHR2YXIgY2FjaGVkTW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXTtcblx0aWYgKGNhY2hlZE1vZHVsZSAhPT0gdW5kZWZpbmVkKSB7XG5cdFx0cmV0dXJuIGNhY2hlZE1vZHVsZS5leHBvcnRzO1xuXHR9XG5cdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG5cdHZhciBtb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdID0ge1xuXHRcdC8vIG5vIG1vZHVsZS5pZCBuZWVkZWRcblx0XHQvLyBubyBtb2R1bGUubG9hZGVkIG5lZWRlZFxuXHRcdGV4cG9ydHM6IHt9XG5cdH07XG5cblx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG5cdF9fd2VicGFja19tb2R1bGVzX19bbW9kdWxlSWRdKG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG5cdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG5cdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbn1cblxuIiwiLy8gZ2V0RGVmYXVsdEV4cG9ydCBmdW5jdGlvbiBmb3IgY29tcGF0aWJpbGl0eSB3aXRoIG5vbi1oYXJtb255IG1vZHVsZXNcbl9fd2VicGFja19yZXF1aXJlX18ubiA9IChtb2R1bGUpID0+IHtcblx0dmFyIGdldHRlciA9IG1vZHVsZSAmJiBtb2R1bGUuX19lc01vZHVsZSA/XG5cdFx0KCkgPT4gKG1vZHVsZVsnZGVmYXVsdCddKSA6XG5cdFx0KCkgPT4gKG1vZHVsZSk7XG5cdF9fd2VicGFja19yZXF1aXJlX18uZChnZXR0ZXIsIHsgYTogZ2V0dGVyIH0pO1xuXHRyZXR1cm4gZ2V0dGVyO1xufTsiLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiX193ZWJwYWNrX3JlcXVpcmVfXy5wID0gXCJcIjsiLCIvKipcclxuICogV2VicGFjayB3aWxsIHJlcGxhY2UgX193ZWJwYWNrX3B1YmxpY19wYXRoX18gd2l0aCBfX3dlYnBhY2tfcmVxdWlyZV9fLnAgdG8gc2V0IHRoZSBwdWJsaWMgcGF0aCBkeW5hbWljYWxseS5cclxuICogVGhlIHJlYXNvbiB3aHkgd2UgY2FuJ3Qgc2V0IHRoZSBwdWJsaWNQYXRoIGluIHdlYnBhY2sgY29uZmlnIGlzOiB3ZSBjaGFuZ2UgdGhlIHB1YmxpY1BhdGggd2hlbiBkb3dubG9hZC5cclxuICogKi9cclxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lXHJcbi8vIEB0cy1pZ25vcmVcclxuX193ZWJwYWNrX3B1YmxpY19wYXRoX18gPSB3aW5kb3cuamltdUNvbmZpZy5iYXNlVXJsXHJcbiIsImltcG9ydCB7IFJlYWN0LCBBbGxXaWRnZXRQcm9wcywgUmVhY3RSZWR1eCwgZ2V0QXBwU3RvcmUgfSBmcm9tICdqaW11LWNvcmUnO1xyXG5pbXBvcnQgeyBJTUNvbmZpZyB9IGZyb20gJy4uL2NvbmZpZyc7XHJcbmltcG9ydCB7IENMU1NUZW1wbGF0ZSwgXHJcbiAgQ29tcG9uZW50VGVtcGxhdGUsXHJcbiAgIEhhemFyZCxcclxuICAgTGlmZUxpbmVUZW1wbGF0ZSxcclxuICAgT3JnYW5pemF0aW9ufSBmcm9tICcuLi8uLi8uLi9jbHNzLWFwcGxpY2F0aW9uL3NyYy9leHRlbnNpb25zL2RhdGEtZGVmaW5pdGlvbnMnO1xyXG5pbXBvcnQgQ2xzc0xvYWRpbmcgZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLWxvYWRpbmcnO1xyXG5pbXBvcnQgeyBDTFNTQWN0aW9uS2V5cyB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvY2xzcy1zdG9yZSc7XHJcbmltcG9ydCB7IGRpc3BhdGNoQWN0aW9uLCBcclxuICBnZXRUZW1wbGF0ZXNcclxuICB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtYXBwbGljYXRpb24vc3JjL2V4dGVuc2lvbnMvYXBpJztcclxuaW1wb3J0IENsc3NFcnJvcnNQYW5lbCBmcm9tICcuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtZXJyb3JzLXBhbmVsJztcclxuaW1wb3J0IHsgRGV0YWlsSGVhZGVyV2lkZ2V0IH0gZnJvbSAnLi9oZWFkZXInO1xyXG5pbXBvcnQgeyBUYWIsIFRhYnMgfSBmcm9tICdqaW11LXVpJztcclxuaW1wb3J0IHsgTGlmZWxpbmVDb21wb25lbnQgfSBmcm9tICcuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtbGlmZWxpbmUtY29tcG9uZW50JztcclxuaW1wb3J0IHsgQWRkT3JnYW5pemF0b25XaWRnZXQgfSBmcm9tICcuLi8uLi8uLi9jbHNzLWN1c3RvbS1jb21wb25lbnRzL2Nsc3MtYWRkLW9yZ2FuaXphdGlvbic7XHJcbmltcG9ydCB7IEFkZEhhemFyZFdpZGdldCB9IGZyb20gJy4uLy4uLy4uL2Nsc3MtY3VzdG9tLWNvbXBvbmVudHMvY2xzcy1hZGQtaGF6YXJkJztcclxuaW1wb3J0IENsc3NOb0RhdGEgZnJvbSAnLi4vLi4vLi4vY2xzcy1jdXN0b20tY29tcG9uZW50cy9jbHNzLW5vLWRhdGEnO1xyXG5jb25zdCB7IHVzZVNlbGVjdG9yIH0gPSBSZWFjdFJlZHV4O1xyXG5cclxuY29uc3QgV2lkZ2V0ID0gKHByb3BzOiBBbGxXaWRnZXRQcm9wczxJTUNvbmZpZz4pID0+IHtcclxuIFxyXG4gIGNvbnN0IFtsb2FkaW5nLCBzZXRMb2FkaW5nXSA9IFJlYWN0LnVzZVN0YXRlPGJvb2xlYW4+KGZhbHNlKTtcclxuICBjb25zdCBbY29uZmlnLCBzZXRDb25maWddID0gUmVhY3QudXNlU3RhdGUobnVsbCk7XHJcbiAgY29uc3QgW2lzQWRkT3JnYW5pemF0aW9uTW9kYWxWaXNpYmxlLCBzZXRBZGRPcmdhbml6YXRpb25Nb2RhbFZpc2liaWxpdHldID0gUmVhY3QudXNlU3RhdGUoZmFsc2UpO1xyXG4gIGNvbnN0IFtpc0FkZEhhemFyZE1vZGFsVmlzaWJsZSwgc2V0QWRkSGF6YXJkTW9kYWxWaXNpYmlsaXR5XSA9IFJlYWN0LnVzZVN0YXRlKGZhbHNlKTtcclxuICBjb25zdCBbc2VsZWN0ZWRIYXphcmQsIHNldFNlbGVjdGVkSGF6YXJkXT1SZWFjdC51c2VTdGF0ZTxIYXphcmQ+KG51bGwpO1xyXG4gIGNvbnN0IFtzZWxlY3RlZE9yZ2FuaXphdGlvbiwgc2V0U2VsZWN0ZWRPcmdhbml6YXRpb25dPVJlYWN0LnVzZVN0YXRlPE9yZ2FuaXphdGlvbj4obnVsbCk7XHJcbiAgIFxyXG4gIGNvbnN0IGVycm9ycyA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5lcnJvcnM7XHJcbiAgfSlcclxuXHJcbiAgY29uc3QgdGVtcGxhdGUgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgcmV0dXJuIHN0YXRlPy5jbHNzU3RhdGU/LnRlbXBsYXRlcy5maW5kKHQgPT4gdC5pc1NlbGVjdGVkKSBhcyBDTFNTVGVtcGxhdGU7XHJcbiAgfSlcclxuXHJcbiAgY29uc3QgY3JlZGVudGlhbCA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5hdXRoZW50aWNhdGU7XHJcbiAgfSlcclxuXHJcbiAgY29uc3QgaGF6YXJkcyA9IHVzZVNlbGVjdG9yKChzdGF0ZTogYW55KSA9PiB7XHJcbiAgICByZXR1cm4gc3RhdGUuY2xzc1N0YXRlPy5oYXphcmRzIGFzIEhhemFyZFtdO1xyXG4gIH0pXHJcblxyXG4gIGNvbnN0IG9yZ2FuaXphdGlvbnMgPSB1c2VTZWxlY3Rvcigoc3RhdGU6IGFueSkgPT4ge1xyXG4gICAgcmV0dXJuIHN0YXRlLmNsc3NTdGF0ZT8ub3JnYW5pemF0aW9ucyBhcyBPcmdhbml6YXRpb25bXTtcclxuICB9KVxyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgaWYoY3JlZGVudGlhbCl7XHJcbiAgICAgICBzZXRDb25maWcoey4uLnByb3BzLmNvbmZpZywgY3JlZGVudGlhbDogY3JlZGVudGlhbH0pXHJcbiAgICB9XHJcbiAgfSwgW2NyZWRlbnRpYWxdKVxyXG5cclxuICBSZWFjdC51c2VFZmZlY3QoKCkgPT4ge1xyXG4gICAgaWYodGVtcGxhdGUgJiYgb3JnYW5pemF0aW9ucyAmJiBvcmdhbml6YXRpb25zLmxlbmd0aCA+IDApeyAgICAgXHJcbiAgICAgICBzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbihvcmdhbml6YXRpb25zLmZpbmQobyA9PiBvLm5hbWUgPT09IHRlbXBsYXRlLm9yZ2FuaXphdGlvbk5hbWUpKVxyXG4gICAgfVxyXG4gIH0sIFt0ZW1wbGF0ZSwgb3JnYW5pemF0aW9uc10pXHJcblxyXG4gIFJlYWN0LnVzZUVmZmVjdCgoKSA9PiB7XHJcbiAgICBpZih0ZW1wbGF0ZSAmJiBoYXphcmRzICYmIGhhemFyZHMubGVuZ3RoID4gMCl7XHJcbiAgICAgICBzZXRTZWxlY3RlZEhhemFyZChoYXphcmRzLmZpbmQoaCA9PiBoLm5hbWUgPT09IHRlbXBsYXRlLmhhemFyZE5hbWUpKVxyXG4gICAgfVxyXG4gIH0sIFt0ZW1wbGF0ZSwgaGF6YXJkc10pXHJcblxyXG4gIGNvbnN0IGNsb3NlRXJyb3I9KCk9PiB7XHJcbiAgICBnZXRBcHBTdG9yZSgpLmRpc3BhdGNoKHtcclxuICAgICAgdHlwZTogQ0xTU0FjdGlvbktleXMuU0VUX0VSUk9SUyxcclxuICAgICAgdmFsOiAnJ1xyXG4gICAgfSlcclxuICB9XHJcblxyXG4gIGNvbnN0IGxvYWRUZW1wbGF0ZXMgPWFzeW5jICgpPT57XHJcbiAgICBjb25zdCBzZWxlY3RlZFRlbXBsYXRlID0gdGVtcGxhdGUgPyB7Li4udGVtcGxhdGV9IDogbnVsbDtcclxuXHJcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGdldFRlbXBsYXRlcyhjb25maWcpO1xyXG5cclxuICAgIGxldCBmZXRjaERhdGEgPSByZXNwb25zZS5kYXRhO1xyXG4gICAgaWYocmVzcG9uc2UuZGF0YSl7XHJcbiAgICAgIGlmKHNlbGVjdGVkVGVtcGxhdGUpe1xyXG4gICAgICAgIGZldGNoRGF0YSA9IHJlc3BvbnNlLmRhdGEubWFwKHQgPT4ge1xyXG4gICAgICAgICAgIHJldHVybiB7XHJcbiAgICAgICAgICAgIC4uLnQsXHJcbiAgICAgICAgICAgIGlzU2VsZWN0ZWQ6IHQuaWQgPT09IHNlbGVjdGVkVGVtcGxhdGUuaWRcclxuICAgICAgICAgICB9XHJcbiAgICAgICAgfSlcclxuICAgICAgfVxyXG4gICAgICBkaXNwYXRjaEFjdGlvbihDTFNTQWN0aW9uS2V5cy5MT0FEX1RFTVBMQVRFU19BQ1RJT04sIGZldGNoRGF0YSk7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcmVzcG9uc2U7XHJcbiAgfVxyXG5cclxuICBjb25zdCBvbkluZGljYXRvckFjdGlvbkNvbXBsZXRlPWFzeW5jKHJlbG9hZD86Ym9vbGVhbik9PnsgICAgXHJcbiAgICBpZihyZWxvYWQpe1xyXG4gICAgICBhd2FpdCBsb2FkVGVtcGxhdGVzKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBpZihsb2FkaW5nKXsgICAgXHJcbiAgICByZXR1cm4gPENsc3NMb2FkaW5nLz5cclxuICB9IFxyXG5cclxuICBpZih0ZW1wbGF0ZSA9PSBudWxsKXsgICAgXHJcbiAgICByZXR1cm4gPENsc3NOb0RhdGEgbWVzc2FnZT0nU2VsZWN0IGEgdGVtcGxhdGUgdG8gdmlldyBkZXRhaWxzJy8+XHJcbiAgfSBcclxuIFxyXG4gIHJldHVybiAoXHJcbiAgICA8ZGl2IGNsYXNzTmFtZT1cIndpZGdldC10ZW1wbGF0ZS1kZXRhaWxcIlxyXG4gICAgICBzdHlsZT17XHJcbiAgICAgICAge1xyXG4gICAgICAgICAgYmFja2dyb3VuZENvbG9yOiBwcm9wcy5jb25maWcuYmFja2dvdW5kQ29sb3JcclxuICAgICAgfX0+XHJcbiAgICAgIDxzdHlsZT5cclxuICAgICAgICB7YFxyXG4gICAgICAgICAgLndpZGdldC10ZW1wbGF0ZS1kZXRhaWwge1xyXG4gICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgaGVpZ2h0OiAxMDAlO1xyXG4gICAgICAgICAgICBwYWRkaW5nOiAyMHB4O1xyXG4gICAgICAgICAgICBvdmVyZmxvdzogYXV0bztcclxuICAgICAgICAgICAgcG9zaXRpb246IHJlbGF0aXZlOyAgICAgICAgICAgIFxyXG4gICAgICAgICAgfVxyXG5cclxuICAgICAgICAgIC5lcnJvci1wYW5lbCB7XHJcbiAgICAgICAgICAgIHBvc2l0aW9uOiBhYnNvbHV0ZTtcclxuICAgICAgICAgICAgbGVmdDogMDtcclxuICAgICAgICAgICAgdG9wOiAwO1xyXG4gICAgICAgICAgICB3aWR0aDogMTAwJTtcclxuICAgICAgICAgICAgei1pbmRleDogOTk5XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICBcclxuICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnR7XHJcbiAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICBoZWlnaHQ6IDEwMCU7IFxyXG4gICAgICAgICAgICBkaXNwbGF5OiBmbGV4O1xyXG4gICAgICAgICAgICBmbGV4LWRpcmVjdGlvbjogY29sdW1uO1xyXG4gICAgICAgICAgICBhbGlnbi1pdGVtczogY2VudGVyOyAgIFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgICBcclxuICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtaGVhZGVye1xyXG4gICAgICAgICAgICBib3JkZXItcmFkaXVzOiAxMHB4IDEwcHggMCAwO1xyXG4gICAgICAgICAgICBwYWRkaW5nOiAzMHB4IDUwcHg7XHJcbiAgICAgICAgICAgIHdpZHRoOiAxMDAlO1xyXG4gICAgICAgICAgICBwb3NpdGlvbjpyZWxhdGl2ZTsgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICBtYXJnaW4tYm90dG9tOiAxMHB4O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgXHJcbiAgICAgICAgICAuaGVhZGVyLXJvd3tcclxuICAgICAgICAgICAgZGlzcGxheTogZmxleDsgICBcclxuICAgICAgICAgICAgbWFyZ2luLWJvdHRvbTogMTBweDsgICAgICAgICAgIFxyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmhlYWRlci1yb3cgbGFiZWx7XHJcbiAgICAgICAgICAgIGZvbnQtc2l6ZTogMS42ZW07XHJcbiAgICAgICAgICAgIGNvbG9yOiAjNGQ0OTQ5O1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmhlYWRlci1yb3cgLnZhbHVle1xyXG4gICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC5oZWFkZXItcm93IC50aXRsZXtcclxuICAgICAgICAgICAgIHdpZHRoOiAxNjVweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC5kZXRhaWxzLWNvbnRlbnQtZGF0YXtcclxuICAgICAgICAgICAgaGVpZ2h0OiAxMDAlO1xyXG4gICAgICAgICAgICBtYXJnaW4tdG9wOiAyMHB4O1xyXG4gICAgICAgICAgICBwYWRkaW5nOiAwO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmRldGFpbHMtY29udGVudC1kYXRhLWhlYWRlcnsgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgIGhlaWdodDogNzVweDtcclxuICAgICAgICAgICAgd2lkdGg6IDEwMCU7XHJcbiAgICAgICAgICAgIGJhY2tncm91bmQ6ICM1MzRjNGM4MDtcclxuICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogMTBweCAxMHB4IDAgMDtcclxuICAgICAgICAgICAgZGlzcGxheTogZmxleDtcclxuICAgICAgICAgICAganVzdGlmeS1jb250ZW50OiBjZW50ZXI7XHJcbiAgICAgICAgICAgIGFsaWduLWl0ZW1zOiBjZW50ZXI7XHJcbiAgICAgICAgICAgIHBhZGRpbmc6IDAgMTBweDtcclxuICAgICAgICAgICAgdGV4dC1hbGlnbjogY2VudGVyO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmRldGFpbHMtY29udGVudC1kYXRhLWhlYWRlciBsYWJlbHtcclxuICAgICAgICAgICAgZm9udC1zaXplOiAxLjZlbTtcclxuICAgICAgICAgICAgY29sb3I6IHdoaXRlO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgLmxpZmVsaW5lcy10YWJze1xyXG4gICAgICAgICAgICB3aWR0aDogMTAwJTsgICAgICAgICAgICAgXHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICAubGlmZWxpbmVzLXRhYnMgLnRhYi10aXRsZXtcclxuICAgICAgICAgICAgZm9udC1zaXplOiAxNXB4O1xyXG4gICAgICAgICAgICBmb250LXdlaWdodDogYm9sZDtcclxuICAgICAgICAgICAgcGFkZGluZzogMTBweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC5saWZlbGluZXMtdGFicyAubmF2LWl0ZW17XHJcbiAgICAgICAgICAgIGhlaWdodDogNDBweDtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIC5saWZlbGluZS10YWItY29udGVudHtcclxuICAgICAgICAgICAgcGFkZGluZzogMTBweDtcclxuICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogd2hpdGU7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgYH1cclxuICAgICAgPC9zdHlsZT5cclxuICAgICAgPGRpdiBjbGFzc05hbWU9XCJkZXRhaWxzLWNvbnRlbnRcIj5cclxuICAgICAgICB7XHJcbiAgICAgICAgICBlcnJvcnMgJiYgIWxvYWRpbmcgPyAoXHJcbiAgICAgICAgICAgIDxkaXYgY2xhc3NOYW1lPSdlcnJvci1wYW5lbCc+XHJcbiAgICAgICAgICAgICAgPENsc3NFcnJvcnNQYW5lbCBjbG9zZT17Y2xvc2VFcnJvcn0gZXJyb3JzPXtlcnJvcnN9Lz5cclxuICAgICAgICAgICAgPC9kaXY+XHJcbiAgICAgICAgICApOiBudWxsXHJcbiAgICAgICAgfSAgICAgIFxyXG4gICAgICAgIFxyXG4gICAgICAgIDxEZXRhaWxIZWFkZXJXaWRnZXQgXHJcbiAgICAgICAgICB0ZW1wbGF0ZT17dGVtcGxhdGV9IFxyXG4gICAgICAgICAgb3JnYW5pemF0aW9ucz17b3JnYW5pemF0aW9uc31cclxuICAgICAgICAgIGhhemFyZHM9e2hhemFyZHN9XHJcbiAgICAgICAgICBvbkFjdGlvbkNvbXBsZXRlPXtvbkluZGljYXRvckFjdGlvbkNvbXBsZXRlfVxyXG4gICAgICAgICAgY29uZmlnPXtjb25maWd9XHJcbiAgICAgICAgICBzZWxlY3RlZE5ld0hhemFyZD17c2VsZWN0ZWRIYXphcmR9XHJcbiAgICAgICAgICBzZWxlY3RlZE5ld09yZ2FuaXphdGlvbj17c2VsZWN0ZWRPcmdhbml6YXRpb259IFxyXG4gICAgICAgICAgdG9nZ2xlSGF6YXJkTW9kYWxWaXNpYmlsaXR5PXtzZXRBZGRIYXphcmRNb2RhbFZpc2liaWxpdHl9XHJcbiAgICAgICAgICB0b2dnbGVPcmdhbml6YXRpb25Nb2RhbFZpc2liaWxpdHk9e3NldEFkZE9yZ2FuaXphdGlvbk1vZGFsVmlzaWJpbGl0eX0vPiBcclxuXHJcbiAgICAgICAgPGRpdiBjbGFzc05hbWU9J2xpZmVsaW5lcy10YWJzJz5cclxuICAgICAgICAgIDxUYWJzIGRlZmF1bHRWYWx1ZT1cInRhYi0xXCIgZmlsbCB0eXBlPVwidGFic1wiPiAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAge1xyXG4gICAgICAgICAgICAgICAgdGVtcGxhdGU/LmxpZmVsaW5lVGVtcGxhdGVzLm1hcCgoKGxpZmVsaW5lOiBMaWZlTGluZVRlbXBsYXRlKSA9PiB7XHJcbiAgICAgICAgICAgICAgICAgIHJldHVybiAoXHJcbiAgICAgICAgICAgICAgICAgICAgPFRhYiBpZD0ge2xpZmVsaW5lPy5pZH0ga2V5PXtsaWZlbGluZT8uaWR9IHRpdGxlPXtsaWZlbGluZS50aXRsZX0+XHJcbiAgICAgICAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzTmFtZT1cImxpZmVsaW5lLXRhYi1jb250ZW50XCI+XHJcbiAgICAgICAgICAgICAgICAgICAgICAgIHsgICAgICAgICAgICAgICAgICAgICAgICAgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGxpZmVsaW5lPy5jb21wb25lbnRUZW1wbGF0ZXM/Lm1hcCgoKGxpZmVsaW5lQ29tcDogQ29tcG9uZW50VGVtcGxhdGUpID0+IHsgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuICg8TGlmZWxpbmVDb21wb25lbnQgIFxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAga2V5PXtsaWZlbGluZUNvbXAuaWR9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBsaWZlbGluZT17bGlmZWxpbmV9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb21wb25lbnQ9IHtsaWZlbGluZUNvbXB9XHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZW1wbGF0ZT17dGVtcGxhdGV9ICBcclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbmZpZz17Y29uZmlnfVxyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgb25BY3Rpb25Db21wbGV0ZT17b25JbmRpY2F0b3JBY3Rpb25Db21wbGV0ZX1cclxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvPilcclxuICAgICAgICAgICAgICAgICAgICAgICAgICB9KSlcclxuICAgICAgICAgICAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgICAgICAgICAgXHJcbiAgICAgICAgICAgICAgICAgICAgICA8L2Rpdj5cclxuICAgICAgICAgICAgICAgICAgICA8L1RhYj5cclxuICAgICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgfSkpXHJcbiAgICAgICAgICAgICAgfSAgICAgICAgICAgICAgXHJcbiAgICAgICAgICA8L1RhYnM+XHJcbiAgICAgICAgPC9kaXY+XHJcbiAgICAgIDwvZGl2PiAgXHJcblxyXG4gICAgICA8QWRkT3JnYW5pemF0b25XaWRnZXQgXHJcbiAgICAgICAgICBwcm9wc0NvbmZpZz17cHJvcHM/LmNvbmZpZ31cclxuICAgICAgICAgIHZpc2libGU9e2lzQWRkT3JnYW5pemF0aW9uTW9kYWxWaXNpYmxlfVxyXG4gICAgICAgICAgc2V0T3JnYW5pemF0aW9uPXtzZXRTZWxlY3RlZE9yZ2FuaXphdGlvbn1cclxuICAgICAgICAgIHRvZ2dsZT17c2V0QWRkT3JnYW5pemF0aW9uTW9kYWxWaXNpYmlsaXR5fS8+IFxyXG5cclxuICAgICAgPEFkZEhhemFyZFdpZGdldCBcclxuICAgICAgICBwcm9wcz17cHJvcHN9XHJcbiAgICAgICAgdmlzaWJsZT17aXNBZGRIYXphcmRNb2RhbFZpc2libGV9XHJcbiAgICAgICAgc2V0SGF6YXJkPXtzZXRTZWxlY3RlZEhhemFyZH1cclxuICAgICAgICB0b2dnbGU9e3NldEFkZEhhemFyZE1vZGFsVmlzaWJpbGl0eX0vPiAgICBcclxuICAgIDwvZGl2PlxyXG4gICkgIFxyXG59XHJcbmV4cG9ydCBkZWZhdWx0IFdpZGdldFxyXG5cclxuXHJcbiJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==