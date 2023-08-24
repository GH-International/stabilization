System.register(["jimu-core","jimu-arcgis","jimu-ui","jimu-layouts/layout-runtime"],(function(e,t){var r={},i={},n={},a={};return{setters:[function(e){r.AppRoot=e.AppRoot,r.ExtensionManager=e.ExtensionManager,r.React=e.React,r.ReactDOM=e.ReactDOM,r.SessionManager=e.SessionManager,r.appActions=e.appActions,r.extensionSpec=e.extensionSpec,r.getAppStore=e.getAppStore,r.init=e.init,r.privilegeUtils=e.privilegeUtils},function(e){i.ArcGISDataSourceFactoryUriExtension=e.ArcGISDataSourceFactoryUriExtension,i.ArcGISDependencyDefineExtension=e.ArcGISDependencyDefineExtension,i.init=e.init},function(e){n.init=e.init},function(e){a.init=e.init}],execute:function(){e((()=>{"use strict";var e={826:e=>{e.exports=i},891:e=>{e.exports=r},758:e=>{e.exports=a},726:e=>{e.exports=n}},t={};function o(r){var i=t[r];if(void 0!==i)return i.exports;var n=t[r]={exports:{}};return e[r](n,n.exports,o),n.exports}o.r=e=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})};var s={};return(()=>{o.r(s);var e=o(891),t=o(826),r=o(726),i=o(758);const n=function(e,t){return e===t||e!=e&&t!=t},a=function(e,t){for(var r=e.length;r--;)if(n(e[r][0],t))return r;return-1};var l=Array.prototype.splice;function u(e){var t=-1,r=null==e?0:e.length;for(this.clear();++t<r;){var i=e[t];this.set(i[0],i[1])}}u.prototype.clear=function(){this.__data__=[],this.size=0},u.prototype.delete=function(e){var t=this.__data__,r=a(t,e);return!(r<0||(r==t.length-1?t.pop():l.call(t,r,1),--this.size,0))},u.prototype.get=function(e){var t=this.__data__,r=a(t,e);return r<0?void 0:t[r][1]},u.prototype.has=function(e){return a(this.__data__,e)>-1},u.prototype.set=function(e,t){var r=this.__data__,i=a(r,e);return i<0?(++this.size,r.push([e,t])):r[i][1]=t,this};const c=u,p="object"==typeof global&&global&&global.Object===Object&&global;var h="object"==typeof self&&self&&self.Object===Object&&self;const d=p||h||Function("return this")(),g=d.Symbol;var b=Object.prototype,f=b.hasOwnProperty,v=b.toString,y=g?g.toStringTag:void 0;var m=Object.prototype.toString;var w=g?g.toStringTag:void 0;const _=function(e){return null==e?void 0===e?"[object Undefined]":"[object Null]":w&&w in Object(e)?function(e){var t=f.call(e,y),r=e[y];try{e[y]=void 0;var i=!0}catch(e){}var n=v.call(e);return i&&(t?e[y]=r:delete e[y]),n}(e):function(e){return m.call(e)}(e)},k=function(e){var t=typeof e;return null!=e&&("object"==t||"function"==t)},z=function(e){if(!k(e))return!1;var t=_(e);return"[object Function]"==t||"[object GeneratorFunction]"==t||"[object AsyncFunction]"==t||"[object Proxy]"==t},S=d["__core-js_shared__"];var O,A=(O=/[^.]+$/.exec(S&&S.keys&&S.keys.IE_PROTO||""))?"Symbol(src)_1."+O:"";var E=Function.prototype.toString;var j=/^\[object .+?Constructor\]$/,T=Function.prototype,x=Object.prototype,L=T.toString,C=x.hasOwnProperty,D=RegExp("^"+L.call(C).replace(/[\\^$.*+?()[\]{}|]/g,"\\$&").replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g,"$1.*?")+"$");const I=function(e){return!(!k(e)||(t=e,A&&A in t))&&(z(e)?D:j).test(function(e){if(null!=e){try{return E.call(e)}catch(e){}try{return e+""}catch(e){}}return""}(e));var t},M=function(e,t){var r=function(e,t){return null==e?void 0:e[t]}(e,t);return I(r)?r:void 0},P=M(d,"Map"),R=M(Object,"create");var N=Object.prototype.hasOwnProperty;var V=Object.prototype.hasOwnProperty;function U(e){var t=-1,r=null==e?0:e.length;for(this.clear();++t<r;){var i=e[t];this.set(i[0],i[1])}}U.prototype.clear=function(){this.__data__=R?R(null):{},this.size=0},U.prototype.delete=function(e){var t=this.has(e)&&delete this.__data__[e];return this.size-=t?1:0,t},U.prototype.get=function(e){var t=this.__data__;if(R){var r=t[e];return"__lodash_hash_undefined__"===r?void 0:r}return N.call(t,e)?t[e]:void 0},U.prototype.has=function(e){var t=this.__data__;return R?void 0!==t[e]:V.call(t,e)},U.prototype.set=function(e,t){var r=this.__data__;return this.size+=this.has(e)?0:1,r[e]=R&&void 0===t?"__lodash_hash_undefined__":t,this};const B=U,F=function(e,t){var r,i,n=e.__data__;return("string"==(i=typeof(r=t))||"number"==i||"symbol"==i||"boolean"==i?"__proto__"!==r:null===r)?n["string"==typeof t?"string":"hash"]:n.map};function G(e){var t=-1,r=null==e?0:e.length;for(this.clear();++t<r;){var i=e[t];this.set(i[0],i[1])}}G.prototype.clear=function(){this.size=0,this.__data__={hash:new B,map:new(P||c),string:new B}},G.prototype.delete=function(e){var t=F(this,e).delete(e);return this.size-=t?1:0,t},G.prototype.get=function(e){return F(this,e).get(e)},G.prototype.has=function(e){return F(this,e).has(e)},G.prototype.set=function(e,t){var r=F(this,e),i=r.size;return r.set(e,t),this.size+=r.size==i?0:1,this};const H=G;function X(e){var t=this.__data__=new c(e);this.size=t.size}X.prototype.clear=function(){this.__data__=new c,this.size=0},X.prototype.delete=function(e){var t=this.__data__,r=t.delete(e);return this.size=t.size,r},X.prototype.get=function(e){return this.__data__.get(e)},X.prototype.has=function(e){return this.__data__.has(e)},X.prototype.set=function(e,t){var r=this.__data__;if(r instanceof c){var i=r.__data__;if(!P||i.length<199)return i.push([e,t]),this.size=++r.size,this;r=this.__data__=new H(i)}return r.set(e,t),this.size=r.size,this};const q=X,$=function(){try{var e=M(Object,"defineProperty");return e({},"",{}),e}catch(e){}}(),J=function(e,t,r){"__proto__"==t&&$?$(e,t,{configurable:!0,enumerable:!0,value:r,writable:!0}):e[t]=r},Y=function(e,t,r){(void 0!==r&&!n(e[t],r)||void 0===r&&!(t in e))&&J(e,t,r)},Z=function(e,t,r){for(var i=-1,n=Object(e),a=r(e),o=a.length;o--;){var s=a[++i];if(!1===t(n[s],s,n))break}return e};var W="object"==typeof exports&&exports&&!exports.nodeType&&exports,Q=W&&"object"==typeof module&&module&&!module.nodeType&&module,K=Q&&Q.exports===W?d.Buffer:void 0,ee=K?K.allocUnsafe:void 0;const te=d.Uint8Array,re=function(e,t){var r,i,n=t?(r=e.buffer,i=new r.constructor(r.byteLength),new te(i).set(new te(r)),i):e.buffer;return new e.constructor(n,e.byteOffset,e.length)};var ie=Object.create;const ne=function(){function e(){}return function(t){if(!k(t))return{};if(ie)return ie(t);e.prototype=t;var r=new e;return e.prototype=void 0,r}}(),ae=(oe=Object.getPrototypeOf,se=Object,function(e){return oe(se(e))});var oe,se,le=Object.prototype;const ue=function(e){var t=e&&e.constructor;return e===("function"==typeof t&&t.prototype||le)},ce=function(e){return null!=e&&"object"==typeof e},pe=function(e){return ce(e)&&"[object Arguments]"==_(e)};var he=Object.prototype,de=he.hasOwnProperty,ge=he.propertyIsEnumerable,be=pe(function(){return arguments}())?pe:function(e){return ce(e)&&de.call(e,"callee")&&!ge.call(e,"callee")};const fe=be,ve=Array.isArray,ye=function(e){return"number"==typeof e&&e>-1&&e%1==0&&e<=9007199254740991},me=function(e){return null!=e&&ye(e.length)&&!z(e)};var we="object"==typeof exports&&exports&&!exports.nodeType&&exports,_e=we&&"object"==typeof module&&module&&!module.nodeType&&module,ke=_e&&_e.exports===we?d.Buffer:void 0;const ze=(ke?ke.isBuffer:void 0)||function(){return!1};var Se=Function.prototype,Oe=Object.prototype,Ae=Se.toString,Ee=Oe.hasOwnProperty,je=Ae.call(Object);var Te={};Te["[object Float32Array]"]=Te["[object Float64Array]"]=Te["[object Int8Array]"]=Te["[object Int16Array]"]=Te["[object Int32Array]"]=Te["[object Uint8Array]"]=Te["[object Uint8ClampedArray]"]=Te["[object Uint16Array]"]=Te["[object Uint32Array]"]=!0,Te["[object Arguments]"]=Te["[object Array]"]=Te["[object ArrayBuffer]"]=Te["[object Boolean]"]=Te["[object DataView]"]=Te["[object Date]"]=Te["[object Error]"]=Te["[object Function]"]=Te["[object Map]"]=Te["[object Number]"]=Te["[object Object]"]=Te["[object RegExp]"]=Te["[object Set]"]=Te["[object String]"]=Te["[object WeakMap]"]=!1;var xe="object"==typeof exports&&exports&&!exports.nodeType&&exports,Le=xe&&"object"==typeof module&&module&&!module.nodeType&&module,Ce=Le&&Le.exports===xe&&p.process,De=function(){try{return Le&&Le.require&&Le.require("util").types||Ce&&Ce.binding&&Ce.binding("util")}catch(e){}}(),Ie=De&&De.isTypedArray;const Me=Ie?function(e){return function(t){return e(t)}}(Ie):function(e){return ce(e)&&ye(e.length)&&!!Te[_(e)]},Pe=function(e,t){if(("constructor"!==t||"function"!=typeof e[t])&&"__proto__"!=t)return e[t]};var Re=Object.prototype.hasOwnProperty;const Ne=function(e,t,r){var i=e[t];Re.call(e,t)&&n(i,r)&&(void 0!==r||t in e)||J(e,t,r)};var Ve=/^(?:0|[1-9]\d*)$/;const Ue=function(e,t){var r=typeof e;return!!(t=null==t?9007199254740991:t)&&("number"==r||"symbol"!=r&&Ve.test(e))&&e>-1&&e%1==0&&e<t};var Be=Object.prototype.hasOwnProperty;const Fe=function(e,t){var r=ve(e),i=!r&&fe(e),n=!r&&!i&&ze(e),a=!r&&!i&&!n&&Me(e),o=r||i||n||a,s=o?function(e,t){for(var r=-1,i=Array(e);++r<e;)i[r]=t(r);return i}(e.length,String):[],l=s.length;for(var u in e)!t&&!Be.call(e,u)||o&&("length"==u||n&&("offset"==u||"parent"==u)||a&&("buffer"==u||"byteLength"==u||"byteOffset"==u)||Ue(u,l))||s.push(u);return s};var Ge=Object.prototype.hasOwnProperty;const He=function(e){if(!k(e))return function(e){var t=[];if(null!=e)for(var r in Object(e))t.push(r);return t}(e);var t=ue(e),r=[];for(var i in e)("constructor"!=i||!t&&Ge.call(e,i))&&r.push(i);return r},Xe=function(e){return me(e)?Fe(e,!0):He(e)},qe=function(e){return function(e,t,r,i){var n=!r;r||(r={});for(var a=-1,o=t.length;++a<o;){var s=t[a],l=i?i(r[s],e[s],s,r,e):void 0;void 0===l&&(l=e[s]),n?J(r,s,l):Ne(r,s,l)}return r}(e,Xe(e))},$e=function(e,t,r,i,n,a,o){var s,l=Pe(e,r),u=Pe(t,r),c=o.get(u);if(c)Y(e,r,c);else{var p=a?a(l,u,r+"",e,t,o):void 0,h=void 0===p;if(h){var d=ve(u),g=!d&&ze(u),b=!d&&!g&&Me(u);p=u,d||g||b?ve(l)?p=l:ce(s=l)&&me(s)?p=function(e,t){var r=-1,i=e.length;for(t||(t=Array(i));++r<i;)t[r]=e[r];return t}(l):g?(h=!1,p=function(e,t){if(t)return e.slice();var r=e.length,i=ee?ee(r):new e.constructor(r);return e.copy(i),i}(u,!0)):b?(h=!1,p=re(u,!0)):p=[]:function(e){if(!ce(e)||"[object Object]"!=_(e))return!1;var t=ae(e);if(null===t)return!0;var r=Ee.call(t,"constructor")&&t.constructor;return"function"==typeof r&&r instanceof r&&Ae.call(r)==je}(u)||fe(u)?(p=l,fe(l)?p=qe(l):k(l)&&!z(l)||(p=function(e){return"function"!=typeof e.constructor||ue(e)?{}:ne(ae(e))}(u))):h=!1}h&&(o.set(u,p),n(p,u,i,a,o),o.delete(u)),Y(e,r,p)}},Je=function e(t,r,i,n,a){t!==r&&Z(r,(function(o,s){if(a||(a=new q),k(o))$e(t,r,s,i,e,n,a);else{var l=n?n(Pe(t,s),o,s+"",t,r,a):void 0;void 0===l&&(l=o),Y(t,s,l)}}),Xe)},Ye=function(e){return e},Ze=function(e,t,r){switch(r.length){case 0:return e.call(t);case 1:return e.call(t,r[0]);case 2:return e.call(t,r[0],r[1]);case 3:return e.call(t,r[0],r[1],r[2])}return e.apply(t,r)};var We=Math.max;const Qe=$?function(e,t){return $(e,"toString",{configurable:!0,enumerable:!1,value:(r=t,function(){return r}),writable:!0});var r}:Ye;var Ke=Date.now;const et=function(e){var t=0,r=0;return function(){var i=Ke(),n=16-(i-r);if(r=i,n>0){if(++t>=800)return arguments[0]}else t=0;return e.apply(void 0,arguments)}}(Qe),tt=function(e,t){return et(function(e,t,r){return t=We(void 0===t?e.length-1:t,0),function(){for(var i=arguments,n=-1,a=We(i.length-t,0),o=Array(a);++n<a;)o[n]=i[t+n];n=-1;for(var s=Array(t+1);++n<t;)s[n]=i[n];return s[t]=r(o),Ze(e,this,s)}}(e,t,Ye),e+"")},rt=(it=function(e,t,r){Je(e,t,r)},tt((function(e,t){var r=-1,i=t.length,a=i>1?t[i-1]:void 0,o=i>2?t[2]:void 0;for(a=it.length>3&&"function"==typeof a?(i--,a):void 0,o&&function(e,t,r){if(!k(r))return!1;var i=typeof t;return!!("number"==i?me(r)&&Ue(t,r.length):"string"==i&&t in r)&&n(r[t],e)}(t[0],t[1],o)&&(a=i<3?void 0:a,i=1),e=Object(e);++r<i;){var s=t[r];s&&it(e,s,r)}return e})));var it;window._cachedModules=window._cachedModules||{},window._cachedModules.EXB_OPTIMIZATION_INJECTION_CODES__APP_DEPENDENCIES_LOG__,window._cachedModules.EXB_OPTIMIZATION_INJECTION_CODES__IMPORT_APP_DEPENDENCIES;const nt=rt({},window._cachedModules,window._cachedModules.EXB_OPTIMIZATION_INJECTION_CODES__APP_DEPENDENCIES_MAP_OBJECT);window._cachedModules=nt;const at=JSON.parse('{"widgets/arcgis/3d-toolbox/":{"name":"3d-toolbox","label":"3D Toolbox","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":138,"height":42},"dependency":"jimu-arcgis","translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"],"properties":{}},"widgets/arcgis/arcgis-map/":{"name":"arcgis-map","label":"Map","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":["EXTENT_CHANGE","DATA_RECORDS_SELECTION_CHANGE"],"messageActions":[{"name":"panTo","label":"Pan to","uri":"message-actions/pan-to-action","settingUri":"message-actions/pan-to-action-setting"},{"name":"zoomToFeature","label":"Zoom to","uri":"message-actions/zoom-to-feature-action","settingUri":"message-actions/zoom-to-feature-action-setting"},{"name":"flash","label":"Flash","uri":"message-actions/flash-action","settingUri":"message-actions/flash-action-setting"},{"name":"filter","label":"Filter","uri":"message-actions/filter-action","settingUri":"message-actions/filter-action-setting"},{"name":"showOnMap","label":"Show on map","uri":"message-actions/show-on-map-action","settingUri":"message-actions/show-on-map-action-setting"}],"defaultSize":{"width":400,"height":400},"properties":{"canCreateMapView":true,"hasEmbeddedLayout":true,"passDataSourceToChildren":false,"coverLayoutBackground":true,"watchViewportVisibility":true,"supportAutoSize":false},"dataActions":[{"name":"zoomToFeature","label":"Zoom to","uri":"data-actions/zoom-to","icon":"runtime/assets/icons/select-tool/select-zoomto.svg"},{"name":"panTo","label":"Pan to","uri":"data-actions/pan-to","icon":"runtime/assets/icons/basemap.svg"},{"name":"showOnMap","label":"Show on map","uri":"data-actions/show-on-map","settingUri":"data-actions/show-on-map-setting","icon":"runtime/assets/icons/ds-map-view.svg"}],"layouts":[{"name":"MapFixedLayout","label":"Map FixedLayout","type":"FIXED"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/bookmark/":{"name":"bookmark","label":"Bookmark","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":516,"height":210},"properties":{"hasEmbeddedLayout":true,"watchViewportVisibility":true,"hasBuilderSupportModule":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/branch-version-management/":{"name":"branch-version-management","label":"Branch Version Management","type":"widget","version":"1.10.0","exbVersion":"1.10.0","requireEnterprise":true,"properties":{},"defaultSize":{"width":350,"height":75},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/coordinate-conversion/":{"name":"coordinate-conversion","label":"Coordinate Conversion","type":"widget","version":"1.10.0","exbVersion":"1.10.0","properties":{},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"],"dependency":"jimu-arcgis","defaultSize":{"width":350,"height":400}},"widgets/arcgis/coordinates/":{"name":"coordinates","label":"Coordinates","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":242,"height":140},"properties":{"hasSettingPage":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"],"dependency":"jimu-arcgis"},"widgets/arcgis/directions/":{"name":"directions","label":"Directions","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":400,"height":550},"dependency":"jimu-arcgis","translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"],"properties":{}},"widgets/arcgis/draw/":{"name":"draw","label":"Draw","type":"widget","version":"1.6.0","exbVersion":"1.6.0","publishMessages":[],"messageActions":[],"defaultSize":{"width":440,"height":444,"autoHeight":true},"properties":{"coverLayoutBackground":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"],"dependency":"jimu-arcgis"},"widgets/arcgis/elevation-profile/":{"name":"elevation-profile","label":"Elevation Profile","type":"widget","version":"1.10.0","exbVersion":"1.10.0","properties":{},"dependency":"jimu-arcgis","translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"],"defaultSize":{"width":600,"height":400}},"widgets/arcgis/feature-info/":{"name":"feature-info","label":"Feature Info","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":["DATA_RECORDS_SELECTION_CHANGE"],"messageActions":[],"defaultSize":{"width":400,"height":400},"properties":{"coverLayoutBackground":true,"flipIcon":true,"canConsumeDataAction":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/floor-filter/":{"name":"floor-filter","label":"Floor Filter","type":"widget","version":"1.10.0","exbVersion":"1.10.0","properties":{},"defaultSize":{"width":120,"height":48,"autoWidth":true,"autoHeight":true},"dependency":["jimu-arcgis"],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/fly-controller/":{"name":"fly-controller","label":"Fly Controller","type":"widget","dependency":["jimu-arcgis"],"settingDependency":"jimu-arcgis","version":"1.10.0","exbVersion":"1.10.0","properties":{"hasSettingPage":true},"defaultSize":{"width":262,"height":44},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/legend/":{"name":"legend","label":"Legend","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":[],"messageActions":[],"defaultSize":{"width":400,"height":400},"properties":{"coverLayoutBackground":true,"flipIcon":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/map-layers/":{"name":"map-layers","label":"Map Layers","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":[],"messageActions":[],"defaultSize":{"width":400,"height":400},"properties":{"coverLayoutBackground":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/oriented-imagery/":{"name":"oriented-imagery","label":"Oriented Imagery","type":"widget","dependency":["jimu-arcgis","https://oi1.img.arcgis.com/api/v2.12/main.js"],"version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":800,"height":800},"extensions":[{"name":"OI store","point":"REDUX_STORE","uri":"extensions/oi-store"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"],"properties":{}},"widgets/arcgis/query/":{"name":"query","label":"Query","type":"widget","version":"1.10.0","exbVersion":"1.10.0","messageActions":[],"publishMessages":[{"messageType":"DATA_RECORDS_SELECTION_CHANGE","messageCarryData":"OUTPUT_DATA_SOURCE"},{"messageType":"DATA_RECORD_SET_CHANGE","messageCarryData":"USE_DATA_SOURCE"}],"properties":{"canConsumeDataAction":true},"defaultSize":{"width":350,"height":400},"extensions":[{"name":"appConfigOperations","point":"APP_CONFIG_OPERATIONS","uri":"tools/app-config-operations"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/suitability-modeler/":{"name":"suitability-modeler","label":"Suitability Modeler","type":"widget","version":"1.6.0","exbVersion":"1.6.0","properties":{},"defaultSize":{"width":400,"height":500},"dependency":["jimu-arcgis"],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/arcgis/utility-network-trace/":{"name":"utility-network-trace","label":"Utility Network Trace (beta)","type":"widget","version":"1.10.0","exbVersion":"1.10.0","requireEnterprise":true,"requiredUserTypeExtensions":["ArcGIS Utility Network"],"properties":{},"dependency":"jimu-arcgis","defaultSize":{"width":300,"height":550},"translatedLocales":["en"]},"widgets/ba-infographic/":{"name":"ba-infographic","label":"BA Infographic (beta)","type":"widget","version":"1.10.0","exbVersion":"1.10.0","properties":{},"translatedLocales":["en"],"dependency":"jimu-arcgis","defaultSize":{"width":800,"height":600}},"widgets/common/button/":{"name":"button","label":"Button","type":"widget","version":"1.10.0","exbVersion":"1.10.0","properties":{"hasSettingPage":true,"supportRepeat":true,"canCrossLayoutBoundary":true,"coverLayoutBackground":true,"hasBuilderSupportModule":true},"extensions":[{"name":"quick-style","point":"CONTEXT_TOOL","uri":"tools/quick-style"}],"defaultSize":{"width":220,"height":50},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/card/":{"name":"card","label":"Card","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":300,"height":405},"properties":{"hasEmbeddedLayout":true,"canCrossLayoutBoundary":true,"flipIcon":false,"coverLayoutBackground":true,"supportAutoSize":false,"hasBuilderSupportModule":true},"layouts":[{"name":"REGULAR","label":"Regular"},{"name":"HOVER","label":"Hover"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/chart/":{"name":"chart","label":"Chart","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":[{"messageType":"DATA_RECORDS_SELECTION_CHANGE","messageCarryData":"OUTPUT_DATA_SOURCE"}],"defaultSize":{"width":450,"height":300},"properties":{"hasSettingPage":true,"canConsumeDataAction":true},"excludeDataActions":["arcgis-map.*"],"extensions":[],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/controller/":{"name":"controller","label":"Widget Controller","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"height":54,"width":400},"properties":{"hasSettingPage":true,"layoutType":"CONTROLLER","hasEmbeddedLayout":true,"hasBuilderSupportModule":true},"layouts":[{"name":"controller","label":"Controller layout"},{"name":"_openwidget","label":"Open widget layout"}],"extensions":[{"name":"previous","point":"CONTEXT_TOOL","uri":"tools/previous"},{"name":"next","point":"CONTEXT_TOOL","uri":"tools/next"},{"name":"add-widget","point":"CONTEXT_TOOL","uri":"tools/add-widget"},{"name":"appConfigOperations","point":"APP_CONFIG_OPERATIONS","uri":"tools/app-config-operations"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/divider/":{"name":"divider","label":"Divider","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":300,"height":50},"properties":{"lockChildren":true,"canCrossLayoutBoundary":true,"flipIcon":true,"hasBuilderSupportModule":true},"extensions":[{"name":"quick-style","point":"CONTEXT_TOOL","uri":"tools/quick-style"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/edit/":{"name":"edit","label":"Edit","type":"widget","dependency":["jimu-arcgis"],"version":"1.10.0","exbVersion":"1.10.0","messageActions":[],"defaultSize":{"width":400,"height":400},"properties":{},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/embed/":{"name":"embed","label":"Embed","type":"widget","version":"1.10.0","exbVersion":"1.10.0","properties":{"hasSettingPage":true,"coverLayoutBackground":true,"supportAutoSize":false},"defaultSize":{"width":400,"height":300},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/filter/":{"name":"filter","label":"Filter","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":["DATA_SOURCE_FILTER_CHANGE"],"properties":{},"defaultSize":{"width":350,"height":400},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/image/":{"name":"image","label":"Image","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":300,"height":300},"properties":{"hasSettingPage":true,"supportRepeat":true,"hasBuilderSupportModule":true},"extensions":[{"name":"chooseshape","point":"CONTEXT_TOOL","uri":"tools/chooseshape"},{"name":"croptool","point":"CONTEXT_TOOL","uri":"tools/croptool"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/list/":{"name":"list","label":"List","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":["DATA_RECORDS_SELECTION_CHANGE"],"defaultSize":{"width":620,"height":275},"properties":{"hasEmbeddedLayout":true,"lockChildren":true,"flipIcon":true,"canConsumeDataAction":true,"canProvideRepeatDataSource":true,"hasBuilderSupportModule":true,"hasGuide":true},"layouts":[{"name":"REGULAR","label":"Regular"},{"name":"SELECTED","label":"Selected"},{"name":"HOVER","label":"Hover"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/menu/":{"name":"menu","label":"Menu","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":300,"height":50},"properties":{"hasSettingPage":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/navigator/":{"name":"navigator","label":"Views Navigation","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"height":60,"width":380},"properties":{"hasSettingPage":true,"coverLayoutBackground":true,"hasBuilderSupportModule":true},"extensions":[{"name":"quick-style","point":"CONTEXT_TOOL","uri":"tools/quick-style"},{"name":"appConfigOperations","point":"APP_CONFIG_OPERATIONS","uri":"tools/app-config-operations"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/print/":{"name":"print","label":"Print","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":360,"height":460},"properties":{"hasSettingPage":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/search/":{"name":"search","label":"Search","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":[{"messageType":"DATA_RECORDS_SELECTION_CHANGE","messageCarryData":"BOTH_DATA_SOURCE"},{"messageType":"DATA_RECORD_SET_CHANGE","messageCarryData":"OUTPUT_DATA_SOURCE"},{"messageType":"DATA_SOURCE_FILTER_CHANGE","messageCarryData":"BOTH_DATA_SOURCE"}],"defaultSize":{"width":400,"height":34},"properties":{"hasSettingPage":true},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/share/":{"name":"share","label":"Share","type":"widget","version":"1.10.0","exbVersion":"1.10.0","properties":{"hasSettingPage":true},"defaultSize":{"width":24,"height":24},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/table/":{"name":"table","label":"Table","type":"widget","version":"1.10.0","exbVersion":"1.10.0","publishMessages":["DATA_RECORDS_SELECTION_CHANGE"],"messageActions":[],"defaultSize":{"width":600,"height":400},"properties":{"coverLayoutBackground":true,"canConsumeDataAction":true},"excludeDataActions":["table.*"],"dataActions":[{"name":"viewInTable","label":"View in table","uri":"data-actions/view-in-table","icon":"runtime/assets/icon.svg"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/text/":{"name":"text","label":"Text","type":"widget","version":"1.10.0","exbVersion":"1.10.0","defaultSize":{"width":360,"height":70},"properties":{"hasSettingPage":true,"supportInlineEditing":true,"supportRepeat":true,"hasBuilderSupportModule":true},"extensions":[{"name":"inline-editing","point":"CONTEXT_TOOL","uri":"tools/inline-editing"},{"name":"expression","point":"CONTEXT_TOOL","uri":"tools/expression"}],"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/common/timeline/":{"name":"timeline","label":"Timeline","type":"widget","version":"1.10.0","exbVersion":"1.10.0","properties":{"coverLayoutBackground":true},"defaultSize":{"width":480,"height":156},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/layout/column/":{"name":"column","label":"Column","type":"widget","widgetType":"LAYOUT","version":"1.10.0","exbVersion":"1.10.0","properties":{"hasBuilderSupportModule":true},"layouts":[{"name":"DEFAULT","label":"Default","type":"COLUMN"}],"defaultSize":{"width":300,"height":600},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/layout/fixed/":{"name":"fixed","label":"Fixed Panel","type":"widget","widgetType":"LAYOUT","version":"1.10.0","exbVersion":"1.10.0","properties":{"hasSettingPage":false,"supportAutoSize":false,"hasConfig":false,"hasBuilderSupportModule":true},"layouts":[{"name":"DEFAULT","label":"Default","type":"FIXED"}],"defaultSize":{"width":400,"height":400},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/layout/grid/":{"name":"grid","label":"Grid","type":"widget","widgetType":"LAYOUT","version":"1.6.0","exbVersion":"1.6.0","properties":{"supportAutoSize":false,"hasBuilderSupportModule":true},"layouts":[{"name":"DEFAULT","label":"Default","type":"GRID"}],"defaultSize":{"width":400,"height":400},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/layout/row/":{"name":"row","label":"Row","type":"widget","widgetType":"LAYOUT","version":"1.10.0","exbVersion":"1.10.0","properties":{"hasBuilderSupportModule":true},"layouts":[{"name":"DEFAULT","label":"Default","type":"ROW"}],"defaultSize":{"width":800,"height":400},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/layout/sidebar/":{"name":"sidebar","label":"Sidebar","type":"widget","widgetType":"LAYOUT","version":"1.10.0","exbVersion":"1.10.0","properties":{"flipIcon":true,"supportAutoSize":false,"hasBuilderSupportModule":true},"layouts":[{"name":"FIRST","label":"First","type":"FIXED"},{"name":"SECOND","label":"Second","type":"FIXED"}],"defaultSize":{"width":800,"height":400},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]},"widgets/survey123/":{"name":"survey123","label":"Survey","type":"widget","version":"1.10.0","dependency":"jimu-arcgis","settingDependency":"jimu-arcgis","exbVersion":"1.10.0","defaultSize":{"width":300,"height":400},"featureActions":[{"name":"ShowVertex","uri":"ShowVertexFeatureAction"}],"properties":{"coverLayoutBackground":true,"supportAutoSize":false},"translatedLocales":["en","ar","bg","bs","ca","cs","da","de","el","es","et","fi","fr","he","hr","hu","id","it","ja","ko","lt","lv","nb","nl","pl","pt-br","pt-pt","ro","ru","sk","sl","sr","sv","th","tr","zh-cn","uk","vi","zh-hk","zh-tw"]}}');window.widgetsManifest=at,(0,e.init)().then(r.init).then(i.init).then(t.init).then((()=>{const r=e.SessionManager.getInstance().getMainSession(),i=(0,e.getAppStore)().getState();e.ExtensionManager.getInstance().registerExtension({epName:e.extensionSpec.ExtensionPoints.DependencyDefine,extension:new t.ArcGISDependencyDefineExtension}),e.ExtensionManager.getInstance().registerExtension({epName:e.extensionSpec.ExtensionPoints.DataSourceFactoryUri,extension:new t.ArcGISDataSourceFactoryUriExtension}),i.appId&&r&&!window.jimuConfig.isInBuilder&&e.privilegeUtils.checkExbAccess(e.privilegeUtils.CheckTarget.Experience).then((t=>{t.valid||(0,e.getAppStore)().dispatch(e.appActions.hasPrivilegeChanged(t.invalidMessage))})).catch((t=>{console.error(t),(0,e.getAppStore)().dispatch(e.appActions.hasPrivilegeChanged(t.message))})),e.ReactDOM.render(e.React.createElement(e.AppRoot,null),document.getElementById("app"))})).catch((e=>{console.error(e)}))})(),s})())}}}));