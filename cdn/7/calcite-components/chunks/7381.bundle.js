/*! For license information please see 7381.bundle.js.LICENSE.txt */
"use strict";(self.webpackChunkexb_client=self.webpackChunkexb_client||[]).push([[7381,6859],{6859:(t,e,n)=>{function r(t){return"Enter"===t||" "===t}n.r(e),n.d(e,{i:()=>r,n:()=>i});var i=["0","1","2","3","4","5","6","7","8","9"]},7381:(t,e,n)=>{n.r(e),n.d(e,{a:()=>v,d:()=>b,g:()=>D,i:()=>l,l:()=>y,p:()=>s,s:()=>p});var r=n(6859),i=/^([-0])0+(?=\d)/,u=/(?!^\.)\.$/,a=/(?!^-)-/g,c=/^-\b0\b\.?0*$/,o=function(){function t(e){if(e instanceof t)return e;var n=String(e).split(".").concat(""),r=n[0],i=n[1];this.value=BigInt(r+i.padEnd(t.DECIMALS,"0").slice(0,t.DECIMALS))+BigInt(t.ROUNDED&&i[t.DECIMALS]>="5"),this.isNegative="-"===e.charAt(0)}return t._divRound=function(e,n){return t.fromBigInt(e/n+(t.ROUNDED?e*BigInt(2)/n%BigInt(2):BigInt(0)))},t.fromBigInt=function(e){return Object.assign(Object.create(t.prototype),{value:e})},t.prototype.toString=function(){var e=this.value.toString().replace(new RegExp("-","g"),"").padStart(t.DECIMALS+1,"0"),n=e.slice(0,-t.DECIMALS),r=e.slice(-t.DECIMALS).replace(/\.?0+$/,""),i=n.concat(r.length?"."+r:"");return(this.isNegative?"-":"").concat(i)},t.prototype.formatToParts=function(e,n){var r=E(e,n),i=this.value.toString().replace(new RegExp("-","g"),"").padStart(t.DECIMALS+1,"0"),u=i.slice(0,-t.DECIMALS),a=i.slice(-t.DECIMALS).replace(/\.?0+$/,""),c=r.formatToParts(BigInt(u));return this.isNegative&&c.unshift({type:"minusSign",value:w(e)}),a.length&&(c.push({type:"decimal",value:D(e)}),a.split("").forEach((function(t){return c.push({type:"fraction",value:t})}))),c},t.prototype.add=function(e){return t.fromBigInt(this.value+new t(e).value)},t.prototype.subtract=function(e){return t.fromBigInt(this.value-new t(e).value)},t.prototype.multiply=function(e){return t._divRound(this.value*new t(e).value,t.SHIFT)},t.prototype.divide=function(e){return t._divRound(this.value*t.SHIFT,new t(e).value)},t}();function l(t){return!(!t||isNaN(Number(t)))}function s(t){return t&&function(t){return r.n.some((function(e){return t.includes(e)}))}(t)?g(t,(function(t){var e=!1,n=t.split("").filter((function(t,n){return t.match(/\./g)&&!e?(e=!0,!0):!(!t.match(/\-/g)||0!==n)||r.n.includes(t)})).reduce((function(t,e){return t+e}));return l(n)?new o(n).toString():""})):""}function f(t){return t.replace(u,"")}function p(t){return g(t,(function(t){var e=function(t){return t.replace(a,"")}(f(function(t){return t.replace(i,"$1")}(t)));return l(e)?c.test(e)?e:new o(e).toString():t}))}function g(t,e){if(!t)return t;var n=t.toLowerCase().indexOf("e")+1;return t.replace(/[eE]*$/g,"").substring(0,n).concat(t.slice(n).replace(/[eE]/g,"")).split(/[eE]/).map((function(t,n){return e(1===n?t.replace(/\./g,""):t)})).join("e").replace(/^e/,"1e")}o.DECIMALS=100,o.ROUNDED=!0,o.SHIFT=BigInt("1"+"0".repeat(o.DECIMALS));var v=["ar","bg","bs","ca","cs","da","de","de-CH","el","en","en-AU","en-CA","en-GB","es","es-MX","et","fi","fr","fr-CH","he","hi","hr","hu","id","it","it-CH","ja","ko","lt","lv","mk","nb","nl","pl","pt","pt-PT","ro","ru","sk","sl","sr","sv","th","tr","uk","vi","zh-CN","zh-HK","zh-TW"],m=new RegExp("[.](?=.*[.])","g"),d=new RegExp("[^0-9-.]","g"),h=new RegExp(",","g"),I=(new Intl.NumberFormat).resolvedOptions().numberingSystem,S="arab"===I?"latn":I;function E(t,e){return void 0===e&&(e=S),new Intl.NumberFormat(t,{minimumFractionDigits:0,maximumFractionDigits:20,numberingSystem:e})}function b(t,e){return g(t,(function(t){var n=t.replace(w(e),"-").replace(C(e),"").replace(D(e),".").replace(m,"").replace(d,"");return l(n)?n:t}))}function C(t){var e=E(t).formatToParts(1234567).find((function(t){return"group"===t.type})).value;return 0===e.trim().length?" ":e}function D(t){return E(t).formatToParts(1.1).find((function(t){return"decimal"===t.type})).value}function w(t){return E(t).formatToParts(-9).find((function(t){return"minusSign"===t.type})).value}function y(t,e,n,r){return void 0===n&&(n=!1),g(t,(function(t){if(t){var i=f(t.replace(h,""));if(l(i)){var u=new o(i).formatToParts(e,r).map((function(t){var r=t.type,i=t.value;switch(r){case"group":return n?C(e):"";case"decimal":return D(e);case"minusSign":return w(e);default:return i}})).reduce((function(t,e){return t+e}));return u}}return t}))}}}]);