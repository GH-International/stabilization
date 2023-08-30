/*! For license information please see 6692.bundle.js.LICENSE.txt */
"use strict";(self.webpackChunkexb_client=self.webpackChunkexb_client||[]).push([[6692,8762],{6692:(t,a,e)=>{e.r(a),e.d(a,{calcite_flow:()=>r});var n=e(3991),i=e(8762),r=function(){function t(t){var a=this;(0,n.r)(this,t),this.panelCount=0,this.flowDirection=null,this.panels=[],this.panelItemMutationObserver=(0,i.c)("mutation",(function(){return a.updateFlowProps()})),this.getFlowDirection=function(t,a){return t&&a>1||t>1?a<t?"retreating":"advancing":null},this.updateFlowProps=function(){var t=a,e=t.el,n=t.panels,i=Array.from(e.querySelectorAll("calcite-panel")).filter((function(t){return!t.matches("calcite-panel calcite-panel")})),r=n.length,o=i.length,c=i[o-1],l=i[o-2];if(o&&c&&i.forEach((function(t){t.showBackButton=t===c&&o>1,t.hidden=t!==c})),l&&(l.menuOpen=!1),a.panels=i,r!==o){var s=a.getFlowDirection(r,o);a.panelCount=o,a.flowDirection=s}}}return t.prototype.back=function(){return function(t,a,e,n){function i(t){return t instanceof e?t:new e((function(a){a(t)}))}return new(e||(e=Promise))((function(e,r){function o(t){try{l(n.next(t))}catch(t){r(t)}}function c(t){try{l(n.throw(t))}catch(t){r(t)}}function l(t){t.done?e(t.value):i(t.value).then(o,c)}l((n=n.apply(t,a||[])).next())}))}(this,void 0,void 0,(function(){var t,a;return function(t,a){var e,n,i,r,o={label:0,sent:function(){if(1&i[0])throw i[1];return i[1]},trys:[],ops:[]};return r={next:c(0),throw:c(1),return:c(2)},"function"==typeof Symbol&&(r[Symbol.iterator]=function(){return this}),r;function c(t){return function(a){return l([t,a])}}function l(r){if(e)throw new TypeError("Generator is already executing.");for(;o;)try{if(e=1,n&&(i=2&r[0]?n.return:r[0]?n.throw||((i=n.return)&&i.call(n),0):n.next)&&!(i=i.call(n,r[1])).done)return i;switch(n=0,i&&(r=[2&r[0],i.value]),r[0]){case 0:case 1:i=r;break;case 4:return o.label++,{value:r[1],done:!1};case 5:o.label++,n=r[1],r=[0];continue;case 7:r=o.ops.pop(),o.trys.pop();continue;default:if(!((i=(i=o.trys).length>0&&i[i.length-1])||6!==r[0]&&2!==r[0])){o=0;continue}if(3===r[0]&&(!i||r[1]>i[0]&&r[1]<i[3])){o.label=r[1];break}if(6===r[0]&&o.label<i[1]){o.label=i[1],i=r;break}if(i&&o.label<i[2]){o.label=i[2],o.ops.push(r);break}i[2]&&o.ops.pop(),o.trys.pop();continue}r=a.call(t,o)}catch(t){r=[6,t],n=0}finally{e=i=0}if(5&r[0])throw r[1];return{value:r[0]?r[1]:void 0,done:!0}}}(this,(function(e){return t=this.panels,(a=t[t.length-1])?[2,(a.beforeBack?a.beforeBack:function(){return Promise.resolve()}).call(a).then((function(){return a.remove(),a}))]:[2]}))}))},t.prototype.connectedCallback=function(){var t;null===(t=this.panelItemMutationObserver)||void 0===t||t.observe(this.el,{childList:!0,subtree:!0}),this.updateFlowProps()},t.prototype.disconnectedCallback=function(){var t;null===(t=this.panelItemMutationObserver)||void 0===t||t.disconnect()},t.prototype.handleCalcitePanelBackClick=function(){this.back()},t.prototype.render=function(){var t,a=this.flowDirection,e=((t={}).frame=!0,t["frame--advancing"]="advancing"===a,t["frame--retreating"]="retreating"===a,t);return(0,n.h)("div",{class:e},(0,n.h)("slot",null))},Object.defineProperty(t.prototype,"el",{get:function(){return(0,n.g)(this)},enumerable:!1,configurable:!0}),t}();r.style="@-webkit-keyframes in{0%{opacity:0}100%{opacity:1}}@keyframes in{0%{opacity:0}100%{opacity:1}}@-webkit-keyframes in-down{0%{opacity:0;-webkit-transform:translate3D(0, -5px, 0);transform:translate3D(0, -5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@keyframes in-down{0%{opacity:0;-webkit-transform:translate3D(0, -5px, 0);transform:translate3D(0, -5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@-webkit-keyframes in-up{0%{opacity:0;-webkit-transform:translate3D(0, 5px, 0);transform:translate3D(0, 5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@keyframes in-up{0%{opacity:0;-webkit-transform:translate3D(0, 5px, 0);transform:translate3D(0, 5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@-webkit-keyframes in-scale{0%{opacity:0;-webkit-transform:scale3D(0.95, 0.95, 1);transform:scale3D(0.95, 0.95, 1)}100%{opacity:1;-webkit-transform:scale3D(1, 1, 1);transform:scale3D(1, 1, 1)}}@keyframes in-scale{0%{opacity:0;-webkit-transform:scale3D(0.95, 0.95, 1);transform:scale3D(0.95, 0.95, 1)}100%{opacity:1;-webkit-transform:scale3D(1, 1, 1);transform:scale3D(1, 1, 1)}}:root{--calcite-animation-timing:calc(150ms * var(--calcite-internal-duration-factor));--calcite-internal-duration-factor:var(--calcite-duration-factor, 1);--calcite-internal-animation-timing-fast:calc(100ms * var(--calcite-internal-duration-factor));--calcite-internal-animation-timing-medium:calc(200ms * var(--calcite-internal-duration-factor));--calcite-internal-animation-timing-slow:calc(300ms * var(--calcite-internal-duration-factor))}.calcite-animate{opacity:0;-webkit-animation-fill-mode:both;animation-fill-mode:both;-webkit-animation-duration:var(--calcite-animation-timing);animation-duration:var(--calcite-animation-timing)}.calcite-animate__in{-webkit-animation-name:in;animation-name:in}.calcite-animate__in-down{-webkit-animation-name:in-down;animation-name:in-down}.calcite-animate__in-up{-webkit-animation-name:in-up;animation-name:in-up}.calcite-animate__in-scale{-webkit-animation-name:in-scale;animation-name:in-scale}:host{-webkit-box-sizing:border-box;box-sizing:border-box;background-color:var(--calcite-ui-foreground-1);color:var(--calcite-ui-text-2);font-size:var(--calcite-font-size--1)}:host *{-webkit-box-sizing:border-box;box-sizing:border-box}:root{--calcite-popper-transition:var(--calcite-animation-timing)}:host([hidden]){display:none}:host{position:relative;display:-ms-flexbox;display:flex;width:100%;-ms-flex:1 1 auto;flex:1 1 auto;-ms-flex-align:stretch;align-items:stretch;overflow:hidden;background-color:transparent}:host .frame{position:relative;margin:0px;display:-ms-flexbox;display:flex;width:100%;-ms-flex:1 1 auto;flex:1 1 auto;-ms-flex-direction:column;flex-direction:column;-ms-flex-align:stretch;align-items:stretch;padding:0px}:host ::slotted(calcite-panel){height:100%}:host ::slotted(.calcite-match-height:last-child){display:-ms-flexbox;display:flex;-ms-flex:1 1 auto;flex:1 1 auto;overflow:hidden}:host .frame--advancing{-webkit-animation:calcite-frame-advance var(--calcite-animation-timing);animation:calcite-frame-advance var(--calcite-animation-timing)}:host .frame--retreating{-webkit-animation:calcite-frame-retreat var(--calcite-animation-timing);animation:calcite-frame-retreat var(--calcite-animation-timing)}@-webkit-keyframes calcite-frame-advance{0%{--tw-bg-opacity:0.5;-webkit-transform:translate3d(50px, 0, 0);transform:translate3d(50px, 0, 0)}100%{--tw-bg-opacity:1;-webkit-transform:translate3d(0, 0, 0);transform:translate3d(0, 0, 0)}}@keyframes calcite-frame-advance{0%{--tw-bg-opacity:0.5;-webkit-transform:translate3d(50px, 0, 0);transform:translate3d(50px, 0, 0)}100%{--tw-bg-opacity:1;-webkit-transform:translate3d(0, 0, 0);transform:translate3d(0, 0, 0)}}@-webkit-keyframes calcite-frame-retreat{0%{--tw-bg-opacity:0.5;-webkit-transform:translate3d(-50px, 0, 0);transform:translate3d(-50px, 0, 0)}100%{--tw-bg-opacity:1;-webkit-transform:translate3d(0, 0, 0);transform:translate3d(0, 0, 0)}}@keyframes calcite-frame-retreat{0%{--tw-bg-opacity:0.5;-webkit-transform:translate3d(-50px, 0, 0);transform:translate3d(-50px, 0, 0)}100%{--tw-bg-opacity:1;-webkit-transform:translate3d(0, 0, 0);transform:translate3d(0, 0, 0)}}"},8762:(t,a,e)=>{function n(t,a,e){var n=function(t){return"intersection"===t?window.IntersectionObserver:"mutation"===t?window.MutationObserver:window.ResizeObserver}(t);return new n(a,e)}e.r(a),e.d(a,{c:()=>n})}}]);