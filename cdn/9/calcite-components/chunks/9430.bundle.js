/*! For license information please see 9430.bundle.js.LICENSE.txt */
"use strict";(self.webpackChunkexb_client=self.webpackChunkexb_client||[]).push([[9430,4485,8762],{9430:(t,e,i)=>{i.r(e),i.d(e,{calcite_dropdown:()=>d,calcite_dropdown_group:()=>m,calcite_dropdown_item:()=>u});var n=i(3991),o=i(7588),a=i(7820),r=i(8762),s=i(4485),c=function(t,e,i,n){function o(t){return t instanceof i?t:new i((function(e){e(t)}))}return new(i||(i=Promise))((function(i,a){function r(t){try{c(n.next(t))}catch(t){a(t)}}function s(t){try{c(n.throw(t))}catch(t){a(t)}}function c(t){t.done?i(t.value):o(t.value).then(r,s)}c((n=n.apply(t,e||[])).next())}))},l=function(t,e){var i,n,o,a,r={label:0,sent:function(){if(1&o[0])throw o[1];return o[1]},trys:[],ops:[]};return a={next:s(0),throw:s(1),return:s(2)},"function"==typeof Symbol&&(a[Symbol.iterator]=function(){return this}),a;function s(t){return function(e){return c([t,e])}}function c(a){if(i)throw new TypeError("Generator is already executing.");for(;r;)try{if(i=1,n&&(o=2&a[0]?n.return:a[0]?n.throw||((o=n.return)&&o.call(n),0):n.next)&&!(o=o.call(n,a[1])).done)return o;switch(n=0,o&&(a=[2&a[0],o.value]),a[0]){case 0:case 1:o=a;break;case 4:return r.label++,{value:a[1],done:!1};case 5:r.label++,n=a[1],a=[0];continue;case 7:a=r.ops.pop(),r.trys.pop();continue;default:if(!((o=(o=r.trys).length>0&&o[o.length-1])||6!==a[0]&&2!==a[0])){r=0;continue}if(3===a[0]&&(!o||a[1]>o[0]&&a[1]<o[3])){r.label=a[1];break}if(6===a[0]&&r.label<o[1]){r.label=o[1],o=a;break}if(o&&r.label<o[2]){r.label=o[2],r.ops.push(a);break}o[2]&&r.ops.pop(),r.trys.pop();continue}a=e.call(t,r)}catch(t){a=[6,t],n=0}finally{i=o=0}if(5&a[0])throw a[1];return{value:a[0]?a[1]:void 0,done:!0}}},p=function(t,e,i){if("string"==typeof e&&(e=Array.prototype.slice.call(e)),i||2===arguments.length)for(var n,o=0,a=e.length;o<a;o++)!n&&o in e||(n||(n=Array.prototype.slice.call(e,0,o)),n[o]=e[o]);return t.concat(n||Array.prototype.slice.call(e))},d=function(){function t(t){var e=this;(0,n.r)(this,t),this.calciteDropdownSelect=(0,n.c)(this,"calciteDropdownSelect",7),this.calciteDropdownBeforeOpen=(0,n.c)(this,"calciteDropdownBeforeOpen",7),this.calciteDropdownOpen=(0,n.c)(this,"calciteDropdownOpen",7),this.calciteDropdownBeforeClose=(0,n.c)(this,"calciteDropdownBeforeClose",7),this.calciteDropdownClose=(0,n.c)(this,"calciteDropdownClose",7),this.active=!1,this.open=!1,this.disableCloseOnSelect=!1,this.disabled=!1,this.maxItems=0,this.overlayPositioning="absolute",this.placement=a.d,this.scale="m",this.selectedItems=[],this.type="click",this.items=[],this.groups=[],this.activeTransitionProp="visibility",this.mutationObserver=(0,r.c)("mutation",(function(){return e.updateItems()})),this.resizeObserver=(0,r.c)("resize",(function(t){return e.resizeObserverCallback(t)})),this.setFilteredPlacements=function(){var t=e,i=t.el,n=t.flipPlacements;e.filteredFlipPlacements=n?(0,a.f)(n,i):null},this.updateTriggers=function(t){e.triggers=t.target.assignedElements({flatten:!0}),e.reposition()},this.updateItems=function(){e.items=e.groups.map((function(t){return Array.from(null==t?void 0:t.querySelectorAll("calcite-dropdown-item"))})).reduce((function(t,e){return p(p([],t,!0),e,!0)}),[]),e.updateSelectedItems(),e.reposition()},this.updateGroups=function(t){var i=t.target.assignedElements({flatten:!0}).filter((function(t){return null==t?void 0:t.matches("calcite-dropdown-group")}));e.groups=i,e.updateItems()},this.resizeObserverCallback=function(t){t.forEach((function(t){var i=t.target;i===e.referenceEl?e.setDropdownWidth():i===e.scrollerEl&&e.setMaxScrollerHeight()}))},this.setDropdownWidth=function(){var t=e,i=t.referenceEl,n=t.scrollerEl,o=null==i?void 0:i.clientWidth;o&&n&&(n.style.minWidth="".concat(o,"px"))},this.setMaxScrollerHeight=function(){var t=e,i=t.active,n=t.scrollerEl,o=t.open;if(n&&(i||o)){e.reposition();var a=e.getMaxScrollerHeight();n.style.maxHeight=a>0?"".concat(a,"px"):"",e.reposition()}},this.setScrollerEl=function(t){e.resizeObserver.observe(t),e.scrollerEl=t,e.scrollerEl.addEventListener("transitionrun",e.transitionRunHandler)},this.transitionEnd=function(t){t.propertyName===e.activeTransitionProp&&(e.open||e.active?e.emitOpenCloseEvent("open"):e.emitOpenCloseEvent("close"))},this.transitionRunHandler=function(t){t.propertyName===e.activeTransitionProp&&(e.active||e.open?e.emitOpenCloseEvent("beforeOpen"):e.emitOpenCloseEvent("beforeClose"))},this.setReferenceEl=function(t){e.referenceEl=t,e.resizeObserver.observe(t)},this.setMenuEl=function(t){e.menuEl=t},this.keyDownHandler=function(t){if(t.target===e.referenceEl){var i=t.key;if((e.open||e.active)&&("Escape"===i||t.shiftKey&&"Tab"===i))e.closeCalciteDropdown();else switch(i){case" ":case"Enter":e.openCalciteDropdown();break;case"Escape":e.closeCalciteDropdown()}}},this.focusOnFirstActiveOrFirstItem=function(){e.getFocusableElement(e.items.find((function(t){return t.active}))||e.items[0])},this.toggleOpenEnd=function(){e.focusOnFirstActiveOrFirstItem(),e.el.removeEventListener("calciteDropdownOpen",e.toggleOpenEnd)},this.openCalciteDropdown=function(){e.active=!e.active,e.open=!e.open,(e.active||e.open)&&e.el.addEventListener("calciteDropdownOpen",e.toggleOpenEnd)}}return t.prototype.activeHandler=function(){this.disabled?(this.active=!1,this.open=!1):this.reposition()},t.prototype.handleDisabledChange=function(t){t||(this.active=!1,this.open=!1)},t.prototype.flipPlacementsHandler=function(){this.setFilteredPlacements()},t.prototype.maxItemsHandler=function(){this.setMaxScrollerHeight()},t.prototype.placementHandler=function(){this.reposition()},t.prototype.connectedCallback=function(){var t;null===(t=this.mutationObserver)||void 0===t||t.observe(this.el,{childList:!0,subtree:!0}),this.createPopper(),this.setFilteredPlacements()},t.prototype.componentDidLoad=function(){this.reposition()},t.prototype.componentDidRender=function(){(0,s.u)(this)},t.prototype.disconnectedCallback=function(){var t,e;null===(t=this.mutationObserver)||void 0===t||t.disconnect(),null===(e=this.resizeObserver)||void 0===e||e.disconnect(),this.destroyPopper(),this.scrollerEl&&this.scrollerEl.removeEventListener("transitionrun",this.transitionRunHandler)},t.prototype.render=function(){var t,e=this.active,i=this.open;return(0,n.h)(n.H,null,(0,n.h)("div",{class:"calcite-dropdown-trigger-container",onClick:this.openCalciteDropdown,onKeyDown:this.keyDownHandler,ref:this.setReferenceEl},(0,n.h)("slot",{"aria-expanded":(0,o.t)(e||i),"aria-haspopup":"true",name:"dropdown-trigger",onSlotchange:this.updateTriggers})),(0,n.h)("div",{"aria-hidden":(0,o.t)(!(e||i)),class:"calcite-dropdown-wrapper",ref:this.setMenuEl},(0,n.h)("div",{class:(t={},t["calcite-dropdown-content"]=!0,t[a.C.animation]=!0,t[a.C.animationActive]=e||i,t),onTransitionEnd:this.transitionEnd,ref:this.setScrollerEl},(0,n.h)("div",{hidden:!(i||e)},(0,n.h)("slot",{onSlotchange:this.updateGroups})))))},t.prototype.reposition=function(){return c(this,void 0,void 0,(function(){var t,e,i,n,o;return l(this,(function(r){switch(r.label){case 0:return e=(t=this).popper,i=t.menuEl,n=t.placement,o=this.getModifiers(),e?[4,(0,a.u)({el:i,modifiers:o,placement:n,popper:e})]:[3,2];case 1:return r.sent(),[3,3];case 2:this.createPopper(),r.label=3;case 3:return[2]}}))}))},t.prototype.closeCalciteDropdownOnClick=function(t){!this.open&&!this.active||t.composedPath().includes(this.el)||this.closeCalciteDropdown(!1)},t.prototype.closeCalciteDropdownOnEvent=function(t){this.closeCalciteDropdown(),t.stopPropagation()},t.prototype.closeCalciteDropdownOnOpenEvent=function(t){t.composedPath().includes(this.el)||(this.active=!1,this.open=!1)},t.prototype.mouseEnterHandler=function(){"hover"===this.type&&this.openCalciteDropdown()},t.prototype.mouseLeaveHandler=function(){"hover"===this.type&&this.closeCalciteDropdown()},t.prototype.calciteInternalDropdownItemKeyEvent=function(t){var e=t.detail.keyboardEvent,i=e.target,n="A"!==i.nodeName?i:i.parentNode,o=0===this.itemIndex(n),a=this.itemIndex(n)===this.items.length-1;switch(e.key){case"Tab":a&&!e.shiftKey||o&&e.shiftKey?this.closeCalciteDropdown():e.shiftKey?this.focusPrevItem(n):this.focusNextItem(n);break;case"ArrowDown":this.focusNextItem(n);break;case"ArrowUp":this.focusPrevItem(n);break;case"Home":this.focusFirstItem();break;case"End":this.focusLastItem()}t.stopPropagation()},t.prototype.handleItemSelect=function(t){this.updateSelectedItems(),t.stopPropagation(),this.calciteDropdownSelect.emit(),this.disableCloseOnSelect&&"none"!==t.detail.requestedDropdownGroup.selectionMode||this.closeCalciteDropdown(),t.stopPropagation()},t.prototype.emitOpenCloseEvent=function(t){var e=this,i={el:this.el},n={beforeOpen:function(){return e.calciteDropdownBeforeOpen.emit(i)},open:function(){return e.calciteDropdownOpen.emit(i)},beforeClose:function(){return e.calciteDropdownBeforeClose.emit(i)},close:function(){return e.calciteDropdownClose.emit(i)}};(n[t]||n["The component state is unknown."])()},t.prototype.getModifiers=function(){var t={name:"flip",enabled:!0};return t.options={fallbackPlacements:this.filteredFlipPlacements||a.p},[t,{name:"eventListeners",enabled:this.open||this.active}]},t.prototype.createPopper=function(){this.destroyPopper();var t=this,e=t.menuEl,i=t.referenceEl,n=t.placement,o=t.overlayPositioning,r=this.getModifiers();this.popper=(0,a.c)({el:e,modifiers:r,overlayPositioning:o,placement:n,referenceEl:i})},t.prototype.destroyPopper=function(){var t=this.popper;t&&t.destroy(),this.popper=null},t.prototype.updateSelectedItems=function(){this.selectedItems=this.items.filter((function(t){return t.active}))},t.prototype.getMaxScrollerHeight=function(){var t,e=this.maxItems,i=0,n=0;return this.groups.forEach((function(o){e>0&&i<e&&Array.from(o.children).forEach((function(o,a){0===a&&(isNaN(t)&&(t=o.offsetTop),n+=t),i<e&&(n+=o.offsetHeight,i+=1)}))})),n},t.prototype.closeCalciteDropdown=function(t){void 0===t&&(t=!0),this.active=!1,this.open=!1,t&&(0,o.f)(this.triggers[0])},t.prototype.focusFirstItem=function(){var t=this.items[0];this.getFocusableElement(t)},t.prototype.focusLastItem=function(){var t=this.items[this.items.length-1];this.getFocusableElement(t)},t.prototype.focusNextItem=function(t){var e=this.itemIndex(t),i=this.items[e+1]||this.items[0];this.getFocusableElement(i)},t.prototype.focusPrevItem=function(t){var e=this.itemIndex(t),i=this.items[e-1]||this.items[this.items.length-1];this.getFocusableElement(i)},t.prototype.itemIndex=function(t){return this.items.indexOf(t)},t.prototype.getFocusableElement=function(t){if(t){var e=t.attributes.isLink?t.shadowRoot.querySelector("a"):t;(0,o.f)(e)}},Object.defineProperty(t.prototype,"el",{get:function(){return(0,n.g)(this)},enumerable:!1,configurable:!0}),Object.defineProperty(t,"watchers",{get:function(){return{active:["activeHandler"],open:["activeHandler"],disabled:["handleDisabledChange"],flipPlacements:["flipPlacementsHandler"],maxItems:["maxItemsHandler"],placement:["placementHandler"]}},enumerable:!1,configurable:!0}),t}();d.style="@-webkit-keyframes in{0%{opacity:0}100%{opacity:1}}@keyframes in{0%{opacity:0}100%{opacity:1}}@-webkit-keyframes in-down{0%{opacity:0;-webkit-transform:translate3D(0, -5px, 0);transform:translate3D(0, -5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@keyframes in-down{0%{opacity:0;-webkit-transform:translate3D(0, -5px, 0);transform:translate3D(0, -5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@-webkit-keyframes in-up{0%{opacity:0;-webkit-transform:translate3D(0, 5px, 0);transform:translate3D(0, 5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@keyframes in-up{0%{opacity:0;-webkit-transform:translate3D(0, 5px, 0);transform:translate3D(0, 5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@-webkit-keyframes in-scale{0%{opacity:0;-webkit-transform:scale3D(0.95, 0.95, 1);transform:scale3D(0.95, 0.95, 1)}100%{opacity:1;-webkit-transform:scale3D(1, 1, 1);transform:scale3D(1, 1, 1)}}@keyframes in-scale{0%{opacity:0;-webkit-transform:scale3D(0.95, 0.95, 1);transform:scale3D(0.95, 0.95, 1)}100%{opacity:1;-webkit-transform:scale3D(1, 1, 1);transform:scale3D(1, 1, 1)}}:root{--calcite-animation-timing:calc(150ms * var(--calcite-internal-duration-factor));--calcite-internal-duration-factor:var(--calcite-duration-factor, 1);--calcite-internal-animation-timing-fast:calc(100ms * var(--calcite-internal-duration-factor));--calcite-internal-animation-timing-medium:calc(200ms * var(--calcite-internal-duration-factor));--calcite-internal-animation-timing-slow:calc(300ms * var(--calcite-internal-duration-factor))}.calcite-animate{opacity:0;-webkit-animation-fill-mode:both;animation-fill-mode:both;-webkit-animation-duration:var(--calcite-animation-timing);animation-duration:var(--calcite-animation-timing)}.calcite-animate__in{-webkit-animation-name:in;animation-name:in}.calcite-animate__in-down{-webkit-animation-name:in-down;animation-name:in-down}.calcite-animate__in-up{-webkit-animation-name:in-up;animation-name:in-up}.calcite-animate__in-scale{-webkit-animation-name:in-scale;animation-name:in-scale}:root{--calcite-popper-transition:var(--calcite-animation-timing)}:host([hidden]){display:none}:host{display:-ms-inline-flexbox;display:inline-flex;-ms-flex:0 1 auto;flex:0 1 auto}:host([disabled]){pointer-events:none;cursor:default;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none;opacity:var(--calcite-ui-opacity-disabled)}:host([disabled]) ::slotted([calcite-hydrated][disabled]),:host([disabled]) [calcite-hydrated][disabled]{opacity:1}:host .calcite-dropdown-wrapper{display:block;position:absolute;z-index:900;-webkit-transform:scale(0);transform:scale(0);visibility:hidden;pointer-events:none}.calcite-dropdown-wrapper .calcite-popper-anim{position:relative;z-index:1;-webkit-transition:var(--calcite-popper-transition);transition:var(--calcite-popper-transition);visibility:hidden;-webkit-transition-property:visibility, opacity, -webkit-transform;transition-property:visibility, opacity, -webkit-transform;transition-property:transform, visibility, opacity;transition-property:transform, visibility, opacity, -webkit-transform;opacity:0;-webkit-box-shadow:0 0 16px 0 rgba(0, 0, 0, 0.16);box-shadow:0 0 16px 0 rgba(0, 0, 0, 0.16);border-radius:0.25rem}.calcite-dropdown-wrapper[data-popper-placement^=bottom] .calcite-popper-anim{-webkit-transform:translateY(-5px);transform:translateY(-5px)}.calcite-dropdown-wrapper[data-popper-placement^=top] .calcite-popper-anim{-webkit-transform:translateY(5px);transform:translateY(5px)}.calcite-dropdown-wrapper[data-popper-placement^=left] .calcite-popper-anim{-webkit-transform:translateX(5px);transform:translateX(5px)}.calcite-dropdown-wrapper[data-popper-placement^=right] .calcite-popper-anim{-webkit-transform:translateX(-5px);transform:translateX(-5px)}.calcite-dropdown-wrapper[data-popper-placement] .calcite-popper-anim--active{opacity:1;visibility:visible;-webkit-transform:translate(0);transform:translate(0)}:host([active]) .calcite-dropdown-wrapper,:host([open]) .calcite-dropdown-wrapper{pointer-events:initial;visibility:visible}:host .calcite-dropdown-content{width:auto;overflow-y:auto;overflow-x:hidden;background-color:var(--calcite-ui-foreground-1);max-height:90vh;width:var(--calcite-dropdown-width)}.calcite-dropdown-trigger-container{position:relative;display:-ms-flexbox;display:flex;-ms-flex:1 1 auto;flex:1 1 auto}@media (forced-colors: active){:host([active]) .calcite-dropdown-wrapper,:host([open]) .calcite-dropdown-wrapper{border:1px solid canvasText}}:host([width=s]){--calcite-dropdown-width:12rem}:host([width=m]){--calcite-dropdown-width:14rem}:host([width=l]){--calcite-dropdown-width:16rem}";var m=function(){function t(t){(0,n.r)(this,t),this.calciteInternalDropdownItemChange=(0,n.c)(this,"calciteInternalDropdownItemChange",7),this.selectionMode="single"}return t.prototype.componentWillLoad=function(){this.groupPosition=this.getGroupPosition()},t.prototype.render=function(){var t,e=this.scale||(0,o.d)(this.el,"scale","m"),i=this.groupTitle?(0,n.h)("span",{"aria-hidden":"true",class:"dropdown-title"},this.groupTitle):null,a=this.groupPosition>0?(0,n.h)("div",{class:"dropdown-separator",role:"separator"}):null;return(0,n.h)(n.H,{role:"menu"},(0,n.h)("div",{class:(t={container:!0},t["container--s"]="s"===e,t["container--m"]="m"===e,t["container--l"]="l"===e,t),title:this.groupTitle},a,i,(0,n.h)("slot",null)))},t.prototype.updateActiveItemOnChange=function(t){this.requestedDropdownGroup=t.detail.requestedDropdownGroup,this.requestedDropdownItem=t.detail.requestedDropdownItem,this.calciteInternalDropdownItemChange.emit({requestedDropdownGroup:this.requestedDropdownGroup,requestedDropdownItem:this.requestedDropdownItem})},t.prototype.getGroupPosition=function(){return Array.prototype.indexOf.call(this.el.parentElement.querySelectorAll("calcite-dropdown-group"),this.el)},Object.defineProperty(t.prototype,"el",{get:function(){return(0,n.g)(this)},enumerable:!1,configurable:!0}),t}();m.style="@-webkit-keyframes in{0%{opacity:0}100%{opacity:1}}@keyframes in{0%{opacity:0}100%{opacity:1}}@-webkit-keyframes in-down{0%{opacity:0;-webkit-transform:translate3D(0, -5px, 0);transform:translate3D(0, -5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@keyframes in-down{0%{opacity:0;-webkit-transform:translate3D(0, -5px, 0);transform:translate3D(0, -5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@-webkit-keyframes in-up{0%{opacity:0;-webkit-transform:translate3D(0, 5px, 0);transform:translate3D(0, 5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@keyframes in-up{0%{opacity:0;-webkit-transform:translate3D(0, 5px, 0);transform:translate3D(0, 5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@-webkit-keyframes in-scale{0%{opacity:0;-webkit-transform:scale3D(0.95, 0.95, 1);transform:scale3D(0.95, 0.95, 1)}100%{opacity:1;-webkit-transform:scale3D(1, 1, 1);transform:scale3D(1, 1, 1)}}@keyframes in-scale{0%{opacity:0;-webkit-transform:scale3D(0.95, 0.95, 1);transform:scale3D(0.95, 0.95, 1)}100%{opacity:1;-webkit-transform:scale3D(1, 1, 1);transform:scale3D(1, 1, 1)}}:root{--calcite-animation-timing:calc(150ms * var(--calcite-internal-duration-factor));--calcite-internal-duration-factor:var(--calcite-duration-factor, 1);--calcite-internal-animation-timing-fast:calc(100ms * var(--calcite-internal-duration-factor));--calcite-internal-animation-timing-medium:calc(200ms * var(--calcite-internal-duration-factor));--calcite-internal-animation-timing-slow:calc(300ms * var(--calcite-internal-duration-factor))}.calcite-animate{opacity:0;-webkit-animation-fill-mode:both;animation-fill-mode:both;-webkit-animation-duration:var(--calcite-animation-timing);animation-duration:var(--calcite-animation-timing)}.calcite-animate__in{-webkit-animation-name:in;animation-name:in}.calcite-animate__in-down{-webkit-animation-name:in-down;animation-name:in-down}.calcite-animate__in-up{-webkit-animation-name:in-up;animation-name:in-up}.calcite-animate__in-scale{-webkit-animation-name:in-scale;animation-name:in-scale}:root{--calcite-popper-transition:var(--calcite-animation-timing)}:host([hidden]){display:none}:host{display:block}.container{text-align:start}.container--s{font-size:var(--calcite-font-size--2);line-height:1rem}.container--s .dropdown-title{padding:0.5rem}.container--m{font-size:var(--calcite-font-size--1);line-height:1rem}.container--m .dropdown-title{padding:0.75rem}.container--l{font-size:var(--calcite-font-size-0);line-height:1.25rem}.container--l .dropdown-title{padding:1rem}.dropdown-title{margin-bottom:-1px;display:block;cursor:default;overflow-wrap:break-word;border-width:0px;border-bottom-width:1px;border-style:solid;border-color:var(--calcite-ui-border-3);font-weight:var(--calcite-font-weight-bold);color:var(--calcite-ui-text-2)}.dropdown-separator{display:block;height:1px;background-color:var(--calcite-ui-border-3)}";var u=function(){function t(t){(0,n.r)(this,t),this.calciteInternalDropdownItemSelect=(0,n.c)(this,"calciteInternalDropdownItemSelect",7),this.calciteInternalDropdownItemKeyEvent=(0,n.c)(this,"calciteInternalDropdownItemKeyEvent",7),this.calciteInternalDropdownCloseRequest=(0,n.c)(this,"calciteInternalDropdownCloseRequest",7),this.active=!1}return t.prototype.setFocus=function(){return c(this,void 0,void 0,(function(){var t;return l(this,(function(e){return null===(t=this.el)||void 0===t||t.focus(),[2]}))}))},t.prototype.componentWillLoad=function(){this.initialize()},t.prototype.connectedCallback=function(){this.initialize()},t.prototype.render=function(){var t,e=this,i=(0,o.d)(this.el,"scale","m"),a=(0,n.h)("calcite-icon",{class:"dropdown-item-icon-start",flipRtl:"start"===this.iconFlipRtl||"both"===this.iconFlipRtl,icon:this.iconStart,scale:"s"}),r=(0,n.h)("span",{class:"dropdown-item-content"},(0,n.h)("slot",null)),s=(0,n.h)("calcite-icon",{class:"dropdown-item-icon-end",flipRtl:"end"===this.iconFlipRtl||"both"===this.iconFlipRtl,icon:this.iconEnd,scale:"s"}),c=this.iconStart&&this.iconEnd?[a,r,s]:this.iconStart?[a,(0,n.h)("slot",null)]:this.iconEnd?[r,s]:r,l=this.href?(0,n.h)("a",{"aria-label":this.label,class:"dropdown-link",href:this.href,ref:function(t){return e.childLink=t},rel:this.rel,target:this.target},c):c,p=this.href?null:"single"===this.selectionMode?"menuitemradio":"multi"===this.selectionMode?"menuitemcheckbox":"menuitem",d="none"!==this.selectionMode?(0,o.t)(this.active):null;return(0,n.h)(n.H,{"aria-checked":d,role:p,tabindex:"0"},(0,n.h)("div",{class:(t={container:!0},t["container--link"]=!!this.href,t["container--s"]="s"===i,t["container--m"]="m"===i,t["container--l"]="l"===i,t["container--multi-selection"]="multi"===this.selectionMode,t["container--single-selection"]="single"===this.selectionMode,t["container--none-selection"]="none"===this.selectionMode,t)},"none"!==this.selectionMode?(0,n.h)("calcite-icon",{class:"dropdown-item-icon",icon:"multi"===this.selectionMode?"check":"bullet-point",scale:"s"}):null,l))},t.prototype.onClick=function(){this.emitRequestedItem()},t.prototype.keyDownHandler=function(t){switch(t.key){case" ":case"Enter":this.emitRequestedItem(),this.href&&this.childLink.click(),t.preventDefault();break;case"Escape":this.calciteInternalDropdownCloseRequest.emit(),t.preventDefault();break;case"Tab":this.calciteInternalDropdownItemKeyEvent.emit({keyboardEvent:t});break;case"ArrowUp":case"ArrowDown":case"Home":case"End":t.preventDefault(),this.calciteInternalDropdownItemKeyEvent.emit({keyboardEvent:t})}},t.prototype.updateActiveItemOnChange=function(t){t.composedPath().includes(this.parentDropdownGroupEl)&&(this.requestedDropdownGroup=t.detail.requestedDropdownGroup,this.requestedDropdownItem=t.detail.requestedDropdownItem,this.determineActiveItem()),t.stopPropagation()},t.prototype.initialize=function(){this.selectionMode=(0,o.d)(this.el,"selection-mode","single"),this.parentDropdownGroupEl=this.el.closest("calcite-dropdown-group"),"none"===this.selectionMode&&(this.active=!1)},t.prototype.determineActiveItem=function(){switch(this.selectionMode){case"multi":this.el===this.requestedDropdownItem&&(this.active=!this.active);break;case"single":this.el===this.requestedDropdownItem?this.active=!0:this.requestedDropdownGroup===this.parentDropdownGroupEl&&(this.active=!1);break;case"none":this.active=!1}},t.prototype.emitRequestedItem=function(){this.calciteInternalDropdownItemSelect.emit({requestedDropdownItem:this.el,requestedDropdownGroup:this.parentDropdownGroupEl})},Object.defineProperty(t.prototype,"el",{get:function(){return(0,n.g)(this)},enumerable:!1,configurable:!0}),t}();u.style="@-webkit-keyframes in{0%{opacity:0}100%{opacity:1}}@keyframes in{0%{opacity:0}100%{opacity:1}}@-webkit-keyframes in-down{0%{opacity:0;-webkit-transform:translate3D(0, -5px, 0);transform:translate3D(0, -5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@keyframes in-down{0%{opacity:0;-webkit-transform:translate3D(0, -5px, 0);transform:translate3D(0, -5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@-webkit-keyframes in-up{0%{opacity:0;-webkit-transform:translate3D(0, 5px, 0);transform:translate3D(0, 5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@keyframes in-up{0%{opacity:0;-webkit-transform:translate3D(0, 5px, 0);transform:translate3D(0, 5px, 0)}100%{opacity:1;-webkit-transform:translate3D(0, 0, 0);transform:translate3D(0, 0, 0)}}@-webkit-keyframes in-scale{0%{opacity:0;-webkit-transform:scale3D(0.95, 0.95, 1);transform:scale3D(0.95, 0.95, 1)}100%{opacity:1;-webkit-transform:scale3D(1, 1, 1);transform:scale3D(1, 1, 1)}}@keyframes in-scale{0%{opacity:0;-webkit-transform:scale3D(0.95, 0.95, 1);transform:scale3D(0.95, 0.95, 1)}100%{opacity:1;-webkit-transform:scale3D(1, 1, 1);transform:scale3D(1, 1, 1)}}:root{--calcite-animation-timing:calc(150ms * var(--calcite-internal-duration-factor));--calcite-internal-duration-factor:var(--calcite-duration-factor, 1);--calcite-internal-animation-timing-fast:calc(100ms * var(--calcite-internal-duration-factor));--calcite-internal-animation-timing-medium:calc(200ms * var(--calcite-internal-duration-factor));--calcite-internal-animation-timing-slow:calc(300ms * var(--calcite-internal-duration-factor))}.calcite-animate{opacity:0;-webkit-animation-fill-mode:both;animation-fill-mode:both;-webkit-animation-duration:var(--calcite-animation-timing);animation-duration:var(--calcite-animation-timing)}.calcite-animate__in{-webkit-animation-name:in;animation-name:in}.calcite-animate__in-down{-webkit-animation-name:in-down;animation-name:in-down}.calcite-animate__in-up{-webkit-animation-name:in-up;animation-name:in-up}.calcite-animate__in-scale{-webkit-animation-name:in-scale;animation-name:in-scale}:root{--calcite-popper-transition:var(--calcite-animation-timing)}:host([hidden]){display:none}.container--s{padding-top:0.25rem;padding-bottom:0.25rem;font-size:var(--calcite-font-size--2);line-height:1rem;-webkit-padding-end:0.5rem;padding-inline-end:0.5rem;-webkit-padding-start:1.5rem;padding-inline-start:1.5rem}.container--m{padding-top:0.5rem;padding-bottom:0.5rem;font-size:var(--calcite-font-size--1);line-height:1rem;-webkit-padding-end:0.75rem;padding-inline-end:0.75rem;-webkit-padding-start:2rem;padding-inline-start:2rem}.container--l{padding-top:0.75rem;padding-bottom:0.75rem;font-size:var(--calcite-font-size-0);line-height:1.25rem;-webkit-padding-end:1rem;padding-inline-end:1rem;-webkit-padding-start:2.5rem;padding-inline-start:2.5rem}.container--s.container--none-selection{-webkit-padding-start:0.25rem;padding-inline-start:0.25rem}.container--s.container--none-selection .dropdown-link{-webkit-padding-start:0px;padding-inline-start:0px}.container--m.container--none-selection{-webkit-padding-start:0.5rem;padding-inline-start:0.5rem}.container--m.container--none-selection .dropdown-link{-webkit-padding-start:0px;padding-inline-start:0px}.container--l.container--none-selection{-webkit-padding-start:0.75rem;padding-inline-start:0.75rem}.container--l.container--none-selection .dropdown-link{-webkit-padding-start:0px;padding-inline-start:0px}:host{position:relative;display:-ms-flexbox;display:flex;-ms-flex-positive:1;flex-grow:1;-ms-flex-align:center;align-items:center}.container{position:relative;display:-ms-flexbox;display:flex;-ms-flex-positive:1;flex-grow:1;cursor:pointer;-ms-flex-align:center;align-items:center;color:var(--calcite-ui-text-3);-webkit-text-decoration-line:none;text-decoration-line:none;-webkit-transition-duration:150ms;transition-duration:150ms;-webkit-transition-timing-function:cubic-bezier(0.4, 0, 0.2, 1);transition-timing-function:cubic-bezier(0.4, 0, 0.2, 1);text-align:start}.dropdown-item-content{-ms-flex:1 1 auto;flex:1 1 auto;-webkit-padding-end:auto;padding-inline-end:auto;-webkit-padding-start:0.25rem;padding-inline-start:0.25rem}:host,.container--link a{outline-color:transparent}:host(:focus){outline:2px solid transparent;outline:2px solid var(--calcite-ui-brand);outline-offset:-2px}.container--link{padding:0px}.container--link a{position:relative;display:-ms-flexbox;display:flex;-ms-flex-positive:1;flex-grow:1;cursor:pointer;-ms-flex-align:center;align-items:center;color:var(--calcite-ui-text-3);-webkit-text-decoration-line:none;text-decoration-line:none;-webkit-transition-duration:150ms;transition-duration:150ms;-webkit-transition-timing-function:cubic-bezier(0.4, 0, 0.2, 1);transition-timing-function:cubic-bezier(0.4, 0, 0.2, 1)}.container--s .dropdown-link{padding-top:0.25rem;padding-bottom:0.25rem;font-size:var(--calcite-font-size--2);line-height:1rem;-webkit-padding-end:0.5rem;padding-inline-end:0.5rem;-webkit-padding-start:1.5rem;padding-inline-start:1.5rem}.container--m .dropdown-link{padding-top:0.5rem;padding-bottom:0.5rem;font-size:var(--calcite-font-size--1);line-height:1rem;-webkit-padding-end:0.75rem;padding-inline-end:0.75rem;-webkit-padding-start:2rem;padding-inline-start:2rem}.container--l .dropdown-link{padding-top:0.75rem;padding-bottom:0.75rem;font-size:var(--calcite-font-size-0);line-height:1.25rem;-webkit-padding-end:1rem;padding-inline-end:1rem;-webkit-padding-start:2.5rem;padding-inline-start:2.5rem}:host(:hover) .container,:host(:active) .container{background-color:var(--calcite-ui-foreground-2);color:var(--calcite-ui-text-1);-webkit-text-decoration-line:none;text-decoration-line:none}:host(:hover) .container--link .dropdown-link,:host(:active) .container--link .dropdown-link{color:var(--calcite-ui-text-1)}:host(:focus) .container{color:var(--calcite-ui-text-1);-webkit-text-decoration-line:none;text-decoration-line:none}:host(:active) .container{background-color:var(--calcite-ui-foreground-3)}:host(:hover) .container:before,:host(:active) .container:before,:host(:focus) .container:before{opacity:1}:host([active]) .container:not(.container--none-selection),:host([active]) .container--link .dropdown-link{font-weight:var(--calcite-font-weight-medium);color:var(--calcite-ui-text-1)}:host([active]) .container:not(.container--none-selection):before,:host([active]) .container--link .dropdown-link:before{opacity:1;color:var(--calcite-ui-brand)}:host([active]) .container:not(.container--none-selection) calcite-icon,:host([active]) .container--link .dropdown-link calcite-icon{color:var(--calcite-ui-brand)}.container--multi-selection:before,.container--none-selection:before{display:none}.container--s:before{inset-inline-start:0.5rem}.container--m:before{inset-inline-start:0.75rem}.container--l:before{inset-inline-start:1rem}.dropdown-item-icon{position:absolute;opacity:0;-webkit-transition-duration:150ms;transition-duration:150ms;-webkit-transition-timing-function:cubic-bezier(0.4, 0, 0.2, 1);transition-timing-function:cubic-bezier(0.4, 0, 0.2, 1);-webkit-transform:scale(0.9);transform:scale(0.9)}.container--s .dropdown-item-icon{inset-inline-start:0.25rem}.container--m .dropdown-item-icon{inset-inline-start:0.5rem}.container--l .dropdown-item-icon{inset-inline-start:0.75rem}:host(:hover) .dropdown-item-icon{color:var(--calcite-ui-border-1);opacity:1}:host([active]) .dropdown-item-icon{color:var(--calcite-ui-brand);opacity:1}.container--s .dropdown-item-icon-start{-webkit-margin-end:0.5rem;margin-inline-end:0.5rem;-webkit-margin-start:0.25rem;margin-inline-start:0.25rem}.container--s .dropdown-item-icon-end{-webkit-margin-start:0.5rem;margin-inline-start:0.5rem}.container--m .dropdown-item-icon-start{-webkit-margin-end:0.75rem;margin-inline-end:0.75rem;-webkit-margin-start:0.25rem;margin-inline-start:0.25rem}.container--m .dropdown-item-icon-end{-webkit-margin-start:0.75rem;margin-inline-start:0.75rem}.container--l .dropdown-item-icon-start{-webkit-margin-end:1rem;margin-inline-end:1rem;-webkit-margin-start:0.25rem;margin-inline-start:0.25rem}.container--l .dropdown-item-icon-end{-webkit-margin-start:1rem;margin-inline-start:1rem}"},4485:(t,e,i)=>{function n(){}function o(t,e){if(void 0===e&&(e=!1),t.disabled)return t.el.setAttribute("tabindex","-1"),t.el.setAttribute("aria-disabled","true"),t.el.contains(document.activeElement)&&document.activeElement.blur(),void(t.el.click=n);t.el.click=HTMLElement.prototype.click,"function"==typeof e?t.el.setAttribute("tabindex",e.call(t)?"0":"-1"):!0===e?t.el.setAttribute("tabindex","0"):!1===e&&t.el.removeAttribute("tabindex"),t.el.removeAttribute("aria-disabled")}i.r(e),i.d(e,{u:()=>o})},8762:(t,e,i)=>{function n(t,e,i){var n=function(t){return"intersection"===t?window.IntersectionObserver:"mutation"===t?window.MutationObserver:window.ResizeObserver}(t);return new n(e,i)}i.r(e),i.d(e,{c:()=>n})}}]);