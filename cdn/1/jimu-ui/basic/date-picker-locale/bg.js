System.register([],(function(t,e){return{execute:function(){t((()=>{"use strict";var t={d:(e,a)=>{for(var r in a)t.o(a,r)&&!t.o(e,r)&&Object.defineProperty(e,r,{enumerable:!0,get:a[r]})},o:(t,e)=>Object.prototype.hasOwnProperty.call(t,e),r:t=>{"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})}},e={};t.r(e),t.d(e,{default:()=>W});var a={lessThanXSeconds:{one:"по-малко от секунда",other:"по-малко от {{count}} секунди"},xSeconds:{one:"1 секунда",other:"{{count}} секунди"},halfAMinute:"половин минута",lessThanXMinutes:{one:"по-малко от минута",other:"по-малко от {{count}} минути"},xMinutes:{one:"1 минута",other:"{{count}} минути"},aboutXHours:{one:"около час",other:"около {{count}} часа"},xHours:{one:"1 час",other:"{{count}} часа"},xDays:{one:"1 ден",other:"{{count}} дни"},aboutXWeeks:{one:"около седмица",other:"около {{count}} седмици"},xWeeks:{one:"1 седмица",other:"{{count}} седмици"},aboutXMonths:{one:"около месец",other:"около {{count}} месеца"},xMonths:{one:"1 месец",other:"{{count}} месеца"},aboutXYears:{one:"около година",other:"около {{count}} години"},xYears:{one:"1 година",other:"{{count}} години"},overXYears:{one:"над година",other:"над {{count}} години"},almostXYears:{one:"почти година",other:"почти {{count}} години"}};function r(t){return function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},a=e.width?String(e.width):t.defaultWidth,r=t.formats[a]||t.formats[t.defaultWidth];return r}}const n={date:r({formats:{full:"EEEE, dd MMMM yyyy",long:"dd MMMM yyyy",medium:"dd MMM yyyy",short:"dd/MM/yyyy"},defaultWidth:"full"}),time:r({formats:{full:"HH:mm:ss zzzz",long:"HH:mm:ss z",medium:"HH:mm:ss",short:"H:mm"},defaultWidth:"full"}),dateTime:r({formats:{any:"{{date}} {{time}}"},defaultWidth:"any"})};function i(t,e){if(e.length<t)throw new TypeError(t+" argument"+(t>1?"s":"")+" required, but only "+e.length+" present")}function o(t){i(1,arguments);var e=Object.prototype.toString.call(t);return t instanceof Date||"object"==typeof t&&"[object Date]"===e?new Date(t.getTime()):"number"==typeof t||"[object Number]"===e?new Date(t):("string"!=typeof t&&"[object String]"!==e||"undefined"==typeof console||(console.warn("Starting with v2.0.0-beta.1 date-fns doesn't accept strings as date arguments. Please use `parseISO` to parse strings. See: https://git.io/fjule"),console.warn((new Error).stack)),new Date(NaN))}function u(t){if(null===t||!0===t||!1===t)return NaN;var e=Number(t);return isNaN(e)?e:e<0?Math.ceil(e):Math.floor(e)}function s(t,e){i(1,arguments);var a=e||{},r=a.locale,n=r&&r.options&&r.options.weekStartsOn,s=null==n?0:u(n),l=null==a.weekStartsOn?s:u(a.weekStartsOn);if(!(l>=0&&l<=6))throw new RangeError("weekStartsOn must be between 0 and 6 inclusively");var c=o(t),d=c.getUTCDay(),f=(d<l?7:0)+d-l;return c.setUTCDate(c.getUTCDate()-f),c.setUTCHours(0,0,0,0),c}function l(t,e,a){i(2,arguments);var r=s(t,a),n=s(e,a);return r.getTime()===n.getTime()}var c=["неделя","понеделник","вторник","сряда","четвъртък","петък","събота"];function d(t){var e=c[t];return 2===t?"'във "+e+" в' p":"'в "+e+" в' p"}var f={lastWeek:function(t,e,a){var r=o(t),n=r.getUTCDay();return l(r,e,a)?d(n):function(t){var e=c[t];switch(t){case 0:case 3:case 6:return"'миналата "+e+" в' p";case 1:case 2:case 4:case 5:return"'миналия "+e+" в' p"}}(n)},yesterday:"'вчера в' p",today:"'днес в' p",tomorrow:"'утре в' p",nextWeek:function(t,e,a){var r=o(t),n=r.getUTCDay();return l(r,e,a)?d(n):function(t){var e=c[t];switch(t){case 0:case 3:case 6:return"'следващата "+e+" в' p";case 1:case 2:case 4:case 5:return"'следващия "+e+" в' p"}}(n)},other:"P"};function h(t){return function(e,a){var r,n=a||{};if("formatting"===(n.context?String(n.context):"standalone")&&t.formattingValues){var i=t.defaultFormattingWidth||t.defaultWidth,o=n.width?String(n.width):i;r=t.formattingValues[o]||t.formattingValues[i]}else{var u=t.defaultWidth,s=n.width?String(n.width):t.defaultWidth;r=t.values[s]||t.values[u]}return r[t.argumentCallback?t.argumentCallback(e):e]}}function m(t,e,a,r,n){var i=function(t){return"quarter"===t}(e)?n:function(t){return"year"===t||"week"===t||"minute"===t||"second"===t}(e)?r:a;return t+"-"+i}var v={ordinalNumber:function(t){var e=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},a=String(e.unit),r=Number(t);if(0===r)return m(0,a,"ев","ева","ево");if(r%1e3==0)return m(r,a,"ен","на","но");if(r%100==0)return m(r,a,"тен","тна","тно");var n=r%100;if(n>20||n<10)switch(n%10){case 1:return m(r,a,"ви","ва","во");case 2:return m(r,a,"ри","ра","ро");case 7:case 8:return m(r,a,"ми","ма","мо")}return m(r,a,"ти","та","то")},era:h({values:{narrow:["пр.н.е.","н.е."],abbreviated:["преди н. е.","н. е."],wide:["преди новата ера","новата ера"]},defaultWidth:"wide"}),quarter:h({values:{narrow:["1","2","3","4"],abbreviated:["1-во тримес.","2-ро тримес.","3-то тримес.","4-то тримес."],wide:["1-во тримесечие","2-ро тримесечие","3-то тримесечие","4-то тримесечие"]},defaultWidth:"wide",argumentCallback:function(t){return Number(t)-1}}),month:h({values:{abbreviated:["яну","фев","мар","апр","май","юни","юли","авг","сеп","окт","ное","дек"],wide:["януари","февруари","март","април","май","юни","юли","август","септември","октомври","ноември","декември"]},defaultWidth:"wide"}),day:h({values:{narrow:["Н","П","В","С","Ч","П","С"],short:["нд","пн","вт","ср","чт","пт","сб"],abbreviated:["нед","пон","вто","сря","чет","пет","съб"],wide:["неделя","понеделник","вторник","сряда","четвъртък","петък","събота"]},defaultWidth:"wide"}),dayPeriod:h({values:{wide:{am:"преди обяд",pm:"след обяд",midnight:"в полунощ",noon:"на обяд",morning:"сутринта",afternoon:"следобед",evening:"вечерта",night:"през нощта"}},defaultWidth:"wide"})};const y=v;function g(t){return function(e){var a=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},r=a.width,n=r&&t.matchPatterns[r]||t.matchPatterns[t.defaultMatchWidth],i=e.match(n);if(!i)return null;var o,u=i[0],s=r&&t.parsePatterns[r]||t.parsePatterns[t.defaultParseWidth],l=Array.isArray(s)?w(s,(function(t){return t.test(u)})):b(s,(function(t){return t.test(u)}));o=t.valueCallback?t.valueCallback(l):l,o=a.valueCallback?a.valueCallback(o):o;var c=e.slice(u.length);return{value:o,rest:c}}}function b(t,e){for(var a in t)if(t.hasOwnProperty(a)&&e(t[a]))return a}function w(t,e){for(var a=0;a<t.length;a++)if(e(t[a]))return a}var p,P={ordinalNumber:(p={matchPattern:/^(\d+)(-?[врмт][аи]|-?т?(ен|на)|-?(ев|ева))?/i,parsePattern:/\d+/i,valueCallback:function(t){return parseInt(t,10)}},function(t){var e=arguments.length>1&&void 0!==arguments[1]?arguments[1]:{},a=t.match(p.matchPattern);if(!a)return null;var r=a[0],n=t.match(p.parsePattern);if(!n)return null;var i=p.valueCallback?p.valueCallback(n[0]):n[0];i=e.valueCallback?e.valueCallback(i):i;var o=t.slice(r.length);return{value:i,rest:o}}),era:g({matchPatterns:{narrow:/^((пр)?н\.?\s?е\.?)/i,abbreviated:/^((пр)?н\.?\s?е\.?)/i,wide:/^(преди новата ера|новата ера|нова ера)/i},defaultMatchWidth:"wide",parsePatterns:{any:[/^п/i,/^н/i]},defaultParseWidth:"any"}),quarter:g({matchPatterns:{narrow:/^[1234]/i,abbreviated:/^[1234](-?[врт]?o?)? тримес.?/i,wide:/^[1234](-?[врт]?о?)? тримесечие/i},defaultMatchWidth:"wide",parsePatterns:{any:[/1/i,/2/i,/3/i,/4/i]},defaultParseWidth:"any",valueCallback:function(t){return Number(t)+1}}),month:g({matchPatterns:{abbreviated:/^(яну|фев|мар|апр|май|юни|юли|авг|сеп|окт|ное|дек)/i,wide:/^(януари|февруари|март|април|май|юни|юли|август|септември|октомври|ноември|декември)/i},defaultMatchWidth:"wide",parsePatterns:{any:[/^я/i,/^ф/i,/^мар/i,/^ап/i,/^май/i,/^юн/i,/^юл/i,/^ав/i,/^се/i,/^окт/i,/^но/i,/^де/i]},defaultParseWidth:"any"}),day:g({matchPatterns:{narrow:/^[нпвсч]/i,short:/^(нд|пн|вт|ср|чт|пт|сб)/i,abbreviated:/^(нед|пон|вто|сря|чет|пет|съб)/i,wide:/^(неделя|понеделник|вторник|сряда|четвъртък|петък|събота)/i},defaultMatchWidth:"wide",parsePatterns:{narrow:[/^н/i,/^п/i,/^в/i,/^с/i,/^ч/i,/^п/i,/^с/i],any:[/^н[ед]/i,/^п[он]/i,/^вт/i,/^ср/i,/^ч[ет]/i,/^п[ет]/i,/^с[ъб]/i]},defaultParseWidth:"any"}),dayPeriod:g({matchPatterns:{any:/^(преди о|след о|в по|на о|през|веч|сут|следо)/i},defaultMatchWidth:"any",parsePatterns:{any:{am:/^преди о/i,pm:/^след о/i,midnight:/^в пол/i,noon:/^на об/i,morning:/^сут/i,afternoon:/^следо/i,evening:/^веч/i,night:/^през н/i}},defaultParseWidth:"any"})};const W={code:"bg",formatDistance:function(t,e){var r,n=arguments.length>2&&void 0!==arguments[2]?arguments[2]:{},i=a[t];return r="string"==typeof i?i:1===e?i.one:i.other.replace("{{count}}",String(e)),n.addSuffix?n.comparison&&n.comparison>0?"след "+r:"преди "+r:r},formatLong:n,formatRelative:function(t,e,a,r){var n=f[t];return"function"==typeof n?n(e,a,r):n},localize:y,match:P,options:{weekStartsOn:1,firstWeekContainsDate:1}};return e})())}}}));