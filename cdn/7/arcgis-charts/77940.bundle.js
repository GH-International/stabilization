"use strict";(self.webpackChunkexb_client=self.webpackChunkexb_client||[]).push([[77940],{77940:(e,t,a)=>{a.r(t),a.d(t,{additionalProperty:()=>P,anyOfValues:()=>x,bubbleChartValidateMsg:()=>S,default:()=>q,defaultError:()=>i,defaultInvalidChart:()=>s,duplicateSeriesID:()=>u,enumValues:()=>g,histogramEmptyField:()=>E,invalidSeriesType:()=>v,layerLoadFailure:()=>m,lineChartMarkersCannotExceedLimit:()=>k,lineChartSeriesAndMarkersCannotExceedLimit:()=>b,maxItems:()=>L,minItems:()=>c,minLength:()=>h,negativeValueInDataForLogTransformation:()=>l,negativeValueInDataForSqrtTransformation:()=>d,nonNumericAggregation:()=>C,or:()=>I,pieChartCannotHaveMixtureOfPositiveAndNegativeSlices:()=>f,pieChartSlicesCannotExceedLimit:()=>V,queryError:()=>y,requiredProperty:()=>$,threePlusSeriesBarCountCannotExceedLimit:()=>o,twoSeriesBarCountCannotExceedLimit:()=>n,uniqueSeriesBarCountCannotExceedLimit:()=>r,whiteSpacePattern:()=>p});const i="حدث خطأ أثناء تحميل المخطط.",r="يوجد إجمالي ${ elementCount } من الأشرطة في هذا المخطط. المخططات الشريطية التي تحتوي على سلسلة واحدة تقتصر على ${ totalLimit } من الأشرطة. اختر حقل فئة بقيم فريدة أقل أو طبّق عامل تصفية على بياناتك.",n="تقتصر المخططات الشريطية التي تحتوي على سلسلتين على ${ totalLimit } من الأشرطة أو ${ seriesLimit } من الأشرطة لكل سلسلة. اختر حقل فئة بقيم فريدة أقل أو طبّق عامل تصفية على بياناتك.",o="تقتصر المخططات الشريطية التي تحتوي على ثلاث سلاسل أو أكثر على ${ totalLimit } من الأشرطة أو ${ seriesLimit } من الأشرطة لكل سلسلة. اختر حقل فئة بقيم فريدة أقل أو طبّق عامل تصفية على بياناتك.",s="حدث خطأ أثناء إنشاء المخطط.",l="يتعذر تطبيق تحويل السِّجل إلى قيم سلبية أو إلى صفر.",d="يتعذر تطبيق تحويل الجذر التربيعي إلى قيم سلبية.",m="حدث خطأ أثناء تحميل الطبقة. URL = ${ url }. معرف عنصر البوابة = ${ portalItemId }.",u="يجب أن يكون ${ dataPath } مميزًا. السلسلة التي اسمها ${ seriesName } تتضمن معرفًا (${ seriesID }) مستخدمًا بالفعل من قبل سلسلة أخرى.",C="يتعذر على ${ dataPath } إجراء تجميع من دون حساب في حقل غير رقمي.",$="يتفقد ${ dataPath } خاصية باسم ${ missingProperty }.",h="يجب ألا يكون ${ dataPath } أقصر من ${ limit } من الحروف.",c="يجب ألا يحتوي ${ dataPath } على أقل من ${ limit } من العناصر.",L="يجب ألا يحتوي ${ dataPath } على أكثر من ${ limit } من العناصر.",p="يجب أن يتضمن ${ dataPath } حرفًا واحدًا على الأقل ليس مسافة بيضاء.",P="يجب أن يحتوي ${ dataPath } على ${ additionalProperty }.",g="يجب أن يكون ${ dataPath } مساويًا لإحدى القيم هذه المسموح بها: ${ allowedValues }",x="يجب أن يتطابق ${ dataPath } مع مخطط أحد ما يلي: ${ schemaOptions }.",S="مخططات التبعثر ذات الرموز المتناسبة غير مدعومة. تم تطبيق حجم الرمز الافتراضي.",y="فشلت قراءة البيانات المدخلة.",E="تتطلب المدرجات التكرارية قيمتين رقميتين على الأقل.",v="نوع السلسلة المتوقع في الفهرس ${ seriesIndex } هو '${ expectedType }' ولكن تم استلام '${ receivedType }' بدلاً من ذلك",I="أو",f="تأكد من أن إجمالي مجموع الحقل الرقمي المختار (الحقول الرقمية المختارة) يُرجع كل القيم الموجبة أو كل القيم السالبة.",V="يوجد إجمالي ${ sliceCount } من الشرائح في هذا المخطط. المخططات الدائرية تقتصر على ${ totalLimit } من الشرائح. اختر حقل فئة يحتوي على عدد أقل من القيم الفريدة، أو أضف عددًا أقل من الحقول الرقمية، أو قم بتطبيق عامل تصفية على بياناتك.",b="يوجد إجمالي ${ seriesCount } من السلاسل و${ elementCount } من نقاط البيانات في هذا المخطط. تقتصر المخططات الخطية على ${ seriesLimit } من السلاسل و${ totalLimit } من نقاط البيانات. قم بتقليل عدد السلاسل أو أعد تجميع بياناتك (أو كليهما) أو قم بتصفيتها.",k="تقتصر المخططات الخطية على ${ totalLimit } من نقاط البيانات. قم بتصفية البيانات أو إعادة تجميعها وأعد المحاولة.";var q={defaultError:"حدث خطأ أثناء تحميل المخطط.",uniqueSeriesBarCountCannotExceedLimit:r,twoSeriesBarCountCannotExceedLimit:n,threePlusSeriesBarCountCannotExceedLimit:o,defaultInvalidChart:"حدث خطأ أثناء إنشاء المخطط.",negativeValueInDataForLogTransformation:"يتعذر تطبيق تحويل السِّجل إلى قيم سلبية أو إلى صفر.",negativeValueInDataForSqrtTransformation:"يتعذر تطبيق تحويل الجذر التربيعي إلى قيم سلبية.",layerLoadFailure:m,duplicateSeriesID:u,nonNumericAggregation:C,requiredProperty:$,minLength:h,minItems:c,maxItems:L,whiteSpacePattern:p,additionalProperty:P,enumValues:g,anyOfValues:x,bubbleChartValidateMsg:S,queryError:"فشلت قراءة البيانات المدخلة.",histogramEmptyField:"تتطلب المدرجات التكرارية قيمتين رقميتين على الأقل.",invalidSeriesType:v,or:"أو",pieChartCannotHaveMixtureOfPositiveAndNegativeSlices:"تأكد من أن إجمالي مجموع الحقل الرقمي المختار (الحقول الرقمية المختارة) يُرجع كل القيم الموجبة أو كل القيم السالبة.",pieChartSlicesCannotExceedLimit:V,lineChartSeriesAndMarkersCannotExceedLimit:b,lineChartMarkersCannotExceedLimit:k}}}]);