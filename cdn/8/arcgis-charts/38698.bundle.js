/*! For license information please see 38698.bundle.js.LICENSE.txt */
"use strict";(self.webpackChunkexb_client=self.webpackChunkexb_client||[]).push([[38698],{38698:(t,i,n)=>{n.r(i),n.d(i,{additionalProperty:()=>$,anyOfValues:()=>k,bubbleChartValidateMsg:()=>L,default:()=>D,defaultError:()=>h,defaultInvalidChart:()=>c,duplicateSeriesID:()=>l,enumValues:()=>y,histogramEmptyField:()=>x,invalidSeriesType:()=>P,layerLoadFailure:()=>u,lineChartMarkersCannotExceedLimit:()=>B,lineChartSeriesAndMarkersCannotExceedLimit:()=>f,maxItems:()=>C,minItems:()=>p,minLength:()=>s,negativeValueInDataForLogTransformation:()=>g,negativeValueInDataForSqrtTransformation:()=>o,nonNumericAggregation:()=>d,or:()=>S,pieChartCannotHaveMixtureOfPositiveAndNegativeSlices:()=>E,pieChartSlicesCannotExceedLimit:()=>I,queryError:()=>v,requiredProperty:()=>m,threePlusSeriesBarCountCannotExceedLimit:()=>r,twoSeriesBarCountCannotExceedLimit:()=>e,uniqueSeriesBarCountCannotExceedLimit:()=>a,whiteSpacePattern:()=>b});const h="Đã xảy ra lỗi khi tải biểu đồ.",a="Có tổng cộng ${ elementCount } cột trong biểu đồ này. Biểu đồ dạng thanh có một chuỗi giới hạn đến ${ totalLimit } thanh. Chọn trường Danh mục có ít giá trị duy nhất hơn hoặc áp dụng bộ lọc cho dữ liệu của bạn.",e="Biểu đồ thanh có hai chuỗi giới hạn đến ${ totalLimit } thanh hoặc ${ seriesLimit } thanh mỗi chuỗi. Chọn trường Danh mục có ít giá trị duy nhất hơn hoặc áp dụng bộ lọc cho dữ liệu của bạn.",r="Biểu đồ thanh có ba chuỗi trở lên giới hạn đến ${ totalLimit } thanh hoặc ${ seriesLimit } thanh mỗi chuỗi. Chọn trường Danh mục có ít giá trị duy nhất hơn hoặc áp dụng bộ lọc cho dữ liệu của bạn.",c="Đã xảy ra lỗi khi tạo biểu đồ.",g="Không thể áp dụng phép biến đổi log lên giá trị âm hoặc bằng không.",o="Không thể áp dụng phép biến đổi căn bậc hai lên giá trị âm.",u="Đã xảy ra lỗi khi tải lớp. URL = ${ url }. ID mục cổng thông tin = ${ portalItemId }.",l="${ dataPath } phải là duy nhất. Chuỗi có tên ${ seriesName } có một ID (${ seriesID }) đã được chuỗi khác sử dụng.",d="${ dataPath } không thể thực hiện tổng hợp không đếm trên trường không phải là số.",m="${ dataPath } đang thiếu một tên phù hợp ${ missingProperty }.",s="${ dataPath } không được ngắn hơn ${ limit } ký tự.",p="${ dataPath } không được chứa dưới ${ limit } mục.",C="${ dataPath } không được chứa nhiều hơn ${ limit } mục.",b="${ dataPath } phải chứa ít nhất một ký tự không phải khoảng trắng.",$="${ dataPath } không được chứa ${ additionalProperty }.",y="${ dataPath } phải bằng một trong những giá trị được phép này: ${ allowedValues }.",k="${ dataPath } phải khớp với lược đồ của một trong những thứ sau: ${ schemaOptions }.",L="Biểu đồ phân tán có ký hiệu tỷ lệ không được hỗ trợ. Đã áp dụng kích cỡ ký hiệu theo mặc định.",v="Không thể đọc dữ liệu đầu vào.",x="Biểu đồ tần số yêu cầu ít nhất hai giá trị số khác nhau.",P="Loại chuỗi mong đợi tại chỉ mục ${ seriesIndex } là '${ expectedType }' nhưng thay vào đó lại nhận được '${ receivedType }'",S="hoặc",E="Đảm bảo tổng cộng của (các) trường dạng số đã chọn trả về tất cả các giá trị dương hoặc tất cả các giá trị âm.",I="Có tổng cộng ${ sliceCount } lát cắt trong biểu đồ này. Biểu đồ hình tròn bị giới hạn ${ totalLimit } lát cắt. Chọn trường Danh mục có ít giá trị duy nhất hơn, thêm ít trường Số hơn hoặc áp dụng bộ lọc cho dữ liệu của bạn.",f="Có tổng cộng ${ seriesCount } chuỗi và ${ elementCount } điểm dữ liệu trong biểu đồ này. Biểu đồ đường bị giới hạn ${ seriesLimit } chuỗi và ${ totalLimit } điểm dữ liệu. Giảm số lượng chuỗi và/hoặc tổng hợp lại hoặc lọc dữ liệu của bạn.",B="Biểu đồ đường bị giới hạn ${ totalLimit } điểm dữ liệu. Lọc hoặc tổng hợp lại dữ liệu của bạn và thử lại.",D={defaultError:"Đã xảy ra lỗi khi tải biểu đồ.",uniqueSeriesBarCountCannotExceedLimit:a,twoSeriesBarCountCannotExceedLimit:e,threePlusSeriesBarCountCannotExceedLimit:r,defaultInvalidChart:"Đã xảy ra lỗi khi tạo biểu đồ.",negativeValueInDataForLogTransformation:"Không thể áp dụng phép biến đổi log lên giá trị âm hoặc bằng không.",negativeValueInDataForSqrtTransformation:"Không thể áp dụng phép biến đổi căn bậc hai lên giá trị âm.",layerLoadFailure:u,duplicateSeriesID:l,nonNumericAggregation:d,requiredProperty:m,minLength:s,minItems:p,maxItems:C,whiteSpacePattern:b,additionalProperty:"${ dataPath } không được chứa ${ additionalProperty }.",enumValues:y,anyOfValues:k,bubbleChartValidateMsg:L,queryError:"Không thể đọc dữ liệu đầu vào.",histogramEmptyField:"Biểu đồ tần số yêu cầu ít nhất hai giá trị số khác nhau.",invalidSeriesType:P,or:"hoặc",pieChartCannotHaveMixtureOfPositiveAndNegativeSlices:"Đảm bảo tổng cộng của (các) trường dạng số đã chọn trả về tất cả các giá trị dương hoặc tất cả các giá trị âm.",pieChartSlicesCannotExceedLimit:I,lineChartSeriesAndMarkersCannotExceedLimit:f,lineChartMarkersCannotExceedLimit:B}}}]);