/*! For license information please see 32891.bundle.js.LICENSE.txt */
"use strict";(self.webpackChunkexb_client=self.webpackChunkexb_client||[]).push([[32891],{32891:(a,e,i)=>{i.r(e),i.d(e,{additionalProperty:()=>h,anyOfValues:()=>g,bubbleChartValidateMsg:()=>k,default:()=>I,defaultError:()=>t,defaultInvalidChart:()=>s,duplicateSeriesID:()=>u,enumValues:()=>b,histogramEmptyField:()=>$,invalidSeriesType:()=>L,layerLoadFailure:()=>m,lineChartMarkersCannotExceedLimit:()=>x,lineChartSeriesAndMarkersCannotExceedLimit:()=>S,maxItems:()=>p,minItems:()=>z,minLength:()=>w,negativeValueInDataForLogTransformation:()=>c,negativeValueInDataForSqrtTransformation:()=>l,nonNumericAggregation:()=>d,or:()=>f,pieChartCannotHaveMixtureOfPositiveAndNegativeSlices:()=>E,pieChartSlicesCannotExceedLimit:()=>P,queryError:()=>C,requiredProperty:()=>y,threePlusSeriesBarCountCannotExceedLimit:()=>r,twoSeriesBarCountCannotExceedLimit:()=>o,uniqueSeriesBarCountCannotExceedLimit:()=>n,whiteSpacePattern:()=>j});const t="Wystąpił błąd podczas wczytywania diagramu.",n="Na tym diagramie znajduje się łącznie następująca liczba słupków: ${ elementCount }. Diagramy słupkowe z jedną serią są ograniczone do następującej liczby słupków: ${ totalLimit }. Wybierz pole Kategoria zawierające mniej wartości unikalnych lub zastosuj filtr do swoich danych.",o="Diagramy słupkowe z dwiema seriami są ograniczone do następującej liczby słupków: ${ totalLimit } lub następującej liczby słupków na serię: ${ seriesLimit }. Wybierz pole Kategoria zawierające mniej wartości unikalnych lub zastosuj filtr do swoich danych.",r="Diagramy słupkowe z trzema lub większą liczbą serii są ograniczone do następującej liczby słupków: ${ totalLimit } lub następującej liczby słupków na serię: ${ seriesLimit }. Wybierz pole Kategoria zawierające mniej wartości unikalnych lub zastosuj filtr do swoich danych.",s="Wystąpił błąd podczas tworzenia diagramu.",c="Nie można zastosować transformacji Logarytm do wartości ujemnych lub równych zero.",l="Nie można zastosować transformacji Pierwiastek kwadratowy do wartości ujemnych.",m="Wystąpił błąd podczas wczytywania warstwy. URL = ${ url }. Identyfikator elementu portalu = ${ portalItemId }.",u="Nazwa ${ dataPath } musi być unikalna. Seria o nazwie ${ seriesName } ma identyfikator (${ seriesID }), który jest już używany przez inną serię.",d="Element ${ dataPath } nie może wykonywać agregacji innej niż zliczenie na polu innym niż liczbowe.",y="W elemencie ${ dataPath } brak właściwości o nazwie ${ missingProperty }.",w="Element ${ dataPath } nie może być krótszy niż następująca liczba znaków: ${ limit }.",z="Element ${ dataPath } nie może mieć mniej elementów niż ${ limit }.",p="Element ${ dataPath } nie może mieć więcej elementów niż ${ limit }.",j="Element ${ dataPath } musi zawierać co najmniej jeden znak inny niż biały znak.",h="Element ${ dataPath } nie może zawierać ${ additionalProperty }.",b="Element ${ dataPath } musi mieć wartość równą jednej z tych dozwolonych wartości: ${ allowedValues }.",g="Element ${ dataPath } musi być zgodny z jednym z tych schematów: ${ schemaOptions }.",k="Diagramy punktowe z symbolami proporcjonalnymi nie są obsługiwane. Zastosowano domyślną wielkość symbolu.",C="Nie powiódł się odczyt danych wejściowych.",$="Histogramy wymagają co najmniej dwóch wartości liczbowych.",L="Oczekiwany typ serii z indeksem ${ seriesIndex } to '${ expectedType }', ale zamiast niego otrzymano '${ receivedType }'",f="lub",E="Sprawdź, czy suma całkowita wybranych pól liczbowych zwraca tylko wartości dodatnie czy tylko wartości ujemne.",P="Na tym diagramie znajduje się łącznie następująca liczba wycinków: ${ sliceCount }. Na diagramach kołowych może znajdować się maksymalnie ${ totalLimit } wycinków. Wybierz pole Kategoria zawierające mniej wartości unikalnych, dodaj mniej pól liczbowych lub zastosuj filtr do swoich danych.",S="Na tym diagramie znajduje się łącznie następująca liczba serii: ${ seriesCount } i następująca liczba punktów danych: ${ elementCount }. W przypadku diagramów liniowych obowiązują ograniczenia do następującej liczby serii: ${ seriesLimit } i następującej liczby punktów danych: ${ totalLimit }. Zmniejsz liczbę serii i/lub ponownie zagreguj lub przefiltruj dane.",x="W przypadku diagramów liniowych obowiązują ograniczenia do następującej liczby punktów danych: ${ totalLimit }. Przefiltruj lub ponownie agreguj dane i spróbuj ponownie.",I={defaultError:t,uniqueSeriesBarCountCannotExceedLimit:n,twoSeriesBarCountCannotExceedLimit:o,threePlusSeriesBarCountCannotExceedLimit:r,defaultInvalidChart:"Wystąpił błąd podczas tworzenia diagramu.",negativeValueInDataForLogTransformation:"Nie można zastosować transformacji Logarytm do wartości ujemnych lub równych zero.",negativeValueInDataForSqrtTransformation:"Nie można zastosować transformacji Pierwiastek kwadratowy do wartości ujemnych.",layerLoadFailure:m,duplicateSeriesID:u,nonNumericAggregation:d,requiredProperty:y,minLength:w,minItems:z,maxItems:p,whiteSpacePattern:j,additionalProperty:h,enumValues:b,anyOfValues:g,bubbleChartValidateMsg:k,queryError:C,histogramEmptyField:$,invalidSeriesType:L,or:"lub",pieChartCannotHaveMixtureOfPositiveAndNegativeSlices:"Sprawdź, czy suma całkowita wybranych pól liczbowych zwraca tylko wartości dodatnie czy tylko wartości ujemne.",pieChartSlicesCannotExceedLimit:P,lineChartSeriesAndMarkersCannotExceedLimit:S,lineChartMarkersCannotExceedLimit:x}}}]);