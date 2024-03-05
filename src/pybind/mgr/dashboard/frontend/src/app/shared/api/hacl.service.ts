import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpResponse} from '@angular/common/http';
import { AwsSignatureService } from "./aws-signature.service";
import { Observable } from 'rxjs';
//import jsAwsSigV4 from 'js-aws-sigv4';

@Injectable({
  providedIn: 'root'
})
export class HAclService {

  signedUrl: string;
  // 빈 함수 생성
  constructor(private http: HttpClient, private awsSignatureService: AwsSignatureService) { }

  // 빈 함수 생성
  getDec(userName: string): Observable<HttpResponse<any>> {
    let method = 'GET';
    let url = "http://localhost:7480/admin/org/dec";
    let service = 's3';
    let region = 'us-east-1';
    let accessKey = 'root';
    let secretKey = 'root';
    let queryParamsDict = {'user': userName, 'json': 'true'}; // 변수 이름 수정
    
    const headers: HttpHeaders = this.awsSignatureService.signRequest(method, url, service, region, accessKey, secretKey, queryParamsDict); // 수정된 변수 이름 사용


    return this.http.get(url, { 
      headers: headers, 
      params: queryParamsDict, 
      observe: 'response', // Get the full response
      responseType: 'json' // Get the full response
    });
  }

  async getSignedUrl(){

    return this.signedUrl;
  }

}