import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams, HttpResponse} from '@angular/common/http';
import { AwsSignatureService } from "./aws-signature.service";
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class HAclService {

  signedUrl: string;
  // 빈 함수 생성
  constructor(private http: HttpClient, private awsSignatureService: AwsSignatureService) { }

  getReqeustInfo(): [HttpHeaders, {[key: string]: string}] {
    let method = 'GET';
    let url = "http://localhost:7480/admin/org/dec?user=user1";
    let service = 's3';
    let region = 'us-east-1';
    let accessKey = 'qwer';
    let secretKey = 'qwer';
    let queryParams = { 'user': 'user1' };

    const headers: HttpHeaders = this.awsSignatureService.signRequest(method, url, service, region, accessKey, secretKey, queryParams);

    return [headers, queryParams]
  }

  // 빈 함수 생성
  getResponse(): Observable<HttpResponse<any>> {
    let method = 'GET';
    let url = "http://localhost:7480/admin/org/dec?";
    let service = 's3';
    let region = 'us-east-1';
    let accessKey = 'qwer';
    let secretKey = 'qwer';
    let qeuryParamsDict = {'user': 'user1'};
    let queryParams = new HttpParams({ fromObject: qeuryParamsDict });

    const headers: HttpHeaders = this.awsSignatureService.signRequest(method, url, service, region, accessKey, secretKey, qeuryParamsDict);

    // Use HttpClient to send the request and get the full response

    return this.http.get(url, { 
      headers: headers, 
      params: queryParams, 
      observe: 'response', // Get the full response
      responseType: 'text' // Return the body as string
    });
  }

  getTreeData() {
    let method = 'GET';
    let url = "http://localhost:7480/admin/org/dec";
    let service = 's3';
    let region = 'us-east-1';
    let accessKey = 'qwer';
    let secretKey = 'qwer';
    let queryParams = {'user': 'user1'};

    const headers: HttpHeaders = this.awsSignatureService.signRequest(method, url, service, region, accessKey, secretKey, queryParams);

    // Use HttpClient to send the request
    return this.http.get(url, { headers, params: queryParams });
  }

  async getSignedUrl(){

    return this.signedUrl;
  }

}