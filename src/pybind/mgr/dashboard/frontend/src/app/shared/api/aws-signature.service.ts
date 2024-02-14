import { Injectable } from '@angular/core';
import * as CryptoJS from 'crypto-js';
import { HttpHeaders } from '@angular/common/http';


@Injectable({
  providedIn: 'root'
})
export class AwsSignatureService {

  constructor() { }

  getSignatureKey(key: string, dateStamp: string, regionName: string, serviceName: string) {
    const secretKey = CryptoJS.enc.Utf8.parse('AWS4' + key);
    const kDate = CryptoJS.HmacSHA256(dateStamp, secretKey);
    const kRegion = CryptoJS.HmacSHA256(regionName, CryptoJS.enc.Hex.parse(kDate.toString(CryptoJS.enc.Hex)));
    const kService = CryptoJS.HmacSHA256(serviceName, CryptoJS.enc.Hex.parse(kRegion.toString(CryptoJS.enc.Hex)));
    const kSigning = CryptoJS.HmacSHA256('aws4_request', CryptoJS.enc.Hex.parse(kService.toString(CryptoJS.enc.Hex)));
    return CryptoJS.enc.Hex.parse(kSigning.toString(CryptoJS.enc.Hex));
  }

  buildCanonicalQueryString(queryParams: {[key: string]: string}): string {
    const sortedKeys = Object.keys(queryParams).sort();
    const pairs = sortedKeys.map(key => {
      return encodeURIComponent(key) + '=' + encodeURIComponent(queryParams[key]);
    });
    return pairs.join('&');
  }

  signRequest(method: string, url: string, service: string, region: string, accessKey: string, secretKey: string, queryParams: {[key: string]: string} = {}) {
    const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.slice(0, 8);
    const algorithm = 'AWS4-HMAC-SHA256';

    // Create the canonical query string
    const canonicalQuerystring = this.buildCanonicalQueryString(queryParams);

    // Create the canonical request
    const canonicalUri = '/admin/org/dec'; // Adjust based on your URL

    const payloadHash = CryptoJS.SHA256('').toString(); // Hash of an empty string for GET requests
    const canonicalHeaders = `host:${new URL(url).hostname}:7480\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date'; // 서명에 포함될 헤더들
  

    const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

    console.log('-------canonicalRequest-------')
    console.log(canonicalRequest);
    // Create the string to sign
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

    console.log('-----canonicalRequest end-----')


    console.log('-----cstringToSign-----')
    const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${CryptoJS.SHA256(canonicalRequest)}`;
    console.log(stringToSign);
    console.log('-----cstringToSign end-----')
  
    // Calculate the signature
    const signingKey = this.getSignatureKey(secretKey, dateStamp, region, service);
    const signature = CryptoJS.HmacSHA256(stringToSign, signingKey);
  
    // Add signing information to the request headers
    const authorizationHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  
    return new HttpHeaders({
      'X-Amz-Date': amzDate,
      'X-Amz-Content-Sha256': payloadHash, // Include this header
      'Authorization': authorizationHeader
    });
  }
}