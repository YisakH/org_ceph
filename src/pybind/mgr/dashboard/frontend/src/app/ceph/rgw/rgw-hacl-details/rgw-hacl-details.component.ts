import { Component, OnInit } from '@angular/core';
import { HAclService } from '~/app/shared/api/hacl.service'

/*
import {
  ITreeOptions,
  TreeComponent,
  TreeNode,
  TreeModel,
  TREE_ACTIONS
} from '@circlon/angular-tree-component';*/

@Component({
  selector: 'cd-rgw-hacl-details',
  templateUrl: './rgw-hacl-details.component.html',
  styleUrls: ['./rgw-hacl-details.component.scss']
})
export class RgwHaclDetailsComponent implements OnInit {

  constructor(private hAclService: HAclService) { } 

  response_status: number;
  response_body: string;
  response_headers: string;
  qeuryParams: string;
  nodes: any;
  error: any;
  
  ngOnInit() {
    /*
    // getRequestInfo의 리턴값을 받아서 사용. 배열의 첫번째 값만 받음
    const [headers, queryParams] = this.hAclService.getReqeustInfo();
    
    this.qeuryParams = queryParams['user'];
    this.response_body = headers.get('Authorization');
    this.response_status = 200;
    */
    this.hAclService.getDec('root').subscribe(response => {
      this.response_status = response.status;
      this.response_body = response.body;
      //response.headers.getAll
      //this.response_headers = response.headers;
      console.log(response.headers);
      console.log(this.response_status);
    }, error => {
      console.log(error);
      console.log(this.response_headers);
    });
  }

  loadHAclTreeData(){

  }
}
