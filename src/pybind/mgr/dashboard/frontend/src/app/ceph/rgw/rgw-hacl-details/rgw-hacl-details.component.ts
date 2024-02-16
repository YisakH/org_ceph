import { Component, OnInit } from '@angular/core';
import { HAclService } from '~/app/shared/api/hacl.service'

import { Icons } from '~/app/shared/enum/icons.enum';

import {
  ITreeOptions,
  //TreeComponent,
  TreeNode,
  TreeModel,
  TREE_ACTIONS,
  //IActionMapping
} from '@circlon/angular-tree-component';

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
  user_name: string;
  loadingIndicator: boolean = false;
  icons = Icons;

  selectedNode: any;
  treeOptions: ITreeOptions = {
    actionMapping: {
      mouse: {
        click: this.selectAndShowNode.bind(this)
      }
    }
  };

  ngOnInit() {
    /*
    // getRequestInfo의 리턴값을 받아서 사용. 배열의 첫번째 값만 받음
    const [headers, queryParams] = this.hAclService.getReqeustInfo();
    
    this.qeuryParams = queryParams['user'];
    this.response_body = headers.get('Authorization');
    this.response_status = 200;
    */
    this.loadHAclTreeData();
  }

  selectNode(node: TreeNode) {
    TREE_ACTIONS.TOGGLE_ACTIVE(undefined, node, undefined);
    this.selectedNode = node;
  }

  selectAndShowNode(tree: TreeModel, node: TreeNode, $event: any) {
    console.log('selectAndShowNode() called');
    TREE_ACTIONS.TOGGLE_EXPANDED(tree, node, $event);
    this.selectNode(node);
  }

  loadHAclTreeData(user_name: string = 'root'){
    this.hAclService.getDec(user_name).subscribe(response => {
      this.response_status = response.status;
      this.response_body = response.body;

      this.nodes = this.transformToTreeData(response.body);
      //response.headers.getAll
      //this.response_headers = response.headers;
      console.log(response.headers);
      console.log(this.response_status);
      console.log(this.response_body);
    }, error => {
      console.log(error);
      console.log(this.response_headers);
    });
  }

  transformToTreeData(data: any): any[] {
    // 재귀 함수를 사용하여 모든 노드의 children 필드를 배열로 보장
    const ensureChildrenArray = (node: any) => {
      if (!Array.isArray(node.children)) {
        node.children = []; // children 필드가 배열이 아니면 빈 배열로 설정
      }
      node.children.forEach((child: any) => ensureChildrenArray(child)); // 자식 노드에 대해 재귀적으로 처리
    };
    ensureChildrenArray(data); // 최상위 노드부터 처리 시작
    return [data]; // 최상위 노드를 배열의 첫 번째 요소로 포함하여 반환
  }

  refreshAllHAcls(){
    this.loadingIndicator = true;
    this.loadHAclTreeData(this.user_name);
    this.loadingIndicator = false;
  }
}
