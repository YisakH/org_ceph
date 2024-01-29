from flask import Flask, render_template
import requests
import botocore.session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import hashlib


app = Flask(__name__)
url = "http://localhost:7480/admin/org/dec"

def sign_request(url, method, service, region, params, access_key, secret_key, session_token=None):
    session = botocore.session.get_session()
    credentials = session.get_credentials()
    credentials = credentials.get_frozen_credentials()

    access_key = access_key or credentials.access_key
    secret_key = secret_key or credentials.secret_key
    session_token = session_token or credentials.token

    request = AWSRequest(method=method, url=url, params=params)
    
    payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()
    request.headers['X-Amz-Content-Sha256'] = payload_hash
    
    SigV4Auth(credentials, service, region).add_auth(request)

    if session_token:
        request.headers['X-Amz-Security-Token'] = session_token

    prepared_request = request.prepare()
    return prepared_request

def send_request(url, method, access_key, secret_key, params=None, service='s3', region='us-east-1'):
    signed_request = sign_request(url, method, service, region, params, access_key, secret_key)
    response = requests.request(method, url, headers=dict(signed_request.headers), params=params)
    
    # resonse를 curl 명령어로 출력
    print("curl -X", method, url, end='')
    for key, value in signed_request.headers.items():
        print(" -H", key + ":" + value, end='')
    # prams도 출력
    print(" -d", params)
    
    
    #print("Signed URL:", signed_request.url)
    #print("Headers:", signed_request.headers)

    return response.status_code, response.text
    

def get_tree_structure():
    # Example usage
    url = "http://localhost:7480/admin/org/dec"
    method = "GET"
    access_key = "qwer"
    secret_key = "qwer"
    
    
    tree_structure = {}
    queue = ['root']
    
    # catch error
    # if db is None:

    try:
        while queue:
            key = queue.pop(0)
            request_code, request_result = send_request(url, method, access_key, secret_key, {"user": key})
            
            # Assume the value is the parent of the key
            
            if request_code is requests.codes.ok and request_result != '':
                children = request_result.split(',')
                tree_structure[key] = children
                queue.extend([child for child in children])
                
    except Exception as e:
        print(e)
    finally:
        return tree_structure
    
def format_tree_structure(tree_structure):
    # Convert the tree structure to a format suitable for display
    # This is a placeholder; you'll need to implement the logic based on your data format
    formatted_structure = {}
    formatted_structure = tree_structure
    # ...
    return formatted_structure

def render_tree(tree, parent):
    # 루트 노드 자체를 렌더링합니다.
    render_html = f'<ul class="tree"><li class="toggle">- {parent}/'
    
    # 루트 노드의 자식들을 재귀적으로 렌더링합니다.
    child_html = render_tree_recursive(tree, parent)
    if child_html:
        render_html += child_html
    
    # 루트 노드의 렌더링을 닫습니다.
    render_html += '</li></ul>'
    
    return render_html

def render_tree_recursive(tree, parent):
    if not parent in tree or not tree[parent]:
        return ''
    
    # 자식 노드들을 렌더링하는 부분입니다.
    render_html = '<ul class="tree">'
    for child in tree[parent]:
        render_html += f'<li class="toggle">- {child}'
        child_html = render_tree_recursive(tree, child)
        if child_html:
            render_html += '/'
            render_html += child_html
        render_html += '</li>'
    render_html += '</ul>'
    return render_html

@app.route('/')
def index():
    tree_structure = get_tree_structure()
    root_node = 'root'
    tree_html = render_tree(tree_structure, root_node)
    return render_template('index.html', tree_html=tree_html)

if __name__ == '__main__':
    app.run(debug=True)