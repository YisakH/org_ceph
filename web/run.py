from flask import Flask, render_template
import rocksdb

app = Flask(__name__)

def get_tree_structure(db_path):
    db = rocksdb.DB(db_path, rocksdb.Options(create_if_missing=False))
    tree_structure = {}
    queue = ['root']
    
    # catch error
    # if db is None:

    try:
        while queue:
            key = queue.pop(0)
            value = db.get(key.encode())
            # Assume the value is the parent of the key
            
            if value is not None:
                children = value.decode().split(',')  # bytes를 문자열로 변환 후 처리
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

@app.route('/')
def index():
    db_path = "/tmp/org/DecDB"
    tree_structure = get_tree_structure(db_path)
    formatted_structure = format_tree_structure(tree_structure)
    return render_template('index.html', tree=formatted_structure)

if __name__ == '__main__':
    app.run(debug=True)