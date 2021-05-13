import datetime
import os
import json
import sys
import re
import shutil
import base64
import glob
from functools import reduce

from flask import Flask, redirect, url_for,request, send_from_directory, send_file, request, jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__,
            static_url_path='', 
            static_folder='static')
auth = HTTPBasicAuth()

users = {}
projects = []
manifest_lock = False


def sanitize_path(path):
    output_path = []
    for item in path:
        output_path.append(re.sub(r'\W+', '', item))
    return output_path


def is_authorized(project,user):
    with open(f"/opt/data/{project}/manifest.json","r") as project_manifest:
        manifest_data = json.load(project_manifest)
        if user in manifest_data['users']:
            return True
        else:
            return False

def write_project_manifest(project,data):
    manifest_lock = True
    with open(f"/opt/data/{project}/manifest.json","w") as project_manifest:
        json.dump(data, project_manifest)
    manifest_lock = False

def read_project_manifest(project):
    with open(f"/opt/data/{project}/manifest.json","r") as project_manifest:
        return json.load(project_manifest)

def wait_for_unlock():
    while manifest_lock:
        pass

def has_checkedout_child(folder_dict):
    mag = []
    if folder_dict == None:
        return False
    for key in folder_dict:
        if key not in ["__file__type__","__locked__","__rev_dbs__"]:
            mag.append(folder_dict[key])
        else:
            mag.append(folder_dict)
    while mag:
        current_node = mag.pop()
        if current_node:
            if not current_node["__file__type__"]:
                # directory
                for key in current_node:
                    if key != "__file__type__":
                        mag.append(current_node[key])
            else:
                # file
                for key in current_node["__rev_dbs__"]:
                    if current_node["__rev_dbs__"][key]["checked-out"]:
                        return True
    return False
        



@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/opendbfile',methods=["POST"])
@auth.login_required
def open_db_file():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])   
    path = sanitize_path(request_data['path'][:-1]) + [request_data['path'][-1].replace("..","")]
    file_name = request_data['file_name'].replace("..","")
    version = request_data['version']
    if not type(version) is int:
        return "UNAUTHORIZED"
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if not os.path.exists(f"/opt/data/{'/'.join(path)}/{version}/{file_name}"):
        return "FILE_DOES_NOT_EXIST"
    
    manifest_data = read_project_manifest(project)
    if reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["checked-out"] == auth.current_user():
        # Avoid returning a new file which would overwrite local changes
        return "FILE_ALREADY_CHECKEDOUT"
    with open(f"/opt/data/{'/'.join(path)}/{version}/{file_name}", "rb") as data_file:
        encoded_file = base64.b64encode(data_file.read())
    with open(f"/opt/data/{'/'.join(path)}/changes.json", "r") as changes_file:
        changes_content = base64.b64encode(changes_file.read().encode())
    return jsonify({"file":encoded_file.decode("utf-8"),"changes":changes_content.decode("utf-8")})

@app.route('/checkout',methods=["POST"])
@auth.login_required
def checkout_db_file():
    request_data = request.json
    version = request_data['version']
    project = re.sub(r'\W+', '', request_data['project'])   
    path = sanitize_path(request_data['path'][:-1]) + [request_data['path'][-1].replace("..","")]
    file_name = request_data['file_name'].replace("..","")
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if not type(version) is int:
        return "UNAUTHORIZED"
    if not os.path.exists(f"/opt/data/{'/'.join(path)}/{version}/{file_name}"):
        return "FILE_DOES_NOT_EXIST"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    if reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["checked-out"] != None:
        return "FILE_ALREADY_CHECKEDOUT"
    reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["checked-out"] = auth.current_user()
    write_project_manifest(project,manifest_data)
    with open(f"/opt/data/{'/'.join(path)}/{version}/{file_name}", "rb") as data_file:
        encoded_file = base64.b64encode(data_file.read())
    with open(f"/opt/data/{'/'.join(path)}/changes.json", "r") as changes_file:
        changes_content = base64.b64encode(changes_file.read().encode())
    return jsonify({"file":encoded_file.decode("utf-8"),"changes":changes_content.decode("utf-8")})
    

@app.route('/checkin',methods=["POST"])
@auth.login_required
def checkin_db_file():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])
    path = sanitize_path(request_data['path'])[:-1]
    path = path + [request_data['path'][-1].replace("..","")]
    file_name = request_data['file_name'].replace("..","")
    checkout = request_data["checkout"]
    comment = request_data["comment"]
    
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()) or ".." in request_data['path'][-1]:
        return "UNAUTHORIZED"
    if not os.path.exists(f"/opt/data/{'/'.join(path)}"):
        return "FILE_DOES_NOT_EXIST"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    if reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["checked-out"] != auth.current_user():
        return  "FILE_NOT_CHECKEDOUT"
    reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["latest"] += 1
    reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["versions"].append(comment)
    if not checkout:
        reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["checked-out"] = None
    write_project_manifest(project,manifest_data)
    
    latest = reduce(dict.get,path,manifest_data)['__rev_dbs__'][os.path.splitext(file_name)[1][1:]]['latest']
    if not os.path.exists(f"/opt/data/{'/'.join(path)}/{latest}"):
        os.mkdir(f"/opt/data/{'/'.join(path)}/{latest}")
    with open(f"/opt/data/{'/'.join(path)}/{latest}/{file_name}","wb") as dest_file:
        dest_file.write(base64.b64decode(request_data['file']))
    with open(f"/opt/data/{'/'.join(path)}/changes.json", "r") as previous_changes_file:
        previous_changes = json.load(previous_changes_file)
    with open(f"/opt/data/{'/'.join(path)}/changes.json","w") as changes_file:
        changes_content = base64.b64decode(request_data["changes"])
        changes_data = json.loads(changes_content)
        '''previous_changes["function_names"].update(changes_data["function_names"])
        for comment in changes_data["comments"]:
            if comment in previous_changes["comments"] and previous_changes["comments"][comment] != "":
                if previous_changes["comments"][comment] != changes_data["comments"][comment]:
                    previous_changes["comments"][comment] = f'{previous_changes["comments"][comment]}; {changes_data["comments"][comment]}'
            else:
                previous_changes["comments"][comment] = changes_data["comments"][comment]'''
        json.dump(changes_data,changes_file)
    return "DONE"

# Works
@app.route('/move',methods=["POST"])
@auth.login_required
def move():
    request_data = request.json
    project = request_data['project_name']
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    source_path_list = sanitize_path(request_data['source_path'][:-1]) + [request_data['source_path'][-1].replace("..","")]
    dest_path_list = sanitize_path(request_data['dest_path'][:-1]) + [request_data['dest_path'][-1].replace("..","")]
    source_path = os.path.join(f"/opt/data/",os.path.join(*source_path_list))
    dest_path = os.path.join(f"/opt/data/", os.path.join(*dest_path_list),source_path_list[-1])
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    if has_checkedout_child(reduce(dict.get,source_path_list,manifest_data)):
        return "CHECKEDOUT_FILE"
    if reduce(dict.get,dest_path_list + [source_path_list[-1]],manifest_data):
        return "ALREADY_EXISTS"
    manifest_source = reduce(dict.get,source_path_list[:-1],manifest_data).pop(source_path_list[-1])
    reduce(dict.get,dest_path_list,manifest_data)[source_path_list[-1]] = manifest_source
    shutil.move(source_path,dest_path)
    write_project_manifest(project,manifest_data)
    return "DONE"


# Works
@app.route('/undocheckout',methods=["POST"])
@auth.login_required
def undo_checkout():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])   
    path = sanitize_path(request_data['path'][:-1]) + [request_data['path'][-1].replace("..","")]
    file_name = request_data['file_name'].replace("..","")
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if not os.path.exists(f"/opt/data/{'/'.join(path)}/0/{file_name}"):
        return "FILE_DOES_NOT_EXIST"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    if reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["checked-out"] != auth.current_user():
        return "FILE_NOT_CHECKEDOUT"
    reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(file_name)[1][1:]]["checked-out"] = None
    write_project_manifest(project,manifest_data)
    return "DONE"

# Works
@app.route('/getfile',methods=["POST"])
@auth.login_required
def getfile():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])   
    path = sanitize_path(request_data['path'])
    filename = request_data['file_name'].replace("..","")
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if not os.path.exists(f"/opt/data/{'/'.join(path)}/{filename}"):
        return "FILE_DOES_NOT_EXIST"
    with open(f"/opt/data/{'/'.join(path)}/{filename}/{filename}", "rb") as data_file:
        encoded_file = base64.b64encode(data_file.read())
    return jsonify({"file":encoded_file.decode("utf-8")})

# Works
@app.route('/push',methods=["POST"])
@auth.login_required
def push():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])
    path = sanitize_path(request_data['path'])
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()) or ".." in request_data['file_name']:
        return "UNAUTHORIZED"
    if os.path.exists(f"/opt/data/{'/'.join(path)}/{request_data['file_name']}"):
        return "FILE_ALREADY_EXISTS"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    reduce(dict.get,path,manifest_data).update({f"{request_data['file_name']}":{"__file__type__":True,"__locked__":None,"__rev_dbs__": {}}})
    write_project_manifest(project,manifest_data)
    os.mkdir(f"/opt/data/{'/'.join(path)}/{request_data['file_name']}")
    with open(f"/opt/data/{'/'.join(path)}/{request_data['file_name']}/{request_data['file_name']}","wb") as dest_file:
        dest_file.write(base64.b64decode(request_data['file']))
    with open(f"/opt/data/{'/'.join(path)}/{request_data['file_name']}/changes.json","wb") as dest_file:
        dest_file.write(b'{"comments":{},"function_names":{}}')
    return "DONE"

# Works
@app.route('/pushdbfile',methods=["POST"])
@auth.login_required
def push_db_file():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])
    path = sanitize_path(request_data['path'])[:-1]
    path = path + [request_data['path'][-1].replace("..","")]
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()) or ".." in request_data['file_name']:
        return "UNAUTHORIZED"
    if os.path.exists(f"/opt/data/{'/'.join(path)}/0/{request_data['file_name']}"):
        return "FILE_ALREADY_EXISTS"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    # "versions" is ordered list of comments assigned to each version, "latest" holds the index of the latest version for the given file 
    reduce(dict.get,path,manifest_data)["__rev_dbs__"][os.path.splitext(request_data['file_name'])[1][1:]] = {"checked-out":None,"latest":0,"versions":["Init"]}
    write_project_manifest(project,manifest_data)
    # Pushing DB is always first operation so push to folder "0"
    if not os.path.exists(f"/opt/data/{'/'.join(path)}/0"):
        os.mkdir(f"/opt/data/{'/'.join(path)}/0")
    with open(f"/opt/data/{'/'.join(path)}/0/{request_data['file_name']}","wb") as dest_file:
        dest_file.write(base64.b64decode(request_data['file']))
    return "DONE"

# Works
@app.route('/mkdir',methods=["POST"])
@auth.login_required
def mkdir():
    '''
    {
        "project": "some",
        "path": ["project_name","folder1"],
        "dirname": "newDir"
    }
    '''
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    dirname = re.sub(r'\W+', '', request_data['dirname'])
    path = sanitize_path(request_data['path'])
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if os.path.exists(f"/opt/data/{'/'.join(path)}/{dirname}"):
        return "FOLDER_ALREADY_EXISTS"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    reduce(dict.get,path,manifest_data).update({f"{dirname}":{"__file__type__":False}})
    write_project_manifest(project,manifest_data)
    os.mkdir(f"/opt/data/{'/'.join(path)}/{dirname}")
    return 'DONE'

# Works
@app.route('/rename',methods=["POST"])
@auth.login_required
def rename_dir():
    '''
    {
        "project": "some",
        "path": ["project_name","folder1"],
        "dirname": "newDir"
    }
    '''
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    dirname = re.sub(r'\W+', '', request_data['dirname'])
    path = sanitize_path(request_data['path'])
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if os.path.exists(f"/opt/data/{'/'.join(path[:-1])}/{dirname}"):
        return "FOLDER_ALREADY_EXISTS"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    old_folder = reduce(dict.get,path[:-1],manifest_data).pop(path[-1])
    reduce(dict.get,path[:-1],manifest_data)[dirname] = old_folder
    write_project_manifest(project,manifest_data)
    shutil.move(os.path.join("/opt/data",*path), os.path.join("/opt/data",*path[:-1],dirname))
    #os.mkdir(f"/opt/data/{'/'.join(path)}/{dirname}")
    return 'DONE'

# works
@app.route('/deletedir',methods=["POST"])
@auth.login_required
def delete_dir():
    '''
    {
        "project": "some",
        "path": ["project_name","folder1"],
        "dirname": "newDir"
    }
    '''
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    dirname = re.sub(r'\W+', '', request_data['dirname'])
    path = sanitize_path(request_data['path'])
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if len(path) == 0:
        return "CANNOT_DELETE_PROJECT_ROOT"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    if has_checkedout_child(reduce(dict.get,path,manifest_data)[dirname]):
        return "CHECKEDOUT_FILE"
    reduce(dict.get,path,manifest_data).pop(f"{dirname}")
    write_project_manifest(project,manifest_data)
    shutil.rmtree(f"/opt/data/{'/'.join(path)}/{dirname}")
    return 'DONE'

# works
@app.route('/deletefile',methods=["POST"])
@auth.login_required
def delete_file():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data['project'])
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    filename = request_data['filename'].replace("..","")
    
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    if filename in ["hop","i64","idb","bndb","rzdb","ghdb","jdb2","asp"]:
        sanitized_filename = request_data['path'][-1].replace("..","")
        path = sanitize_path(request_data['path'][:-1]) + [sanitized_filename]
        if reduce(dict.get,path,manifest_data)["__rev_dbs__"][filename]["checked-out"]:
            return "CHECKEDOUT_FILE"
        reduce(dict.get,path,manifest_data)["__rev_dbs__"].pop(filename)
        for (dirname, dirs, files) in os.walk(os.path.join(os.path.join("/opt/data",*path))):
            for file in files:
                if file.endswith(f".{filename}"):
                    source_file = os.path.join(dirname, file)
                    os.remove(source_file)
    else:
        # Whole file has to go
        path = sanitize_path(request_data['path'])
        for db_file in reduce(dict.get,path + [filename],manifest_data)["__rev_dbs__"]:
            if reduce(dict.get,path + [filename],manifest_data)["__rev_dbs__"][db_file]["checked-out"]:
                return "CHECKEDOUT_FILE"
        reduce(dict.get,path,manifest_data).pop(f"{filename}")
        shutil.rmtree(f"/opt/data/{'/'.join(path)}/{filename}")
    write_project_manifest(project,manifest_data)
    return 'DONE'

# Works
@app.route('/getprojectlist')
@auth.login_required
def get_project_list():
    authorized_projects = []
    for project in projects:
        if is_authorized(project,auth.current_user()):
            authorized_projects.append(project)
    return jsonify({"projects":authorized_projects})

# Works
@app.route('/createproject', methods=["POST"])
@auth.login_required
def create_project():
    '''
    {
        "project": "name_here",
        "users": [user1,user2]
    }
    '''
    request_data = request.json
    project = re.sub(r'\W+', '', request_data["project"])
    if project in projects:
        return "ALREADY_EXISTS"
    os.mkdir(f"/opt/data/{project}")
    manifest_content = {
        "users": [],
        f"{project}": {"__file__type__":False}
    }
    for user in request_data["users"]:
        if user not in manifest_content["users"] and user in users.keys():
            manifest_content["users"].append(user)
    with open(f"/opt/data/{project}/manifest.json","w") as project_manifest:
        json.dump(manifest_content, project_manifest)
    projects.append(project)
    with open("/opt/data/projects.list","w") as projects_file:
        for item in projects:
            projects_file.write(f"{item}\n")
    return jsonify(manifest_content)

# Works
@app.route('/deleteproject')
@auth.login_required
def delete_project():
    project = re.sub(r'\W+', '', request.args.get('project'))
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    shutil.rmtree(f"/opt/data/{project}")
    projects.remove(project)
    with open("/opt/data/projects.list","w") as projects_file:
        for item in projects:
            projects_file.write(f"{item}\n")
    return 'DONE'

# works
@app.route('/openproject')
@auth.login_required
def open_project():
    project = re.sub(r'\W+', '', request.args.get('project'))
    if project not in projects:
        return "PROJECT_DOES_NOT_EXIST"
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    with open(f"/opt/data/{project}/manifest.json","r") as project_manifest:
        manifest_data = json.load(project_manifest)
    return jsonify(manifest_data)

# Works
@app.route('/addprojectusers', methods=["POST"])
@auth.login_required
def add_project_user():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data["project"])
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if not project in projects:
        return "PROJECT_DOES_NOT_EXIST"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    for user in request_data["users"]:
        if user not in manifest_data["users"] and user in users.keys():
            manifest_data["users"].append(user)
    write_project_manifest(project,manifest_data)
    return 'DONE'

# Works
@app.route('/getusers')
@auth.login_required
def get_userlist():
    return jsonify({"users":list(users.keys())})

# Works
@app.route('/getprojectusers')
@auth.login_required
def get_project_userlist():
    project = re.sub(r'\W+', '', request.args.get('project'))
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    return jsonify({"users":read_project_manifest(project)["users"]})

# Works
@app.route('/deleteprojectuser',methods=["POST"])
@auth.login_required
def delete_project_user():
    request_data = request.json
    project = re.sub(r'\W+', '', request_data["project"])
    if not is_authorized(project,auth.current_user()):
        return "UNAUTHORIZED"
    if not project in projects:
        return "PROJECT_DOES_NOT_EXIST"
    wait_for_unlock()
    manifest_data = read_project_manifest(project)
    for user in request_data["users"]:
        manifest_data["users"].remove(user)
    write_project_manifest(project,manifest_data)
    return 'DONE'

# Works
@app.route('/ping')
@auth.login_required
def index():
    return "SUCCESS"

# Works
@app.route('/adduser',methods=['POST'])
@auth.login_required
def add_user():
    if auth.current_user() != 'admin':
        return 'UNAUTHORIZED'
    users[request.form.get('username')] = generate_password_hash(request.form.get('password'))
    dump_users_to_file()
    return "DONE"

# Works
@app.route('/deluser',methods=['POST'])
@auth.login_required
def delete_user():
    if auth.current_user() != 'admin':
        return 'UNAUTHORIZED'
    request_data = request.json
    for user in request_data["users"]:
        # Delete only non-admins
        if user != "admin":
            users.pop(user)
    for prj in projects:
        wait_for_unlock()
        manifest_data = read_project_manifest(prj.strip())
        for user in request_data["users"]:
            if user in manifest_data["users"]:
                manifest_data["users"].remove(user)
            if len(manifest_data["users"]) == 0:
                # Auto append admin for projects with no users
                manifest_data["users"].append("admin")
        write_project_manifest(prj.strip(),manifest_data)
    dump_users_to_file()
    return "DONE"

# Works
@app.route('/changepwd',methods=['POST'])
@auth.login_required
def change_pwd():
    users[auth.current_user()] = generate_password_hash(request.form.get('password'))
    dump_users_to_file()
    return "DONE"
    
# Works
def dump_users_to_file():
    with open("/opt/data/users.txt","w") as users_file:
        for key,value in users.items():
            users_file.write(f"{key};{value}\n")


if __name__ == '__main__':
    #print(f"admin:{generate_password_hash('admin')}", file=sys.stderr)
    # Read users file
    with open("/opt/data/users.txt","r") as users_file:
        for user in users_file.readlines():
            users[user.split(";")[0]] = user.split(";")[1].strip()
    with open("/opt/data/projects.list","r") as projects_file:
        for project in projects_file.readlines():
            projects.append(project.strip())
    app.run(host='0.0.0.0', port=5090, debug=True)
