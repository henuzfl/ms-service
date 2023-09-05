import subprocess
from exceptions import MosquittoError
from common import config

MOSQUITTO_USER = config["mosquitto"]["username"]
MOSQUITTO_PASSWORD = config["mosquitto"]["password"]
MOSQUITTO_CTRL = "mosquitto_ctrl -u %s -P %s dynsec" % (
    MOSQUITTO_USER, MOSQUITTO_PASSWORD)


def create_user(username, password, role=""):
    if role == "":
        role = username
    # 创建用户
    if username in get_all_clients():
        raise MosquittoError("Client %s already exists" % username)
    create_client(username, password)
    # 创建角色
    if role not in get_all_roles():
        create_role(role)
    # 用户添加到角色
    if username not in get_client_roles(username):
        add_client_to_role(username, username)


def create_client(username, password):
    p = subprocess.Popen(MOSQUITTO_CTRL + " createClient " + username, shell=True,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
    p.communicate(input=password + "\n" + password)[0]
    p.wait(5)
    if p.poll() == 0:
        print("Client %s added" % username)
    else:
        raise MosquittoError(p.stderr.read())


def delete_user(username):
    delete_role(username)
    cmd(MOSQUITTO_CTRL + " deleteClient " + username)


def delete_role(role):
    cmd(MOSQUITTO_CTRL + " deleteRole " + role)


def add_acl_to_client(username, read_topic=[], write_topic=[]):
    for topic in read_topic:
        if topic not in get_role_acl(username)[0]:
            add_read_acl_to_role(username, topic)
    for topic in write_topic:
        if topic not in get_role_acl(username)[1]:
            add_write_acl_to_role(username, topic)


def delete_acl_from_client(username, read_topic=[], write_topic=[]):
    for topic in read_topic:
        if topic in get_role_acl(username)[0]:
            remove_read_acl_to_role(username, topic)
    for topic in write_topic:
        if topic in get_role_acl(username)[1]:
            remove_write_acl_to_role(username, topic)


def update_password(username, password):
    cmd(MOSQUITTO_CTRL + " setClientPassword " + username + " " + password)


def create_role(role):
    cmd(MOSQUITTO_CTRL + " createRole " + role)


def add_client_to_role(username, role):
    cmd(MOSQUITTO_CTRL + " addClientRole " + username + " " + role + " Z")


def add_read_acl_to_role(role, topic):
    oper = "subscribePattern" if topic.endswith("#") else "subscribeLiteral"
    cmd(MOSQUITTO_CTRL + " addRoleACL " +
        role + " " + oper + " " + topic + " allow 5")


def add_write_acl_to_role(role, topic):
    cmd(MOSQUITTO_CTRL + " addRoleACL " + role +
        " publishClientSend " + topic + " allow 5")


def remove_read_acl_to_role(role, topic):
    oper = "subscribePattern" if topic.endswith("#") else "subscribeLiteral"
    cmd(MOSQUITTO_CTRL + " removeRoleACL " +
        role + " " + oper + " " + topic)


def remove_write_acl_to_role(role, topic):
    cmd(MOSQUITTO_CTRL + " removeRoleACL " + role +
        " publishClientSend " + topic)


def get_client_acl(username):
    read_topic = []
    write_topic = []
    for role in get_client_roles(username):
        r, w = get_role_acl(role)
        read_topic.extend(r)
        write_topic.extend(w)
    return read_topic, write_topic


def get_all_clients():
    res = cmd(MOSQUITTO_CTRL + " listClients")
    return [line.strip() for line in res.split("\n") if line.strip() != ""]


def get_all_roles():
    res = cmd(MOSQUITTO_CTRL + " listRoles")
    return [line.strip() for line in res.split("\n") if line.strip() != ""]


def get_client_roles(username):
    res = cmd(MOSQUITTO_CTRL + " getClient " + username)
    ans = []
    flag = False
    for line in res.split("\n"):
        if line == "":
            continue
        if flag:
            item = line.split("(")[0]
        if not flag and line.startswith("Roles"):
            flag = True
            item = line.split(":")[1].split("(")[0]
        if flag:
            ans.append(item.strip())
    return ans


def get_role_acl(role):
    read_topic = []
    write_topic = []
    flag = False
    res = cmd(MOSQUITTO_CTRL + " getRole " + role)
    for line in res.split("\n"):
        if line == "":
            break
        if flag:
            item = line.split(":")
        if not flag and line.startswith("ACLs"):
            flag = True
            item = line.split(":")[1:]
        if flag:
            event = item[0].strip()
            oper = item[1].strip()
            topic = item[2].strip().split(" ")[0]
            if oper == "deny":
                continue
            if event.startswith("subscribe") or event == "publishClientReceive":
                read_topic.append(topic)
            elif event == "publishClientSend":
                write_topic.append(topic)
    return read_topic, write_topic


def cmd(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, encoding="utf-8")
    p.wait(5)
    if p.poll() == 0:
        return p.stdout.read()
    else:
        raise MosquittoError(p.stderr.read())
