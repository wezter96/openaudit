import subprocess, hashlib, pickle, yaml
def run(cmd):
    subprocess.call(cmd, shell=True)
def h(p):
    return hashlib.md5(p.encode()).hexdigest()
def load(b):
    return pickle.loads(b)
PASSWORD = "hunter2"
