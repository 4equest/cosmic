from core.api.grpc import client
from core.api.grpc.wrappers import SessionState

victim_ip = "10.0.0.10"
attacker_command = "pkill -f -SIGINT httperf"
cosmic_command = "pkill -f -SIGINT python"

def attacker_command_run():
    attacker_nodes = {}
    for node_id in range(1, session.nodes + 1):
        node = core.get_node(session.id, node_id)
        if node.node.name.startswith("attacker"):
            attacker_nodes[node_id] = node.node
            core.node_command(session.id, node.node.id, attacker_command, wait=False, shell=True)
            print(f"{node.node.name} stopped")
    return attacker_nodes

def cosmic_command_run():
    cosmic_nodes = {}
    for node_id in range(1, session.nodes + 1):
        node = core.get_node(session.id, node_id)
        if node.node.name.startswith("cosmic"):
            cosmic_nodes[node_id] = node.node
            core.node_command(session.id, node.node.id, cosmic_command, wait=False, shell=True)
            print(f"{node.node.name} stopped")
    return cosmic_nodes

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

cosmic_command_run()
attacker_command_run()
