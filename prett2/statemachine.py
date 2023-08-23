import states
import modeller_h2
import validator_h2
from transitions.extensions import GraphMachine as Machine
import scapy.contrib.http2 as h2
import util
import time
import logging
import sys
from collections import OrderedDict
import copy

logger = logging.getLogger(__name__)

frame_db = ['DATA', 'HEADERS', 'PRIORITY', 'SETTINGS', 'PUSHPROMISE', 'WINDOW_UPDATE', 'CONTINUATION']
# token_db = ['GET', 'POST', 'HEAD', 'PUT', "DELETE", 'TRACE', 'CONNECT', 'OPTIONS']
args_db = ['/index.php', '/', '/index.html', 'index']


class ProtoModel(object):
    def __init__(self, name):
        self.name = name

        # overall status
        self.is_pruning = False
        self.current_level = 1
        self.dst_ip = None
        self.timeout = 10

        # State searching information
        self.current_state = 0
        self.num_of_states = 0
        self.state_list = states.StateList(state_list=[states.State('init', 1)])  # basic state '0' in level 1
        self.candidate_state_list = states.StateList(state_list=[])

        # Transition information
        # trigger as key (string) : [src_state (string), dest_state (string), cnt]
        self.transition_info = {}
        self.testmsgs = None


class MergeData():
    def __init__(self):
        self.src_s = None
        self.dst_s = None
        self.t_label = None


def generate_sm():
    pm = ProtoModel("Protocol Model")
    sm = Machine(model=pm, states=['init', 'fin'], initial='init', auto_transitions=False)
    return pm, sm


def get_move_state_h2msgs(pm, target_state):
    # Get state moving message to reach current state
    # Return list of H2 messages
    move_state_h2msgs = []
    move_state_num = 0
    while True:
        parent_state = target_state.parent_state
        if parent_state is not None:  # non-root node
            parent_h2msg = copy.deepcopy(target_state.h2msg_sent)
            # parent_h2msg.frames.reverse()
            move_state_h2msgs.append(parent_h2msg)
            move_state_num = move_state_num + 1
            target_state = parent_state
            continue
        else:  # root node
            break

    move_state_h2msgs.reverse()
    return move_state_h2msgs


def update_candidates(pm, sm, h2msg_sent, h2msg_rcvd, elapsedTime):
    # sm : state machine, current_state : current state,
    # spyld_str : send h2 frame sequence in string, h2msg_sent : send h2 frame sequence,
    # rpyld_str : response h2 frame sequence in string, h2msg_rcvd : response h2 frame sequence
    # elapsedTime : elapsed time for response of h2msg_rcvd to h2msg_sent
    # Build and fix a state machine based on the response

    """ # depricated (No more distinguising loop or hanging state in terms of candidates.)
	if elapsedTime == -1: # loop transition
		vs_payload = spyld_str + "... / " + rpyld_str + "..."
		sm.add_transition(vs_payload + "\n", source = str(pm.current_state), dest = str(pm.current_state))
		return
	elif elapsedTime == -2: # loop transition for 10+ mins
		vs_payload = spyld_str + "... / " + rpyld_str + "... / wait over 10 min"
		sm.add_transition(vs_payload + "\n", source = str(pm.current_state), dest = str(pm.current_state))
		return
	else: # New state found
	"""

    # pm.transition_info[t_label] = [str(pm.current_state.name), str(pm.num_of_states), 1]
    # No valid state found yet. Add candidate states in protocol model first.
    pm.num_of_states += 1
    cand_s = states.State(name=str(pm.num_of_states), level=pm.current_level + 1, parent_state=pm.current_state,
                          h2msg_sent=h2msg_sent, h2msg_rcvd=h2msg_rcvd, elapsedTime=elapsedTime)
    pm.candidate_state_list.add_state(cand_s)
    print("    [+] Candidate state %s added (%s -> %s)" % (cand_s.name, cand_s.parent_state.name, cand_s.name))
    logger.info("    [+] Candidate state %s added (%s -> %s)" % (cand_s.name, cand_s.parent_state.name, cand_s.name))


def check_dupstate(pm, md, cand_s, mode):
    if mode == 'p':
        # Case 1. Parent
        # Compare its SR dict with that of its parent
        # print('  [lv.%d-MINIMIZATION-STATE %s] Testing with its parent state %s ... ' % (pm.current_level,
        #     str(cand_s.name), str(cand_s.parent_state.name)))
        # logger.info('  [lv.%d-MINIMIZATION-STATE %s] Testing with its parent state %s ... ' % (pm.current_level,
        #     str(cand_s.name), str(cand_s.parent_state.name)))

        # target_sr_dict: messages from a parent node to its child nodes ( key : request, value : resposnses )
        # target_sr_dict = OrderedDict()
        # for cand_s_tmp in pm.candidate_state_list.state_list:
        #     if cand_s_tmp.parent_state == cand_s.parent_state:
        #         h2msg_sent_str = util.h2msg_to_str(cand_s_tmp.h2msg_sent)
        #         h2msg_rcvd_str = util.h2msg_to_str(cand_s_tmp.h2msg_rcvd)
        #         target_sr_dict[h2msg_sent_str] = h2msg_rcvd_str + ' / ' + str(int(cand_s_tmp.elapsedTime))

        # if cand_s.parent_state.child_sr_dict is not None and not util.compare_ordered_dict(
        #         cand_s.parent_state.child_sr_dict, target_sr_dict):  # For debugging
        #     print("check_dupstate(): parent state %s's child_sr_dict changed!" % cand_s.parent_state.name)
        # cand_s.parent_state.child_sr_dict = target_sr_dict

        if util.compare_ordered_dict(cand_s.parent_state.child_sr_dict, cand_s.child_sr_dict):
            md.src_s = cand_s.parent_state
            md.dst_s = cand_s.parent_state
            return True
        else:
            return False

    elif mode == 's':
        # STEP 2. Sibling
        # Compare its child dict with that of states whose parent is same.
        # print("  [lv.%d-MINIMIZATION-STATE %s] -> Different from parent %s. Now check with sibling nodes ..." % (pm.current_level,
        #     cand_s.name, cand_s.parent_state.name))
        # logger.info("  [lv.%d-MINIMIZATION-STATE %s] -> Different from parent %s. Now check with sibling nodes ..." % (pm.current_level,
        #     cand_s.name, cand_s.parent_state.name))

        for state_v in pm.state_list.state_list:  # check all states that are valid till now
            if state_v.parent_state is not None and state_v.parent_state.name == cand_s.parent_state.name:  #
                # siblings; same parent
                # print("Compare state %s with sibling state %s" % (cand_s.name, state_v.name))
                if util.compare_ordered_dict(state_v.child_sr_dict, cand_s.child_sr_dict):
                    md.src_s = cand_s.parent_state
                    md.dst_s = state_v
                    return True
        return False

    elif mode == 'r':
        # Step 3. Relatives
        # Compare its child dict with that of the other states
        # print("  [lv.%d-MINIMIZATION-STATE %s] -> Different from siblings, Now check with relative nodes ..." % (pm.current_level, cand_s.name))
        # logger.info(
        #     "  [lv.%d-MINIMIZATION-STATE %s] -> Different from siblings, Now check with relative nodes ..." % (pm.current_level, cand_s.name))

        for state_v in pm.state_list.state_list:  # check all states that are valid till now
            if state_v.name == cand_s.parent_state.name:
                # print("Relative of state %s is same as its parent state %s" % (cand_s.name, state_v.name))
                continue
            if state_v.parent_state is None or state_v.parent_state.name != cand_s.parent_state.name:  # relative; different parent or ancestor
                # print("Comparing state %s with its relative state %s" % (cand_s.name, state_v.name))
                if util.compare_ordered_dict(state_v.child_sr_dict, cand_s.child_sr_dict):
                    md.src_s = cand_s.parent_state
                    md.dst_s = state_v
                    return True
        return False

    else:
        print("[ERROR] (check_dupstate()) Invalid mode.")
        logger.info("[ERROR] (check_dupstate()) Invalid mode.")
        sys.exit()


def update_sm(pm, sm, cand_s, md):
    # Mergable
    if md.src_s is not None and md.dst_s is not None:
        if len(sm.get_transitions(trigger=md.t_label + "\n", source=md.src_s.name, dest=md.dst_s.name)) > 0:
            return
        sm.add_transition(md.t_label + "\n", source=md.src_s.name, dest=md.dst_s.name)
    # Unique
    else:
        # Finished
        if int(cand_s.elapsedTime) == 0:
            print("  [lv.%d-MINIMIZATION-STATE %s] It is finishing state!" % (pm.current_level, cand_s.name))
            logger.info("  [lv.%d-MINIMIZATION-STATE %s] It is finishing state!" % (pm.current_level, cand_s.name))
            if len(sm.get_transitions(trigger=md.t_label + "\n", source=cand_s.parent_state.name, dest='fin')) > 0:
                return
            sm.add_transition(md.t_label + "\n", source=cand_s.parent_state.name, dest='fin')
        # Non-finished
        else:
            pm.state_list.add_state(cand_s)
            sm.add_state(cand_s.name)
            sm.add_transition(md.t_label + "\n", source=cand_s.parent_state.name, dest=cand_s.name)


def expand_sm(pm, sm, leaf_states):
    # Find candidate states in the next level from leaf states found in the current level.
    leafstate_num = 1
    for leaf_state in leaf_states:
        sr_dict = OrderedDict()
        try:
            print("  [lv.%d-EXPANSION-LEAF] Expanding leaf state %s (%d/%d leaves)" % (pm.current_level,
                leaf_state.name, leafstate_num, len(leaf_states)))
            logger.info("  [lv.%d-EXPANSION-LEAF] Expanding leaf state %s (%d/%d leaves)" % (pm.current_level,
                leaf_state.name, leafstate_num, len(leaf_states)))
        except Exception as e:
            print(e)
            print(leaf_state)
        move_state_h2msgs_list = get_move_state_h2msgs(pm, leaf_state)
        # print("[expand_sm] h2msg of get_move_state_h2msgs ---")
        # util.h2msg_to_str(move_state_h2msgs_list)
        message_num = 1
        pm.current_state = leaf_state
        parent_elapsed_time = leaf_state.elapsedTime
        for h2msg_sent in pm.testmsgs:  # test messages : SE-WI, DA-HE-DA .... (from pcap)
            print("    [lv.%d-EXPANSION-STATE-\'%s\'] move Frame: %s, send Frame: %s (%d/%d msgs)" % (pm.current_level,
                leaf_state.name, util.h2msg_to_str(move_state_h2msgs_list), util.h2msg_to_str(h2msg_sent), message_num,
                len(pm.testmsgs)))
            logger.info("    [lv.%d-EXPANSION-STATE-\'%s\'] move Frame: %s, send Frame: %s (%d/%d msgs)" % (pm.current_level,
                leaf_state.name, util.h2msg_to_str(move_state_h2msgs_list), util.h2msg_to_str(h2msg_sent), message_num,
                len(pm.testmsgs)))
            # print ("  [ ] It may take time for receiving Go Away frame..")
            h2msg_rcvd, elapsedTime = modeller_h2.send_receive_http2(pm, move_state_h2msgs_list, h2msg_sent,
                                                                     parent_elapsed_time)
            update_candidates(pm, sm, h2msg_sent, h2msg_rcvd, elapsedTime)
            message_num += 1
            h2msg_sent_str = util.h2msg_to_str(h2msg_sent)
            h2msg_rcvd_str = util.h2msg_to_str(h2msg_rcvd)
            sr_dict[h2msg_sent_str] = h2msg_rcvd_str + " (%s)" % str(int(elapsedTime))
        leafstate_num += 1
        pm.current_state.child_sr_dict = sr_dict


## if Elapsed time is 0, it means end state
def minimize_sm(pm, sm):
    # Among candidate states in the next level, unique states in current level are determined in minimize_sm() via pruning.
    cand_s_list = pm.candidate_state_list.state_list
    if len(cand_s_list) == 0:
        print("  [+] No more candidate states ...")
        return

    print("  [INFO] Test %d candidate states in level %d" % (len(cand_s_list), pm.current_level))
    for cand_s in cand_s_list:
        md = MergeData()
        h2msg_sent_str = util.h2msg_to_str(cand_s.h2msg_sent)
        h2msg_rcvd_str = util.h2msg_to_str(cand_s.h2msg_rcvd)
        sr_msg = "%s => %s (%s)" % (h2msg_sent_str, h2msg_rcvd_str, str(int(cand_s.elapsedTime)))
        md.t_label = sr_msg

        ######## Filter out quick-disconnected (finishing) state #######
        if int(cand_s.elapsedTime) == 0 and h2msg_rcvd_str.find("GO") >= 0:
            pass

        ######## Retrieve cand_s SR info ########
        else: # cand_sr_dict: messages from cand_s to and its child node (Do the same test as parent).
            print('  [lv.%d-MINIMIZATION-STATE %s] Retrieving its SR dict' % (pm.current_level, cand_s.name))
            cand_sr_dict = OrderedDict()
            move_state_h2msgs_list = get_move_state_h2msgs(pm, cand_s)
            move_state_h2msgs_str = util.h2msg_to_str(move_state_h2msgs_list)

            for h2msg_sent in pm.testmsgs:
                h2msg_rcvd, elapsedTime = modeller_h2.send_receive_http2(pm, move_state_h2msgs_list, h2msg_sent,
                                                                         cand_s.elapsedTime)
                h2msg_sent_str = util.h2msg_to_str(h2msg_sent)
                h2msg_rcvd_str = util.h2msg_to_str(h2msg_rcvd)
                cand_sr_dict[h2msg_sent_str] = h2msg_rcvd_str + " (%s)" % str(int(elapsedTime))

            cand_s.child_sr_dict = cand_sr_dict

            ######## Check duplication of cand_s in 3 ways ########
            if check_dupstate(pm, md, cand_s, 'p'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as parent state %s. Merge with its parent" % (pm.current_level, 
                    cand_s.name, md.dst_s.name))
                logger.debug(
                    "  [lv.%d-MINIMIZATION-STATE %s] Same as parent state %s. Merge with its parent" % (pm.current_level,
                        cand_s.name, md.dst_s.name))
            elif check_dupstate(pm, md, cand_s, 's'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as sibling state %s. Merge with its sibling" % (pm.current_level,
                    cand_s.name, md.dst_s.name))
                logger.debug(
                    "  [lv.%d-MINIMIZATION-STATE %s] Same as sibling state %s. Merge with its sibling" % (pm.current_level,
                        cand_s.name, md.dst_s.name))
            elif check_dupstate(pm, md, cand_s, 'r'):
                print("  [lv.%d-MINIMIZATION-STATE %s] Same as relative state %s. Merge with its relative" % (pm.current_level,
                    cand_s.name, md.dst_s.name))
                logger.debug(
                    "  [lv.%d-MINIMIZATION-STATE %s] Same as relative state %s. Merge with its relative" % (pm.current_level,
                        cand_s.name, md.dst_s.name))
            else:
                # no dup state found.
                print("  [lv.%d-MINIMIZATION-STATE %s] -> **** Unique state %s found ****" % (pm.current_level, cand_s.name, cand_s.name))
                logger.info("  [lv.%d-MINIMIZATION-STATE %s] -> **** Unique state %s found ****" % (pm.current_level, cand_s.name, cand_s.name))

        update_sm(pm, sm, cand_s, md)

#
# # Valid state add edges
# print("  [INFO] Adding %s valid states ..." % (len(pm.state_list.alive_state_list)))
# for cand_s, src_state, dst_state, vs_payload, elapsedTime in pm.state_list.get_alive_states():
# 	cand_s = pm.state_list.get_state_by_name(cand_s.name)
# 	if int(elapsedTime) > 0:
# 		vs_payload = vs_payload + " / "+str(int(elapsedTime))
# 		abnormal_result = validator_h2.abnormal_checker(pm, cand_s, vs_payload, cand_s.parent_state)
# 		sm.add_state(cand_s.name+abnormal_result) # prev. style (putting on SM)
# 		pm.state_list.add_state(cand_s)
# 		# logger.debug("[+] Abnormal state %d found with result %s" % (cand_s.name, abnormal_result))
# 		sm.add_transition(vs_payload + "\n", source = cand_s.parent_state, dest = cand_s.name)
# 		print ("[+] Valid state " + cand_s.name + " in level " + str(pm.current_level) + " added")
# 		logger.debug("[+] Valid state " + cand_s.name + " in level " + str(pm.current_level) + " added")
# 		# valid_states_buf.append([cand_s.name, src_state, dst_state, vs_payload, elapsedTime])
# 	else:
# 		vs_payload = vs_payload + " / "+str(int(elapsedTime))
# 		sm.add_transition(vs_payload + "\n", source = cand_s.parent_state, dest = 'fin')
# 		print ("[+] Valid state " + cand_s.name + " in level " + str(pm.current_level) + " added as end (initial) state")
# 		logger.debug("[+] Valid state " + cand_s.name + " in level " + str(pm.current_level) + " added as end (initial) state")
# 		valid_states_end_buf.append([cand_s.name, src_state, dst_state, vs_payload, elapsedTime])
# 	index += 1
#
# pm.state_list.alive_state_list = []

# # Remove invalid states
# print("  [INFO] Removing %s invalid states ..." % (len(pm.invalid_states)))
# for self_numb, src_state, dst_state, vs_payload, elapsedTime in invalid_states:
# 	child_state = pm.state_list.get_state_by_name(self_numb)
# 	if int(elapsedTime) == 0:
# 		vs_payload = vs_payload + " / " + str(int(elapsedTime))
# 		sm.add_transition(vs_payload + "\n", source = str(src_state), dest = 'fin')
# 		pm.state_list.remove_state(child_state)
# 		print ("[+] Invalid state " + self_numb + " in level " + str(pm.current_level) + " removed and go root time: "+ str(int(elapsedTime)))
# 		logger.debug("[+] Invalid state %s removed in level %d" % (self_numb, pm.current_level))

# 	elif int(elapsedTime) > 0:
# 		vs_payload = vs_payload + " / " + str(int(elapsedTime))
# 		sm.add_transition(vs_payload + "\n", source = str(src_state), dest = str(src_state))
# 		pm.state_list.remove_state(child_state)
# 		print ("[+] Invalid state " + self_numb + " in level " + str(pm.current_level) + " removed and go root time: "+ str(int(elapsedTime)))
# 		logger.debug("[+] Invalid state %s removed in level %d" % (self_numb, pm.current_level))


# for self_numb_end, src_state_end, dst_state_end, vs_payload_end, elapsedTime_end in valid_states_end_buf:
# 	self_state = pm.state_list.get_state_by_name(self_numb_end)
# 	pm.state_list.remove_state(self_state)
