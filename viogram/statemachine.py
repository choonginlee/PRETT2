from states import *
from modeller_h2 import send_receive_http2
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

frameInfoArr = ['DATA','HEADERS','PRIORITY','RST_STREAM','SETTINGS','PUSHPROMISE','PING','GO_AWAY','WINDOW_UPDATE','CONTINUATION']
frameShortInfoArr = ['DA','HE','PR','RS','SE','PU','PI','GO','WI','CO']

frame_db = ['DATA','HEADERS','PRIORITY','SETTINGS','PUSHPROMISE','WINDOW_UPDATE','CONTINUATION']
# token_db = ['GET', 'POST', 'HEAD', 'PUT', "DELETE", 'TRACE', 'CONNECT', 'OPTIONS']
args_db = ['/index.php', '/', '/index.html', 'index']

class ProtoModel(object):
	def __init__(self, name):
		self.name = name

		# overall status
		self.is_pruning = False
		self.current_level = 1
		self.level_dict = {1 : ['0']} # contains states for each level
		self.dst_ip = None

		# State searching information
		self.current_state = 0
		self.num_of_states = 0
		self.new_state = []
		self.state_list = StateList([State('0', 1)]) # basic state '0' in level 1

		# Transition information
		# trigger as key (string) : [src_state (string), dest_state (string), cnt]
		self.transition_info = {}
		self.testmsgs = None

def generate_sm():
	pm = ProtoModel("Protocol Model")
	sm = Machine(model = pm, states = ['0', 'fin'], initial = '0', auto_transitions=False)
	return pm, sm

def get_move_state_h2msgs(pm, target_state_no):
	# Get state moving message to reach current state
	move_state_h2msgs = h2.H2Seq()
	move_state_num = 0
	while True:
		parent_node = pm.state_list.get_state_by_num(target_state_no).parent_node
		if parent_node is not None: # non-last node
			parent_h2msg = copy.deepcopy(pm.state_list.get_state_by_num(target_state_no).h2msg_sent)
			parent_h2msg.frames.reverse()
			move_state_h2msgs.frames.extend(parent_h2msg.frames)
			move_state_num = move_state_num + 1
			target_state_no = parent_node
			continue
		elif parent_node is None and move_state_num == 0: # last node
			break
		else: # root node
			break
	
	move_state_h2msgs.frames.reverse()
	return move_state_h2msgs

def update_candidates(pm, sm, h2msg_sent, h2msg_rcvd, elapsedTime):
	# sm : state machine, current_state : current state, 
	# spyld_str : send h2 frame sequence in string, h2msg_sent : send h2 frame sequence, 
	# rpyld_str : response h2 frame sequence in string, h2msg_rcvd : response h2 frame sequence
	# elapsedTime : elapsed time for response of h2msg_rcvd to h2msg_sent
	# Build and fix a state machine based on the response

	spyld_str = util.h2msg_to_str(h2msg_sent)
	rpyld_str = util.h2msg_to_str(h2msg_rcvd)

	t_label = spyld_str + " / " + rpyld_str

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

	pm.transition_info[t_label] = [str(pm.current_state), str(pm.num_of_states), 1]
	# No valid state found yet. Add candidate states in protocol model first.
	pm.num_of_states += 1
	pm.state_list.add_state(State(numb = str(pm.num_of_states), level = pm.current_level+1, parent_node=str(pm.current_state), h2msg_sent = h2msg_sent, h2msg_rcvd = h2msg_rcvd, elapsedTime = elapsedTime, group=" "))
	print("  [+] State %s added (%d -> %d)" % (str(pm.num_of_states), pm.current_state, pm.num_of_states))
	logger.info("  [+] State %s added (%d -> %d)" % (str(pm.num_of_states), pm.current_state, pm.num_of_states) + " (transition %s)" % t_label)

def expand_sm(pm, sm, leaf_states):
	leafstate_num = 1
	print(leaf_states)
	for state_no in leaf_states:
		try:
			print("  [EXPANSION-LEAF] Expanding state %s (%d/%d leaves)" % (str(state_no), leafstate_num, len(leaf_states)))
			logger.info("  [EXPANSION-LEAF] Expanding state %s (%d/%d leaves)" % (str(state_no), leafstate_num, len(leaf_states)))
		except Exception as e:
			print(e)
			print(state_no)
			print(str(state_no))
		move_state_h2msgs = get_move_state_h2msgs(pm, state_no)
		# print("[expand_sm] h2msg of get_move_state_h2msgs ---")
		# util.h2msg_to_str(move_state_h2msgs)
		parent_elapsed_time = pm.state_list.get_state_by_num(state_no).elapsedTime
		message_num = 1
		pm.current_state = int(state_no)
		print("current state is %d" % pm.current_state)
		for h2msg_sent in pm.testmsgs:  # test messages : SE-WI, DA-HE-DA .... (from pcap)
			print("    [EXPANSION-STATE-%s] move Frame: %s, send Frame: %s (%d/%d msgs)" % (str(state_no), util.h2msg_to_str(move_state_h2msgs), util.h2msg_to_str(h2msg_sent), message_num, len(pm.testmsgs)))
			logger.info("    [EXPANSION-STATE-%s] move Frame: %s, send Frame: %s (%d/%d msgs)" % (str(state_no), util.h2msg_to_str(move_state_h2msgs), util.h2msg_to_str(h2msg_sent), message_num, len(pm.testmsgs)))
			# print ("  [ ] It may take time for receiving Go Away frame..")
			h2msg_rcvd, elapsedTime = send_receive_http2(pm, move_state_h2msgs, h2msg_sent, parent_elapsed_time)
			update_candidates(pm, sm, h2msg_sent, h2msg_rcvd, elapsedTime)
			message_num += 1
		leafstate_num += 1

def check_dupstate(pm, sm, cand_s, mode):
	######## Compare SR dicts in multiple cases. ########
	if mode == 'p':
		# STEP1. Parent
		# - Compare child dict with parent dict
		# print('  [MINIMIZATION-STATE %s] Testing with its parent state %s ... ' % (str(cand_s.numb), str(cand_s.parent_node)))
		# logger.info('  [MINIMIZATION-STATE %s] Testing with its parent state %s ... ' % (str(cand_s.numb), str(cand_s.parent_node)))
		pass
	elif mode == 's':
		pass
	elif mode == 'r':
		pass
	else:
		print("[ERROR] (check_dupstate()) Invalid mode.")
		logger.info("[ERROR] (check_dupstate()) Invalid mode.")
		sys.exit()


	cand_s_list = pm.state_list.get_states_by_level(pm.current_level+1)


## if Elapsed time is 0, it means end state
def minimize_sm(pm, sm):
	invalid_states = []

	# Among candidate states in the next level, unique states in current level are determined in minimize_sm() via pruning.
	cand_s_list = pm.state_list.get_states_by_level(pm.current_level+1)
	if len(cand_s_list) == 0:
		return

	print ("  [INFO] # of candidate states in level %d : %d" % (pm.current_level, len(cand_s_list)))

	for cand_s_no in cand_s_list:
		cand_s = pm.state_list.get_state_by_num(cand_s_no)
		check_dupstate(pm, sm, cand_s, 'p')

		######## Retrieve parent SR info ########
		# Optimize??
		# parent_sr_dict is messages from parent node to child node  ( key : request value : resposnses )
		parent_sr_dict = OrderedDict()
		for child_num in cand_s_list:
			child_node = pm.state_list.get_state_by_num(child_num)
			if child_node.parent_node == cand_s.parent_node:
				h2msg_sent_str = util.h2msg_to_str(child_node.h2msg_sent)
				h2msg_rcvd_str = util.h2msg_to_str(child_node.h2msg_rcvd)
				parent_sr_dict[h2msg_sent_str] = h2msg_rcvd_str + ' / '+ str(int(child_node.elapsedTime))

		pm.state_list.get_state_by_num(cand_s.parent_node).child_sr_dict = parent_sr_dict

		######## Retrieve child(cand_s) SR info ########
		# child_sr_dict is messages from itself to and its child node (Do the same test as parent).
		print('  [MINIMIZATION-STATE %s] Retrieving its SR dict' % (cand_s_no))
		child_sr_dict = OrderedDict()
		child_elapsedtime = pm.state_list.get_state_by_num(cand_s_no).elapsedTime
		move_state_h2msgs = get_move_state_h2msgs(pm, cand_s_no)
		move_state_h2msgs_str = util.h2msg_to_str(move_state_h2msgs)

		for msg_sent in pm.testmsgs:
			h2msg_rcvd, elapsedTime = send_receive_http2(pm, move_state_h2msgs, msg_sent, child_elapsedtime)
			h2msg_sent_str = util.h2msg_to_str(msg_sent)
			h2msg_rcvd_str = util.h2msg_to_str(h2msg_rcvd)
			child_sr_dict[h2msg_sent_str] = h2msg_rcvd_str + ' / ' + str(int(elapsedTime))



		pm.state_list.get_state_by_num(cand_s_no).child_sr_dict = child_sr_dict
		h2msg_sent_str = util.h2msg_to_str(cand_s.h2msg_sent)
		h2msg_rcvd_str = util.h2msg_to_str(cand_s.h2msg_rcvd)

		if util.compare_ordered_dict(parent_sr_dict, child_sr_dict) == True: # same state, prune state
			print ("  [MINIMIZATION-STATE %s] Same as parent %s. Merge with its parent state " % (cand_s_no, cand_s.parent_node))
			invalid_states.append([cand_s_no, cand_s.parent_node, cand_s.parent_node, h2msg_sent_str + " / " + h2msg_rcvd_str, cand_s.elapsedTime])
			logger.debug("[+] state number to be pruned (same as parent %s) : %s" % (cand_s.parent_node, str(cand_s_no)))
		else: 
			print ("  [MINIMIZATION-STATE %s] -> Different from parent %s. Now check with sibling nodes ..." % (cand_s_no, cand_s.parent_node))
			# STEP 2. Sibling
			# - Compare its child dict with that of other childs whose parent is same.
			unique_in_step_2 = True

			child_level = pm.current_level + 1
			for valid_state_numb, src_state, dst_state, vs_payload, elapsedTime in pm.new_state:
				sibling_state = pm.state_list.get_state_by_num(valid_state_numb)
				if sibling_state.parent_node == cand_s.parent_node: # siblings which have same parent
					# compare child_dict between sibling and current state
					if util.compare_ordered_dict(sibling_state.child_sr_dict, cand_s.child_sr_dict) == True: # same state! Merge with sibling!
						invalid_states.append([cand_s_no, cand_s.parent_node, valid_state_numb, h2msg_sent_str + " / " + h2msg_rcvd_str, cand_s.elapsedTime])
						unique_in_step_2 = False
						print ("  [MINIMIZATION-STATE %s] Same as sibling %s. Merge with its sibling" % (cand_s_no, valid_state_numb))
						logger.debug("[+] state number to be pruned (same as sibling %s) : %s" % (valid_state_numb, str(cand_s_no)))
						break
					else:
						continue
				else:
					continue

			# Step 3. Relatives
			# Compare with the other relatives
			if unique_in_step_2:
				print ("  [MINIMIZATION-STATE %s] -> Different from siblings, Now check with relative nodes ..." % (cand_s_no)) 
				target_level = pm.current_level + 1
				currently_unique = True
				if target_level > 2:
					currently_unique = False
				else: # state in level 2
					currently_unique = True

				while True:
					if target_level == pm.current_level + 1:
						for valid_state_numb, src_state, dst_state, vs_payload, elapsedTime in pm.new_state:
							first_cousin = pm.state_list.get_state_by_num(valid_state_numb)
							if first_cousin.parent_node != cand_s.parent_node: # siblings which have same parent
								print ("[-] -> compare state " + cand_s.numb + " with other sibling state " + str(valid_state_numb) + " in same level")
								# compare child_dict between sibling and current state
								if util.compare_ordered_dict(first_cousin.child_sr_dict, cand_s.child_sr_dict) == True: # same state! Merge with sibling!
									invalid_states.append([cand_s_no, cand_s.parent_node, valid_state_numb, h2msg_sent_str + " / " + h2msg_rcvd_str, cand_s.elapsedTime])
									currently_unique = False
									print ("[+] -> Same as " + valid_state_numb + " in Step 3. Merge with state " + valid_state_numb)
									logger.debug("[+] state number to be pruned (same as relative %s): %s" % (valid_state_numb, str(cand_s_no)))
									break
								else:
									currently_unique = True
									continue
							else:
								currently_unique = True
								continue
						
						if len(pm.new_state) == 0:
							currently_unique = True

					else:
						# get all parents in previous level
						for target_numb_in_level in pm.state_list.get_states_by_level(target_level - 1):
							# validition
							# compare with other parents
							if target_numb_in_level != cand_s.parent_node:
								print ("[-] -> compare state " + cand_s.numb + " with ancestor state " + target_numb_in_level)
								parent_state_in_level = pm.state_list.get_state_by_num(target_numb_in_level)
								# compare child_dict between prev and current state
								if util.compare_ordered_dict(parent_state_in_level.child_sr_dict, cand_s.child_sr_dict) == True: # same state! Add transition to parent_state_in_level!
									invalid_states.append([cand_s_no, cand_s.parent_node, target_numb_in_level, h2msg_sent_str + " / " + h2msg_rcvd_str, cand_s.elapsedTime])
									print ("[+] -> Same as " + parent_state_in_level.numb + ". Add transitions to state " + parent_state_in_level.numb)
									logger.debug("[+] state number to be pruned : %s" % str(cand_s_no))
									currently_unique = False
									break
								else:
									print ("[-] -> Differnt from relative state " + target_numb_in_level)
									currently_unique = True
									continue
					

					if currently_unique == True: # valid yet
						target_level = target_level - 1
						print ("[-] target parent level : " + str(target_level))
						if target_level == 0:
							break
						else:
							continue
					else:
						break

				if currently_unique == True: # real valid state
					print ("[+] -> **** Unique state " + cand_s_no + " found ****")
					pm.new_state.append([cand_s_no, pm.current_state, cand_s_no, h2msg_sent_str + " / " + h2msg_rcvd_str, cand_s.elapsedTime])
					logger.debug("[+] unique state %s found!" % (str(cand_s_no)))


	valid_states_buf = []
	valid_states_end_buf = []
	index = 0
	# Valid state add edges
	print("  [INFO] Adding %s valid states ..." % (len(pm.new_state))) 
	for self_numb, src_state, dst_state, vs_payload, elapsedTime in pm.new_state:
		self_state = pm.state_list.get_state_by_num(self_numb)
		if int(elapsedTime) > 0:
			vs_payload = vs_payload + " / "+str(int(elapsedTime))
			abnormal_result = validator_h2.abnormal_checker(pm, self_state, vs_payload, self_state.parent_node)
			# sm.add_state(self_numb+abnormal_result) # prev. style (putting on SM)
			logger.debu("[+] Abnormal state %d found with result %s" % (self_numb, abnormal_result))
			sm.add_transition(vs_payload + "\n", source = self_state.parent_node, dest = self_numb)
			print ("[+] Valid state " + self_numb + " in level " + str(pm.current_level) + " added")
			logger.debug("[+] Valid state " + self_numb + " in level " + str(pm.current_level) + " added")
			# valid_states_buf.append([self_numb, src_state, dst_state, vs_payload, elapsedTime])
		else:
			vs_payload = vs_payload + " / "+str(int(elapsedTime))
			sm.add_transition(vs_payload + "\n", source = self_state.parent_node, dest = 'fin')
			print ("[+] Valid state " + self_numb + " in level " + str(pm.current_level) + " added as end (initial) state")
			logger.debug("[+] Valid state " + self_numb + " in level " + str(pm.current_level) + " added as end (initial) state")
			valid_states_end_buf.append([self_numb, src_state, dst_state, vs_payload, elapsedTime])
		index += 1

	pm.new_state = []

	# Remove invalid states
	print("  [INFO] Removing %s invalid states ..." % (len(invalid_states))) 
	for self_numb, src_state, dst_state, vs_payload, elapsedTime in invalid_states:
		child_state = pm.state_list.get_state_by_num(self_numb)
		if int(elapsedTime) == 0:
			vs_payload = vs_payload + " / " + str(int(elapsedTime))
			sm.add_transition(vs_payload + "\n", source = str(src_state), dest = 'fin')
			pm.state_list.remove_state(child_state)
			print ("[+] Invalid state " + self_numb + " in level " + str(pm.current_level) + " removed and go root time: "+ str(int(elapsedTime)))
			logger.debug("[+] Invalid state %s removed in level %d" % (self_numb, pm.current_level))
			
		elif int(elapsedTime) > 0:
			vs_payload = vs_payload + " / " + str(int(elapsedTime))
			sm.add_transition(vs_payload + "\n", source = str(src_state), dest = str(src_state))
			pm.state_list.remove_state(child_state)
			print ("[+] Invalid state " + self_numb + " in level " + str(pm.current_level) + " removed and go root time: "+ str(int(elapsedTime)))
			logger.debug("[+] Invalid state %s removed in level %d" % (self_numb, pm.current_level))


	for self_numb_end, src_state_end, dst_state_end, vs_payload_end, elapsedTime_end in valid_states_end_buf:
		self_state = pm.state_list.get_state_by_num(self_numb_end)
		pm.state_list.remove_state(self_state)