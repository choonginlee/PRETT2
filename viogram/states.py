class State:
	def __init__(self, name, level, parent_state = None, spyld=None, h2msg_sent = None, rpyld=None, h2msg_rcvd=None, elapsedTime = 0, group=None, child_sr_dict=None, is_abnormal=False):
		self.name = name
		self.level = level
		self.parent_state = parent_state
		# send h2 sequence
		self.h2msg_sent = h2msg_sent
		# response h2 sequence
		self.h2msg_rcvd = h2msg_rcvd
		# connection TTL time after receiving a response (to reach itself)
		self.elapsedTime = elapsedTime
		self.group = group
		self.child_sr_dict = child_sr_dict
		# security violation checking variable
		self.isAbnormal = is_abnormal

	def set_abnormal(self):
		self.isAbnormal = True

	def get_is_abnormal(self):
		return self.isAbnormal

class StateList:
	def __init__(self, state_list=[]):
		self.state_list = state_list

	def add_state(self, state):
		self.state_list.append(state)

	def add_candidate_state(self, state):
		self.candidate_state_list.append(state)

	def add_alive_state(self, state):
		self.alive_state_list.append(state)

	def remove_state(self, state):
		self.state_list.remove(state)

	def get_state_by_name(self, name):
		for state in self.state_list:
			if state.name == name:
				return state
		for state in self.candidate_state_list:
			if state.name == name:
				return state

	def get_candidate_states(self):
		return self.candidate_state_list

	def get_alive_states(self):
		return self.alive_state_list

	def get_states_by_level(self, level):
		states_list = []
		for state in self.state_list:
			if state.level == level:
				states_list.append(state)
		return states_list

	def get_valid_states_by_level(self, level):
		states_list = []
		for state in self.state_list:
			if state.level == level and int(state.elapsedTime) > 0 :
				states_list.append(state)
		return states_list

	def print_states(self):
		print("state list length : " + str(len(self.state_list)))
		for state in self.state_list:
			print(state.name)

	def print_candidate_states(self):
		print("candidate state list length : " + str(len(self.candidate_state_list)))
		for state in self.candidate_state_list:
			print(state.name)

	def print_payloadPair(self):
		print("State list length : " + str(len(self.state_list)))
		for state in self.state_list:
			print ("Sent payload : "+str(state.spyld))
			print ("Receive payload : "+str(state.rpyld))
			print("")

	def get_allElapsedTime_by_level(self, level):
		elapsedTimeArr = []
		for state in self.state_list:
			if state.level == level:
				elapsedTimeArr.append(state.elapsedTime)
		return elapsedTimeArr

