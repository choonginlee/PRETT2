class State:
	def __init__(self, name, level, parent_state=None, spyld=None, h2msg_sent=None, rpyld=None, h2msg_rcvd=None,
				 elapsedTime=0, child_sr_dict=None, is_abnormal=False):
		self.name = name
		self.level = level
		self.parent_state = parent_state
		# send h2 sequence
		self.h2msg_sent = h2msg_sent
		# response h2 sequence
		self.h2msg_rcvd = h2msg_rcvd
		# connection TTL time after receiving a response (to reach itself)
		self.elapsedTime = elapsedTime
		self.child_sr_dict = child_sr_dict
		# security violation checking variable
		self.isAbnormal = is_abnormal

	def set_abnormal(self):
		self.isAbnormal = True

	def is_abnormal(self):
		return self.isAbnormal

class StateList:
	def __init__(self, state_list=[]):
		self.state_list = state_list

	def add_state(self, state):
		self.state_list.append(state)

	def remove_state(self, state):
		self.state_list.remove(state)

	def get_state_by_name(self, name):
		for state in self.state_list:
			if state.name == name:
				return state

	def get_states_by_level(self, level):
		states_list = []
		for state in self.state_list:
			if state.level == level:
				states_list.append(state)
		return states_list

	def print_state_list(self):
		tmplist = []
		print("state list length : " + str(len(self.state_list)))
		for s in self.state_list:
			tmplist.append(s.name)
		print(tmplist)

	def print_payloadPair(self):
		print("State list length : " + str(len(self.state_list)))
		for state in self.state_list:
			print("State name : %s" % state.name)
			print("Sent payload : " + str(state.spyld))
			print ("Receive payload : "+str(state.rpyld))

	def get_allElapsedTime_by_level(self, level):
		elapsedTimeArr = []
		for state in self.state_list:
			if state.level == level:
				elapsedTimeArr.append(state.elapsedTime)
		return elapsedTimeArr

