from .base import baseTriggerAction

#
# Dummy trigger action, can be assigned as trigger_action on Buttons
#	
class Dummy(baseTriggerAction):
	"""this dummy trigger really does nothing."""
	
	def trigger(self):
		pass
	