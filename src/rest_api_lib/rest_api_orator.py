# from flask.views import MethodView
# from flask import make_response, jsonify, request, abort
from .rest_api_flask import RestApi 


class RestApiOrator(RestApi):
	_orator_model = None
	
	def set_orator_model(self, model):
		self._orator_model = model
	
	def db_find_one(self, id):
		# find 1 in data layer
		return(self._orator_model.find(id))

	def db_list(self):
		# get list from data layer
		return(self._orator_model.get())

	def db_create(self, item):
		# create in data layer
		new = self._orator_model.create(item)
		
		# let's return a fresh copy for the client.
		return self.db_find_one(new.get_key())
			
	def db_update(self, id, new_item, old_item=None):
		
		if old_item is None:
			old_item = self.db_find_one(id)
			
		if old_item.update(new_item):
			# let's return a fresh copy for the client
			return self.db_find_one(id)
		else:
			return(False)
	
	def db_delete(self, id):
		# delete in data layer
		return self._orator_model.destroy(id)
		
	def cast_object(self, object, instance=None):
		# cast incomming json into python object similar like orator does from sql:
		
		# change time-date into pendulum objects:
		# we need to initialize the model to get_dates()
		
		if instance is None:
			#instance = self._orator_model()
			## hack to workarround issuse with TypeError: 'HasMany' object is not callable 
			instance = self._orator_model.find_or_new(None)
			
		# get date attributes on this model
		dates = instance.get_dates()
		
		# cast our dates
		for key in dates:
			if key in object:
				object[key] = instance.as_datetime(object[key])
		
		return(object)
		
		
		
		

		
	# TODO : implement PATCH , or not ?...
		