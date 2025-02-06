# consumers.py
import json

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer, JsonWebsocketConsumer

import logging

logger = logging.getLogger(__name__)

# . TODO
# [ ] reset var on Lock connect?
# [ ] connect -> online status.. == reset
# [ ] disconnect -> offline status == offline
# [ ] add_target() <- serverside "var" response with [lock.name, lock.description, ?offline/online status ]


#   # send message from somehwere else:
#   import channels.layers
#   channel_layer = channels.layers.get_channel_layer()
#   from asgiref.sync import async_to_sync
#   async_to_sync(channel_layer.group_send)('chat_withall', {"type": "chat.message", "message": "Hi van de shell..."})


from .models import *
import uuid


#
# Broadcast Event:
#
# - websocket json: {type: event, target: null, event: event_name }
#   - receive_json(...) --> relay to my group channel f'group_{persistet_name}'
#      - channel group_send(f'group_{persistet_name}', *websocket_event )
#
#
### websocket json:
## broadcast event to group:
# >>     event:     {type: event, event: event_name }
# <<     event:     {type: event, from: persisted_name , event: event_name }
#
#
## send event to device: (no direct answer)
# >>     event:     {type: event, to: persisted_name , event: event_name }
#
## send variable to group:
# >>     variable:  {type: variable, variable: { variable_name: variable_value }}
# <<     variable:  {type: variable, from: persisted_name, variable: { variable_name: variable_value }, [reset_cache: bool]}
#
## ask for variable to device: (channel client will add from: and channel server will answer)
# >>     variable:  {type: variable, to: *persisted_name, variable: { variable_name: variable_value }}
# <<     variable:  {type: variable, from: *persisted_name, variable: { variable_name: variable_value }}
#
# channel   dict:
#      passthru  :  {type: channel.passthru , data: **websocket_json } # --> def channel_passthru()
#      serverside:  {type: channel.serverside, request: ['get_var_cache'] } # --> channel.serverside()
#


def cleanup_ws_event(ws_event, defaults={}, check_type=True):
    # set defaults
    for k in defaults:
        if k in ws_event:
            print(
                f"DEBUG, event[{k}] ({ws_event[k]}) will be overwritten with '{defaults[k]}'"
            )
        ws_event[k] = defaults[k]

    # remove None
    for k in list(ws_event.keys()):
        if ws_event[k] == None:
            del ws_event[k]

    # only allow one type
    if check_type:
        if (
            int("event" in ws_event)
            + int("var" in ws_event)
            + int("task" in ws_event)
            + int("comm" in ws_event)
            != 1
        ):
            raise ValueError(
                f"Atleast and only 1 of 'event, var, task, comm' can be specified. ({ws_event})"
            )

    # set type
    for t in ["event", "var", "task", "comm"]:
        if t in ws_event:
            ws_event["type"] = t

    return ws_event


class WebUserPermision:
    def __init__(self):
        # read/write var per target
        self.allowed_read_var = {"Lock.5": True, "Lock.6": True}
        self.allowed_write_var = {"Lock.6": False}
        # self.allowed_write_var =  {'Lock.6': True}
        # self.allowed_write_var_keys =  {'Lock.6': ['lockname']}

        self.allowed_events = {
            "Lock.5": [
                "open_solenoid",
                "cancel_open_solenoid",
                "toggle_permanent_open",
            ],
            "Lock.6": [
                "open_solenoid",
                "cancel_open_solenoid",
                "toggle_permanent_open",
            ],
        }

        self.allowed_targets = ["Lock.5", "Lock.6"]
        # self.group_subscriptions = ['group_Lock.6']

    def get_groupchannel_by_target(self, target):
        return f"group_{target}"

    def is_allowed_event(self, data):
        try:
            to = data["to"]
            event = data["event"]
            return event in self.allowed_events[to]
        except:
            return False

    def is_var_allowed(self, data):
        try:
            to = data["to"]
            return self.allowed_read_var[to]
        except:
            return False

    @property
    def var_allowed_targets(self):
        return self.allowed_read_var.keys()

    def is_allowed_write_var(self, data):
        try:
            to = data["to"]
            return self.allowed_write_var[to]
        except:
            return False


class BaseDoorlockConsumer(JsonWebsocketConsumer):

    @property
    def from_name(self):
        """Get from_name, if available the persistent_name (like Lock.6) or else the full channel_name"""
        try:
            return self.persistent_name
        except:
            pass

        return self.channel_name

    def send_to_serverside(self, channel_name, request):
        # add type , so it calls method channel_serverside(data)
        event = {
            "type": "channel.serverside",
            "request": request,
            "from": self.channel_name,
        }

        print("DEBUG send_to_serverside:", event)

        # get persistent_name
        async_to_sync(self.channel_layer.send)(channel_name, event)

    def send_to_one(self, channel_name, data):
        # set from:
        data = cleanup_ws_event(data, {"from": self.from_name, "to": channel_name})

        # add type , so it method channel_passtru(data)
        event = {"type": "channel.passthru", "data": data}

        print("DEBUG send_to_one:", event)

        # get persistent_name
        async_to_sync(self.channel_layer.send)(channel_name, event)

    def send_to_all_followers(self, data):
        # set 'from' field in data
        data = cleanup_ws_event(data, {"from": self.persistent_name})

        # add type , so it method channel_passtru(data)
        event = {"type": "channel.passthru", "data": data}

        print("DEBUG send_to_all_followers:", event)

        async_to_sync(self.channel_layer.group_send)(
            self.room_group_name,
            event,
        )

    def channel_serverside(self, event):
        # request vars from cache:
        if event["request"] == "get_vars_from_cache" and hasattr(self, "var_cache"):
            chan = event["from"]

            # we send our complete cache so clients may overwrite their complete dict = reset_cache: True
            self.send_to_one(chan, {"comm": "reset"})
            self.send_to_one(chan, {"var": self.var_cache, "reset_cache": True})
            self.send_to_one(chan, {"comm": "ready"})

    def channel_passthru(self, event):
        # forward channel.passthru to websocket
        self.send_json(event["data"])

    def add_target(self, target):
        """Connect to an Lock.x"""
        if target not in self.permisions.allowed_targets:
            print(f"connect_target {target} not allowed!")
            self.send_json({"error": f"connect_target {target} not allowed!"})
            return

        # request var_cache
        try:
            self.send_to_serverside(
                LockWebsocketChannel.objects.get(persistent_name=target).channel_name,
                "get_vars_from_cache",
            )
        except LockWebsocketChannel.DoesNotExist as e:
            # # target offline, let's send the serverside vars:
            # self.send_to_one(chan, {'comm': 'reset'})
            # self.send_to_one(chan, {'var': , 'reset_cache': True})

            print(
                f"info: add_target: '{target}' doesn't exist right now. silently ignored."
            )

        # subscribe to group channel
        groupchannel = self.permisions.get_groupchannel_by_target(target)
        async_to_sync(self.channel_layer.group_add)(groupchannel, self.channel_name)

    def remove_target(self, target):
        """Disconnect to an Lock.x"""
        print(f"   .....             self.remove_target({target})")

        # Leave room group
        groupchannel = self.permisions.get_groupchannel_by_target(target)
        async_to_sync(self.channel_layer.group_discard)(groupchannel, self.channel_name)

        # fake offline message from target
        self.send_json({"type": "comm", "comm": "offline", "from": target})
        print({"type": "comm", "comm": "offline", "from": target})


class WebUserSessionConsumer(BaseDoorlockConsumer):
    def connect(self):
        # Auth user:
        self.accept()
        if not self.scope.get("user", False) or not self.scope["user"].has_perm(
            "doorlockdb.view_lock"
        ):
            self.send_json(
                {"error": f"auth error: user has no permision here"}, close=3000
            )

        # dress up our Consumer
        self.permisions = WebUserPermision()

        # # add target (or only on request (task add_target ???))
        # self.add_target('Lock.6')

        # welcome
        self.send_json(cleanup_ws_event({"comm": "ready", "from": "serverside"}))

    def disconnect(self, close_code):
        # remove target (or only on request (task remove_target ???))
        self.remove_target("Lock.6")

    def receive_json(self, data):
        # cleanup event data
        try:
            data = cleanup_ws_event(data, {"from": None})  # will set in when sending
            print("WS(u): >>>: ", data)
        except Exception as e:
            self.send_json({"error": f"Exception: {e}."})
            return

        # to='serverside'
        if data.get("to", False) == "serverside":

            # add target
            if (data.get("type", False) == "task") and (data["task"] == "add_target"):
                self.add_target(data.get("add_target", None))
                return

            # remove target
            if (data.get("type", False) == "task") and (
                data["task"] == "remove_target"
            ):
                self.remove_target(data.get("remove_target", None))
                return

        # type=event is received event in allowed_events
        if data.get("type", False) == "event" and self.permisions.is_allowed_event(
            data
        ):
            self.send_to_one(
                LockWebsocketChannel.objects.get(
                    persistent_name=data["to"]
                ).channel_name,
                data,
            )
            return

        # request vars
        if data.get("type", False) == "var" and self.permisions.is_allowed_write_var(
            data
        ):
            self.send_to_one(
                LockWebsocketChannel.objects.get(
                    persistent_name=data["to"]
                ).channel_name,
                data,
            )
            return

        # json ignored
        # self.send_json({'event':'error', 'error': "last json-data was ignored, didn't match any.", 'from':'serverside'})
        print(f"error, json-data ignored doesn't match any: {data}")


class LockConsumer(BaseDoorlockConsumer):
    def connect(self):
        self.accept()

        self.var_cache = {}

        # authenticate lock using Client SSL Certificate
        try:
            self.lock = Helpers.AuthWithByClientSSL(scope=self.scope)

            # cleanup zombie sockets:
            LockWebsocketChannel.objects.filter(lock=self.lock).delete()

            # Make a database row with our channel name
            lwc = LockWebsocketChannel.objects.create(
                lock=self.lock, channel_name=self.channel_name
            )
            self.persistent_name = lwc.persistent_name

        except Exception as e:
            logger.warning(
                f"Auth failure: {self.scope['type']} {self.scope['path']}, {e}."
            )
            self.send(text_data=json.dumps({"error": f"auth error: {e}"}), close=3000)

        # set some vars inside var_cache
        self.var_cache["lock_name"] = self.lock.name
        self.var_cache["lock_description"] = self.lock.description

        # set our broudcasting group
        self.room_group_name = f"group_{self.persistent_name}"

        # welcome
        self.send_json(cleanup_ws_event({"comm": "ready", "from": "serverside"}))

        # send connect event to our followers
        self.send_to_all_followers({"comm": "reset"})

    def disconnect(self, close_code):
        # send disconnect event to our followers
        self.send_to_all_followers({"comm": "offline"})

        # Note that in some rare cases (power loss, etc) disconnect may fail
        # to run; this naive example would leave zombie channel names around.
        LockWebsocketChannel.objects.filter(
            lock=self.lock, channel_name=self.channel_name
        ).delete()

        # Leave room group
        async_to_sync(self.channel_layer.group_discard)(
            self.room_group_name, self.channel_name
        )

        # pass

    def receive_json(self, data):
        # cleanup event data
        try:
            # data = cleanup_ws_event(data, {'from': None}) # will set when sending
            data = cleanup_ws_event(data)  # will set when sending
        except Exception as e:
            self.send_json({"error": f"Exception: {e}."})
            return

        # Received event message relay to group
        if data.get("type", False) == "event":
            self.send_to_all_followers(data)
            return

        # Received event message relay to group
        if data.get("type", False) == "var":
            # update local
            self.var_cache = {**self.var_cache, **data.get("var", {})}

            # cleanup None:
            for k in list(self.var_cache.keys()):
                if self.var_cache[k] == None:
                    del self.var_cache[k]

            self.send_to_all_followers(data)
            return

        # Received comm event relay to group
        if data.get("type", False) == "comm":
            self.send_to_all_followers(data)
            return
