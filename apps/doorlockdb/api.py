#
# Ninja api
#
from asyncio.log import logger
from dataclasses import dataclass
from .models import *


from ninja import NinjaAPI, Schema
from pydantic import PositiveInt
from typing import List

from django.core import serializers

import uuid
from datetime import datetime


#
# client SSL certificate authentication
#
class LockAuhClientSSL:
    #
    # this class will work like classes from ninja.security
    #
    def __call__(self, request):
        return Helpers.AuthWithByClientSSL(request)


api = NinjaAPI(auth=LockAuhClientSSL(), version="1.1.2", title="Doorlockd API")
#
# Version Changelog:
# api v 1.1.2: in /api/lock/log.unknownkeys + /api/lock/log.keys_last_seen ( "err_msgs": [] response)
# api v 1.1.1: adds /api/key/merge.meta_data_json (add/merge meta_data_json for existing keys)
# api v 1.1.0: meta_data_json added to /api/lock/log.unknownkeys,
#              incompatible with prior versions! upgrade backend and client at same time.
# api v 1.0.0: not documented, see /api/docs#/ on running backend.
#


@api.exception_handler(Helpers.ErrorClientSSLCert)
def on_client_ssl_cert_error(request, exc):
    return api.create_response(
        request, {"error": f"Client SSL Certificate error :'{exc}'"}, status=401
    )


@api.exception_handler(ValidationError)
def on_client_ssl_cert_error(request, exc):
    return api.create_response(
        request, {"error": f"ValidationError:'{exc}'"}, status=422
    )


@api.exception_handler(Exception)
def on_unexpected_exception(request, exc):
    """Catch unexpected exceptions, hide them for outsiders and give an log reference (log_ref) to lookup in the logs."""

    log_ref = uuid.uuid4()
    logging.error(
        f"Unexpected exception (log_ref: {log_ref}) in request '{request}'; '{exc}'.",
        exc_info=exc,
    )

    return api.create_response(
        request,
        {"error": f"Unexpected exception, see log for details (log_ref: {log_ref})"},
        status=500,
    )


#
#  endpoint handlers:
#
@api.get("/lock/")
def locks(request):
    """Get some information about a lock."""
    # get Lock from authentication
    l = request.auth

    # return serializers.serialize("json", Lock.objects.all())
    # return serializers.serialize("python", Lock.objects.filter(id=lock_id))
    return serializers.serialize("python", [l])[0]


class ErrorOutputSchema(Schema):
    error: str


class SyncKeysInputSchema(Schema):
    keys_hash: str


class SyncKeysOutputSchema(Schema):
    lockname: str = None
    keys: dict = None
    synchronised: bool = None
    disabled: bool = None


@api.post(
    "/lock/sync.keys", response={200: SyncKeysOutputSchema, 401: ErrorOutputSchema}
)
def api_lock_sync_keys(request, input_data: SyncKeysInputSchema):
    """Synchronise keys accesslist"""
    # return 'keys' OR 'synchronised' OR 'error'.
    # keys:           -> client must update key list
    # synchronised:   -> if value is true , client is up to date.
    # disabled:       -> additional bool value, if lock is disabled. (client must show warning in logs on lock)
    # lockname:       -> lockname to show in logfile

    # 401:
    # error:          -> error message.

    # get Lock from authentication
    l = request.auth

    # init response dict with lockname
    resp = dict(lockname=l.name)

    # if lock disabled (client will update to empty keys list):
    if not l.is_enabled:
        # we just add an additional error mesage to the response
        resp["disabled"] = True

    # store keys_on_lock so we know the current config on the lock
    sync, created = SyncLockKeys.objects.get_or_create(lock=l)
    out_of_sync, db_keys_config = sync.compare_hash_and_sync(input_data.keys_hash)

    # compare list
    # out_of_sync, db_keys_config = sync.out_of_sync()
    if out_of_sync:
        # out of sync:
        return {**resp, "message": "need update", "keys": db_keys_config}
    else:
        # in sync
        return {**resp, "message": "ok", "synchronised": True}


class LogUnknownKeySchema(Schema):
    key: str
    timestamp: str  # 'datetime.datetime.fromtimestamp(datetime.datetime.utcnow().timestamp()).isoformat()'
    count: PositiveInt
    meta_data_json: str = "{}"


class LogUnknownKeysOutputSchema(Schema):
    saved: List[LogUnknownKeySchema]
    err_msgs: List[str]


class LogUnknownKeysInputSchema(Schema):
    unknownkeys: List[LogUnknownKeySchema]


#
# Sync unknownkeys
#
@api.post(
    "/lock/log.unknownkeys",
    response={200: LogUnknownKeysOutputSchema, 401: ErrorOutputSchema},
)
def api_lock_log_unknownkeys(request, input_data: LogUnknownKeysInputSchema):
    """Post unknown_keys statistics"""
    saved = []
    err_msgs = []

    # get Lock from authentication
    l = request.auth

    # proces input list of dicts[{'key': hwid, 'timestamp': ..., 'count': int}]
    for uk in input_data.unknownkeys:
        # parse timestamp:
        try:
            timestamp = datetime.fromisoformat(uk.timestamp)
        except Exception as e:
            err_msg = f"Can't process timestamp for hwid[{uk.key}]: '{e}'"
            logging.error(f"Error in api_lock_log_unknownkeys[]: {err_msg}")

            # for api response:
            err_msgs.append(err_msg)

            # continue with next 'uk' in list
            continue

        # process json input:
        try:
            meta_data = json.loads(uk.meta_data_json)
        except json.decoder.JSONDecodeError as e:
            # this item fails, put error in log file and append messsage in api response.
            err_msg = f"Can't process meta_data_json for hwid[{uk.key}]: '{e}'"
            logging.error(f"Error in api_lock_log_unknownkeys[]: {err_msg}")

            # for api response:
            err_msgs.append(err_msg)

            # continue with next 'uk' in list
            continue

        # save item:
        try:
            LogUnknownKey.register(uk.key, l, timestamp, uk.count, meta_data)
            saved.append(uk)
        except Exception as e:
            # this item fails, put error in log file and append messsage in api response.
            err_msg = f"Unexpected exception during hwid[{uk.key}]."
            logging.error(f"Error in api_lock_log_unknownkeys[]: {err_msg}", exc_info=e)

            # for api response:
            err_msgs.append(f"{err_msg}, see log for details.")

            # continue with next 'uk' in list
            continue

    return {"saved": saved, "err_msgs": err_msgs}


#
# Log Last Seen:
#
class LogKeysLastSeenSchema(Schema):
    key: str
    timestamp_begin: str  # 'datetime.datetime.fromtimestamp(datetime.datetime.utcnow().timestamp()).isoformat()'
    timestamp_end: str  # 'datetime.datetime.fromtimestamp(datetime.datetime.utcnow().timestamp()).isoformat()'
    count: PositiveInt


class LogKeysLastSeenOutputSchema(Schema):
    saved: List[LogKeysLastSeenSchema]
    err_msgs: List[str]


class LogKeysLastSeenInputSchema(Schema):
    keys_last_seen: List[LogKeysLastSeenSchema]


@api.post(
    "/lock/log.keys_last_seen",
    response={200: LogKeysLastSeenOutputSchema, 401: ErrorOutputSchema},
)
def api_lock_log_keys_last_seen(request, input_data: LogKeysLastSeenInputSchema):
    """Post keys statistics"""
    saved = []
    err_msgs = []

    # get Lock from authentication
    l = request.auth

    # LogKeyLastSeen.addLastSeen(hwid, lock, last_seen_start=None, last_seen_end=None, count=1):
    # proces input list of dicts[{'key': hwid, 'timestamp': ..., 'count': int}]
    for k in input_data.keys_last_seen:
        # parse timestamp_begin:
        try:
            timestamp_begin = datetime.fromisoformat(k.timestamp_begin)
        except Exception as e:
            err_msg = f"Can't process timestamp_begin for hwid[{k.key}]: '{e}'"
            logging.error(f"Error in api_lock_log_keys_last_seen[]: {err_msg}")

            # for api response:
            err_msgs.append(err_msg)

            # continue with next 'k' in list
            continue

        # parse timestamp_end:
        try:
            timestamp_end = datetime.fromisoformat(k.timestamp_end)
        except Exception as e:
            err_msg = f"Can't process timestamp_end for hwid[{k.key}]: '{e}'"
            logging.error(f"Error in api_lock_log_keys_last_seen[]: {err_msg}")

            # for api response:
            err_msgs.append(err_msg)

            # continue with next 'k' in list
            continue

        try:
            LogKeyLastSeen.addLastSeen(
                k.key, l, timestamp_begin, timestamp_end, k.count
            )
            saved.append(k)
        except Exception as e:
            # this item fails, put error in log file and append messsage in api response.
            err_msg = f"Unexpected exception during hwid[{k.key}]."
            logging.error(
                f"Error in api_lock_log_keys_last_seen[]: {err_msg}", exc_info=e
            )

            # for api response:
            err_msgs.append(f"{err_msg}, see log for details.")

            # continue with next 'uk' in list
            continue

    return {"saved": saved, "err_msgs": err_msgs}


#
# set/update meta_data_json
#
class KeyMetaDataJsonInputSchema(Schema):
    key: str
    meta_data_json: str = "{}"


class KeyMetaDataJsonOutputSchema(Schema):
    saved: bool


@api.post(
    "/key/merge.meta_data_json",
    response={200: KeyMetaDataJsonOutputSchema, 401: ErrorOutputSchema},
)
def api_merge_key_meta_data_json(request, input_data: KeyMetaDataJsonInputSchema):
    """Set or Merge keys meta_data_json"""

    # get Lock from authentication
    l = request.auth

    if not Key.objects.filter(hwid=input_data.key).exists():
        logging.error(f"api KeyMetaData merge. Key does not exist: '{input_data.key}'.")
        return {"saved": False}

    # process json input:
    try:
        meta_data = json.loads(input_data.meta_data_json)
    except json.decoder.JSONDecodeError as e:
        return api.create_response(
            request, {"error": f"Can't process meta_data_json: '{e}'"}, status=422
        )

    # create or merge KeyMetaData:
    md, created = KeyMetaData.objects.get_or_create(hwid=input_data.key)
    md.merge_meta_data_json(meta_data)
    md.save()
    logging.info(f"api KeyMetaData '{input_data.key}' successfully merged.")

    return {"saved": True}


#
# wait for an event. Long poll request
#
@api.post("lock/event.long_poll")
def api_lock_event_long_poll(request):
    """Attemp to create a long_poll request in Ninja api:
    this endpoint will wait for max ~500s before returning an event.
    """
    data = {}

    # get Lock from authentication
    lock = request.auth

    # get Sync object from db
    sync, created = SyncLockKeys.objects.get_or_create(lock=lock)

    resp = {}
    import datetime
    import time

    for c in range(0, 100):
        # counter for debug purpose
        resp["c"] = c
        resp["t"] = datetime.datetime.isoformat(datetime.datetime.now())

        # check sync state:
        sync.refresh_from_db()
        if not sync.synchronized:
            return {**resp, "event": "sync", "synchronized": sync.synchronized}

        time.sleep(5)

    return {**resp, "event": "no_event"}
